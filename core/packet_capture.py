# ============================================================
# 模块: 数据包捕获器 (packet_capture.py)
# 功能: 实时捕获网络数据包，支持在线抓包和离线 PCAP 回放
# 负责人: 成员A
# ============================================================

import time
import threading
import logging
from typing import Callable, List, Optional, Dict, Any
from collections import deque

logger = logging.getLogger(__name__)

# 尝试导入 Scapy
try:
    from scapy.all import sniff, AsyncSniffer, conf
    from scapy.utils import rdpcap
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logger.warning("Scapy 未安装，数据包捕获功能受限。请运行: pip install scapy")


class PacketCapture:
    """
    数据包捕获器

    支持模式:
    1. 在线模式: 实时从网卡捕获数据包
    2. 离线模式: 从 PCAP 文件回放（用于测试和复盘）

    架构: 生产者-消费者模型
      [抓包线程] → (回调链) → [ProtocolParser] → [检测引擎]

    使用示例:
        capture = PacketCapture(interface='eth0', filter_rule='tcp')
        capture.add_callback(my_detection_function)
        capture.start()
        ...
        capture.stop()
    """

    def __init__(self,
                 interface: Optional[str] = None,
                 filter_rule: str = 'tcp',
                 promiscuous: bool = True,
                 snaplen: int = 65535,
                 timeout: int = 1000,
                 buffer_size: int = 10000):
        """
        Args:
            interface: 网卡接口名
                       - Linux: 'eth0', 'wlan0', 'any'
                       - Windows: None（自动获取）
                       - None: 自动选择默认接口
            filter_rule: BPF 过滤规则
                         'tcp' — 仅 TCP
                         'ip' — 所有 IP
                         'tcp port 80 or tcp port 443' — HTTP/HTTPS
                         'tcp and (port 22 or port 80)' — SSH + HTTP
            promiscuous: 是否启用混杂模式
            snaplen: 捕获快照长度（字节）
            timeout: 超时时间（毫秒）
            buffer_size: 内部缓冲区大小
        """
        if not HAS_SCAPY:
            raise ImportError("需要安装 Scapy: pip install scapy")

        self.interface = interface
        self.filter_rule = filter_rule
        self.promiscuous = promiscuous
        self.snaplen = snaplen
        self.timeout = timeout

        # 回调函数链
        self._callbacks: List[Callable] = []
        self._lock = threading.RLock()

        # 状态
        self._running = False
        self._paused = False
        self._sniffer: Optional[AsyncSniffer] = None

        # 统计
        self.packets_captured = 0
        self.bytes_captured = 0
        self.start_time = 0.0
        self._last_stats_time = 0.0
        self._pps_counter = 0          # 每秒包数计数器
        self._current_pps = 0.0        # 当前包速率

        # 最近包缓冲区（用于 GUI 显示）
        self.recent_packets = deque(maxlen=buffer_size)
        self.recent_alerts = deque(maxlen=buffer_size)

    # ─── 回调管理 ───

    def add_callback(self, callback: Callable[[Any], None]):
        """添加包处理回调函数

        Args:
            callback: 函数签名为 callback(packet: scapy.Packet) -> None
        """
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def remove_callback(self, callback: Callable):
        """移除回调函数"""
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    # ─── 在线捕获 ───

    def start(self):
        """开始实时抓包（异步，不阻塞主线程）"""
        if self._running:
            logger.warning("抓包已在运行中")
            return

        if self.interface is None:
            # 自动获取默认接口
            try:
                self.interface = conf.iface
                logger.info(f"自动选择网络接口: {self.interface}")
            except Exception:
                self.interface = conf.loopback_name
                logger.info(f"使用回环接口: {self.interface}")

        self._running = True
        self._paused = False
        self.start_time = time.time()
        self._last_stats_time = time.time()

        # 使用 AsyncSniffer（不阻塞）
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.filter_rule,
            prn=self._on_packet,
            store=False,           # 不存储所有包以节省内存
            promisc=self.promiscuous,
            timeout=self.timeout,
        )
        self._sniffer.start()
        logger.info(f"抓包已启动: 接口={self.interface}, 过滤={self.filter_rule}")

    def start_blocking(self, count: int = 0):
        """以阻塞模式开始抓包（适用于简单脚本）

        Args:
            count: 抓包数量，0 表示持续抓包
        """
        self._running = True
        self._paused = False
        self.start_time = time.time()
        self._last_stats_time = time.time()

        logger.info(f"开始阻塞抓包: 接口={self.interface}, 过滤={self.filter_rule}")
        sniff(
            iface=self.interface,
            filter=self.filter_rule,
            prn=self._on_packet,
            store=False,
            count=count,
            promisc=self.promiscuous,
        )

    def stop(self):
        """停止抓包"""
        self._running = False

        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None

        elapsed = time.time() - self.start_time if self.start_time else 0
        logger.info(f"抓包已停止: 共处理 {self.packets_captured} 个包, "
                     f"持续 {elapsed:.1f} 秒")

    def pause(self):
        """暂停抓包（回调仍触发但不计数）"""
        self._paused = True
        logger.info("抓包已暂停")

    def resume(self):
        """恢复抓包"""
        self._paused = False
        logger.info("抓包已恢复")

    # ─── PCAP 回放 ───

    def replay_pcap(self, pcap_path: str, speed: float = 1.0) -> Dict[str, Any]:
        """
        回放 PCAP 文件（重放捕获的流量用于测试）

        Args:
            pcap_path: PCAP 文件路径
            speed: 回放速度倍率（1.0 = 原始速度, 0 = 最快）

        Returns:
            dict: 回放统计 {'total': int, 'alerts': int, 'duration': float}
        """
        if not HAS_SCAPY:
            raise ImportError("需要安装 Scapy: pip install scapy")

        logger.info(f"开始回放 PCAP: {pcap_path}")

        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            logger.error(f"读取 PCAP 文件失败: {e}")
            return {'total': 0, 'alerts': 0, 'duration': 0, 'error': str(e)}

        total = len(packets)
        logger.info(f"加载了 {total} 个数据包")

        start_time = time.time()
        prev_pkt_time = None

        for i, pkt in enumerate(packets):
            if not self._running and self._sniffer is None:
                # 回放时 _running 为 False 但没 sniffer，设置标志
                self._running = True

            # 速度控制
            if speed > 0 and hasattr(pkt, 'time') and prev_pkt_time is not None:
                dt = float(pkt.time) - prev_pkt_time
                if dt > 0:
                    time.sleep(dt / speed)

            if hasattr(pkt, 'time'):
                prev_pkt_time = float(pkt.time)

            # 处理包
            self._on_packet(pkt, is_replay=True)

            # 进度日志
            if (i + 1) % 10000 == 0:
                logger.info(f"  回放进度: {i+1}/{total} ({100*(i+1)/total:.1f}%)")

        self._running = False
        duration = time.time() - start_time

        stats = {
            'total': total,
            'duration': duration,
            'pps': total / duration if duration > 0 else 0,
        }
        logger.info(f"PCAP 回放完成: {total} 包, {duration:.1f} 秒, "
                     f"{stats['pps']:.0f} pps")
        return stats

    # ─── 内部处理 ───

    def _on_packet(self, packet, is_replay: bool = False):
        """收到数据包时的内部处理"""
        if self._paused:
            return

        self.packets_captured += 1
        if hasattr(packet, 'len'):
            self.bytes_captured += packet.len

        # PPS 统计
        self._pps_counter += 1
        now = time.time()
        dt = now - self._last_stats_time
        if dt >= 1.0:
            self._current_pps = self._pps_counter / dt
            self._pps_counter = 0
            self._last_stats_time = now

        # 存入缓冲区
        self.recent_packets.append(packet)

        # 触发回调链
        with self._lock:
            for callback in self._callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    logger.debug(f"回调异常: {e}")

    # ─── 状态查询 ───

    @property
    def is_running(self) -> bool:
        return self._running and not self._paused

    @property
    def pps(self) -> float:
        """当前包速率（packets per second）"""
        return self._current_pps

    def get_status(self) -> Dict[str, Any]:
        """获取抓包器状态"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            'running': self._running,
            'paused': self._paused,
            'interface': self.interface,
            'filter': self.filter_rule,
            'packets_captured': self.packets_captured,
            'bytes_captured': self.bytes_captured,
            'pps': self._current_pps,
            'elapsed_seconds': elapsed,
            'callbacks_count': len(self._callbacks),
        }

    @staticmethod
    def list_interfaces() -> List[str]:
        """列出可用网络接口"""
        if HAS_SCAPY:
            from scapy.all import get_if_list
            return get_if_list()
        return []

    @staticmethod
    def get_default_interface() -> Optional[str]:
        """获取默认网络接口"""
        if HAS_SCAPY:
            try:
                return conf.iface
            except Exception:
                return None
        return None
