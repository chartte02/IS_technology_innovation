# ============================================================
# 模块: 基线学习器 (baseline_learner.py)
# 功能: 对正常网络流量进行学习，建立行为基线
# 负责人: 成员C
# ============================================================

import json
import time
import threading
import logging
from collections import defaultdict
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class NetworkBaseline:
    """网络行为基线"""
    # 全局指标
    avg_packets_per_second: float = 0.0
    avg_bytes_per_second: float = 0.0
    avg_connections_per_second: float = 0.0

    # 协议分布
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0
    http_ratio: float = 0.0
    dns_ratio: float = 0.0
    other_ratio: float = 0.0

    # 端口分布 TOP 10
    top_ports: List[Dict] = field(default_factory=list)

    # 每台主机的基线
    host_baselines: Dict[str, 'HostBaseline'] = field(default_factory=dict)

    # 时间特征（按小时的流量模式）
    hourly_traffic_pattern: List[float] = field(
        default_factory=lambda: [0.0] * 24)

    # 学习元数据
    learning_start: float = 0.0
    learning_end: float = 0.0
    learning_duration: float = 0.0
    sample_count: int = 0


@dataclass
class HostBaseline:
    """单台主机的行为基线"""
    ip: str = ''
    avg_conn_count: float = 0.0
    avg_packet_rate: float = 0.0
    avg_bytes_out: float = 0.0
    avg_bytes_in: float = 0.0
    avg_unique_ports: float = 0.0
    avg_unique_dst_ips: float = 0.0
    common_ports: List[int] = field(default_factory=list)
    common_dst_ips: List[str] = field(default_factory=list)
    is_server: bool = False


class BaselineLearner:
    """
    基线学习器

    功能:
    1. 在学习模式下采集正常流量指标
    2. 计算统计基线（均值、标准差、百分位）
    3. 识别网络中的服务器和客户端角色
    4. 支持基线的保存与加载
    5. 支持增量更新基线

    使用场景:
    - 部署初期：在确认无攻击的环境下运行 1-24 小时建立基线
    - 持续运行：定期更新基线以适应网络行为变化

    使用示例:
        learner = BaselineLearner()
        learner.start_learning(duration=3600)  # 学习 1 小时
        time.sleep(3600)
        baseline = learner.stop_learning()
        learner.save_baseline('baseline.json')
    """

    def __init__(self, config: Dict = None):
        cfg = config or {}
        self.default_learning_duration = cfg.get(
            'baseline_learning_period', 3600)
        self.sample_interval = cfg.get(
            'bucket_size', 5)  # 采样间隔（秒）

        # 采集数据缓冲区
        self._samples: List[Dict] = []

        # 流状态
        self._learning = False
        self._learning_start = 0.0
        self._lock = threading.RLock()

        # 按小时统计
        self._hourly_packets: Dict[int, int] = defaultdict(int)
        self._hourly_bytes: Dict[int, int] = defaultdict(int)

        # 端口计数（用于 TOP N）
        self._port_counter: Dict[int, int] = defaultdict(int)

        # 每台主机的累加器
        self._host_samples: Dict[str, List[Dict]] = defaultdict(list)

        # 协议计数
        self._proto_counter: Dict[str, int] = defaultdict(int)

        # 结果
        self.baseline: Optional[NetworkBaseline] = None

        # 定时器
        self._running = True
        self._timer = None

    # ─── 学习控制 ───

    def start_learning(self, duration: float = None):
        """
        开始基线学习

        Args:
            duration: 学习时长（秒），None 则手动停止
        """
        self._learning = True
        self._learning_start = time.time()
        self._samples.clear()
        self._host_samples.clear()
        self._port_counter.clear()
        self._proto_counter.clear()

        logger.info(f"基线学习已开始（计划时长: "
                     f"{duration or self.default_learning_duration:.0f} 秒）")

        # 如果指定了时长，启动定时器
        if duration:
            self._timer = threading.Timer(duration, self.stop_learning)
            self._timer.start()

    def stop_learning(self) -> Optional[NetworkBaseline]:
        """停止学习，计算并返回基线"""
        if not self._learning:
            return self.baseline

        self._learning = False
        duration = time.time() - self._learning_start

        if not self._samples:
            logger.warning("基线学习: 无数据样本")
            return None

        self.baseline = self._compute_baseline(duration)
        logger.info(f"基线学习完成: {duration:.0f} 秒, "
                     f"{len(self._samples)} 个样本, "
                     f"{len(self.baseline.host_baselines)} 台主机")
        return self.baseline

    def is_learning(self) -> bool:
        """是否正在学习中"""
        return self._learning

    # ─── 数据采集 ───

    def feed(self, parsed: Dict[str, Any]):
        """
        喂入解析后的数据包用于学习
        （与 AnomalyDetector.update 类似但不做检测）
        """
        if not self._learning:
            return

        src_ip = parsed.get('src_ip', '')
        dst_ip = parsed.get('dst_ip', '')
        dst_port = parsed.get('dst_port', 0)
        payload_len = parsed.get('payload_len', 0)

        # 协议计数
        proto = parsed.get('app_protocol')
        if proto:
            proto_str = proto.value if hasattr(proto, 'value') else str(proto)
            self._proto_counter[proto_str] += 1

        # 端口计数
        self._port_counter[dst_port] += 1

        # 按小时统计
        hour = time.localtime().tm_hour
        self._hourly_packets[hour] += 1
        self._hourly_bytes[hour] += payload_len

        # 主机统计（仅记录源 IP 的发包情况）
        if src_ip:
            if src_ip not in self._host_samples:
                self._host_samples[src_ip] = []
            # 简化：每个包记一条（实际应定期聚合）
            self._host_samples[src_ip].append({
                'timestamp': time.time(),
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'payload_len': payload_len,
            })

    def _sample(self):
        """定期采集快照（由外部定时器调用）"""
        if not self._learning:
            return

        now = time.time()
        total_packets = sum(sum(1 for _ in samples)
                            for samples in self._host_samples.values())
        total_bytes = sum(sum(s.get('payload_len', 0)
                              for s in samples)
                          for samples in self._host_samples.values())

        sample = {
            'timestamp': now,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'host_count': len(self._host_samples),
        }
        self._samples.append(sample)

    # ─── 基线计算 ───

    def _compute_baseline(self, duration: float) -> NetworkBaseline:
        """从采集的数据计算网络基线"""
        nb = NetworkBaseline()
        nb.learning_start = self._learning_start
        nb.learning_end = time.time()
        nb.learning_duration = duration

        # 全局流量指标
        total_packets = sum(s['total_packets'] for s in self._samples)
        total_bytes = sum(s['total_bytes'] for s in self._samples)
        nb.avg_packets_per_second = total_packets / max(duration, 1)
        nb.avg_bytes_per_second = total_bytes / max(duration, 1)
        nb.sample_count = len(self._samples)

        # 协议分布
        total_proto = sum(self._proto_counter.values())
        if total_proto > 0:
            nb.tcp_ratio = self._proto_counter.get('TCP', 0) / total_proto
            nb.udp_ratio = self._proto_counter.get('UDP', 0) / total_proto
            nb.http_ratio = self._proto_counter.get('HTTP', 0) / total_proto
            nb.dns_ratio = self._proto_counter.get('DNS', 0) / total_proto
            known = (nb.tcp_ratio + nb.udp_ratio + nb.http_ratio + nb.dns_ratio)
            nb.other_ratio = max(0, 1.0 - known)

        # TOP 10 端口
        port_sorted = sorted(self._port_counter.items(),
                             key=lambda x: x[1], reverse=True)[:10]
        nb.top_ports = [{'port': p, 'count': c, 'service': self._guess_service(p)}
                        for p, c in port_sorted]

        # 每台主机的基线
        for ip, samples in self._host_samples.items():
            hb = self._compute_host_baseline(ip, samples, duration)
            nb.host_baselines[ip] = hb

        # 按小时流量分布
        total_hourly = sum(self._hourly_packets.values())
        if total_hourly > 0:
            nb.hourly_traffic_pattern = [
                self._hourly_packets.get(h, 0) / total_hourly
                for h in range(24)
            ]

        return nb

    def _compute_host_baseline(self, ip: str, samples: List[Dict],
                                duration: float) -> HostBaseline:
        """计算单台主机的基线"""
        hb = HostBaseline(ip=ip)

        if not samples:
            return hb

        hb.avg_conn_count = len(samples) / max(duration, 1)
        hb.avg_bytes_out = sum(s.get('payload_len', 0)
                                for s in samples) / max(duration, 1)

        # 唯一目标
        unique_dst = set(s['dst_ip'] for s in samples if s.get('dst_ip'))
        unique_ports = set(s['dst_port'] for s in samples)
        hb.avg_unique_ports = len(unique_ports)
        hb.avg_unique_dst_ips = len(unique_dst)

        # 常用端口 TOP 5
        port_count: Dict[int, int] = defaultdict(int)
        for s in samples:
            port_count[s.get('dst_port', 0)] += 1
        hb.common_ports = [p for p, _ in
                            sorted(port_count.items(),
                                   key=lambda x: x[1], reverse=True)[:5]]

        # 常用目标 IP TOP 5
        ip_count: Dict[str, int] = defaultdict(int)
        for s in samples:
            if s.get('dst_ip'):
                ip_count[s['dst_ip']] += 1
        hb.common_dst_ips = [ip for ip, _ in
                              sorted(ip_count.items(),
                                     key=lambda x: x[1], reverse=True)[:5]]

        # 判断是否为服务器（接收连接多于发起）
        # 简化：端口在 1-1023 → 可能是服务器
        hb.is_server = any(p <= 1023 for p in hb.common_ports)

        return hb

    # ─── 基线持久化 ───

    def save_baseline(self, filepath: str):
        """将基线保存为 JSON 文件"""
        if not self.baseline:
            logger.warning("无基线数据可保存")
            return

        data = {
            'avg_packets_per_second': self.baseline.avg_packets_per_second,
            'avg_bytes_per_second': self.baseline.avg_bytes_per_second,
            'tcp_ratio': self.baseline.tcp_ratio,
            'http_ratio': self.baseline.http_ratio,
            'dns_ratio': self.baseline.dns_ratio,
            'top_ports': self.baseline.top_ports,
            'learning_duration': self.baseline.learning_duration,
            'sample_count': self.baseline.sample_count,
            'hourly_traffic_pattern': self.baseline.hourly_traffic_pattern,
            'host_count': len(self.baseline.host_baselines),
            # 主机基线（可选，可能很大）
            'host_baselines': {
                ip: asdict(hb)
                for ip, hb in self.baseline.host_baselines.items()
            },
            'saved_at': time.time(),
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"基线已保存: {filepath}")

    def load_baseline(self, filepath: str) -> Optional[NetworkBaseline]:
        """从 JSON 文件加载基线"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            nb = NetworkBaseline()
            nb.avg_packets_per_second = data.get('avg_packets_per_second', 0)
            nb.avg_bytes_per_second = data.get('avg_bytes_per_second', 0)
            nb.tcp_ratio = data.get('tcp_ratio', 0)
            nb.http_ratio = data.get('http_ratio', 0)
            nb.dns_ratio = data.get('dns_ratio', 0)
            nb.top_ports = data.get('top_ports', [])
            nb.learning_duration = data.get('learning_duration', 0)
            nb.sample_count = data.get('sample_count', 0)
            nb.hourly_traffic_pattern = data.get('hourly_traffic_pattern', [0]*24)

            for ip, hb_data in data.get('host_baselines', {}).items():
                hb = HostBaseline(
                    ip=hb_data.get('ip', ip),
                    avg_conn_count=hb_data.get('avg_conn_count', 0),
                    avg_packet_rate=hb_data.get('avg_packet_rate', 0),
                    avg_bytes_out=hb_data.get('avg_bytes_out', 0),
                    avg_bytes_in=hb_data.get('avg_bytes_in', 0),
                    avg_unique_ports=hb_data.get('avg_unique_ports', 0),
                    avg_unique_dst_ips=hb_data.get('avg_unique_dst_ips', 0),
                    common_ports=hb_data.get('common_ports', []),
                    common_dst_ips=hb_data.get('common_dst_ips', []),
                    is_server=hb_data.get('is_server', False),
                )
                nb.host_baselines[ip] = hb

            self.baseline = nb
            logger.info(f"基线已加载: {filepath} ({len(nb.host_baselines)} 台主机)")
            return nb

        except Exception as e:
            logger.error(f"加载基线失败: {e}")
            return None

    @staticmethod
    def _guess_service(port: int) -> str:
        """根据端口号猜测服务名"""
        services = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
            25: 'SMTP', 53: 'DNS', 3306: 'MySQL', 1433: 'MSSQL',
            3389: 'RDP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            23: 'Telnet', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS',
            995: 'POP3S', 6379: 'Redis', 27017: 'MongoDB',
        }
        return services.get(port, 'Unknown')

    def shutdown(self):
        """安全关闭"""
        self._running = False
        if self._timer and self._timer.is_alive():
            self._timer.cancel()
