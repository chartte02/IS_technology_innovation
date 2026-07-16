# ============================================================
# 模块: 异常检测引擎 (anomaly_detector.py)
# 功能: 基于统计基线偏离检测异常行为
# 负责人: 成员C
# ============================================================

import time
import threading
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Any, Set, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class HostStats:
    """单台主机的实时统计指标"""
    ip: str

    # ─── 连接统计 ───
    conn_count: int = 0                    # 当前窗口内连接数
    syn_count: int = 0                     # SYN 包计数
    syn_ack_count: int = 0                 # SYN+ACK 计数（判断扫描方向）

    # ─── 多样性统计 ───
    unique_dst_ips: Set[str] = field(default_factory=set)
    unique_dst_ports: Set[int] = field(default_factory=set)
    unique_src_ports: Set[int] = field(default_factory=set)

    # ─── 流量统计 ───
    bytes_sent: int = 0                    # 发出字节数
    bytes_received: int = 0                # 接收字节数
    packet_count: int = 0                  # 包计数

    # ─── 登录相关 ───
    login_attempts: int = 0                # 登录尝试（成功+失败）
    login_failures: int = 0                # 登录失败

    # ─── 时间 ───
    first_seen: float = 0.0
    last_seen: float = 0.0

    def reset(self):
        """重置计数器（每个窗口周期后调用）"""
        self.conn_count = 0
        self.syn_count = 0
        self.syn_ack_count = 0
        self.unique_dst_ips.clear()
        self.unique_dst_ports.clear()
        self.unique_src_ports.clear()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.packet_count = 0
        self.login_attempts = 0
        self.login_failures = 0


class BaselineProfile:
    """正常行为基线（通过学习期数据建立）"""

    def __init__(self):
        self.avg_conn_count: float = 0.0
        self.avg_packet_rate: float = 0.0   # 每秒包数
        self.avg_bytes_rate: float = 0.0    # 每秒字节数
        self.avg_unique_ports: float = 0.0  # 平均不同端口数
        self.avg_unique_ips: float = 0.0    # 平均不同目标 IP 数
        self.avg_login_attempts: float = 0.0
        self.max_conn_count: float = 0.0
        self.max_packet_rate: float = 0.0
        self.max_unique_ports: float = 0.0
        self.learning_duration: float = 0.0


class AnomalyDetector:
    """
    异常检测引擎

    检测策略:
    1. 端口扫描: 短时间内访问大量不同端口
    2. 横向扫描: 短时间内访问大量不同 IP
    3. SYN Flood: 异常高的 SYN 包比例
    4. DDoS 检测: 异常高的包速率
    5. 暴力破解: 短时间内大量登录失败
    6. 异常外联: 连接陌生 IP（配合威胁情报）
    7. 数据外泄: 异常大量上行流量

    使用示例:
        detector = AnomalyDetector(config={'port_scan': {...}})
        detector.update(parsed_packet)
        alerts = detector.check_all()
    """

    def __init__(self, config: Dict = None): #type: ignore
        # ─── 配置 ───
        cfg = config or {}
        self.time_window = cfg.get('time_window', 60)          # 统计窗口（秒）
        self.bucket_size = cfg.get('bucket_size', 5)            # 时间桶粒度

        # 阈值配置
        self.port_scan_threshold = cfg.get('port_scan', {}).get(
            'unique_ports_threshold', 20)
        self.horizontal_scan_threshold = cfg.get('horizontal_scan', {}).get(
            'unique_ips_threshold', 50)
        self.brute_force_threshold = cfg.get('brute_force', {}).get(
            'login_fail_threshold', 5)
        self.syn_threshold = cfg.get('syn_flood', {}).get(
            'syn_threshold', 1000)
        self.syn_ratio = cfg.get('syn_flood', {}).get(
            'syn_ratio', 0.8)
        self.pps_threshold = cfg.get('ddos', {}).get(
            'pps_threshold', 10000)

        # ─── 状态 ───
        # IP → HostStats（按窗口分桶）
        self._stats: Dict[str, HostStats] = defaultdict(HostStats) #type: ignore
        self._lock = threading.RLock()

        # 基线
        self.baseline: Optional[BaselineProfile] = None
        self._baseline_data: List[Dict] = []  # 学习期收集的数据
        self._learning = False
        self._learning_start = 0.0

        # 白名单
        self.whitelist_ips: Set[str] = set()
        self.whitelist_ports: Set[int] = set()

        # 统计
        self.total_processed = 0
        self.total_alerts = 0
        self.window_start = time.time()

        # 定时器：定期重置窗口
        self._running = True
        self._timer = threading.Thread(target=self._window_timer, daemon=True)
        self._timer.start()

    # ─── 数据采集 ───

    def update(self, parsed: Dict[str, Any]) -> None:
        """
        根据一个已解析的数据包更新统计指标

        Args:
            parsed: ProtocolParser.parse() 的返回结果
        """
        src_ip = parsed.get('src_ip', '')
        dst_ip = parsed.get('dst_ip', '')
        src_port = parsed.get('src_port', 0)
        dst_port = parsed.get('dst_port', 0)
        flags = parsed.get('flags', 0)
        payload_len = parsed.get('payload_len', 0)
        timestamp = parsed.get('timestamp') or time.time()

        if not src_ip:
            return

        with self._lock:
            self.total_processed += 1

            # 更新源 IP 统计
            src_stats = self._get_or_create_host(src_ip)
            src_stats.conn_count += 1
            src_stats.packet_count += 1
            src_stats.bytes_sent += payload_len
            src_stats.unique_dst_ips.add(dst_ip)
            src_stats.unique_dst_ports.add(dst_port)
            src_stats.last_seen = timestamp

            # SYN 计数
            from core.protocol_parser import ProtocolParser
            if ProtocolParser.is_syn_packet(flags):
                src_stats.syn_count += 1
            if (flags & 0x02) and (flags & 0x10):  # SYN+ACK
                src_stats.syn_ack_count += 1

            # 登录检测（检查是否含登录失败特征）
            payload = parsed.get('payload', b'')
            if payload:
                self._check_login_pattern(src_stats, payload)

            # 更新目标 IP 统计（收包情况）
            dst_stats = self._get_or_create_host(dst_ip)
            dst_stats.packet_count += 1
            dst_stats.bytes_received += payload_len
            dst_stats.last_seen = timestamp

    # ─── 异常检测 ───

    def check_all(self) -> List[Dict[str, Any]]:
        """
        对所有主机的当前统计进行检查，返回异常告警列表
        """
        alerts = []

        with self._lock:
            for ip, stats in self._stats.items():
                # 跳过白名单
                if ip in self.whitelist_ips:
                    continue

                host_alerts = self._check_host(ip, stats)
                alerts.extend(host_alerts)

        self.total_alerts += len(alerts)
        return alerts

    def _check_host(self, ip: str, stats: HostStats) -> List[Dict]:
        """对单台主机进行全面的异常检查"""
        alerts = []

        # 1. 端口扫描检测
        ps = self._check_port_scan(ip, stats)
        if ps:
            alerts.append(ps)

        # 2. 横向扫描检测
        hs = self._check_horizontal_scan(ip, stats)
        if hs:
            alerts.append(hs)

        # 3. SYN Flood 检测
        sf = self._check_syn_flood(ip, stats)
        if sf:
            alerts.append(sf)

        # 4. 暴力破解检测
        bf = self._check_brute_force(ip, stats)
        if bf:
            alerts.append(bf)

        # 5. DDoS / 高频流量检测
        dd = self._check_high_frequency(ip, stats)
        if dd:
            alerts.append(dd)

        # 6. 基线偏离检测（如果有基线）
        if self.baseline:
            bd = self._check_baseline_deviation(ip, stats)
            if bd:
                alerts.append(bd)

        return alerts

    def _check_port_scan(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测端口扫描"""
        unique_ports = len(stats.unique_dst_ports)
        if unique_ports >= self.port_scan_threshold:
            return {
                'type': 'port_scan',
                'category': 'scan',
                'severity': 'medium',
                'src_ip': ip,
                'description': f'端口扫描: {unique_ports} 个不同端口 (阈值: {self.port_scan_threshold})',
                'detail': {'unique_ports': unique_ports,
                            'syn_count': stats.syn_count,
                            'conn_count': stats.conn_count},
                'timestamp': time.time(),
            }
        return None

    def _check_horizontal_scan(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测横向扫描（同一端口访问大量 IP）"""
        unique_ips = len(stats.unique_dst_ips)
        if unique_ips >= self.horizontal_scan_threshold:
            return {
                'type': 'horizontal_scan',
                'category': 'scan',
                'severity': 'high',
                'src_ip': ip,
                'description': f'横向扫描: 访问 {unique_ips} 个不同目标 IP (阈值: {self.horizontal_scan_threshold})',
                'detail': {'unique_ips': unique_ips},
                'timestamp': time.time(),
            }
        return None

    def _check_syn_flood(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测 SYN Flood 攻击"""
        if stats.syn_count >= self.syn_threshold:
            ratio = stats.syn_count / max(stats.conn_count, 1)
            if ratio >= self.syn_ratio:
                return {
                    'type': 'syn_flood',
                    'category': 'dos',
                    'severity': 'critical',
                    'src_ip': ip,
                    'description': f'SYN Flood: {stats.syn_count} SYN 包 (占比 {ratio:.0%})',
                    'detail': {'syn_count': stats.syn_count,
                                'total_conn': stats.conn_count,
                                'ratio': ratio},
                    'timestamp': time.time(),
                }
        return None

    def _check_brute_force(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测暴力破解"""
        if stats.login_failures >= self.brute_force_threshold:
            return {
                'type': 'brute_force',
                'category': 'brute_force',
                'severity': 'high',
                'src_ip': ip,
                'description': f'暴力破解: {stats.login_failures} 次登录失败 (阈值: {self.brute_force_threshold})',
                'detail': {'login_failures': stats.login_failures},
                'timestamp': time.time(),
            }
        return None

    def _check_high_frequency(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测高频流量（可能的 DDoS）"""
        duration = max(time.time() - self.window_start, 1)
        pps = stats.packet_count / duration
        if pps >= self.pps_threshold:
            return {
                'type': 'high_frequency',
                'category': 'dos',
                'severity': 'critical',
                'src_ip': ip,
                'description': f'异常高频流量: {pps:.0f} pps (阈值: {self.pps_threshold})',
                'detail': {'pps': pps, 'packets': stats.packet_count,
                            'duration': duration},
                'timestamp': time.time(),
            }
        return None

    def _check_baseline_deviation(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测基线偏离"""
        if not self.baseline:
            return None

        deviations = []

        # 检查端口多样性偏离
        port_ratio = len(stats.unique_dst_ports) / max(self.baseline.avg_unique_ports, 1)
        if port_ratio > 3.0:
            deviations.append(
                f'端口数异常: {len(stats.unique_dst_ports)} '
                f'(基线均值: {self.baseline.avg_unique_ports:.1f})')

        # 检查连接数偏离
        if self.baseline.avg_conn_count > 0:
            conn_ratio = stats.conn_count / max(self.baseline.avg_conn_count, 1)
            if conn_ratio > 5.0:
                deviations.append(
                    f'连接数异常: {stats.conn_count} '
                    f'(基线均值: {self.baseline.avg_conn_count:.1f})')

        if deviations:
            return {
                'type': 'baseline_deviation',
                'category': 'anomaly',
                'severity': 'medium',
                'src_ip': ip,
                'description': '; '.join(deviations),
                'detail': {'deviations': deviations},
                'timestamp': time.time(),
            }
        return None

    # ─── 基线学习 ───

    def start_learning(self):
        """开始基线学习"""
        self._learning = True
        self._learning_start = time.time()
        self._baseline_data.clear()
        logger.info("基线学习已开始...")

    def stop_learning(self) -> BaselineProfile:
        """停止学习并生成基线"""
        self._learning = False
        duration = time.time() - self._learning_start
        self.baseline = self._compute_baseline(duration)
        logger.info(f"基线学习完成 (持续 {duration:.0f} 秒): "
                     f"平均连接数={self.baseline.avg_conn_count:.1f}")
        return self.baseline

    def _compute_baseline(self, duration: float) -> BaselineProfile:
        """从学习数据计算基线"""
        bp = BaselineProfile()
        bp.learning_duration = duration

        if not self._baseline_data:
            return bp

        n = len(self._baseline_data)
        bp.avg_conn_count = sum(d['conn_count'] for d in self._baseline_data) / n
        bp.avg_packet_rate = sum(d['packet_count'] for d in self._baseline_data) / duration
        bp.avg_bytes_rate = sum(d['bytes_sent'] + d['bytes_received']
                                 for d in self._baseline_data) / duration
        bp.avg_unique_ports = sum(d['unique_ports'] for d in self._baseline_data) / n
        bp.avg_unique_ips = sum(d['unique_ips'] for d in self._baseline_data) / n
        bp.avg_login_attempts = sum(d['login_attempts'] for d in self._baseline_data) / n
        bp.max_conn_count = max((d['conn_count'] for d in self._baseline_data), default=0)
        bp.max_packet_rate = max((d['packet_count'] for d in self._baseline_data),
                                  default=0) / max(duration / n, 1)
        bp.max_unique_ports = max((d['unique_ports'] for d in self._baseline_data), default=0)

        return bp

    def _snapshot_for_baseline(self):
        """采集当前快照用于基线学习"""
        if not self._learning:
            return

        total_conn = 0
        total_pkt = 0
        total_bytes_sent = 0
        total_bytes_received = 0
        total_unique_ports = 0
        total_unique_ips = 0
        total_login = 0

        unique_ips_set = set()
        unique_ports_set = set()

        with self._lock:
            for ip, stats in self._stats.items():
                total_conn += stats.conn_count
                total_pkt += stats.packet_count
                total_bytes_sent += stats.bytes_sent
                total_bytes_received += stats.bytes_received
                total_login += stats.login_attempts
                unique_ips_set.update(stats.unique_dst_ips)
                unique_ports_set.update(stats.unique_dst_ports)

            total_unique_ips = len(unique_ips_set)
            total_unique_ports = len(unique_ports_set)

        self._baseline_data.append({
            'conn_count': total_conn,
            'packet_count': total_pkt,
            'bytes_sent': total_bytes_sent,
            'bytes_received': total_bytes_received,
            'unique_ports': total_unique_ports,
            'unique_ips': total_unique_ips,
            'login_attempts': total_login,
        })

    # ─── 辅助方法 ───

    def _get_or_create_host(self, ip: str) -> HostStats:
        """获取或创建主机统计对象"""
        if ip not in self._stats:
            self._stats[ip] = HostStats(ip=ip)
            self._stats[ip].first_seen = time.time()
        return self._stats[ip]

    def _check_login_pattern(self, stats: HostStats, payload: bytes):
        """检查载荷中是否包含登录失败的模式"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            # SSH
            if 'permission denied' in payload_str or \
               'authentication failed' in payload_str or \
               'invalid user' in payload_str or \
               'failed password' in payload_str:
                stats.login_attempts += 1
                stats.login_failures += 1
            # FTP
            if '530 login incorrect' in payload_str or \
               '530 user' in payload_str:
                stats.login_attempts += 1
                stats.login_failures += 1
            # HTTP 401
            if '401 unauthorized' in payload_str:
                stats.login_attempts += 1
                stats.login_failures += 1
            # Telnet
            if 'login incorrect' in payload_str or \
               'login failed' in payload_str:
                stats.login_attempts += 1
                stats.login_failures += 1
            # RDP / SMB
            if 'logon failure' in payload_str:
                stats.login_attempts += 1
                stats.login_failures += 1
        except Exception:
            pass

    def _window_timer(self):
        """窗口定时器：定期重置统计和采集基线快照"""
        while self._running:
            time.sleep(self.bucket_size)

            # 采集基线快照
            self._snapshot_for_baseline()

            # 检查是否需要重置窗口
            if time.time() - self.window_start >= self.time_window:
                with self._lock:
                    for stats in self._stats.values():
                        stats.reset()
                    self.window_start = time.time()
                logger.debug(f"异常检测窗口已重置 ({time.time():.0f})")

    def add_whitelist(self, ip: str = None, port: int = None):#type: ignore
        """添加白名单"""
        if ip:
            self.whitelist_ips.add(ip)
        if port:
            self.whitelist_ports.add(port)

    def remove_whitelist(self, ip: str = None, port: int = None):#type: ignore
        """移除白名单"""
        if ip:
            self.whitelist_ips.discard(ip)
        if port:
            self.whitelist_ports.discard(port)

    def get_stats_by_ip(self, ip: str) -> Optional[HostStats]:
        """获取指定 IP 的统计信息"""
        with self._lock:
            return self._stats.get(ip)

    def get_top_talkers(self, n: int = 10) -> List[Tuple[str, int]]:
        """获取流量最高的 N 个 IP"""
        with self._lock:
            top = sorted(self._stats.items(),
                        key=lambda x: x[1].packet_count, reverse=True)
            return [(ip, s.packet_count) for ip, s in top[:n]]

    def get_statistics(self) -> Dict[str, Any]:
        """获取异常检测统计"""
        with self._lock:
            return {
                'total_hosts_tracked': len(self._stats),
                'total_packets_processed': self.total_processed,
                'total_alerts': self.total_alerts,
                'window_start': self.window_start,
                'has_baseline': self.baseline is not None,
            }

    def shutdown(self):
        """安全关闭"""
        self._running = False
        self._timer.join(timeout=5)
