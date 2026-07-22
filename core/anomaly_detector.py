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

import numpy as np

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


class AdaptiveThresholdManager:
    """
    动态阈值自适应管理器 (μ±kσ 方案)

    持续观察各主机的流量指标，用均值(μ)和标准差(σ)建模正常行为，
    动态计算检测阈值: threshold = μ + k * σ

    优势:
    - 自动适应不同网络环境，无需手动调参
    - 流量模式变化后阈值自动跟随
    - 针对 slow drift（缓慢漂移）天然稳健

    使用方式:
        adaptive = AdaptiveThresholdManager(k=3.0, min_samples=10)
        adaptive.observe('port_scan', 15)   # 观察一个值
        th = adaptive.get_threshold('port_scan', default=20)
    """

    def __init__(self, k: float = 3.0, min_samples: int = 10,
                 enabled: bool = True, window_size: int = 200):
        """
        Args:
            k: 标准差倍数，3 = μ+3σ（99.7% 正常值在此范围内）
            min_samples: 开始计算动态阈值的最小样本数
            enabled: 是否启用自适应
            window_size: 滑动窗口大小，保留最近 N 个观察值
        """
        self.k = k
        self.min_samples = min_samples
        self.enabled = enabled
        self.window_size = window_size

        # metric_name → list of observed values
        self._observations: Dict[str, List[float]] = defaultdict(list)
        # metric_name → 当前 (mean, std) 缓存
        self._computed: Dict[str, Tuple[float, float]] = {}

        logger.info(
            f"自适应阈值管理器: enabled={enabled}, "
            f"k={k}, min_samples={min_samples}")

    # ─── 观察与计算 ───

    def observe(self, metric: str, value: float):
        """观察一个指标值，用于更新统计"""
        obs = self._observations[metric]
        obs.append(value)
        # 滑动窗口：超出后丢弃最早的一半，保持统计新鲜度
        if len(obs) > self.window_size:
            self._observations[metric] = obs[-(self.window_size // 2):]
        self._recompute(metric)

    def observe_batch(self, metric: str, values: List[float]):
        """批量观察"""
        for v in values:
            self.observe(metric, v)

    def _recompute(self, metric: str):
        """重新计算均值和样本标准差"""
        values = self._observations[metric]
        if len(values) >= 2:
            mean = float(np.mean(values))
            std = float(np.std(values, ddof=1))
            self._computed[metric] = (mean, std)

    # ─── 阈值查询 ───

    def get_threshold(self, metric: str, default: float = 20.0,
                      lower_bound: float = None, upper_bound: float = None) -> float:
        """
        获取动态阈值。

        Returns:
            threshold = mean + k * std，但受 lower_bound / upper_bound 约束。
            数据不足时返回 default。
        """
        if not self.enabled or metric not in self._computed:
            return default

        mean, std = self._computed[metric]
        n = len(self._observations.get(metric, []))
        if n < self.min_samples:
            return default

        threshold = mean + self.k * std

        # 约束边界
        if lower_bound is not None:
            threshold = max(threshold, lower_bound)
        if upper_bound is not None:
            threshold = min(threshold, upper_bound)

        return threshold

    def get_deviation(self, metric: str, value: float) -> float:
        """
        获取当前值相对于基线的偏差倍数。
        Returns: (value - mean) / max(std, 1e-10)
        """
        if metric in self._computed:
            mean, std = self._computed[metric]
            return (value - mean) / max(std, 1e-10)
        return 0.0

    # ─── 统计与重置 ───

    def get_statistics(self) -> Dict[str, Any]:
        """获取所有指标的自适应阈值统计"""
        stats = {}
        for metric in sorted(self._observations.keys()):
            obs = self._observations[metric]
            if metric in self._computed:
                mean, std = self._computed[metric]
                stats[metric] = {
                    'mean': round(mean, 2),
                    'std': round(std, 2),
                    'samples': len(obs),
                    'k': self.k,
                    'dynamic_threshold': round(mean + self.k * std, 2),
                    'threshold_range': (
                        round(mean - self.k * std, 2),
                        round(mean + self.k * std, 2),
                    ),
                }
            else:
                stats[metric] = {
                    'samples': len(obs),
                    'status': 'collecting',
                }
        return stats

    def reset(self, metric: str = None):
        """重置观察数据"""
        if metric:
            self._observations.pop(metric, None)
            self._computed.pop(metric, None)
        else:
            self._observations.clear()
            self._computed.clear()


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

        # ─── 自适应阈值（选做：μ±kσ 动态阈值） ───
        adaptive_cfg = cfg.get('adaptive_threshold', {})
        self.adaptive = AdaptiveThresholdManager(
            k=adaptive_cfg.get('k', 3.0),
            min_samples=adaptive_cfg.get('min_samples', 10),
            enabled=adaptive_cfg.get('enabled', True),
            window_size=adaptive_cfg.get('window_size', 200),
        )
        if self.adaptive.enabled:
            logger.info(
                f"自适应阈值已启用: μ±{self.adaptive.k}σ, "
                f"min_samples={self.adaptive.min_samples}")

        # ─── ML 异常检测 ───
        two_stage_enabled = cfg.get('two_stage', {}).get('enabled', False)
        ml_enabled = cfg.get('ml_detection', {}).get('enabled', False)
        self.ml_detector = None
        self.two_stage = None

        if two_stage_enabled:
            from core.ml_anomaly import TwoStageDetector
            ts_cfg = cfg.get('two_stage', {})
            self.two_stage = TwoStageDetector(ts_cfg)
            logger.info("两阶段检测器已启用 (IF + RF)")

            # 两阶段模式下，RF 需要喂养标签样本
            self._two_stage_feeding = ts_cfg.get('feeding', True)
            self._two_stage_pos_feeds = 0
            self._two_stage_neg_feeds = 0
            self._two_stage_min_feed = ts_cfg.get('min_feed', 50)
        elif ml_enabled:
            from core.ml_anomaly import MLAnomalyDetector
            ml_cfg = cfg.get('ml_detection', {})
            self.ml_detector = MLAnomalyDetector(ml_cfg)
            logger.info("ML 异常检测器已启用 (Isolation Forest)")
        else:
            self.ml_detector = None

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

            # ML 特征收集（训练模式下）
            if self.ml_detector and self.ml_detector.is_ready() is False:
                if not hasattr(self, '_ml_collected'):
                    self._ml_collected = set()
                if src_ip not in self._ml_collected:
                    self.ml_detector.collect_features(src_stats)
                    self._ml_collected.add(src_ip)
                    # 达到样本数后自动训练
                    if len(self._ml_collected) >= (getattr(self.ml_detector, 'min_samples', 20)):
                        self.ml_detector.train()

            # 两阶段模式: 自动收集无监督特征
            if self.two_stage and self.two_stage.if_detector.is_ready() is False:
                if not hasattr(self, '_ts_collected'):
                    self._ts_collected = set()
                if src_ip not in self._ts_collected:
                    self.two_stage.if_detector.collect_features(src_stats)
                    self._ts_collected.add(src_ip)
                    if len(self._ts_collected) >= (
                            getattr(self.two_stage.if_detector, 'min_samples', 20)):
                        self.two_stage.if_detector.train()

            # 更新目标 IP 统计（收包情况）
            dst_stats = self._get_or_create_host(dst_ip)
            dst_stats.packet_count += 1
            dst_stats.bytes_received += payload_len
            dst_stats.last_seen = timestamp

    # ─── 两阶段模式 ───

    def feed_two_stage(self, alert: Dict, host_stats=None):
        """
        向两阶段检测器喂标签数据。
        规则引擎触发的告警 → 正样本；无告警 → 负样本。

        应在 check_all() 后调用，传入规则引擎已确认的告警信息。
        """
        if self.two_stage is None:
            return
        if not self._two_stage_feeding:
            return

        src_ip = alert.get('src_ip', '')
        if not src_ip or src_ip in self.whitelist_ips:
            return

        stats = host_stats or self._stats.get(src_ip)
        if stats is None:
            return

        # 规则引擎触发的告警 = 正样本（真攻击）
        source = alert.get('_source', '')
        is_attack = source == 'misuse' or alert.get('severity') in ('critical', 'high')

        self.two_stage.feed_labeled(stats, is_attack=True if is_attack else False)
        if is_attack:
            self._two_stage_pos_feeds += 1
        else:
            self._two_stage_neg_feeds += 1

        # 当正负样本都充足时自动训练 RF
        total = self._two_stage_pos_feeds + self._two_stage_neg_feeds
        if (total >= self._two_stage_min_feed
                and not self.two_stage._rf_trained
                and self._two_stage_pos_feeds >= 10
                and self._two_stage_neg_feeds >= 10):
            logger.info(
                f"两阶段喂养完成: 正={self._two_stage_pos_feeds}, "
                f"负={self._two_stage_neg_feeds}, 开始 RF 训练...")
            self.two_stage.train_rf()

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

        # 7. 两阶段 ML 异常检测 (IF + RF)
        if self.two_stage:
            verdict, conf = self.two_stage.predict(stats)
            if verdict in ('attack', 'unsure'):
                severity = 'medium' if verdict == 'attack' else 'low'
                alerts.append({
                    'type': 'two_stage_anomaly',
                    'category': 'anomaly',
                    'severity': severity,
                    'src_ip': ip,
                    'description': (
                        f'两阶段检测: {verdict} (置信度: {conf:.2f})'
                        if verdict == 'attack' else
                        f'IF 异常但 RF 未确认 (分数: {conf:.2f})'
                    ),
                    'detail': {
                        'verdict': verdict,
                        'confidence': round(conf, 4),
                        'two_stage': True,
                    },
                    'timestamp': time.time(),
                })

        # 8. 单阶段 ML 异常检测（IF 模式）
        if self.ml_detector and self.ml_detector.is_ready():
            ml_pred = self.ml_detector.predict(host_stats=stats, ip=ip, use_cache=True)
            if ml_pred == -1:
                score = self.ml_detector.decision_score(stats)
                alerts.append({
                    'type': 'ml_anomaly',
                    'category': 'anomaly',
                    'severity': 'medium',
                    'src_ip': ip,
                    'description': f'ML 模型标记为异常 (分数: {score:.4f})',
                    'detail': {
                        'ml_score': score,
                        'features': self.ml_detector.get_feature_summary(stats),
                    },
                    'timestamp': time.time(),
                })

        return alerts

    def _check_port_scan(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测端口扫描（支持自适应阈值）"""
        unique_ports = len(stats.unique_dst_ports)
        # 观察并获取动态阈值
        self.adaptive.observe('port_scan', unique_ports)
        threshold = self.adaptive.get_threshold(
            'port_scan', default=self.port_scan_threshold,
            lower_bound=3,  # 至少 3 个端口
        )
        if unique_ports >= threshold:
            return {
                'type': 'port_scan',
                'category': 'scan',
                'severity': 'medium',
                'src_ip': ip,
                'description': f'端口扫描: {unique_ports} 个不同端口 '
                               f'(阈值: {threshold:.0f}, '
                               f'原始: {self.port_scan_threshold})',
                'detail': {'unique_ports': unique_ports,
                            'syn_count': stats.syn_count,
                            'conn_count': stats.conn_count,
                            'dynamic_threshold': round(threshold, 1)},
                'timestamp': time.time(),
            }
        return None

    def _check_horizontal_scan(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测横向扫描（支持自适应阈值）"""
        unique_ips = len(stats.unique_dst_ips)
        self.adaptive.observe('horizontal_scan', unique_ips)
        threshold = self.adaptive.get_threshold(
            'horizontal_scan', default=self.horizontal_scan_threshold,
            lower_bound=3,
        )
        if unique_ips >= threshold:
            return {
                'type': 'horizontal_scan',
                'category': 'scan',
                'severity': 'high',
                'src_ip': ip,
                'description': f'横向扫描: 访问 {unique_ips} 个不同目标 IP '
                               f'(阈值: {threshold:.0f}, '
                               f'原始: {self.horizontal_scan_threshold})',
                'detail': {'unique_ips': unique_ips,
                            'dynamic_threshold': round(threshold, 1)},
                'timestamp': time.time(),
            }
        return None

    def _check_syn_flood(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测 SYN Flood 攻击（支持自适应阈值）"""
        syn_count = stats.syn_count
        self.adaptive.observe('syn_flood', syn_count)
        threshold = self.adaptive.get_threshold(
            'syn_flood', default=self.syn_threshold,
            lower_bound=10,
            upper_bound=100000,
        )
        if syn_count >= threshold:
            ratio = syn_count / max(stats.conn_count, 1)
            if ratio >= self.syn_ratio:
                return {
                    'type': 'syn_flood',
                    'category': 'dos',
                    'severity': 'critical',
                    'src_ip': ip,
                    'description': f'SYN Flood: {syn_count} SYN 包 '
                                   f'(占比 {ratio:.0%}, '
                                   f'阈值: {threshold:.0f})',
                    'detail': {'syn_count': syn_count,
                                'total_conn': stats.conn_count,
                                'ratio': ratio,
                                'dynamic_threshold': round(threshold, 1)},
                    'timestamp': time.time(),
                }
        return None

    def _check_brute_force(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测暴力破解（支持自适应阈值）"""
        login_failures = stats.login_failures
        self.adaptive.observe('brute_force', login_failures)
        threshold = self.adaptive.get_threshold(
            'brute_force', default=self.brute_force_threshold,
            lower_bound=2,
        )
        if login_failures >= threshold:
            return {
                'type': 'brute_force',
                'category': 'brute_force',
                'severity': 'high',
                'src_ip': ip,
                'description': f'暴力破解: {login_failures} 次登录失败 '
                               f'(阈值: {threshold:.0f}, '
                               f'原始: {self.brute_force_threshold})',
                'detail': {'login_failures': login_failures,
                            'dynamic_threshold': round(threshold, 1)},
                'timestamp': time.time(),
            }
        return None

    def _check_high_frequency(self, ip: str, stats: HostStats) -> Optional[Dict]:
        """检测高频流量（可能的 DDoS，支持自适应阈值）"""
        duration = max(time.time() - self.window_start, 1)
        pps = stats.packet_count / duration
        self.adaptive.observe('high_frequency', pps)
        threshold = self.adaptive.get_threshold(
            'high_frequency', default=self.pps_threshold,
            lower_bound=100,  # floor: prevent false positives from normal browsing (5-50 pps)
        )
        if pps >= threshold:
            return {
                'type': 'high_frequency',
                'category': 'dos',
                'severity': 'critical',
                'src_ip': ip,
                'description': f'异常高频流量: {pps:.0f} pps '
                               f'(阈值: {threshold:.0f}, '
                               f'原始: {self.pps_threshold})',
                'detail': {'pps': round(pps, 1),
                            'packets': stats.packet_count,
                            'duration': round(duration, 1),
                            'dynamic_threshold': round(threshold, 1)},
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
        """停止学习并生成基线，同时训练 ML 模型"""
        self._learning = False
        duration = time.time() - self._learning_start
        self.baseline = self._compute_baseline(duration)
        logger.info(f"基线学习完成 (持续 {duration:.0f} 秒): "
                     f"平均连接数={self.baseline.avg_conn_count:.1f}")

        # 自动训练 ML 模型
        if self.ml_detector:
            self._collect_ml_training_data()
            self.ml_detector.train()

        return self.baseline

    def _collect_ml_training_data(self):
        """将当前所有主机的统计作为 ML 训练数据收集"""
        if not self.ml_detector:
            return
        with self._lock:
            for stats in self._stats.values():
                self.ml_detector.collect_features(stats)

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
            stats = {
                'total_hosts_tracked': len(self._stats),
                'total_packets_processed': self.total_processed,
                'total_alerts': self.total_alerts,
                'window_start': self.window_start,
                'has_baseline': self.baseline is not None,
            }
            if self.ml_detector:
                stats['ml'] = self.ml_detector.get_statistics()
            if self.adaptive and self.adaptive.enabled:
                stats['adaptive_threshold'] = self.adaptive.get_statistics()
            return stats

    def get_adaptive_statistics(self) -> Dict[str, Any]:
        """获取自适应阈值统计详情"""
        return self.adaptive.get_statistics() if self.adaptive else {}

    def shutdown(self):
        """安全关闭"""
        self._running = False
        self._timer.join(timeout=5)
