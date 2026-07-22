# ============================================================
# 模块: 误报自动降噪 (alert_filter.py)
# 功能: 基于基线 + 资产重要性 + 上下文行为过滤无效告警
# 负责人: 成员C（基线降噪 + 资产重要性）+ 成员A（上下文过滤）
# ============================================================
#
# 三层降噪策略:
# 1. 白名单过滤: 白名单 IP 的告警直接丢弃
# 2. 资产重要性: 低重要性资产的告警降级, 高重要性资产升级
# 3. 基线降噪:    当前指标在基线正常范围内 → 降级或丢弃
#
# 使用示例:
#   filter = AlertFilter(assets_config, baseline_profile)
#   filtered = filter.process(alert)
#   stats = filter.get_statistics()
# ============================================================

import time
import ipaddress
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# 严重度排序（用于升降级计算）
SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _ip_in_network(ip_str: str, network_str: str) -> bool:
    """检查 IP 是否在 CIDR 网段内"""
    try:
        ip = ipaddress.ip_address(ip_str)
        if '/' in network_str:
            net = ipaddress.ip_network(network_str, strict=False)
            return ip in net
        return ip_str == network_str
    except ValueError:
        return ip_str == network_str


@dataclass
class FilterStats:
    """降噪过滤器统计"""
    total_input: int = 0
    total_output: int = 0
    dropped_whitelist: int = 0
    downgraded_by_asset: int = 0
    upgraded_by_asset: int = 0
    downgraded_by_baseline: int = 0
    dropped_by_baseline: int = 0
    unchanged: int = 0

    def summary(self) -> Dict:
        return {
            '输入告警数': self.total_input,
            '输出告警数': self.total_output,
            '白名单丢弃': self.dropped_whitelist,
            '资产降级': self.downgraded_by_asset,
            '资产升级': self.upgraded_by_asset,
            '基线降级': self.downgraded_by_baseline,
            '基线丢弃': self.dropped_by_baseline,
            '未变更': self.unchanged,
            '降噪率': f"{(1 - self.total_output / max(self.total_input, 1)) * 100:.1f}%",
        }


class AlertFilter:
    """
    告警降噪过滤器

    将告警在提交到 AlertManager 之前进行过滤和 severity 调整。
    支持白名单、资产重要性、基线偏离三种过滤策略。

    使用方式:
        1. 创建过滤器: 传入资产配置和基线
        2. 逐条处理: filtered = alert_filter.process(alert)
        3. 批量处理: results = alert_filter.process_batch(alerts)
        4. 获取统计: stats = alert_filter.get_statistics()
    """

    def __init__(self,
                 assets_config: Optional[Dict] = None,
                 baseline_profile=None,
                 anomaly_detector_ref=None):
        """
        Args:
            assets_config: config.yaml 中的 assets 配置
            baseline_profile: BaselineProfile 基线数据
            anomaly_detector_ref: AnomalyDetector 引用（懒加载 baseline）
        """
        cfg = assets_config or {}

        # 资产分级配置
        self._critical_networks = cfg.get('critical', [])
        self._important_networks = cfg.get('important', [])
        self._normal_networks = cfg.get('normal', [])
        self._whitelist = cfg.get('whitelist', [])

        # 基线数据（支持懒加载）
        self._baseline = baseline_profile
        self._anomaly_detector_ref = anomaly_detector_ref

        # 统计
        self.stats = FilterStats()

    @property
    def baseline(self):
        """懒加载基线：优先返回最新基线数据"""
        if self._anomaly_detector_ref is not None:
            ref_baseline = getattr(self._anomaly_detector_ref, 'baseline', None)
            if ref_baseline is not None:
                return ref_baseline
        return self._baseline

    @baseline.setter
    def baseline(self, value):
        self._baseline = value

        logger.info(
            f"告警过滤器已初始化: "
            f"{len(self._whitelist)} 白名单, "
            f"{len(self._critical_networks)} 关键网段, "
            f"基线={'有' if self.baseline else '无'}")

    # ─── 核心过滤方法 ───

    def process(self, alert: Dict) -> Optional[Dict]:
        """
        对一条告警执行三层过滤。

        返回调整后的告警字典，或 None（被丢弃）。
        返回的告警会增加以下字段:
        - _filter_original_severity: 原始严重度
        - _filter_reason: 降噪原因
        """
        self.stats.total_input += 1

        alert = dict(alert)  # 不修改原始数据
        src_ip = alert.get('src_ip', '')
        dst_ip = alert.get('dst_ip', '')
        original_severity = alert.get('severity', 'low')
        alert_type = alert.get('type', '')

        # ── 第1层：白名单过滤（仅过滤源 IP，不因目标 IP 在白名单中而忽略攻击）──
        if self._is_whitelisted(src_ip):
            self.stats.dropped_whitelist += 1
            logger.debug(f"白名单丢弃: {src_ip} → {dst_ip} ({alert_type})")
            return None

        # ── 第2层：资产重要性调整 ──
        importance = self._get_asset_importance(dst_ip)
        new_severity = original_severity
        filter_reasons = []

        if importance == 'critical':
            # 高重要性资产 → 升级
            rank = SEVERITY_RANK.get(original_severity, 1)
            new_severity = SEVERITY_ORDER[min(rank + 1, 3)]
            if new_severity != original_severity:
                self.stats.upgraded_by_asset += 1
                filter_reasons.append(f"资产升级: {dst_ip} 为关键资产")
        elif importance == 'normal':
            # 低重要性资产 → 降级
            rank = SEVERITY_RANK.get(original_severity, 1)
            new_severity = SEVERITY_ORDER[max(rank - 1, 0)]
            if new_severity != original_severity:
                self.stats.downgraded_by_asset += 1
                filter_reasons.append(f"资产降级: {dst_ip} 为普通资产")

        # ── 第3层：基线降噪 ──
        if self.baseline is not None:
            baseline_result = self._check_baseline(alert, alert_type)
            if baseline_result == 'drop':
                self.stats.dropped_by_baseline += 1
                logger.debug(f"基线丢弃: {src_ip} → {dst_ip} ({alert_type})")
                return None
            elif baseline_result == 'downgrade':
                rank = SEVERITY_RANK.get(new_severity, 1)
                new_severity = SEVERITY_ORDER[max(rank - 1, 0)]
                self.stats.downgraded_by_baseline += 1
                filter_reasons.append("基线降级: 指标在正常范围内")

        # 记录过滤信息
        if new_severity != original_severity:
            alert['_filter_original_severity'] = original_severity
            alert['severity'] = new_severity

        if filter_reasons:
            alert['_filter_reason'] = '; '.join(filter_reasons)

        if new_severity == original_severity and not filter_reasons:
            self.stats.unchanged += 1

        self.stats.total_output += 1
        return alert

    def process_batch(self, alerts: List[Dict]) -> List[Dict]:
        """批量处理告警，自动跳过 None"""
        results = []
        for alert in alerts:
            filtered = self.process(alert)
            if filtered is not None:
                results.append(filtered)
        return results

    # ─── 白名单检查 ───

    def _is_whitelisted(self, ip: str) -> bool:
        if not ip:
            return False
        for entry in self._whitelist:
            if _ip_in_network(ip, entry):
                return True
        return False

    # ─── 资产重要性 ───

    def _get_asset_importance(self, ip: str) -> str:
        """
        判断目标 IP 的资产重要性等级

        Returns:
            'critical' | 'important' | 'normal' | 'unknown'
        """
        if not ip:
            return 'unknown'

        for net in self._critical_networks:
            if _ip_in_network(ip, net):
                return 'critical'
        for net in self._important_networks:
            if _ip_in_network(ip, net):
                return 'important'
        for net in self._normal_networks:
            if _ip_in_network(ip, net):
                return 'normal'

        return 'unknown'

    # ─── 基线降噪 ───

    def _check_baseline(self, alert: Dict, alert_type: str) -> str:
        """
        基于基线判断告警是否需要降噪。

        Args:
            alert: 告警字典
            alert_type: 告警类型

        Returns:
            'keep':      保持
            'downgrade': 降级
            'drop':      丢弃
        """
        if self.baseline is None:
            return 'keep'

        # 不同告警类型对应不同的基线指标
        detail = alert.get('detail', {})
        baseline = self.baseline

        if alert_type == 'port_scan':
            # 端口扫描：检查唯一端口数是否在基线范围内
            n_ports = detail.get('unique_ports', 0)
            if baseline.avg_unique_ports > 0 and n_ports <= baseline.avg_unique_ports * 1.5:
                return 'downgrade'

        elif alert_type == 'horizontal_scan':
            # 横向扫描：检查唯一 IP 数
            n_ips = detail.get('unique_ips', 0)
            if baseline.avg_unique_ips > 0 and n_ips <= baseline.avg_unique_ips * 1.5:
                return 'downgrade'

        elif alert_type in ('syn_flood', 'high_frequency'):
            # 高频流量：检查包速率
            pps = detail.get('pps', 0)
            if baseline.avg_packet_rate > 0 and pps <= baseline.avg_packet_rate * 2:
                return 'downgrade'

        elif alert_type == 'brute_force':
            # 暴力破解：检查登录尝试是否在基线内
            n_fails = detail.get('login_failures', 0)
            if baseline.avg_login_attempts > 0 and n_fails <= baseline.avg_login_attempts * 1.5:
                return 'downgrade'

        elif alert_type in ('baseline_deviation', 'ml_anomaly'):
            # 基线偏离 / ML 告警：如果连接数在基线范围内，丢弃
            deets = detail.get('deviations', [])
            if not deets:
                return 'drop'

        return 'keep'

    # ─── 统计 ───

    def get_statistics(self) -> Dict:
        """获取过滤统计"""
        return self.stats.summary()

    def print_report(self):
        """打印降噪报告到控制台"""
        s = self.stats
        print(f"\n{'='*50}")
        print(f"  误报自动降噪报告")
        print(f"{'='*50}")
        print(f"  输入告警:      {s.total_input}")
        print(f"  输出告警:      {s.total_output}")
        print(f"  ───────────────────────────")
        print(f"  白名单丢弃:     {s.dropped_whitelist}")
        print(f"  资产降级:       {s.downgraded_by_asset}")
        print(f"  资产升级:       {s.upgraded_by_asset}")
        print(f"  基线降级:       {s.downgraded_by_baseline}")
        print(f"  基线丢弃:       {s.dropped_by_baseline}")
        print(f"  未变更:         {s.unchanged}")
        print(f"  ───────────────────────────")
        print(f"  降噪率:         {s.summary()['降噪率']}")
        print(f"{'='*50}\n")

    def reset_statistics(self):
        """重置统计"""
        self.stats = FilterStats()
