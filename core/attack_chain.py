# ============================================================
# 模块: 攻击链关联分析 (attack_chain.py)
# 功能: 将单条独立告警串联为完整攻击链路
# 负责人: 成员C
# ============================================================
# 攻击链示例:
#   [10:00:01] 端口扫描 10.0.0.1 → 10.0.0.5:多个端口  (侦察)
#   [10:00:15] SSH暴力破解 10.0.0.1 → 10.0.0.5:22     (入侵)
#   [10:00:30] 后门通信 10.0.0.1 → 10.0.0.5:4444    (C2)
#   → 关联为一条攻击链: 侦察→入侵→C2
# ============================================================

import time
import logging
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# 攻击阶段定义（按典型攻击生命周期排序）
ATTACK_STAGES = [
    'reconnaissance',       # 侦察扫描：端口扫描、横向扫描、指纹探测
    'exploit',              # 漏洞利用：SQL注入、命令注入、文件包含
    'initial_access',       # 初始入侵：暴力破解、WebShell上传
    'persistence',          # 持久化：后门安装、定时任务
    'command_and_control',  # C2通信：C2心跳、DNS隧道
    'lateral_movement',     # 横向扩散：内网扫描、凭证窃取
    'impact',               # 最终目标：数据外泄、DoS攻击
]

# 告警类型 → 攻击阶段映射
ALERT_TYPE_TO_STAGE: Dict[str, str] = {
    # 侦察
    'port_scan': 'reconnaissance',
    'horizontal_scan': 'reconnaissance',
    'scan': 'reconnaissance',
    # 漏洞利用
    'sql_injection': 'exploit',
    'xss': 'exploit',
    'web_attack': 'exploit',
    'command_injection': 'exploit',
    'file_inclusion': 'exploit',
    'ssrf': 'exploit',
    'xxe': 'exploit',
    'ssti': 'exploit',
    # 初始入侵
    'brute_force': 'initial_access',
    'password_guess': 'initial_access',
    'login_attempt': 'initial_access',
    'webshell': 'initial_access',
    'upload': 'initial_access',
    # 持久化 / 后门
    'backdoor': 'persistence',
    'trojan': 'persistence',
    'webshell_access': 'persistence',
    # C2
    'c2': 'command_and_control',
    'c2_beacon': 'command_and_control',
    'dns_tunnel': 'command_and_control',
    'tls_anomaly': 'command_and_control',
    # 横向移动
    'lateral_scan': 'lateral_movement',
    'credential_theft': 'lateral_movement',
    # 影响
    'dos': 'impact',
    'ddos': 'impact',
    'syn_flood': 'impact',
    'high_frequency': 'impact',
    'data_exfil': 'impact',
    # 异常检测
    'ml_anomaly': 'exploit',
    'baseline_deviation': 'exploit',
}

# 严重度数值映射
SEVERITY_ORDER = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

# 阶段严重度颜色（供 GUI / 日志使用）
STAGE_COLORS = {
    'reconnaissance': '\033[36m',       # 青色
    'exploit': '\033[33m',              # 黄色
    'initial_access': '\033[91m',       # 亮红
    'persistence': '\033[95m',          # 紫色
    'command_and_control': '\033[91m',  # 亮红
    'lateral_movement': '\033[93m',     # 橙色
    'impact': '\033[31m',               # 红色
}


@dataclass
class AttackChain:
    """
    一条完整的攻击链

    由同一来源 IP 在时间窗口内的多条告警关联而成，
    按攻击阶段组织。
    """
    chain_id: str                       # 攻击链唯一 ID
    src_ip: str                         # 攻击来源 IP
    dst_ips: Set[str] = field(default_factory=set)   # 涉及的目标 IP
    alerts: List[Dict] = field(default_factory=list)  # 关联的告警列表
    stages_observed: Set[str] = field(default_factory=set)  # 观察到攻击阶段
    first_seen: float = 0.0             # 首次告警时间
    last_seen: float = 0.0              # 末次告警时间
    max_severity: str = 'low'           # 链中最高严重度
    alert_count: int = 0                # 告警总数
    is_closed: bool = False             # 是否已关闭（超时未更新）

    def add_alert(self, alert: Dict):
        """向攻击链添加一条告警"""
        self.alerts.append(alert)
        self.alert_count += 1

        ip = alert.get('dst_ip', '')
        if ip:
            self.dst_ips.add(ip)

        t = alert.get('timestamp', 0)
        if self.first_seen == 0 or t < self.first_seen:
            self.first_seen = t
        if t > self.last_seen:
            self.last_seen = t

        # 更新攻击阶段
        alert_type = alert.get('type', '')
        stage = ALERT_TYPE_TO_STAGE.get(alert_type, 'exploit')
        self.stages_observed.add(stage)

        # 更新最高严重度
        sev = alert.get('severity', 'low')
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(self.max_severity, 0):
            self.max_severity = sev

    def get_stage_sequence(self) -> List[str]:
        """
        按攻击生命周期顺序返回已观察到的阶段

        Returns:
            ['reconnaissance', 'exploit', ...] 按 ATTACK_STAGES 排序
        """
        return [s for s in ATTACK_STAGES if s in self.stages_observed]

    def get_stage_count(self) -> int:
        """已覆盖的攻击阶段数"""
        return len(self.stages_observed)

    def summary(self) -> str:
        """攻击链摘要"""
        stages = '→'.join(self.get_stage_sequence()) if self.stages_observed else 'unknown'
        duration = self.last_seen - self.first_seen if self.first_seen else 0
        color = STAGE_COLORS.get(self.max_severity, '\033[0m')
        reset = '\033[0m'
        return (
            f'{color}[{self.chain_id}]{reset} '
            f'{self.src_ip} → {len(self.dst_ips)} 目标 | '
            f'{stages} | '
            f'{self.alert_count} 条告警 | '
            f'{duration:.0f}s | '
            f'severity={self.max_severity}'
        )

    def to_dict(self) -> Dict:
        """转为字典（供导出/展示）"""
        return {
            'chain_id': self.chain_id,
            'src_ip': self.src_ip,
            'dst_ips': list(self.dst_ips),
            'stages': self.get_stage_sequence(),
            'stage_count': self.get_stage_count(),
            'alert_count': self.alert_count,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'duration': self.last_seen - self.first_seen if self.first_seen else 0,
            'max_severity': self.max_severity,
            'is_closed': self.is_closed,
            'alerts': [
                {
                    'type': a.get('type', ''),
                    'category': a.get('category', ''),
                    'severity': a.get('severity', ''),
                    'description': a.get('description', ''),
                    'src_ip': a.get('src_ip', ''),
                    'dst_ip': a.get('dst_ip', ''),
                    'timestamp': a.get('timestamp', 0),
                }
                for a in self.alerts
            ],
        }


class AttackChainAnalyzer:
    """
    攻击链关联分析器

    功能:
    - 将独立告警按来源 IP 和时间窗口串联为攻击链
    - 自动识别攻击阶段（侦察→入侵→C2→横向扩散）
    - 超时自动关闭旧链
    - 输出完整的攻击链报告

    使用示例:
        analyzer = AttackChainAnalyzer()
        analyzer.feed(alert_dict)       # 喂入告警
        analyzer.feed_batch(alerts)     # 批量喂入
        chains = analyzer.get_chains()  # 获取攻击链
        report = analyzer.get_report()  # 完整报告
    """

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}

        self.time_window = cfg.get('time_window', 300)    # 关联窗口（秒）
        self.min_alerts = cfg.get('min_alerts', 3)         # 最少告警数才构成链
        self.close_timeout = cfg.get('close_timeout', 600) # 关闭超时（秒）

        # 活跃攻击链: src_ip → AttackChain
        self._chains: Dict[str, AttackChain] = {}

        # 已关闭的攻击链（历史记录）
        self._closed_chains: List[AttackChain] = []

        # 告警时间戳索引（用于关闭超时链）
        self._last_alert_time: Dict[str, float] = {}

        # 统计
        self._chain_counter = 0
        self.total_alerts_fed = 0
        self.total_chains_formed = 0

        logger.info(
            f"攻击链分析器已初始化: window={self.time_window}s, "
            f"min_alerts={self.min_alerts}")

    # ─── 数据入口 ───

    def feed(self, alert: Dict) -> Optional[AttackChain]:
        """
        喂入一条告警，尝试归入已有攻击链或新建攻击链。

        Args:
            alert: 5.2 节格式的告警字典

        Returns:
            该告警所属的攻击链（如果满足形成条件），否则 None
        """
        src_ip = alert.get('src_ip', '')
        timestamp = alert.get('timestamp', time.time())

        if not src_ip:
            return None

        self.total_alerts_fed += 1

        # 关闭超时的活跃链
        self._close_expired(timestamp)

        # 查找或创建攻击链
        if src_ip in self._chains:
            chain = self._chains[src_ip]
            # 如果超时未更新，关闭旧链创建新链
            if timestamp - chain.last_seen > self.time_window:
                self._close_chain(src_ip)
                chain = self._create_chain(src_ip, timestamp)
        else:
            chain = self._create_chain(src_ip, timestamp)

        # 添加告警
        chain.add_alert(alert)
        self._last_alert_time[src_ip] = timestamp

        # 如果满足形成条件，标记为已形成
        if chain.alert_count >= self.min_alerts and chain not in self._closed_chains:
            self.total_chains_formed += 1

        logger.debug(f"攻击链更新: {src_ip} → {chain.get_stage_count()} 阶段, "
                     f"{chain.alert_count} 告警")

        return chain if chain.alert_count >= self.min_alerts else None

    def feed_batch(self, alerts: List[Dict]) -> List[AttackChain]:
        """批量喂入告警"""
        results = []
        for alert in alerts:
            chain = self.feed(alert)
            if chain:
                results.append(chain)
        return results

    # ─── 查询 ───

    def get_chains(self, min_stages: int = 2,
                   min_alerts: int = None,
                   severity: str = None) -> List[AttackChain]:
        """
        获取活跃的攻击链，支持筛选。

        Args:
            min_stages: 最少攻击阶段数（默认 2 阶段）
            min_alerts: 最少告警数
            severity:   最低严重度筛选

        Returns:
            符合条件的攻击链列表（按首次发现时间降序）
        """
        chains = list(self._chains.values()) + self._closed_chains
        min_a = min_alerts or self.min_alerts

        filtered = []
        for c in chains:
            if c.get_stage_count() < min_stages:
                continue
            if c.alert_count < min_a:
                continue
            if severity and SEVERITY_ORDER.get(c.max_severity, 0) < SEVERITY_ORDER.get(severity, 0):
                continue
            filtered.append(c)

        # 按最后活跃时间降序排列
        filtered.sort(key=lambda x: x.last_seen, reverse=True)
        return filtered

    def get_chain_by_ip(self, src_ip: str) -> Optional[AttackChain]:
        """按来源 IP 获取活跃的攻击链"""
        return self._chains.get(src_ip)

    def get_all_chains(self) -> List[AttackChain]:
        """获取所有攻击链（活跃+已关闭）"""
        return list(self._chains.values()) + self._closed_chains

    # ─── 攻击链报告 ───

    def get_report(self) -> Dict[str, Any]:
        """获取完整的攻击链分析报告"""
        all_chains = self.get_all_chains()
        active_chains = list(self._chains.values())

        # 按阶段统计
        stage_counts: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)
        top_attackers: Dict[str, int] = defaultdict(int)
        total_stages = 0

        for c in all_chains:
            for s in c.stages_observed:
                stage_counts[s] += 1
            severity_counts[c.max_severity] += 1
            top_attackers[c.src_ip] += c.alert_count
            total_stages += c.get_stage_count()

        # 按告警数排序
        top_attackers_sorted = sorted(
            top_attackers.items(), key=lambda x: x[1], reverse=True)[:10]

        # 找到最长攻击链
        longest_chain = max(all_chains, key=lambda c: c.get_stage_count()) if all_chains else None

        return {
            'total_chains': len(all_chains),
            'active_chains': len(active_chains),
            'total_alerts_fed': self.total_alerts_fed,
            'total_chains_formed': self.total_chains_formed,
            'stages_distribution': dict(stage_counts),
            'severity_distribution': dict(severity_counts),
            'top_attackers': top_attackers_sorted,
            'longest_chain': longest_chain.to_dict() if longest_chain else None,
            'avg_stages_per_chain': total_stages / max(len(all_chains), 1),
            'chains': [c.to_dict() for c in all_chains],
        }

    def print_summary(self):
        """打印攻击链摘要到控制台"""
        all_chains = self.get_all_chains()
        print(f"\n{'='*60}")
        print(f"  攻击链分析报告")
        print(f"  总攻击链: {len(all_chains)} | "
              f"活跃: {len(self._chains)} | "
              f"告警总数: {self.total_alerts_fed}")
        print(f"{'='*60}")

        if not all_chains:
            print("  无攻击链")
            return

        for c in all_chains:
            if c.get_stage_count() >= 2:
                print(f"  {c.summary()}")
            else:
                print(f"  [短链] {c.summary()}")

        print(f"{'='*60}\n")

    # ─── 内部方法 ───

    def _create_chain(self, src_ip: str, timestamp: float) -> AttackChain:
        """创建新的攻击链"""
        self._chain_counter += 1
        chain_id = f"AC-{self._chain_counter:04d}"
        chain = AttackChain(
            chain_id=chain_id,
            src_ip=src_ip,
            first_seen=timestamp,
            last_seen=timestamp,
        )
        self._chains[src_ip] = chain
        logger.debug(f"新攻击链: {chain_id} ({src_ip})")
        return chain

    def _close_chain(self, src_ip: str):
        """关闭指定 IP 的攻击链"""
        if src_ip in self._chains:
            chain = self._chains.pop(src_ip)
            chain.is_closed = True
            self._closed_chains.append(chain)
            logger.debug(f"攻击链已关闭: {chain.chain_id} ({src_ip})")

    def _close_expired(self, now: float):
        """关闭所有超时未更新的攻击链"""
        expired_ips = [
            ip for ip, chain in self._chains.items()
            if now - chain.last_seen > self.close_timeout
        ]
        for ip in expired_ips:
            self._close_chain(ip)

    def shutdown(self):
        """安全关闭：关闭所有活跃链"""
        for ip in list(self._chains.keys()):
            self._close_chain(ip)
        logger.info(f"攻击链分析器已关闭: 共 {len(self._closed_chains)} 条攻击链")
