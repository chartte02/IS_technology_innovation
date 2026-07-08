# ============================================================
# 模块: 告警管理器 (alert_manager.py)
# 功能: 统一管理告警的生成、去重、存储、导出和统计
# 负责人: 成员D
# ============================================================

import json
import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """告警数据结构"""
    alert_id: int = 0
    timestamp: float = 0.0
    source: str = ''            # 'misuse' | 'anomaly'
    type: str = ''              # 'sql_injection' | 'xss' | 'port_scan' | ...
    category: str = ''          # 'sql_injection' | 'web_attack' | 'scan' | 'dos' | ...
    severity: str = 'medium'    # 'critical' | 'high' | 'medium' | 'low' | 'info'
    signature_id: str = ''
    signature_name: str = ''
    description: str = ''

    # 网络信息
    src_ip: str = ''
    dst_ip: str = ''
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ''
    matched_pattern: str = ''
    matched_text: str = ''

    # 元数据
    acknowledged: bool = False
    false_positive: bool = False
    detail: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


class AlertManager:
    """
    告警管理器

    功能:
    1. 统一告警入口：接收来自误用检测和异常检测的所有告警
    2. 告警去重：相同来源的同类告警在窗口期内去重
    3. 告警分级：按严重程度分类管理
    4. 持久化：写入日志文件和 JSON 文件
    5. 统计报表：按时间、类型、来源等维度统计
    6. 回调通知：支持向 GUI 推送新告警

    使用示例:
        mgr = AlertManager()
        mgr.submit(alert_dict)
        stats = mgr.get_statistics()
    """

    def __init__(self,
                 dedup_window: float = 10.0,       # 去重时间窗口（秒）
                 max_alerts: int = 10000,           # 最大告警数
                 enable_console: bool = True,
                 enable_json_export: bool = True,
                 json_file: str = './alerts.json',
                 log_file: str = './alerts.log'):
        """
        Args:
            dedup_window: 同类告警去重窗口（秒）
            max_alerts: 内存中最大告警数
            enable_console: 是否输出到控制台
            enable_json_export: 是否导出 JSON
            json_file: JSON 导出文件路径
            log_file: 日志文件路径
        """
        self.dedup_window = dedup_window
        self.max_alerts = max_alerts
        self.enable_console = enable_console
        self.enable_json_export = enable_json_export
        self.json_file = json_file

        # 告警存储
        self.alerts: List[Alert] = []
        self._alert_counter = 0
        self._lock = threading.RLock()

        # 去重缓存: (signature_id, src_ip, dst_ip) → last_alert_time
        self._dedup_cache: Dict[tuple, float] = {}

        # 统计数据
        self._stats = {
            'total': 0,
            'by_severity': defaultdict(int),
            'by_category': defaultdict(int),
            'by_type': defaultdict(int),
            'by_source': defaultdict(int),
            'by_src_ip': defaultdict(int),      # TOP 攻击来源
            'by_hour': defaultdict(int),         # 按小时分布
        }

        # 回调函数（用于 GUI 实时更新）
        self._callbacks: List[callable] = []

        # 最近告警（用于 GUI 展示）
        self.recent_alerts = deque(maxlen=500)

        # 配置文件日志
        if log_file:
            fh = logging.FileHandler(log_file, encoding='utf-8')
            fh.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s'))
            logger.addHandler(fh)

    # ─── 告警提交 ───

    def submit(self, raw_alert: Dict[str, Any],
               source: str = 'misuse') -> Optional[Alert]:
        """
        提交一条告警

        Args:
            raw_alert: 原始告警字典（来自检测引擎）
            source: 告警来源 'misuse' | 'anomaly'

        Returns:
            Alert | None: 如果去重过滤返回 None，否则返回 Alert 对象
        """
        # 去重检查
        dedup_key = (
            raw_alert.get('signature_id', raw_alert.get('type', '')),
            raw_alert.get('src_ip', ''),
            raw_alert.get('dst_ip', ''),
        )
        now = time.time()

        if dedup_key in self._dedup_cache:
            last_time = self._dedup_cache[dedup_key]
            if now - last_time < self.dedup_window:
                return None  # 窗口期内重复告警，丢弃

        self._dedup_cache[dedup_key] = now

        # 构造 Alert 对象
        with self._lock:
            self._alert_counter += 1
            alert = Alert(
                alert_id=self._alert_counter,
                timestamp=now,
                source=source,
                type=raw_alert.get('type', raw_alert.get('category', 'unknown')),
                category=raw_alert.get('category', 'unknown'),
                severity=raw_alert.get('severity', 'medium'),
                signature_id=raw_alert.get('signature_id', ''),
                signature_name=raw_alert.get('signature_name', ''),
                description=raw_alert.get('description', ''),
                src_ip=raw_alert.get('src_ip', ''),
                dst_ip=raw_alert.get('dst_ip', ''),
                src_port=raw_alert.get('src_port', 0),
                dst_port=raw_alert.get('dst_port', 0),
                protocol=raw_alert.get('app_protocol', ''),
                matched_pattern=raw_alert.get('matched_pattern', ''),
                matched_text=raw_alert.get('matched_text', ''),
                detail=raw_alert.get('detail', {}),
            )

            # 存储
            self.alerts.append(alert)
            self.recent_alerts.append(alert)

            # 限制数量
            if len(self.alerts) > self.max_alerts:
                self.alerts = self.alerts[-self.max_alerts:]

        # 更新统计
        self._update_stats(alert)

        # 输出
        if self.enable_console:
            self._print_alert(alert)

        # JSON 导出
        if self.enable_json_export:
            self._export_json(alert)

        # 通知回调
        self._notify_callbacks(alert)

        return alert

    def submit_batch(self, alerts: List[Dict],
                     source: str = 'misuse') -> List[Alert]:
        """批量提交告警"""
        results = []
        for raw in alerts:
            alert = self.submit(raw, source=source)
            if alert:
                results.append(alert)
        return results

    # ─── 告警查询 ───

    def get_alerts(self, limit: int = 100,
                   severity: str = None,
                   category: str = None) -> List[Alert]:
        """获取告警列表（支持筛选）"""
        with self._lock:
            results = self.alerts
            if severity:
                results = [a for a in results if a.severity == severity]
            if category:
                results = [a for a in results if a.category == category]
            return results[-limit:]

    def get_alert_by_id(self, alert_id: int) -> Optional[Alert]:
        """根据 ID 获取告警"""
        with self._lock:
            for a in self.alerts:
                if a.alert_id == alert_id:
                    return a
        return None

    def acknowledge(self, alert_id: int):
        """确认告警"""
        with self._lock:
            for a in self.alerts:
                if a.alert_id == alert_id:
                    a.acknowledged = True
                    break

    def mark_false_positive(self, alert_id: int):
        """标记误报"""
        with self._lock:
            for a in self.alerts:
                if a.alert_id == alert_id:
                    a.false_positive = True
                    break

    def clear_all(self):
        """清除所有告警"""
        with self._lock:
            self.alerts.clear()
            self.recent_alerts.clear()
            self._dedup_cache.clear()

    # ─── 统计 ───

    def get_statistics(self,
                       hours: int = 24) -> Dict[str, Any]:
        """获取告警统计报告"""
        with self._lock:
            cutoff = time.time() - hours * 3600
            recent = [a for a in self.alerts if a.timestamp >= cutoff]

            by_severity = defaultdict(int)
            by_category = defaultdict(int)
            by_source = defaultdict(int)
            top_ip: Dict[str, int] = defaultdict(int)

            for a in recent:
                by_severity[a.severity] += 1
                by_category[a.category] += 1
                by_source[a.source] += 1
                if a.src_ip:
                    top_ip[a.src_ip] += 1

            # TOP 10 攻击来源
            top_ip_sorted = sorted(top_ip.items(),
                                   key=lambda x: x[1], reverse=True)[:10]

            return {
                'total': len(recent),
                'total_all': len(self.alerts),
                'period_hours': hours,
                'by_severity': dict(by_severity),
                'by_category': dict(by_category),
                'by_source': dict(by_source),
                'top_attack_sources': top_ip_sorted,
                'false_positives': sum(1 for a in recent if a.false_positive),
                'acknowledged': sum(1 for a in recent if a.acknowledged),
            }

    def get_realtime_stats(self) -> Dict[str, Any]:
        """获取实时统计（最近60秒）"""
        cutoff = time.time() - 60
        with self._lock:
            recent = [a for a in self.alerts if a.timestamp >= cutoff]
            return {
                'last_60s_total': len(recent),
                'critical': sum(1 for a in recent if a.severity == 'critical'),
                'high': sum(1 for a in recent if a.severity == 'high'),
                'medium': sum(1 for a in recent if a.severity == 'medium'),
                'low': sum(1 for a in recent if a.severity == 'low'),
            }

    # ─── 内部方法 ───

    def _update_stats(self, alert: Alert):
        """更新统计计数器"""
        self._stats['total'] += 1
        self._stats['by_severity'][alert.severity] += 1
        self._stats['by_category'][alert.category] += 1
        self._stats['by_type'][alert.type] += 1
        self._stats['by_source'][alert.source] += 1
        if alert.src_ip:
            self._stats['by_src_ip'][alert.src_ip] += 1

    def _print_alert(self, alert: Alert):
        """格式化输出告警到控制台"""
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': '⚪',
        }
        emoji = severity_emoji.get(alert.severity, '❓')
        direction = f"{alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port}"
        print(f"{emoji} [{alert.severity.upper()}] [{alert.category}] "
              f"{alert.signature_name or alert.description} | {direction}")

    def _export_json(self, alert: Alert):
        """追加导出到 JSON 文件"""
        try:
            # 读取现有数据
            try:
                with open(self.json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                data = []

            # 追加新告警
            data.append(alert.to_dict())

            # 限制大小（最多保留 10000 条）
            if len(data) > 10000:
                data = data[-10000:]

            with open(self.json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"JSON 导出失败: {e}")

    # ─── 回调管理（用于 GUI 通信） ───

    def add_callback(self, callback):
        """添加告警回调（GUI 可注册此回调接收实时告警）"""
        self._callbacks.append(callback)

    def remove_callback(self, callback):
        """移除告警回调"""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def _notify_callbacks(self, alert: Alert):
        """通知所有注册的回调函数"""
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.debug(f"告警回调异常: {e}")

    # ─── 清理 ───

    def shutdown(self):
        """安全关闭告警管理器"""
        stats = self.get_statistics()
        logger.info(f"告警管理器关闭: 总计 {stats['total_all']} 条告警")
