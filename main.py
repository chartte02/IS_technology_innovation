#!/usr/bin/env python3
# ============================================================
# 常见网络攻击检测系统 (NADS) — 主入口
# ============================================================
# 运行方式:
#   python main.py                    # 启动 GUI
#   python main.py --console          # 命令行模式
#   python main.py --replay test.pcap # 回放 PCAP
#   python main.py --learn 3600       # 学习基线 1 小时
# ============================================================

import sys
import os
import time
import yaml
import logging
import argparse
from typing import Optional, Dict

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.packet_capture import PacketCapture
from core.protocol_parser import ProtocolParser
from core.tcp_reassembler import TCPStreamReassembler
from core.misuse_detector import SignatureMatcher
from core.anomaly_detector import AnomalyDetector
from core.alert_manager import AlertManager
from core.baseline_learner import BaselineLearner

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('NADS')


# ============================================================
# 集成引擎 — 将所有模块组合为一个完整的 IDS
# ============================================================

class IDSEngine:
    """
    IDS 集成引擎

    模块协作流程:
        [PacketCapture] → [ProtocolParser] → [TCPReassembler]
              ↓                                       ↓
        [MisuseDetector] ←─────────────── [Reassembled Streams]
              ↓
        [AnomalyDetector] ←── [Parsed Packets]
              ↓                    ↓
        [AlertManager] ←───────────┘
              ↓
        [GUI / Console / File]
    """

    def __init__(self, config_path: str = 'config.yaml'):
        """初始化 IDS 引擎

        Args:
            config_path: YAML 配置文件路径
        """
        # ─── 加载配置 ───
        self.config = self._load_config(config_path)

        # ─── 初始化各模块 ───
        logger.info("=" * 50)
        logger.info("初始化 常见网络攻击检测系统 (NADS)...")
        logger.info("=" * 50)

        # 1. 协议解析器
        self.parser = ProtocolParser()
        logger.info("[✓] 协议解析器")

        # 2. TCP 流重组器
        tcp_cfg = self.config.get('tcp_reassembly', {})
        self.reassembler = TCPStreamReassembler(
            timeout=tcp_cfg.get('stream_timeout', 300),
            max_stream_size=tcp_cfg.get('max_stream_size', 10 * 1024 * 1024),
            max_streams=tcp_cfg.get('max_concurrent_streams', 1000),
        )
        logger.info("[✓] TCP 流重组器")

        # 3. 误用检测引擎
        sig_cfg = self.config.get('signatures', {})
        sig_dir = sig_cfg.get('directory', './signatures')
        self.misuse_detector = SignatureMatcher(sig_dir)
        sig_count = self.misuse_detector.load_all()

        # 配置白名单和内网范围（PDF 扩展：误报自动降噪）
        whitelist = sig_cfg.get('whitelist_ips', [])
        if whitelist:
            self.misuse_detector.set_whitelist(whitelist)
        internal_prefixes = sig_cfg.get('internal_prefixes', [])
        if internal_prefixes:
            self.misuse_detector.set_internal_ranges(internal_prefixes)

        logger.info(f"[✓] 误用检测引擎 ({sig_count} 条规则)")

        # 4. 异常检测引擎
        anomaly_cfg = self.config.get('anomaly', {})
        self.anomaly_detector = AnomalyDetector(anomaly_cfg)
        logger.info("[✓] 异常检测引擎")

        # 5. 告警管理器
        alert_cfg = self.config.get('alert', {})
        self.alert_mgr = AlertManager(
            dedup_window=alert_cfg.get('dedup_window', 10),
            max_alerts=alert_cfg.get('max_alerts_in_memory', 10000),
            enable_console=alert_cfg.get('enable_console_output', True),
            enable_json_export=alert_cfg.get('enable_json_export', True),
            json_file=alert_cfg.get('json_export_file', './alerts.json'),
        )
        logger.info("[✓] 告警管理器")

        # 6. 基线学习器
        self.baseline_learner = BaselineLearner(anomaly_cfg)
        logger.info("[✓] 基线学习器")

        # 6.5 告警降噪过滤器（PDF必做：误报自动降噪）
        assets_cfg = self.config.get('assets', {})
        self.alert_filter = None
        if assets_cfg and assets_cfg.get('enabled', True):
            from core.alert_filter import AlertFilter
            self.alert_filter = AlertFilter(
                assets_config=assets_cfg,
                baseline_profile=None,
                anomaly_detector_ref=self.anomaly_detector,
            )
            logger.info("[✓] 告警降噪过滤器")

        # 6.6 攻击链关联分析器（PDF必做：攻击链关联）
        ac_cfg = self.config.get('attack_chain', {})
        self.attack_chain_analyzer = None
        if ac_cfg.get('enabled', False):
            from core.attack_chain import AttackChainAnalyzer
            self.attack_chain_analyzer = AttackChainAnalyzer(ac_cfg)
            logger.info("[✓] 攻击链关联分析器")

        # 6.7 ML 异常检测器（PDF必做：ML识别未知攻击）
        ml_cfg = self.config.get('ml_anomaly', {})
        self.ml_detector = None
        self._ml_trained = False
        if ml_cfg.get('enabled', True):
            try:
                from core.ml_anomaly import MLAnomalyDetector
                self.ml_detector = MLAnomalyDetector(config=ml_cfg)
                logger.info("[✓] ML 异常检测器 (Isolation Forest)")
            except ImportError:
                logger.info("[✗] ML 检测器跳过 (sklearn 未安装)")

        # 7. 数据包捕获器
        capture_cfg = self.config.get('capture', {})
        self.capture = PacketCapture(
            interface=capture_cfg.get('interface'),
            filter_rule=capture_cfg.get('filter_rule', 'tcp'),
            promiscuous=capture_cfg.get('promiscuous', True),
            snaplen=capture_cfg.get('snaplen', 65535),
            timeout=capture_cfg.get('timeout', 1000),
        )

        # 8. TLS 加密流量检测器（成员B）
        from core.tls_detector import TLSDetector
        self.tls_detector = TLSDetector()
        logger.info("[✓] TLS 加密流量检测器 (JA3指纹+证书异常)")

        # ─── 性能监控 ───
        self._perf_stats = {
            'parse':    {'total': 0.0, 'count': 0},
            'misuse':   {'total': 0.0, 'count': 0},
            'reassemble': {'total': 0.0, 'count': 0},
            'anomaly':  {'total': 0.0, 'count': 0},
            'tls':      {'total': 0.0, 'count': 0},
        }

        # ─── 速率限制 (token bucket per IP) ───
        rate_cfg = self.config.get('rate_limit', {})
        self._rate_max_pps = rate_cfg.get('max_pps', 20000)
        self._rate_burst = rate_cfg.get('burst', 1000)
        self._rate_tokens: Dict[str, float] = {}
        self._rate_dropped = 0

        # 注册回调解耦模块
        self.capture.add_callback(self._on_packet)
        logger.info("[✓] 数据包捕获器")

        logger.info("=" * 50)
        logger.info("IDS 引擎初始化完成")
        logger.info("=" * 50)

    # ─── 核心回调：每个数据包的处理流程 ───

    def _on_packet(self, packet):
        """
        数据包处理回调 — 全链路流水线:
          parse → rate_limit → misuse → tls → reassemble → anomaly → alert
        """
        t_start = time.perf_counter()

        # Step 1: 协议解析
        parsed = self.parser.parse(packet)
        self._perf_stats['parse']['total'] += time.perf_counter() - t_start
        self._perf_stats['parse']['count'] += 1
        if parsed is None:
            return

        # 速率限制: token bucket per source IP
        src_ip = parsed.get('src_ip', '')
        if src_ip and self._rate_max_pps > 0:
            now_ts = time.time()
            tokens = self._rate_tokens.get(src_ip, self._rate_burst)
            last_ts = self._rate_tokens.get(f'_ts_{src_ip}', now_ts)
            tokens += (now_ts - last_ts) * self._rate_max_pps
            tokens = min(tokens, self._rate_burst)
            self._rate_tokens[f'_ts_{src_ip}'] = now_ts
            if tokens < 1.0:
                self._rate_dropped += 1
                return
            tokens -= 1.0
            self._rate_tokens[src_ip] = tokens

        # Step 2: 误用检测
        t0 = time.perf_counter()
        misuse_alerts = self.misuse_detector.match_packet(parsed)
        self._perf_stats['misuse']['total'] += time.perf_counter() - t0
        self._perf_stats['misuse']['count'] += 1

        # Step 3: TLS 加密流量检测 (JA3指纹 + 证书异常)
        t0 = time.perf_counter()
        app_proto = parsed.get('app_protocol')
        if app_proto and hasattr(app_proto, 'value') and app_proto.value in ('HTTPS', 'TLS'):
            try:
                payload = parsed.get('payload', b'')
                if payload:
                    # 尝试 ClientHello 分析 (JA3 指纹)
                    result = self.tls_detector.analyze_client_hello(payload)
                    if result.get('is_anomalous'):
                        for anom in result.get('anomalies', []):
                            self.alert_mgr.submit({
                                'signature_id': f"TLS-{anom.get('type','?')}",
                                'signature_name': f"TLS Anomaly: {anom.get('desc','')}",
                                'type': 'tls_anomaly',
                                'category': 'backdoor',
                                'severity': anom.get('severity', 'medium'),
                                'description': anom.get('desc', ''),
                                'src_ip': parsed.get('src_ip', ''),
                                'dst_ip': parsed.get('dst_ip', ''),
                                'src_port': parsed.get('src_port', 0),
                                'dst_port': parsed.get('dst_port', 0),
                                'timestamp': parsed.get('timestamp', time.time()),
                                'detail': {'ja3': result.get('ja3', ''),
                                           'sni': result.get('sni', '')},
                            }, source='tls')
                    # JA3 恶意指纹查询
                    ja3 = result.get('ja3', '')
                    if ja3:
                        info = self.tls_detector.lookup_ja3(ja3)
                        if info:
                            self.alert_mgr.submit({
                                'signature_id': 'TLS-JA3-MALICIOUS',
                                'signature_name':
                                    f"TLS Malicious JA3: {info.get('family', 'Unknown')}",
                                'type': 'tls_anomaly',
                                'category': 'backdoor',
                                'severity': 'critical',
                                'description':
                                    f"TLS fingerprint matches known malware: "
                                    f"{info.get('family', 'Unknown')} "
                                    f"(confidence: {info.get('confidence', 'unknown')})",
                                'src_ip': parsed.get('src_ip', ''),
                                'dst_ip': parsed.get('dst_ip', ''),
                                'src_port': parsed.get('src_port', 0),
                                'dst_port': parsed.get('dst_port', 0),
                                'timestamp': parsed.get('timestamp', time.time()),
                                'detail': {'ja3': ja3,
                                           'family': info.get('family', ''),
                                           'source': info.get('source', '')},
                            }, source='tls')
            except Exception:
                pass  # 非 ClientHello 消息则跳过
        self._perf_stats['tls']['total'] += time.perf_counter() - t0
        self._perf_stats['tls']['count'] += 1

        # Step 4: TCP 流重组
        t0 = time.perf_counter()
        if self.config.get('tcp_reassembly', {}).get('enabled', True):
            stream_data = self.reassembler.feed(parsed)
            if stream_data:
                flow_info = {
                    'src_ip': parsed['src_ip'],
                    'dst_ip': parsed['dst_ip'],
                    'src_port': parsed['src_port'],
                    'dst_port': parsed['dst_port'],
                }
                stream_alerts = self.misuse_detector.match_stream(
                    stream_data, flow_info)
                misuse_alerts.extend(stream_alerts)
        self._perf_stats['reassemble']['total'] += time.perf_counter() - t0
        self._perf_stats['reassemble']['count'] += 1

        # Step 5: 异常检测
        self.anomaly_detector.update(parsed)

        # Step 6: 基线学习
        if self.baseline_learner.is_learning():
            self.baseline_learner.feed(parsed)

        # Step 7: 误报降噪 + 提交误用检测告警
        if misuse_alerts:
            if self.alert_filter:
                misuse_alerts = self.alert_filter.process_batch(misuse_alerts)
            if misuse_alerts:
                self.alert_mgr.submit_batch(misuse_alerts, source='misuse')

        # Step 8: 定期检查异常 + ML + 攻击链（每 5 秒）
        now = time.time()
        if not hasattr(self, '_last_anomaly_check'):
            self._last_anomaly_check = 0.0
        if now - self._last_anomaly_check >= 5.0:
            self._last_anomaly_check = now

            # 8a: 异常检测
            anomaly_alerts = self.anomaly_detector.check_all()
            if anomaly_alerts:
                if self.alert_filter:
                    anomaly_alerts = self.alert_filter.process_batch(anomaly_alerts)
                if anomaly_alerts:
                    submitted = self.alert_mgr.submit_batch(anomaly_alerts, source='anomaly')
                    if self.attack_chain_analyzer and submitted:
                        self.attack_chain_analyzer.feed_batch(submitted)

            # 8b: ML 异常检测 (Isolation Forest)
            if self.ml_detector:
                try:
                    # 积累数据后自动训练
                    ad_stats = self.anomaly_detector.get_statistics()
                    if ad_stats.get('total_hosts_tracked', 0) >= 10 and not self._ml_trained:
                        self.ml_detector.collect_features(self.anomaly_detector)
                        if self.ml_detector.is_ready():
                            self.ml_detector.start_training()
                            self._ml_trained = True
                            logger.info("[ML] 模型训练完成")

                    # 定期预测
                    if self._ml_trained and self.ml_detector.is_ready():
                        ml_alerts = self.ml_detector.predict_all(
                            self.anomaly_detector)
                        if ml_alerts:
                            self.alert_mgr.submit_batch(ml_alerts, source='ml')
                except Exception as e:
                    logger.debug(f"[ML] 检测跳过: {e}")

            # 8c: 攻击链关联 (告警已通过 feed_batch 累积)
            if self.attack_chain_analyzer:
                try:
                    chain_results = self.attack_chain_analyzer.get_chains()
                    if chain_results and chain_results.get('chains'):
                        # 攻击链已形成，保存到引擎属性供 GUI 读取
                        self._attack_chains = chain_results
                except Exception:
                    pass

    # ─── 控制接口 ───

    def start(self, interface: str = None, filter_rule: str = None):
        """启动检测"""
        if interface:
            self.capture.interface = interface
        if filter_rule:
            self.capture.filter_rule = filter_rule
        self.capture.start()
        logger.info(f"IDS 已启动: {self.capture.interface}")

    def stop(self):
        """停止检测"""
        self.capture.stop()
        logger.info("IDS 已停止")

    def replay_pcap(self, pcap_path: str):
        """回放 PCAP 文件（含最终异常检测 + 攻击链刷新）"""
        result = self.capture.replay_pcap(pcap_path)

        # 回放完成后强制一次异常检测（短 PCAP 可能不够 5 秒触发定时检查）
        anomaly_alerts = self.anomaly_detector.check_all()
        if anomaly_alerts:
            if self.alert_filter:
                anomaly_alerts = self.alert_filter.process_batch(anomaly_alerts)
            if anomaly_alerts:
                self.alert_mgr.submit_batch(anomaly_alerts, source='anomaly')
                if self.attack_chain_analyzer:
                    for a in anomaly_alerts:
                        self.attack_chain_analyzer.feed(a)

        # 刷新攻击链
        if self.attack_chain_analyzer:
            try:
                chain_results = self.attack_chain_analyzer.get_chains()
                if chain_results and chain_results.get('chains'):
                    self._attack_chains = chain_results
            except Exception:
                pass

        return result

    def get_status(self) -> dict:
        """获取引擎整体状态（含性能监控）"""
        capture_status = self.capture.get_status()
        alert_stats = self.alert_mgr.get_realtime_stats()
        perf = {}
        for stage, data in self._perf_stats.items():
            if data['count'] > 0:
                perf[stage] = {
                    'avg_us': round(data['total'] / data['count'] * 1e6, 1),
                    'total_ms': round(data['total'] * 1e3, 1),
                    'count': data['count'],
                }

        return {
            **capture_status,
            'alerts_last_60s': alert_stats,
            'pipeline_perf_us': perf,
            'rate_limit_dropped': self._rate_dropped,
        }

    def reload_signatures(self) -> int:
        """
        热更新特征库 — 不重启引擎即可加载最新规则。

        Returns:
            重新加载的规则数
        """
        logger.info("正在热更新特征库...")
        count = self.misuse_detector.reload()
        logger.info(f"特征库热更新完成: {count} 条规则")
        return count

    def enable_auto_reload(self, interval: float = 3.0) -> None:
        """
        启用文件监听自动热加载 — 监控 signatures/ 目录，
        YAML 文件改动后自动调用 reload_signatures()。

        Args:
            interval: 检查间隔（秒）
        """
        import threading

        sig_dir = os.path.abspath(
            self.config.get('signatures', {}).get('directory', './signatures')
        )
        self._auto_reload_enabled = True

        def watcher():
            last_mtimes = {}
            logger.info(f"文件监听已启动: {sig_dir} (间隔 {interval}s)")
            while getattr(self, '_auto_reload_enabled', False):
                try:
                    current = {}
                    for f in os.listdir(sig_dir):
                        if f.endswith('.yaml'):
                            fp = os.path.join(sig_dir, f)
                            current[f] = os.path.getmtime(fp)

                    if last_mtimes and current != last_mtimes:
                        changed = [f for f in current
                                   if current[f] != last_mtimes.get(f, 0)]
                        logger.info(
                            f"检测到特征库变更: {changed}, 自动热更新..."
                        )
                        self.reload_signatures()

                    last_mtimes = current
                except Exception as e:
                    logger.error(f"文件监听异常: {e}")

                time.sleep(interval)

        t = threading.Thread(target=watcher, daemon=True)
        t.start()

    def start_gui(self):
        """启动 GUI 界面"""
        try:
            from gui.main_window import IDSMainWindow
            from PyQt5.QtWidgets import QApplication

            app = QApplication(sys.argv)
            window = IDSMainWindow()
            window.set_engine(self)
            window.show()
            sys.exit(app.exec_())
        except ImportError as e:
            logger.error(f"无法启动 GUI: {e}")
            logger.info("请安装 PyQt5: pip install pyqt5 pyqtchart")
            logger.info("或使用命令行模式: python main.py --console")

    def shutdown(self):
        """安全关闭所有模块"""
        logger.info("正在关闭 IDS...")
        self.stop()
        self.reassembler.shutdown()
        self.anomaly_detector.shutdown()
        self.baseline_learner.shutdown()
        self.alert_mgr.shutdown()
        logger.info("IDS 已安全关闭")

    # ─── 辅助方法 ───

    @staticmethod
    def _load_config(path: str) -> dict:
        """加载 YAML 配置文件"""
        if not os.path.exists(path):
            logger.warning(f"配置文件不存在: {path}, 使用默认配置")
            return {}

        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        if config is None:
            return {}
        return config


# ============================================================
# 命令行入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='常见网络攻击检测系统 (NADS)')

    parser.add_argument('--config', '-c', default='config.yaml',
                        help='配置文件路径 (默认: config.yaml)')
    parser.add_argument('--console', action='store_true',
                        help='命令行模式 (不启动GUI)')
    parser.add_argument('--replay', '-r', type=str,
                        help='回放 PCAP 文件')
    parser.add_argument('--interface', '-i', type=str,
                        help='指定网络接口')
    parser.add_argument('--filter', '-f', type=str, default='tcp',
                        help='BPF 过滤规则 (默认: tcp)')
    parser.add_argument('--learn', '-l', type=int,
                        help='基线学习时长（秒）')

    args = parser.parse_args()

    # 创建引擎
    engine = IDSEngine(config_path=args.config)

    try:
        if args.console:
            # 命令行模式
            logger.info("启动命令行模式...")
            engine.start(
                interface=args.interface,
                filter_rule=args.filter
            )

            if args.learn:
                engine.baseline_learner.start_learning(duration=args.learn)
                logger.info(f"基线学习将持续 {args.learn} 秒...")

            logger.info("按 Ctrl+C 停止")
            while True:
                time.sleep(1)

        elif args.replay:
            # PCAP 回放模式
            logger.info(f"PCAP 回放模式: {args.replay}")
            result = engine.replay_pcap(args.replay)
            logger.info(f"回放结果: {result}")

        else:
            # GUI 模式
            engine.start_gui()

    except KeyboardInterrupt:
        logger.info("\n用户中断")
    finally:
        engine.shutdown()


if __name__ == '__main__':
    main()
