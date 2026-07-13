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
from typing import Optional

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

        # 7. 数据包捕获器
        capture_cfg = self.config.get('capture', {})
        self.capture = PacketCapture(
            interface=capture_cfg.get('interface'),
            filter_rule=capture_cfg.get('filter_rule', 'tcp'),
            promiscuous=capture_cfg.get('promiscuous', True),
            snaplen=capture_cfg.get('snaplen', 65535),
            timeout=capture_cfg.get('timeout', 1000),
        )

        # 注册回调解耦模块
        self.capture.add_callback(self._on_packet)
        logger.info("[✓] 数据包捕获器")

        logger.info("=" * 50)
        logger.info("IDS 引擎初始化完成")
        logger.info("=" * 50)

    # ─── 核心回调：每个数据包的处理流程 ───

    def _on_packet(self, packet):
        """
        数据包处理回调 — 整个检测流水线
        每个捕获到的包都会经过此函数处理

        流程图:
          packet → ProtocolParser.parse()
                 → TCPReassembler.feed()      (流重组)
                      → MisuseDetector        (流级别检测)
                 → AnomalyDetector.update()   (统计更新)
                      → AnomalyDetector.check()(异常检测)
                 → AlertManager.submit()      (统一告警)
        """
        # Step 1: 协议解析
        parsed = self.parser.parse(packet)
        if parsed is None:
            return

        # Step 2: 误用检测 — 单包匹配
        misuse_alerts = self.misuse_detector.match_packet(parsed)

        # Step 3: TCP 流重组 → 流级别匹配（抗逃避）
        if self.config.get('tcp_reassembly', {}).get('enabled', True):
            stream_data = self.reassembler.feed(parsed)
            if stream_data:
                flow_key = (parsed['src_ip'], parsed['dst_ip'],
                           parsed['src_port'], parsed['dst_port'])
                flow_info = {
                    'src_ip': parsed['src_ip'],
                    'dst_ip': parsed['dst_ip'],
                    'src_port': parsed['src_port'],
                    'dst_port': parsed['dst_port'],
                }
                stream_alerts = self.misuse_detector.match_stream(
                    stream_data, flow_info)
                misuse_alerts.extend(stream_alerts)

        # Step 4: 异常检测更新
        self.anomaly_detector.update(parsed)

        # Step 5: 基线学习更新
        if self.baseline_learner.is_learning():
            self.baseline_learner.feed(parsed)

        # Step 6: 提交误用检测告警
        if misuse_alerts:
            self.alert_mgr.submit_batch(misuse_alerts, source='misuse')

        # Step 7: 定期检查异常（每 5 秒检查一次，避免每个包都检查）
        now = time.time()
        if not hasattr(self, '_last_anomaly_check'):
            self._last_anomaly_check = 0.0
        if now - self._last_anomaly_check >= 5.0:
            self._last_anomaly_check = now
            anomaly_alerts = self.anomaly_detector.check_all()
            if anomaly_alerts:
                self.alert_mgr.submit_batch(anomaly_alerts, source='anomaly')

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
        """回放 PCAP 文件"""
        return self.capture.replay_pcap(pcap_path)

    def get_status(self) -> dict:
        """获取引擎整体状态"""
        capture_status = self.capture.get_status()
        alert_stats = self.alert_mgr.get_realtime_stats()
        return {
            **capture_status,
            'alerts_last_60s': alert_stats,
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
