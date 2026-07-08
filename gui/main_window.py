# ============================================================
# 模块: IDS 主界面 (main_window.py)
# 功能: PyQt5 桌面 GUI，集成所有检测模块
# 负责人: 成员D
# ============================================================

import sys
import time
import threading
from collections import deque
from typing import Optional

try:
    from PyQt5.QtWidgets import (
        QMainWindow, QApplication, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QTableWidget, QTableWidgetItem, QPushButton,
        QLabel, QComboBox, QLineEdit, QTextEdit, QSplitter,
        QGroupBox, QGridLayout, QHeaderView, QStatusBar, QMessageBox,
        QMenuBar, QAction, QFileDialog, QProgressBar, QCheckBox,
        QSpinBox, QFormLayout
    )
    from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
    from PyQt5.QtGui import QFont, QColor, QIcon, QPalette
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False
    print("警告: PyQt5 未安装，GUI 功能不可用。运行: pip install pyqt5 pyqtchart")


# ─── 工作线程（在后台运行检测引擎，不阻塞 GUI） ───

class DetectionWorker(QThread):
    """检测引擎工作线程"""
    alert_received = pyqtSignal(object)    # 实时告警信号
    stats_updated = pyqtSignal(object)     # 统计更新信号

    def __init__(self, engine=None):
        super().__init__()
        self.engine = engine
        self._running = False

    def run(self):
        """线程主函数"""
        self._running = True
        while self._running:
            if self.engine:
                try:
                    stats = self.engine.get_status()
                    self.stats_updated.emit(stats)
                except Exception:
                    pass
            self.msleep(1000)  # 1 秒刷新一次

    def stop(self):
        self._running = False


# ─── 主窗口 ───

class IDSMainWindow(QMainWindow):
    """IDS 系统主窗口"""

    def __init__(self):
        if not HAS_PYQT5:
            raise ImportError("需要安装 PyQt5: pip install pyqt5 pyqtchart")

        super().__init__()
        self.engine = None          # 将在外部注入
        self._init_ui()
        self._init_timers()
        self._init_menu()

    def set_engine(self, engine):
        """注入检测引擎实例"""
        self.engine = engine

    # ─── UI 初始化 ───

    def _init_ui(self):
        """初始化界面布局"""
        self.setWindowTitle("常见网络攻击检测系统 (NADS) v1.0")
        self.setMinimumSize(1200, 800)

        # 设置暗色主题
        self._set_dark_theme()

        # 中央 Widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        # ─── 顶部控制栏 ───
        control_bar = self._create_control_bar()
        main_layout.addLayout(control_bar)

        # ─── Tab 标签页 ───
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_dashboard_tab(), "📊 仪表盘")
        self.tabs.addTab(self._create_alert_tab(), "🚨 告警列表")
        self.tabs.addTab(self._create_statistics_tab(), "📈 统计分析")
        self.tabs.addTab(self._create_signature_tab(), "🔍 特征库管理")
        self.tabs.addTab(self._create_log_tab(), "📝 系统日志")
        main_layout.addWidget(self.tabs)

        # ─── 状态栏 ───
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.status_label = QLabel("就绪")
        self.statusBar.addWidget(self.status_label, 1)
        self.pps_label = QLabel("PPS: 0")
        self.statusBar.addPermanentWidget(self.pps_label)
        self.alerts_label = QLabel("告警: 0")
        self.statusBar.addPermanentWidget(self.alerts_label)
        self.uptime_label = QLabel("运行: 00:00:00")
        self.statusBar.addPermanentWidget(self.uptime_label)

    def _create_control_bar(self) -> QHBoxLayout:
        """顶部控制栏"""
        layout = QHBoxLayout()

        # 启动/停止按钮
        self.btn_start = QPushButton("▶ 开始检测")
        self.btn_start.setStyleSheet(
            "QPushButton { background-color: #2e7d32; color: white; "
            "padding: 8px 20px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background-color: #388e3c; }"
        )
        self.btn_start.clicked.connect(self._on_start_stop)
        layout.addWidget(self.btn_start)

        self.btn_pause = QPushButton("⏸ 暂停")
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self._on_pause_resume)
        layout.addWidget(self.btn_pause)

        layout.addSpacing(20)

        # 接口选择
        layout.addWidget(QLabel("网络接口:"))
        self.cmb_interface = QComboBox()
        self.cmb_interface.setMinimumWidth(150)
        self._populate_interfaces()
        layout.addWidget(self.cmb_interface)

        # 过滤规则
        layout.addWidget(QLabel("BPF过滤:"))
        self.edit_filter = QLineEdit("tcp")
        self.edit_filter.setMaximumWidth(200)
        layout.addWidget(self.edit_filter)

        # 基线学习
        layout.addSpacing(20)
        self.btn_learn = QPushButton("📚 开始学习基线")
        self.btn_learn.clicked.connect(self._on_learn_baseline)
        layout.addWidget(self.btn_learn)

        # PCAP 回放
        self.btn_replay = QPushButton("📂 回放PCAP")
        self.btn_replay.clicked.connect(self._on_replay_pcap)
        layout.addWidget(self.btn_replay)

        layout.addStretch()

        # 状态指示
        self.led_status = QLabel("⚪ 已停止")
        layout.addWidget(self.led_status)

        return layout

    def _create_dashboard_tab(self) -> QWidget:
        """仪表盘标签页"""
        w = QWidget()
        layout = QVBoxLayout(w)

        # 统计卡片行
        cards = QHBoxLayout()
        cards.setSpacing(10)

        self.card_total_alerts = self._make_stat_card("总告警数", "0")
        self.card_critical = self._make_stat_card("🔴 严重", "0", "#d32f2f")
        self.card_high = self._make_stat_card("🟠 高危", "0", "#f57c00")
        self.card_medium = self._make_stat_card("🟡 中危", "0", "#fbc02d")
        self.card_total_packets = self._make_stat_card("处理包数", "0")

        cards.addWidget(self.card_total_alerts)
        cards.addWidget(self.card_critical)
        cards.addWidget(self.card_high)
        cards.addWidget(self.card_medium)
        cards.addWidget(self.card_total_packets)
        layout.addLayout(cards)

        # 下方：最近告警 + 实时流量
        splitter = QSplitter(Qt.Horizontal)

        # 最近告警
        alert_group = QGroupBox("最近告警 (实时)")
        alert_layout = QVBoxLayout(alert_group)
        self.table_recent = QTableWidget()
        self.table_recent.setColumnCount(5)
        self.table_recent.setHorizontalHeaderLabels(
            ["时间", "严重度", "类型", "来源IP", "描述"])
        self.table_recent.horizontalHeader().setStretchLastSection(True)
        self.table_recent.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)
        alert_layout.addWidget(self.table_recent)
        splitter.addWidget(alert_group)

        # 实时流量指标
        traffic_group = QGroupBox("实时流量统计")
        traffic_layout = QGridLayout(traffic_group)

        traffic_layout.addWidget(QLabel("包速率:"), 0, 0)
        self.lbl_pps = QLabel("0 pps")
        traffic_layout.addWidget(self.lbl_pps, 0, 1)

        traffic_layout.addWidget(QLabel("字节速率:"), 1, 0)
        self.lbl_bps = QLabel("0 B/s")
        traffic_layout.addWidget(self.lbl_bps, 1, 1)

        traffic_layout.addWidget(QLabel("活跃连接:"), 2, 0)
        self.lbl_conn = QLabel("0")
        traffic_layout.addWidget(self.lbl_conn, 2, 1)

        traffic_layout.addWidget(QLabel("跟踪主机:"), 3, 0)
        self.lbl_hosts = QLabel("0")
        traffic_layout.addWidget(self.lbl_hosts, 3, 1)

        traffic_layout.addWidget(QLabel("TCP流数:"), 4, 0)
        self.lbl_streams = QLabel("0")
        traffic_layout.addWidget(self.lbl_streams, 4, 1)

        traffic_layout.addWidget(QLabel(""), 5, 0)

        # TOP 攻击来源
        traffic_layout.addWidget(QLabel("TOP 攻击来源:"), 6, 0, 1, 2)
        self.text_top_ip = QTextEdit()
        self.text_top_ip.setReadOnly(True)
        self.text_top_ip.setMaximumHeight(100)
        traffic_layout.addWidget(self.text_top_ip, 7, 0, 1, 2)

        splitter.addWidget(traffic_group)
        layout.addWidget(splitter)

        return w

    def _create_alert_tab(self) -> QWidget:
        """告警列表标签页"""
        w = QWidget()
        layout = QVBoxLayout(w)

        # 筛选栏
        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("严重度:"))
        self.cmb_severity = QComboBox()
        self.cmb_severity.addItems(["全部", "critical", "high", "medium", "low"])
        filter_bar.addWidget(self.cmb_severity)

        filter_bar.addWidget(QLabel("类别:"))
        self.cmb_category = QComboBox()
        self.cmb_category.addItems(
            ["全部", "sql_injection", "xss", "web_attack",
             "brute_force", "backdoor", "scan", "dos"])
        filter_bar.addWidget(self.cmb_category)

        self.btn_filter = QPushButton("筛选")
        filter_bar.addWidget(self.btn_filter)
        self.btn_export = QPushButton("导出 JSON")
        filter_bar.addWidget(self.btn_export)
        filter_bar.addStretch()
        layout.addLayout(filter_bar)

        # 告警表格
        self.table_alerts = QTableWidget()
        self.table_alerts.setColumnCount(8)
        self.table_alerts.setHorizontalHeaderLabels(
            ["ID", "时间", "严重度", "来源", "类别", "攻击名称", "源IP", "目标IP:端口"])
        self.table_alerts.horizontalHeader().setStretchLastSection(True)
        self.table_alerts.setAlternatingRowColors(True)
        layout.addWidget(self.table_alerts)

        return w

    def _create_statistics_tab(self) -> QWidget:
        """统计分析标签页"""
        w = QWidget()
        layout = QVBoxLayout(w)

        grid = QGridLayout()

        grid.addWidget(QLabel("按严重度分布:"), 0, 0)
        self.text_severity = QTextEdit()
        self.text_severity.setReadOnly(True)
        self.text_severity.setMaximumHeight(120)
        grid.addWidget(self.text_severity, 0, 1)

        grid.addWidget(QLabel("按类别分布:"), 1, 0)
        self.text_category = QTextEdit()
        self.text_category.setReadOnly(True)
        self.text_category.setMaximumHeight(120)
        grid.addWidget(self.text_category, 1, 1)

        grid.addWidget(QLabel("TOP 10 攻击源IP:"), 2, 0)
        self.text_top_src = QTextEdit()
        self.text_top_src.setReadOnly(True)
        self.text_top_src.setMaximumHeight(200)
        grid.addWidget(self.text_top_src, 2, 1)

        layout.addLayout(grid)

        self.btn_refresh_stats = QPushButton("刷新统计")
        self.btn_refresh_stats.clicked.connect(self._refresh_statistics)
        layout.addWidget(self.btn_refresh_stats)

        return w

    def _create_signature_tab(self) -> QWidget:
        """特征库管理标签页"""
        w = QWidget()
        layout = QVBoxLayout(w)

        # 特征库概览
        info_bar = QHBoxLayout()
        info_bar.addWidget(QLabel("特征库文件:"))
        self.cmb_sig_file = QComboBox()
        self.cmb_sig_file.addItems([
            "sql_injection.yaml", "xss.yaml", "web_attack.yaml",
            "brute_force.yaml", "backdoor.yaml", "scan.yaml", "dos.yaml"
        ])
        info_bar.addWidget(self.cmb_sig_file)
        self.btn_load_sig = QPushButton("查看")
        info_bar.addWidget(self.btn_load_sig)
        self.btn_reload_all = QPushButton("重新加载全部")
        info_bar.addWidget(self.btn_reload_all)
        info_bar.addStretch()
        layout.addLayout(info_bar)

        self.text_sig = QTextEdit()
        self.text_sig.setReadOnly(True)
        self.text_sig.setFont(QFont("Consolas", 10))
        layout.addWidget(self.text_sig)

        return w

    def _create_log_tab(self) -> QWidget:
        """系统日志标签页"""
        w = QWidget()
        layout = QVBoxLayout(w)
        self.text_log = QTextEdit()
        self.text_log.setReadOnly(True)
        self.text_log.setFont(QFont("Consolas", 9))
        layout.addWidget(self.text_log)
        return w

    def _make_stat_card(self, title: str, value: str,
                         color: str = "#1976d2") -> QGroupBox:
        """创建统计卡片"""
        gb = QGroupBox(title)
        gb.setStyleSheet(f"QGroupBox {{ border: 1px solid {color}; "
                         f"border-radius: 6px; padding: 8px; "
                         f"font-weight: bold; }}")
        layout = QVBoxLayout(gb)
        lbl = QLabel(value)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
        layout.addWidget(lbl)
        return gb

    def _set_dark_theme(self):
        """设置暗色主题"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, QColor(220, 220, 220))
        palette.setColor(QPalette.Base, QColor(40, 40, 40))
        palette.setColor(QPalette.AlternateBase, QColor(50, 50, 50))
        palette.setColor(QPalette.Text, QColor(220, 220, 220))
        palette.setColor(QPalette.Button, QColor(50, 50, 50))
        palette.setColor(QPalette.ButtonText, QColor(220, 220, 220))
        palette.setColor(QPalette.Highlight, QColor(25, 118, 210))
        self.setPalette(palette)

    # ─── 定时器 ───

    def _init_timers(self):
        """初始化刷新定时器"""
        self._refresh_timer = QTimer()
        self._refresh_timer.timeout.connect(self._refresh_ui)
        self._refresh_timer.start(1000)  # 每秒刷新

    # ─── 菜单 ───

    def _init_menu(self):
        """初始化菜单栏"""
        menubar = self.menuBar()

        # 文件菜单
        file_menu = menubar.addMenu("文件")
        act_export = QAction("导出告警...", self)
        act_export.triggered.connect(self._on_export_alerts)
        file_menu.addAction(act_export)
        act_exit = QAction("退出", self)
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # 设置菜单
        settings_menu = menubar.addMenu("设置")
        act_config = QAction("配置...", self)
        settings_menu.addAction(act_config)

        # 帮助菜单
        help_menu = menubar.addMenu("帮助")
        act_about = QAction("关于", self)
        act_about.triggered.connect(self._on_about)
        help_menu.addAction(act_about)

    # ─── 槽函数 ───

    def _on_start_stop(self):
        """启动/停止检测"""
        if self.engine is None:
            self._log("错误: 未注入检测引擎")
            return

        if self.engine.capture.is_running:
            self.engine.stop()
            self.btn_start.setText("▶ 开始检测")
            self.btn_start.setStyleSheet(
                "QPushButton { background-color: #2e7d32; color: white; "
                "padding: 8px 20px; border-radius: 4px; font-weight: bold; }")
            self.btn_pause.setEnabled(False)
            self.led_status.setText("⚪ 已停止")
            self._log("检测引擎已停止")
        else:
            self.engine.start(
                interface=self.cmb_interface.currentText(),
                filter_rule=self.edit_filter.text()
            )
            self.btn_start.setText("■ 停止检测")
            self.btn_start.setStyleSheet(
                "QPushButton { background-color: #c62828; color: white; "
                "padding: 8px 20px; border-radius: 4px; font-weight: bold; }")
            self.btn_pause.setEnabled(True)
            self.led_status.setText("🟢 运行中")
            self._log("检测引擎已启动")

    def _on_pause_resume(self):
        """暂停/恢复"""
        if self.engine and self.engine.capture.is_running:
            if self.engine.capture._paused:
                self.engine.capture.resume()
                self.btn_pause.setText("⏸ 暂停")
                self.led_status.setText("🟢 运行中")
            else:
                self.engine.capture.pause()
                self.btn_pause.setText("▶ 恢复")
                self.led_status.setText("🟡 已暂停")

    def _on_learn_baseline(self):
        """基线学习"""
        QMessageBox.information(
            self, "基线学习",
            "基线学习将在后台进行，建议运行至少 1 小时以确保基线准确。\n"
            "学习期间请确保网络处于正常状态（无攻击）。"
        )
        if self.engine:
            self.engine.anomaly_detector.start_learning()
            self._log("基线学习已开始...")

    def _on_replay_pcap(self):
        """回放 PCAP"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "选择 PCAP 文件", "", "PCAP 文件 (*.pcap *.pcapng);;所有文件 (*)"
        )
        if filepath:
            self._log(f"开始回放: {filepath}")
            if self.engine:
                # 在独立线程中回放以避免阻塞 GUI
                thread = threading.Thread(
                    target=self.engine.replay_pcap,
                    args=(filepath,),
                    daemon=True
                )
                thread.start()

    def _on_export_alerts(self):
        """导出告警"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "导出告警", "alerts_export.json", "JSON 文件 (*.json)"
        )
        if filepath and self.engine:
            import json
            alerts = [a.to_dict() for a in self.engine.alert_mgr.alerts]
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, ensure_ascii=False, indent=2)
            self._log(f"告警已导出: {filepath}")

    def _on_about(self):
        """关于对话框"""
        QMessageBox.about(
            self, "关于 NADS",
            "<h2>常见网络攻击检测系统</h2>"
            "<p>Network Attack Detection System v1.0</p>"
            "<p>基于特征串匹配 + 异常行为检测的混合入侵检测系统</p>"
            "<hr>"
            "<p>IS_technology_innovation 课程项目</p>"
        )

    def _refresh_ui(self):
        """定时刷新界面"""
        if self.engine is None:
            return

        try:
            status = self.engine.get_status()

            # 更新仪表盘卡片
            stats = self.engine.alert_mgr.get_realtime_stats()
            all_stats = self.engine.alert_mgr.get_statistics()
            self.card_total_alerts.findChild(QLabel).setText(
                str(all_stats['total']))
            self.card_critical.findChild(QLabel).setText(
                str(stats.get('critical', 0)))
            self.card_high.findChild(QLabel).setText(
                str(stats.get('high', 0)))
            self.card_medium.findChild(QLabel).setText(
                str(stats.get('medium', 0)))
            self.card_total_packets.findChild(QLabel).setText(
                str(status.get('packets_captured', 0)))

            # 更新流量统计
            self.lbl_pps.setText(f"{status.get('pps', 0):.0f} pps")
            self.lbl_bps.setText(f"{status.get('bytes_captured', 0) / max(status.get('elapsed', 1), 1):.0f} B/s")

            # 状态栏
            self.pps_label.setText(f"PPS: {status.get('pps', 0):.0f}")
            self.alerts_label.setText(f"告警: {all_stats['total']}")
            elapsed = status.get('elapsed', 0)
            h, m = divmod(int(elapsed), 3600)
            m, s = divmod(m, 60)
            self.uptime_label.setText(f"运行: {h:02d}:{m:02d}:{s:02d}")

            # 最近告警表
            alerts = list(self.engine.alert_mgr.recent_alerts)
            self.table_recent.setRowCount(min(len(alerts), 20))
            for i, alert in enumerate(alerts[-20:]):
                self.table_recent.setItem(i, 0,
                    QTableWidgetItem(time.strftime('%H:%M:%S',
                                        time.localtime(alert.timestamp))))
                self.table_recent.setItem(i, 1,
                    QTableWidgetItem(alert.severity))
                self.table_recent.setItem(i, 2,
                    QTableWidgetItem(alert.category))
                self.table_recent.setItem(i, 3,
                    QTableWidgetItem(alert.src_ip))
                self.table_recent.setItem(i, 4,
                    QTableWidgetItem(alert.description))

        except Exception as e:
            pass

    def _refresh_statistics(self):
        """刷新统计面板"""
        if self.engine is None:
            return

        stats = self.engine.alert_mgr.get_statistics()

        # 按严重度
        lines = []
        for sev, count in stats['by_severity'].items():
            lines.append(f"  {sev}: {count}")
        self.text_severity.setText('\n'.join(lines) if lines else "无数据")

        # 按类别
        lines = []
        for cat, count in stats['by_category'].items():
            lines.append(f"  {cat}: {count}")
        self.text_category.setText('\n'.join(lines) if lines else "无数据")

        # TOP 攻击源
        lines = []
        for ip, count in stats.get('top_attack_sources', [])[:10]:
            lines.append(f"  {ip}: {count} 次攻击")
        self.text_top_src.setText('\n'.join(lines) if lines else "无数据")

    def _populate_interfaces(self):
        """填充网络接口列表"""
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            self.cmb_interface.addItems(ifaces)
        except Exception:
            self.cmb_interface.addItems(["eth0", "wlan0", "lo"])

    def _log(self, msg: str):
        """追加日志"""
        timestamp = time.strftime('%H:%M:%S')
        self.text_log.append(f"[{timestamp}] {msg}")
