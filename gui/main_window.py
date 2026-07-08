# ============================================================
# 模块: IDS 主界面 (main_window.py)
# 功能: PyQt5 桌面 GUI，集成所有检测模块
# 负责人: 成员D
# ============================================================

import sys
import time
import threading
import os
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
    from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QMargins
    from PyQt5.QtGui import QFont, QColor, QIcon, QPalette, QPainter
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False
    print("Warning: PyQt5 not installed. Run: pip install pyqt5 pyqtchart")

try:
    from PyQt5.QtChart import (
        QChart, QChartView, QPieSeries, QBarSeries, QBarSet,
        QLineSeries, QValueAxis, QBarCategoryAxis
    )
    HAS_PYQTCHART = True
except ImportError:
    HAS_PYQTCHART = False
    print("Warning: PyQtChart not installed. Run: pip install pyqtchart")


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

        # Chart data buffers (for real-time line chart)
        self._pps_history = deque(maxlen=60)     # 60 seconds of PPS data
        self._bps_history = deque(maxlen=60)     # 60 seconds of BPS data
        self._chart_time_counter = 0

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

        # 实时流量面板 = 折线图 + 文本指标 + TOP攻击来源
        traffic_group = QGroupBox("实时流量")
        traffic_layout = QVBoxLayout(traffic_group)

        # --- 实时 PPS 折线图 ---
        if HAS_PYQTCHART:
            self._pps_series = QLineSeries()
            self._pps_series.setName("PPS")
            self._pps_series.setColor(QColor(0, 188, 212))
            self._pps_chart = QChart()
            self._pps_chart.addSeries(self._pps_series)
            self._pps_chart.setTitle("Real-time Packet Rate")
            self._pps_chart.setAnimationOptions(QChart.SeriesAnimations)
            self._pps_chart.legend().hide()
            self._pps_chart.setMargins(QMargins(0, 0, 0, 0))
            self._pps_axis_x = QValueAxis()
            self._pps_axis_x.setRange(0, 60)
            self._pps_axis_x.setLabelFormat("%d")
            self._pps_axis_x.setTitleText("Seconds ago")
            self._pps_axis_y = QValueAxis()
            self._pps_axis_y.setRange(0, 100)
            self._pps_axis_y.setTitleText("PPS")
            self._pps_chart.addAxis(self._pps_axis_x, Qt.AlignBottom)
            self._pps_chart.addAxis(self._pps_axis_y, Qt.AlignLeft)
            self._pps_series.attachAxis(self._pps_axis_x)
            self._pps_series.attachAxis(self._pps_axis_y)
            self._pps_chart_view = QChartView(self._pps_chart)
            self._pps_chart_view.setRenderHint(QPainter.Antialiasing)
            self._pps_chart_view.setMinimumHeight(180)
            traffic_layout.addWidget(self._pps_chart_view)
        else:
            self._pps_chart_view = None

        # --- 文本指标（紧凑一行）---
        stats_row = QHBoxLayout()
        self.lbl_pps = QLabel("PPS: 0")
        self.lbl_bps = QLabel("BPS: 0")
        self.lbl_conn = QLabel("Conn: 0")
        self.lbl_hosts = QLabel("Hosts: 0")
        self.lbl_streams = QLabel("TCP: 0")
        for lbl in [self.lbl_pps, self.lbl_bps, self.lbl_conn, self.lbl_hosts, self.lbl_streams]:
            lbl.setStyleSheet("font-size: 11px; padding: 2px 6px;")
            stats_row.addWidget(lbl)
        stats_row.addStretch()
        traffic_layout.addLayout(stats_row)

        # --- TOP 攻击来源 ---
        traffic_layout.addWidget(QLabel("TOP Attack Sources:"))
        self.text_top_ip = QTextEdit()
        self.text_top_ip.setReadOnly(True)
        self.text_top_ip.setMaximumHeight(100)
        traffic_layout.addWidget(self.text_top_ip)

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
        """统计分析标签页 — PyQtChart 图表"""
        w = QWidget()
        layout = QVBoxLayout(w)

        # --- 图表行：左饼图 + 右柱状图 ---
        charts_row = QHBoxLayout()

        # 告警严重度饼图
        if HAS_PYQTCHART:
            self._pie_severity = QPieSeries()
            self._pie_chart = QChart()
            self._pie_chart.addSeries(self._pie_severity)
            self._pie_chart.setTitle("Alert Severity Distribution")
            self._pie_chart.setAnimationOptions(QChart.SeriesAnimations)
            self._pie_chart.legend().setAlignment(Qt.AlignRight)
            self._pie_chart_view = QChartView(self._pie_chart)
            self._pie_chart_view.setRenderHint(QPainter.Antialiasing)
            self._pie_chart_view.setMinimumSize(300, 250)
            charts_row.addWidget(self._pie_chart_view)
        else:
            self._pie_chart_view = None

        # 攻击类别柱状图
        if HAS_PYQTCHART:
            self._bar_set = QBarSet("Count")
            self._bar_set.setColor(QColor(255, 152, 0))
            self._bar_series = QBarSeries()
            self._bar_series.append(self._bar_set)
            self._bar_chart = QChart()
            self._bar_chart.addSeries(self._bar_series)
            self._bar_chart.setTitle("Attack Category Distribution")
            self._bar_chart.setAnimationOptions(QChart.SeriesAnimations)
            self._bar_chart.legend().hide()
            self._bar_axis_x = QBarCategoryAxis()
            self._bar_axis_y = QValueAxis()
            self._bar_axis_y.setTitleText("Count")
            self._bar_chart.addAxis(self._bar_axis_x, Qt.AlignBottom)
            self._bar_chart.addAxis(self._bar_axis_y, Qt.AlignLeft)
            self._bar_series.attachAxis(self._bar_axis_x)
            self._bar_series.attachAxis(self._bar_axis_y)
            self._bar_chart_view = QChartView(self._bar_chart)
            self._bar_chart_view.setRenderHint(QPainter.Antialiasing)
            self._bar_chart_view.setMinimumSize(300, 250)
            charts_row.addWidget(self._bar_chart_view)
        else:
            self._bar_chart_view = None

        layout.addLayout(charts_row)

        # --- TOP 攻击来源（保留文本，因为柱状图标签太多时效果差）---
        layout.addWidget(QLabel("TOP 10 Attack Source IPs:"))
        self.text_top_src = QTextEdit()
        self.text_top_src.setReadOnly(True)
        self.text_top_src.setMaximumHeight(150)
        layout.addWidget(self.text_top_src)

        # 刷新按钮
        self.btn_refresh_stats = QPushButton("Refresh Statistics")
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
        self.btn_load_sig.clicked.connect(self._on_view_signature)
        info_bar.addWidget(self.btn_load_sig)
        self.btn_reload_all = QPushButton("重新加载全部")
        self.btn_reload_all.clicked.connect(self._on_reload_signatures)
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
        lbl.setObjectName(f"stat_card_value_{title}")  # 用 objectName 精确查找
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
        layout.addWidget(lbl)
        # 保存引用，避免 findChild 不确定性
        gb._value_label = lbl
        return gb

    @staticmethod
    def _set_card_value(card: QGroupBox, text: str):
        """安全更新统计卡片的值"""
        lbl = getattr(card, '_value_label', None)
        if lbl is not None:
            lbl.setText(text)

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

    def _on_view_signature(self):
        """查看特征库文件内容"""
        import os
        sig_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'signatures')
        fname = self.cmb_sig_file.currentText()
        fpath = os.path.join(sig_dir, fname)
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                self.text_sig.setPlainText(f.read())
            self._log(f"已加载: {fname}")
        except Exception as e:
            self.text_sig.setPlainText(f"读取失败: {e}")
            self._log(f"读取特征库失败: {e}")

    def _on_reload_signatures(self):
        """重新加载所有特征库"""
        if self.engine is None or self.engine.misuse_detector is None:
            self._log("错误: 未注入检测引擎，无法重载特征库")
            return
        try:
            count = self.engine.misuse_detector.reload()
            self._log(f"特征库已重新加载: {count} 条规则")
            QMessageBox.information(self, "重载完成",
                                    f"成功重新加载 {count} 条攻击特征规则")
        except Exception as e:
            self._log(f"重载特征库失败: {e}")
            QMessageBox.warning(self, "重载失败", str(e))

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

            # 更新仪表盘卡片（使用 _value_label 精确引用）
            stats = self.engine.alert_mgr.get_realtime_stats()
            all_stats = self.engine.alert_mgr.get_statistics()
            self._set_card_value(self.card_total_alerts, str(all_stats['total']))
            self._set_card_value(self.card_critical, str(stats.get('critical', 0)))
            self._set_card_value(self.card_high, str(stats.get('high', 0)))
            self._set_card_value(self.card_medium, str(stats.get('medium', 0)))
            self._set_card_value(self.card_total_packets,
                str(status.get('packets_captured', 0)))

            # 更新流量统计
            self.lbl_pps.setText(f"PPS: {status.get('pps', 0):.0f}")
            self.lbl_bps.setText(f"BPS: {status.get('bytes_captured', 0) / max(status.get('elapsed', 1), 1):.0f}")
            self.lbl_conn.setText(f"Conn: 0")
            self.lbl_hosts.setText(f"Hosts: 0")
            self.lbl_streams.setText(f"TCP: 0")

            # 更新 PPS 历史 + 实时折线图
            current_pps = status.get('pps', 0)
            self._pps_history.append(current_pps)
            self._bps_history.append(
                status.get('bytes_captured', 0) / max(status.get('elapsed', 1), 1)
            )
            self._chart_time_counter += 1
            self._update_realtime_chart()

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

        # Auto-refresh statistics charts every 5 seconds
        if self._chart_time_counter % 5 == 0:
            self._refresh_statistics()

    def _update_realtime_chart(self):
        """更新实时 PPS 折线图"""
        if not HAS_PYQTCHART or self._pps_chart_view is None:
            return

        series = self._pps_series
        series.clear()

        # Plot from oldest (left) to newest (right)
        n = len(self._pps_history)
        for i, pps in enumerate(self._pps_history):
            # X axis: seconds ago (0 = now)
            x = -(n - 1 - i)
            series.append(x, pps)

        # Adjust Y axis range
        max_pps = max(self._pps_history) if self._pps_history else 10
        self._pps_axis_y.setRange(0, max(100, max_pps * 1.3))
        self._pps_axis_x.setRange(-n, 5)

    def _refresh_statistics(self):
        """刷新统计面板图表（按按钮或定时器触发）"""
        if self.engine is None:
            return

        stats = self.engine.alert_mgr.get_statistics()

        # 严重度饼图
        if HAS_PYQTCHART and hasattr(self, '_pie_severity'):
            self._pie_severity.clear()
            severity_colors = {
                'critical': QColor(0xd3, 0x2f, 0x2f),
                'high':     QColor(0xf5, 0x7c, 0x00),
                'medium':   QColor(0xfb, 0xc0, 0x2d),
                'low':      QColor(0x19, 0x76, 0xd2),
            }
            for sev, count in sorted(stats.get('by_severity', {}).items(),
                                     key=lambda x: {'critical':0,'high':1,'medium':2,'low':3}.get(x[0],9)):
                if count > 0:
                    sl = self._pie_severity.append(sev, count)
                    if sev in severity_colors:
                        sl.setColor(severity_colors[sev])
            # Add "info" / "other" as grey
            for sev, count in stats.get('by_severity', {}).items():
                if count > 0 and sev not in severity_colors:
                    sl = self._pie_severity.append(sev, count)
                    sl.setColor(QColor(0x9e, 0x9e, 0x9e))

        # 类别柱状图
        if HAS_PYQTCHART and hasattr(self, '_bar_set'):
            cats = sorted(stats.get('by_category', {}).items(),
                          key=lambda x: x[1], reverse=True)
            self._bar_set.remove(0, self._bar_set.count())
            categories = []
            for cat, count in cats[:8]:  # top 8 categories
                self._bar_set.append(count)
                categories.append(cat)
            self._bar_axis_x.clear()
            self._bar_axis_x.append(categories)
            max_val = max([c for _, c in cats[:8]], default=1)
            self._bar_axis_y.setRange(0, max_val * 1.2)

        # TOP 攻击源 IP
        lines = []
        for ip, count in stats.get('top_attack_sources', [])[:10]:
            lines.append(f"  {ip}: {count} attacks")
        self.text_top_src.setText('\n'.join(lines) if lines else "No data")

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
