# ============================================================
# 模块: IDS 主界面 (main_window.py)
# 功能: PyQt5 桌面 GUI，Apple 风格设计，集成所有检测模块
# 负责人: 成员D
# 版本: v2.0 — Apple-style redesign (sidebar + card layout)
# 调试: 修改主题 → 编辑 gui/theme.py, 重启 GUI 即生效
#      修改布局 → 编辑本文件, 各 _create_*_tab() 方法
#      修改逻辑 → 编辑 _on_*/_refresh_* 槽函数
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
        QTableWidget, QTableWidgetItem, QPushButton,
        QLabel, QComboBox, QLineEdit, QTextEdit, QSplitter,
        QGroupBox, QGridLayout, QHeaderView, QStatusBar, QMessageBox,
        QMenuBar, QAction, QFileDialog, QProgressBar, QCheckBox,
        QSpinBox, QFormLayout, QStackedWidget, QListWidget,
        QListWidgetItem, QFrame, QSizePolicy,
    )
    from PyQt5.QtCore import (
        Qt, QTimer, pyqtSignal, QThread, QMargins, QSize,
    )
    from PyQt5.QtGui import QFont, QColor, QIcon, QPalette, QPainter
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False
    print("Warning: PyQt5 not installed. Run: pip install pyqt5 pyqtchart")

try:
    from PyQt5.QtChart import (
        QChart, QChartView, QPieSeries, QBarSeries, QBarSet,
        QLineSeries, QValueAxis, QBarCategoryAxis,
    )
    HAS_PYQTCHART = True
except ImportError:
    HAS_PYQTCHART = False
    print("Warning: PyQtChart not installed. Run: pip install pyqtchart")

# 主题系统 (独立模块, 可单独调试)
from gui.theme import LIGHT_THEME, DARK_THEME, build_stylesheet


# ═══════════════════════════════════════════════════════════════
# 主窗口
# ═══════════════════════════════════════════════════════════════

class IDSMainWindow(QMainWindow):
    """IDS 系统主窗口 — Apple 风格设计"""

    def __init__(self):
        if not HAS_PYQT5:
            raise ImportError("需要安装 PyQt5: pip install pyqt5 pyqtchart")

        super().__init__()
        self.engine = None
        self._current_theme = 'light'

        # Chart data buffers (for real-time line chart)
        self._pps_history = deque(maxlen=60)
        self._bps_history = deque(maxlen=60)
        self._chart_time_counter = 0

        self._init_ui()
        self._init_timers()
        self._init_menu()

    def set_engine(self, engine):
        """注入检测引擎实例"""
        self.engine = engine

    # ─── UI 初始化 ───

    def _init_ui(self):
        """初始化界面布局 — Apple 风格: 侧边栏 + 堆叠内容页"""
        self.setWindowTitle("NADS — 常见网络攻击检测系统")
        self.setMinimumSize(1200, 800)

        # 中央 Widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ─── 顶部控制栏 ───
        control_bar = self._create_control_bar()
        control_widget = QWidget()
        control_widget.setLayout(control_bar)
        control_widget.setContentsMargins(16, 10, 16, 10)
        main_layout.addWidget(control_widget)

        # ─── 分隔线 ───
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setObjectName("toolbarSeparator")
        main_layout.addWidget(sep)

        # ─── 主体: 侧边栏 + 内容区 ───
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # 侧边栏导航
        self.sidebar = self._create_sidebar()
        body.addWidget(self.sidebar)

        # 内容页 (QStackedWidget)
        self.stack = QStackedWidget()
        self.stack.setObjectName("contentStack")
        self.stack.addWidget(self._create_dashboard_tab())     # 0
        self.stack.addWidget(self._create_alert_tab())          # 1
        self.stack.addWidget(self._create_statistics_tab())     # 2
        self.stack.addWidget(self._create_signature_tab())      # 3
        self.stack.addWidget(self._create_log_tab())            # 4
        body.addWidget(self.stack, 1)

        main_layout.addLayout(body, 1)

        # ─── 状态栏 ───
        self.statusBar = QStatusBar()
        self.statusBar.setObjectName("appStatusBar")
        self.setStatusBar(self.statusBar)
        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusLabel")
        self.statusBar.addWidget(self.status_label, 1)
        self.pps_label = QLabel("PPS: 0")
        self.statusBar.addPermanentWidget(self.pps_label)
        self.alerts_label = QLabel("Alerts: 0")
        self.statusBar.addPermanentWidget(self.alerts_label)
        self.uptime_label = QLabel("Uptime: 00:00:00")
        self.statusBar.addPermanentWidget(self.uptime_label)

        # Apple Light Theme — 在所有 widget 创建完毕后应用 QSS, 避免 Qt CSS 引擎崩溃
        self._apply_apple_theme('light')

        # 初始化侧边栏选中 (必须在 stack 创建后)
        self.sidebar.setCurrentRow(0)

    # ─── 侧边栏 ───

    def _create_sidebar(self) -> QListWidget:
        """创建 Apple 风格侧边栏导航"""
        sidebar = QListWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sidebar.setSpacing(0)

        # 导航项目: (显示文本, 页索引)
        items = [
            ("  ◉  Dashboard",   0),   # ◉
            ("  ⚠  Alerts",      1),   # ⚠
            ("  ▶  Statistics",  2),   # ▶
            ("  ☰  Signatures",  3),   # ☰
            ("  ☷  Log",         4),   # ☷
        ]
        for label, idx in items:
            item = QListWidgetItem(label)
            item.setSizeHint(QSize(200, 42))
            item.setData(Qt.UserRole, idx)
            sidebar.addItem(item)

        # 分隔符
        sep_item = QListWidgetItem("")
        sep_item.setSizeHint(QSize(200, 1))
        sep_item.setFlags(Qt.NoItemFlags)
        sidebar.addItem(sep_item)

        # 主题切换
        theme_item = QListWidgetItem("  ☀  Toggle Theme")   # ☀
        theme_item.setSizeHint(QSize(200, 40))
        theme_item.setData(Qt.UserRole, 99)
        sidebar.addItem(theme_item)

        sidebar.currentRowChanged.connect(self._on_sidebar_changed)
        return sidebar

    def _on_sidebar_changed(self, row: int):
        """侧边栏点击处理: 导航或主题切换"""
        if row == 6:  # Theme toggle
            self._on_toggle_theme()
            # 恢复选中到当前内容页
            self.sidebar.blockSignals(True)
            self.sidebar.setCurrentRow(self.stack.currentIndex())
            self.sidebar.blockSignals(False)
        elif 0 <= row <= 4:
            self.stack.setCurrentIndex(row)

    # ─── Apple 主题系统 ───

    def _on_toggle_theme(self):
        """切换亮/暗主题"""
        new = 'dark' if self._current_theme == 'light' else 'light'
        self._apply_apple_theme(new)
        self._log("Theme switched to " + new)

    def _apply_apple_theme(self, theme_name: str):
        """应用完整的 Apple 风格主题 (调色板 + 全局 QSS)"""
        c = DARK_THEME if theme_name == 'dark' else LIGHT_THEME
        self._current_theme = theme_name

        # 1. QPalette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(c['window']))
        palette.setColor(QPalette.WindowText, QColor(c['windowText']))
        palette.setColor(QPalette.Base, QColor(c['base']))
        palette.setColor(QPalette.AlternateBase, QColor(c['alternateBase']))
        palette.setColor(QPalette.Text, QColor(c['text']))
        palette.setColor(QPalette.Button, QColor(c['button']))
        palette.setColor(QPalette.ButtonText, QColor(c['buttonText']))
        palette.setColor(QPalette.Highlight, QColor(c['highlight']))
        palette.setColor(QPalette.HighlightedText, QColor('#FFFFFF'))
        self.setPalette(palette)

        # 2. 全局 QSS (由 gui/theme.py 生成)
        self.setStyleSheet(build_stylesheet(c))

    # ─── 控制栏 ───

    def _create_control_bar(self) -> QHBoxLayout:
        """顶部控制栏 — Apple 工具栏风格"""
        layout = QHBoxLayout()
        layout.setSpacing(8)

        # 启动/停止按钮
        self.btn_start = QPushButton("▶  Start Detection")  # ▶
        self.btn_start.setObjectName("btnStart")
        self.btn_start.setProperty("state", "stopped")
        self.btn_start.clicked.connect(self._on_start_stop)
        layout.addWidget(self.btn_start)

        # 暂停按钮
        self.btn_pause = QPushButton("⏸  Pause")  # ⏸
        self.btn_pause.setObjectName("ctrlBtn")
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self._on_pause_resume)
        layout.addWidget(self.btn_pause)

        layout.addSpacing(20)

        # 分隔竖线
        vsep1 = QFrame()
        vsep1.setFrameShape(QFrame.VLine)
        vsep1.setMaximumWidth(1)
        layout.addWidget(vsep1)

        # 接口选择
        layout.addWidget(QLabel("Interface:"))
        self.cmb_interface = QComboBox()
        self.cmb_interface.setMinimumWidth(150)
        self._populate_interfaces()
        layout.addWidget(self.cmb_interface)

        # 过滤规则
        layout.addWidget(QLabel("BPF:"))
        self.edit_filter = QLineEdit("tcp")
        self.edit_filter.setMaximumWidth(180)
        layout.addWidget(self.edit_filter)

        layout.addSpacing(16)

        # 分隔竖线
        vsep2 = QFrame()
        vsep2.setFrameShape(QFrame.VLine)
        vsep2.setMaximumWidth(1)
        layout.addWidget(vsep2)

        # 基线学习
        self.btn_learn = QPushButton("☁  Learn Baseline")  # ☁
        self.btn_learn.setObjectName("ctrlBtn")
        self.btn_learn.clicked.connect(self._on_learn_baseline)
        layout.addWidget(self.btn_learn)

        # PCAP 回放
        self.btn_replay = QPushButton("📂  Replay PCAP")
        self.btn_replay.setObjectName("ctrlBtn")
        self.btn_replay.clicked.connect(self._on_replay_pcap)
        layout.addWidget(self.btn_replay)

        layout.addStretch()

        # 状态指示
        self.led_status = QLabel("○  Stopped")  # ○
        self.led_status.setObjectName("statusLabel")
        layout.addWidget(self.led_status)

        return layout

    # ─── Dashboard 页 ───

    def _create_dashboard_tab(self) -> QWidget:
        """仪表盘 — Apple 卡片式布局"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # 标题
        title = QLabel("Dashboard")
        title.setObjectName("sectionTitle")
        title.setStyleSheet("font-size: 28px; font-weight: 700; padding-bottom: 4px;")
        layout.addWidget(title)

        # ─── 统计卡片行 (6 张卡片) ───
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.card_total_alerts = self._make_stat_card("Total Alerts", "0", "#007AFF")
        self.card_critical = self._make_stat_card("Critical", "0", "#FF3B30")
        self.card_high = self._make_stat_card("High", "0", "#FF9500")
        self.card_medium = self._make_stat_card("Medium", "0", "#FFCC00")
        self.card_low = self._make_stat_card("Low", "0", "#AF52DE")
        self.card_total_packets = self._make_stat_card("Packets", "0", "#5AC8FA")

        for card in [self.card_total_alerts, self.card_critical, self.card_high,
                      self.card_medium, self.card_low, self.card_total_packets]:
            cards_layout.addWidget(card)
        layout.addLayout(cards_layout)

        # ─── 下方: 最近告警 + 实时流量 ───
        splitter = QSplitter(Qt.Horizontal)

        # 最近告警卡片
        alert_card = QFrame()
        alert_card.setObjectName("contentCard")
        alert_card_layout = QVBoxLayout(alert_card)
        alert_card_layout.setContentsMargins(16, 12, 16, 12)

        alert_title = QLabel("Recent Alerts")
        alert_title.setObjectName("sectionTitle")
        alert_card_layout.addWidget(alert_title)

        self.table_recent = QTableWidget()
        self.table_recent.setColumnCount(5)
        self.table_recent.setHorizontalHeaderLabels(
            ["Time", "Severity", "Type", "Source IP", "Description"])
        self.table_recent.horizontalHeader().setStretchLastSection(True)
        self.table_recent.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)
        self.table_recent.setAlternatingRowColors(True)
        alert_card_layout.addWidget(self.table_recent)
        splitter.addWidget(alert_card)

        # 实时流量卡片
        traffic_card = QFrame()
        traffic_card.setObjectName("contentCard")
        traffic_layout = QVBoxLayout(traffic_card)
        traffic_layout.setContentsMargins(16, 12, 16, 12)

        traffic_title = QLabel("Real-time Traffic")
        traffic_title.setObjectName("sectionTitle")
        traffic_layout.addWidget(traffic_title)

        # PPS 折线图
        if HAS_PYQTCHART:
            self._pps_series = QLineSeries()
            self._pps_series.setName("PPS")
            self._pps_series.setColor(QColor(0, 122, 255))

            self._bps_series = QLineSeries()
            self._bps_series.setName("BPS")
            self._bps_series.setColor(QColor(52, 199, 89))

            self._pps_chart = QChart()
            self._pps_chart.addSeries(self._pps_series)
            self._pps_chart.addSeries(self._bps_series)
            self._pps_chart.setTitle("Packet Rate")
            self._pps_chart.setAnimationOptions(QChart.SeriesAnimations)
            self._pps_chart.legend().setAlignment(Qt.AlignTop)
            self._pps_chart.setMargins(QMargins(0, 0, 0, 0))
            self._pps_chart.setBackgroundBrush(Qt.transparent)
            self._pps_chart.legend().setLabelColor(
                QColor(LIGHT_THEME['text'] if self._current_theme == 'light'
                       else DARK_THEME['text']))

            self._pps_axis_x = QValueAxis()
            self._pps_axis_x.setRange(0, 60)
            self._pps_axis_x.setLabelFormat("%d")
            self._pps_axis_x.setTitleText("Seconds ago")
            self._pps_axis_y = QValueAxis()
            self._pps_axis_y.setRange(0, 100)
            self._pps_axis_y.setTitleText("Rate")
            self._pps_chart.addAxis(self._pps_axis_x, Qt.AlignBottom)
            self._pps_chart.addAxis(self._pps_axis_y, Qt.AlignLeft)
            self._pps_series.attachAxis(self._pps_axis_x)
            self._pps_series.attachAxis(self._pps_axis_y)
            self._bps_series.attachAxis(self._pps_axis_x)
            self._bps_series.attachAxis(self._pps_axis_y)

            self._pps_chart_view = QChartView(self._pps_chart)
            self._pps_chart_view.setRenderHint(QPainter.Antialiasing)
            self._pps_chart_view.setMinimumHeight(200)
            traffic_layout.addWidget(self._pps_chart_view)
        else:
            self._pps_chart_view = None

        # 文本指标行
        stats_row = QHBoxLayout()
        self.lbl_pps = QLabel("PPS: 0")
        self.lbl_bps = QLabel("BPS: 0")
        self.lbl_conn = QLabel("Conn: 0")
        self.lbl_hosts = QLabel("Hosts: 0")
        self.lbl_streams = QLabel("TCP: 0")
        for lbl in [self.lbl_pps, self.lbl_bps, self.lbl_conn,
                     self.lbl_hosts, self.lbl_streams]:
            lbl.setStyleSheet("font-size: 13px; padding: 4px 10px; "
                            "background-color: " +
                            (LIGHT_THEME['alternateBase'] if self._current_theme == 'light'
                             else DARK_THEME['alternateBase']) +
                            "; border-radius: 4px;")
            stats_row.addWidget(lbl)
        stats_row.addStretch()
        traffic_layout.addLayout(stats_row)

        # TOP 攻击来源
        traffic_layout.addWidget(QLabel("Top Attack Sources:"))
        self.text_top_ip = QTextEdit()
        self.text_top_ip.setReadOnly(True)
        self.text_top_ip.setMaximumHeight(90)
        traffic_layout.addWidget(self.text_top_ip)

        splitter.addWidget(traffic_card)
        layout.addWidget(splitter)

        return page

    # ─── Alerts 页 ───

    def _create_alert_tab(self) -> QWidget:
        """告警列表 — 卡片包裹"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title = QLabel("Alerts")
        title.setStyleSheet("font-size: 28px; font-weight: 700; padding-bottom: 4px;")
        layout.addWidget(title)

        card = QFrame()
        card.setObjectName("contentCard")
        card_layout = QVBoxLayout(card)

        # 筛选栏
        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("Severity:"))
        self.cmb_severity = QComboBox()
        self.cmb_severity.addItems(["All", "critical", "high", "medium", "low"])
        filter_bar.addWidget(self.cmb_severity)

        filter_bar.addWidget(QLabel("Category:"))
        self.cmb_category = QComboBox()
        self.cmb_category.addItems(
            ["All", "sql_injection", "xss", "web_attack",
             "brute_force", "backdoor", "scan", "dos"])
        filter_bar.addWidget(self.cmb_category)

        self.btn_filter = QPushButton("Filter")
        self.btn_filter.clicked.connect(self._on_filter_alerts)
        filter_bar.addWidget(self.btn_filter)

        self.btn_export = QPushButton("Export JSON")
        self.btn_export.clicked.connect(self._on_export_alerts_tab)
        filter_bar.addWidget(self.btn_export)

        filter_bar.addStretch()
        card_layout.addLayout(filter_bar)

        # 告警表格
        self.table_alerts = QTableWidget()
        self.table_alerts.setColumnCount(8)
        self.table_alerts.setHorizontalHeaderLabels(
            ["ID", "Time", "Severity", "Source", "Category",
             "Attack Name", "Src IP", "Dst IP:Port"])
        self.table_alerts.horizontalHeader().setStretchLastSection(True)
        self.table_alerts.setAlternatingRowColors(True)
        card_layout.addWidget(self.table_alerts)

        layout.addWidget(card)
        return page

    # ─── Statistics 页 ───

    def _create_statistics_tab(self) -> QWidget:
        """统计分析 — 图表卡片"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title = QLabel("Statistics")
        title.setStyleSheet("font-size: 28px; font-weight: 700; padding-bottom: 4px;")
        layout.addWidget(title)

        # 图表行: 饼图 + 柱状图
        charts_row = QHBoxLayout()
        charts_row.setSpacing(16)

        # 饼图卡片
        if HAS_PYQTCHART:
            pie_card = QFrame()
            pie_card.setObjectName("contentCard")
            pie_layout = QVBoxLayout(pie_card)
            pie_label = QLabel("Alert Severity Distribution")
            pie_label.setObjectName("sectionTitle")
            pie_layout.addWidget(pie_label)

            self._pie_severity = QPieSeries()
            self._pie_chart = QChart()
            self._pie_chart.addSeries(self._pie_severity)
            self._pie_chart.setAnimationOptions(QChart.SeriesAnimations)
            self._pie_chart.legend().setAlignment(Qt.AlignRight)
            self._pie_chart.setBackgroundBrush(Qt.transparent)
            self._pie_chart_view = QChartView(self._pie_chart)
            self._pie_chart_view.setRenderHint(QPainter.Antialiasing)
            self._pie_chart_view.setMinimumSize(280, 250)
            pie_layout.addWidget(self._pie_chart_view)
            charts_row.addWidget(pie_card)
        else:
            self._pie_chart_view = None

        # 柱状图卡片
        if HAS_PYQTCHART:
            bar_card = QFrame()
            bar_card.setObjectName("contentCard")
            bar_layout = QVBoxLayout(bar_card)
            bar_label = QLabel("Attack Category Distribution")
            bar_label.setObjectName("sectionTitle")
            bar_layout.addWidget(bar_label)

            self._bar_set = QBarSet("Count")
            self._bar_set.setColor(QColor(255, 149, 0))
            self._bar_series = QBarSeries()
            self._bar_series.append(self._bar_set)
            self._bar_chart = QChart()
            self._bar_chart.addSeries(self._bar_series)
            self._bar_chart.setAnimationOptions(QChart.SeriesAnimations)
            self._bar_chart.legend().hide()
            self._bar_chart.setBackgroundBrush(Qt.transparent)
            self._bar_axis_x = QBarCategoryAxis()
            self._bar_axis_y = QValueAxis()
            self._bar_axis_y.setTitleText("Count")
            self._bar_chart.addAxis(self._bar_axis_x, Qt.AlignBottom)
            self._bar_chart.addAxis(self._bar_axis_y, Qt.AlignLeft)
            self._bar_series.attachAxis(self._bar_axis_x)
            self._bar_series.attachAxis(self._bar_axis_y)
            self._bar_chart_view = QChartView(self._bar_chart)
            self._bar_chart_view.setRenderHint(QPainter.Antialiasing)
            self._bar_chart_view.setMinimumSize(280, 250)
            bar_layout.addWidget(self._bar_chart_view)
            charts_row.addWidget(bar_card)
        else:
            self._bar_chart_view = None

        layout.addLayout(charts_row)

        # TOP 攻击来源卡片
        top_card = QFrame()
        top_card.setObjectName("contentCard")
        top_layout = QVBoxLayout(top_card)
        top_title = QLabel("Top 10 Attack Source IPs")
        top_title.setObjectName("sectionTitle")
        top_layout.addWidget(top_title)

        self.text_top_src = QTextEdit()
        self.text_top_src.setReadOnly(True)
        self.text_top_src.setMaximumHeight(150)
        top_layout.addWidget(self.text_top_src)

        self.btn_refresh_stats = QPushButton("Refresh Statistics")
        self.btn_refresh_stats.clicked.connect(self._refresh_statistics)
        top_layout.addWidget(self.btn_refresh_stats)
        layout.addWidget(top_card)

        return page

    # ─── Signatures 页 ───

    def _create_signature_tab(self) -> QWidget:
        """特征库管理 — 卡片包裹"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title = QLabel("Signature Library")
        title.setStyleSheet("font-size: 28px; font-weight: 700; padding-bottom: 4px;")
        layout.addWidget(title)

        card = QFrame()
        card.setObjectName("contentCard")
        card_layout = QVBoxLayout(card)

        info_bar = QHBoxLayout()
        info_bar.addWidget(QLabel("Signature file:"))
        self.cmb_sig_file = QComboBox()
        self.cmb_sig_file.addItems([
            "sql_injection.yaml", "xss.yaml", "web_attack.yaml",
            "brute_force.yaml", "backdoor.yaml", "scan.yaml", "dos.yaml",
            "webshell.yaml", "imported_suricata.yaml",
        ])
        info_bar.addWidget(self.cmb_sig_file)
        self.btn_load_sig = QPushButton("View")
        self.btn_load_sig.clicked.connect(self._on_view_signature)
        info_bar.addWidget(self.btn_load_sig)
        self.btn_reload_all = QPushButton("Reload All")
        self.btn_reload_all.clicked.connect(self._on_reload_signatures)
        info_bar.addWidget(self.btn_reload_all)
        info_bar.addStretch()
        card_layout.addLayout(info_bar)

        self.text_sig = QTextEdit()
        self.text_sig.setReadOnly(True)
        self.text_sig.setFont(QFont("Consolas", 12))
        card_layout.addWidget(self.text_sig)

        layout.addWidget(card)
        return page

    # ─── Log 页 ───

    def _create_log_tab(self) -> QWidget:
        """系统日志 — 卡片包裹"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title = QLabel("System Log")
        title.setStyleSheet("font-size: 28px; font-weight: 700; padding-bottom: 4px;")
        layout.addWidget(title)

        card = QFrame()
        card.setObjectName("contentCard")
        card_layout = QVBoxLayout(card)

        self.text_log = QTextEdit()
        self.text_log.setReadOnly(True)
        self.text_log.setFont(QFont("Consolas", 11))
        card_layout.addWidget(self.text_log)

        layout.addWidget(card)
        return page

    # ─── 统计卡片工厂 ───

    def _make_stat_card(self, title: str, value: str,
                         accent: str = "#007AFF") -> QFrame:
        """创建 Apple 风格统计卡片 (圆角白底 + 左侧色条)"""
        card = QFrame()
        card.setObjectName("statCard")
        card.setMinimumHeight(90)

        inner = QVBoxLayout(card)
        inner.setContentsMargins(16, 10, 12, 10)
        inner.setSpacing(4)

        # 数值 (大号粗体)
        lbl_value = QLabel(value)
        lbl_value.setObjectName("cardValue")
        lbl_value.setStyleSheet(
            "font-size: 34px; font-weight: 700; color: {0};".format(accent))
        lbl_value.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        inner.addWidget(lbl_value)

        # 标题 (小号灰色)
        lbl_title = QLabel(title.upper())
        lbl_title.setObjectName("cardTitle")
        inner.addWidget(lbl_title)

        card._value_label = lbl_value
        return card

    @staticmethod
    def _set_card_value(card: QFrame, text: str):
        """安全更新统计卡片的值"""
        lbl = getattr(card, '_value_label', None)
        if lbl is not None:
            lbl.setText(text)

    # ─── 定时器 ───

    def _init_timers(self):
        """初始化刷新定时器"""
        self._refresh_timer = QTimer()
        self._refresh_timer.timeout.connect(self._refresh_ui)
        self._refresh_timer.start(1000)

    # ─── 菜单栏 ───

    def _init_menu(self):
        """初始化菜单栏"""
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")
        act_export = QAction("Export Alerts...", self)
        act_export.triggered.connect(self._on_export_alerts)
        file_menu.addAction(act_export)
        act_exit = QAction("Exit", self)
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        settings_menu = menubar.addMenu("Settings")
        act_config = QAction("View Config...", self)
        act_config.triggered.connect(self._on_config)
        settings_menu.addAction(act_config)

        help_menu = menubar.addMenu("Help")
        act_about = QAction("About NADS", self)
        act_about.triggered.connect(self._on_about)
        help_menu.addAction(act_about)

    # ═══════════════════════════════════════════════════════════
    # 槽函数 (业务逻辑 — 与旧版一致)
    # ═══════════════════════════════════════════════════════════

    def _on_start_stop(self):
        """启动/停止检测"""
        if self.engine is None:
            self._log("[ERROR] No detection engine injected")
            return

        if self.engine.capture.is_running:
            self.engine.stop()
            self.btn_start.setText("▶  Start Detection")
            self.btn_start.setProperty("state", "stopped")
            self.btn_start.style().unpolish(self.btn_start)
            self.btn_start.style().polish(self.btn_start)
            self.btn_pause.setEnabled(False)
            self.led_status.setText("○  Stopped")
            self._log("Detection engine stopped")
        else:
            self.engine.start(
                interface=self.cmb_interface.currentText(),
                filter_rule=self.edit_filter.text()
            )
            self.btn_start.setText("■  Stop Detection")
            self.btn_start.setProperty("state", "running")
            self.btn_start.style().unpolish(self.btn_start)
            self.btn_start.style().polish(self.btn_start)
            self.btn_pause.setEnabled(True)
            self.led_status.setText("●  Running")
            self._log("Detection engine started")

    def _on_pause_resume(self):
        """暂停/恢复"""
        if self.engine is None or self.engine.capture is None:
            return
        if not self.engine.capture._running:
            return
        if self.engine.capture._paused:
            self.engine.capture.resume()
            self.btn_pause.setText("⏸  Pause")
            self.led_status.setText("●  Running")
        else:
            self.engine.capture.pause()
            self.btn_pause.setText("▶  Resume")
            self.led_status.setText("◐  Paused")

    def _on_learn_baseline(self):
        """基线学习"""
        QMessageBox.information(
            self, "Baseline Learning",
            "Baseline learning will run in the background.\n"
            "It is recommended to run for at least 1 hour\n"
            "with normal (non-attack) network traffic."
        )
        if self.engine:
            self.engine.anomaly_detector.start_learning()
            self._log("Baseline learning started...")

    def _on_replay_pcap(self):
        """回放 PCAP"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select PCAP File", "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if filepath:
            self._log("Replaying: " + filepath)
            if self.engine:
                thread = threading.Thread(
                    target=self.engine.replay_pcap,
                    args=(filepath,),
                    daemon=True
                )
                thread.start()

    def _on_export_alerts(self):
        """导出全部告警 (菜单)"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts", "alerts_export.json",
            "JSON Files (*.json)"
        )
        if filepath and self.engine:
            import json
            alerts = [a.to_dict() for a in self.engine.alert_mgr.alerts]
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, ensure_ascii=False, indent=2)
            self._log("Alerts exported: " + filepath)

    def _on_filter_alerts(self):
        """按严重度和类别筛选告警列表"""
        if self.engine is None:
            return
        severity = self.cmb_severity.currentText()
        category = self.cmb_category.currentText()
        if severity == "All":
            severity = None
        if category == "All":
            category = None
        alerts = self.engine.alert_mgr.get_alerts(
            limit=500, severity=severity, category=category)
        self._populate_alert_table(alerts)
        self._log(
            "Filter: severity={0}, category={1} -> {2} results".format(
                severity or 'all', category or 'all', len(alerts))
        )

    def _on_export_alerts_tab(self):
        """导出筛选后的告警 (告警 Tab)"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Filtered Alerts", "alerts_filtered.json",
            "JSON Files (*.json)"
        )
        if not filepath or self.engine is None:
            return
        import json
        severity = self.cmb_severity.currentText()
        category = self.cmb_category.currentText()
        if severity == "All":
            severity = None
        if category == "All":
            category = None
        alerts = self.engine.alert_mgr.get_alerts(
            limit=10000, severity=severity, category=category)
        data = [a.to_dict() for a in alerts]
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self._log("Filtered alerts exported: {0} ({1} records)".format(
            filepath, len(data)))

    def _populate_alert_table(self, alerts: list):
        """填充告警表格"""
        self.table_alerts.setRowCount(len(alerts))
        for i, alert in enumerate(alerts):
            self.table_alerts.setItem(i, 0,
                QTableWidgetItem(str(alert.alert_id)))
            self.table_alerts.setItem(i, 1,
                QTableWidgetItem(time.strftime('%H:%M:%S',
                                    time.localtime(alert.timestamp))))
            self.table_alerts.setItem(i, 2,
                QTableWidgetItem(alert.severity))
            self.table_alerts.setItem(i, 3,
                QTableWidgetItem(alert.source))
            self.table_alerts.setItem(i, 4,
                QTableWidgetItem(alert.category))
            self.table_alerts.setItem(i, 5,
                QTableWidgetItem(alert.signature_name or alert.description))
            self.table_alerts.setItem(i, 6,
                QTableWidgetItem(alert.src_ip))
            self.table_alerts.setItem(i, 7,
                QTableWidgetItem("{0}:{1}".format(alert.dst_ip, alert.dst_port)))
        self.table_alerts.resizeColumnsToContents()

    def _on_view_signature(self):
        """查看特征库文件内容"""
        sig_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'signatures')
        fname = self.cmb_sig_file.currentText()
        fpath = os.path.join(sig_dir, fname)
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                self.text_sig.setPlainText(f.read())
            self._log("Loaded: " + fname)
        except Exception as e:
            self.text_sig.setPlainText("Read error: " + str(e))
            self._log("Failed to read signature: " + str(e))

    def _on_reload_signatures(self):
        """重新加载所有特征库"""
        if self.engine is None or self.engine.misuse_detector is None:
            self._log("[ERROR] No engine, cannot reload signatures")
            return
        try:
            count = self.engine.misuse_detector.reload()
            self._log("Signatures reloaded: {0} rules".format(count))
            QMessageBox.information(
                self, "Reload Complete",
                "Successfully reloaded {0} attack signature rules.".format(count))
        except Exception as e:
            self._log("Signature reload failed: " + str(e))
            QMessageBox.warning(self, "Reload Failed", str(e))

    def _on_about(self):
        """关于对话框"""
        QMessageBox.about(
            self, "About NADS",
            "<h2>NADS</h2>"
            "<p>Network Attack Detection System v2.0</p>"
            "<p>Hybrid IDS: signature matching + anomaly detection</p>"
            "<hr>"
            "<p>IS_technology_innovation course project</p>"
        )

    def _on_config(self):
        """查看配置文件 (Settings > View Config)"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                msg = QMessageBox(self)
                msg.setWindowTitle("Configuration")
                msg.setText("Config file: config.yaml")
                msg.setDetailedText(content)
                msg.exec_()
            except Exception as e:
                QMessageBox.warning(self, "Config Error", str(e))
        else:
            QMessageBox.information(
                self, "Config",
                "Config file not found: {0}".format(config_path))

    # ═══════════════════════════════════════════════════════════
    # 定时刷新 (每秒)
    # ═══════════════════════════════════════════════════════════

    def _refresh_ui(self):
        """定时刷新界面"""
        if self.engine is None:
            return

        try:
            status = self.engine.get_status()

            # 更新仪表盘卡片
            stats = self.engine.alert_mgr.get_realtime_stats()
            all_stats = self.engine.alert_mgr.get_statistics()
            self._set_card_value(self.card_total_alerts,
                str(all_stats['total']))
            self._set_card_value(self.card_critical,
                str(stats.get('critical', 0)))
            self._set_card_value(self.card_high,
                str(stats.get('high', 0)))
            self._set_card_value(self.card_medium,
                str(stats.get('medium', 0)))
            self._set_card_value(self.card_low,
                str(stats.get('low', 0)))
            self._set_card_value(self.card_total_packets,
                str(status.get('packets_captured', 0)))

            # 更新流量统计 (Fix #2: 连接真实数据源)
            current_pps = status.get('pps', 0)
            current_bps = (status.get('bytes_captured', 0) /
                          max(status.get('elapsed_seconds', 1), 1))
            self.lbl_pps.setText("PPS: {0:.0f}".format(current_pps))
            self.lbl_bps.setText("BPS: {0:.0f}".format(current_bps))

            # 从 TCP 重组器获取连接数
            if self.engine and self.engine.reassembler:
                rs = self.engine.reassembler.get_stats()
                self.lbl_streams.setText(
                    "TCP: {0}".format(rs.get('active_streams', 0)))
                self.lbl_conn.setText(
                    "Conn: {0}".format(rs.get('total_streams_created', 0)))
            else:
                self.lbl_conn.setText("Conn: 0")
                self.lbl_streams.setText("TCP: 0")

            # 从异常检测器获取主机数
            if self.engine and self.engine.anomaly_detector:
                ad = self.engine.anomaly_detector.get_statistics()
                self.lbl_hosts.setText(
                    "Hosts: {0}".format(ad.get('total_hosts_tracked', 0)))
            else:
                self.lbl_hosts.setText("Hosts: 0")

            # 更新 PPS/BPS 历史 + 实时折线图
            self._pps_history.append(current_pps)
            self._bps_history.append(current_bps)
            self._chart_time_counter += 1
            self._update_realtime_chart()

            # 更新仪表盘 TOP 攻击来源 (Fix #1)
            top_lines = []
            for ip, count in all_stats.get('top_attack_sources', [])[:5]:
                top_lines.append("  {0}: {1} attacks".format(ip, count))
            self.text_top_ip.setText(
                '\n'.join(top_lines) if top_lines else "  No data")

            # 状态栏
            self.pps_label.setText(
                "PPS: {0:.0f}".format(status.get('pps', 0)))
            self.alerts_label.setText(
                "Alerts: {0}".format(all_stats['total']))
            elapsed = status.get('elapsed_seconds', 0)
            h, m = divmod(int(elapsed), 3600)
            m, s = divmod(m, 60)
            self.uptime_label.setText(
                "Uptime: {0:02d}:{1:02d}:{2:02d}".format(h, m, s))

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

        except Exception:
            pass

        # 每 5 秒刷新统计图表 + 告警表格
        if self._chart_time_counter % 5 == 0:
            self._refresh_statistics()
            if self.stack.currentIndex() == 1:
                self._on_filter_alerts()

    def _update_realtime_chart(self):
        """更新实时 PPS/BPS 折线图 (Fix #3: 添加 BPS 线)"""
        if not HAS_PYQTCHART or self._pps_chart_view is None:
            return

        # PPS 系列
        self._pps_series.clear()
        n = len(self._pps_history)
        for i, pps in enumerate(self._pps_history):
            x = -(n - 1 - i)
            self._pps_series.append(x, pps)

        # BPS 系列 (Fix #3)
        self._bps_series.clear()
        n_bps = len(self._bps_history)
        for i, bps in enumerate(self._bps_history):
            x = -(n_bps - 1 - i)
            self._bps_series.append(x, bps)

        # Y 轴自适应
        max_pps = max(self._pps_history) if self._pps_history else 10
        max_bps = max(self._bps_history) if self._bps_history else 10
        self._pps_axis_y.setRange(0, max(100, max(max_pps, max_bps) * 1.3))
        self._pps_axis_x.setRange(-max(n, n_bps), 5)

    def _refresh_statistics(self):
        """刷新统计面板图表"""
        if self.engine is None:
            return

        stats = self.engine.alert_mgr.get_statistics()

        # 严重度饼图
        if HAS_PYQTCHART and hasattr(self, '_pie_severity'):
            self._pie_severity.clear()
            severity_colors = {
                'critical': QColor(0xFF, 0x3B, 0x30),
                'high':     QColor(0xFF, 0x95, 0x00),
                'medium':   QColor(0xFF, 0xCC, 0x00),
                'low':      QColor(0x00, 0x7A, 0xFF),
            }
            sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            for sev, count in sorted(
                    stats.get('by_severity', {}).items(),
                    key=lambda x: sev_order.get(x[0], 9)):
                if count > 0:
                    sl = self._pie_severity.append(sev, count)
                    if sev in severity_colors:
                        sl.setColor(severity_colors[sev])
            # 未知严重度用灰色
            for sev, count in stats.get('by_severity', {}).items():
                if count > 0 and sev not in severity_colors:
                    sl = self._pie_severity.append(sev, count)
                    sl.setColor(QColor(0x9E, 0x9E, 0x9E))

        # 类别柱状图
        if HAS_PYQTCHART and hasattr(self, '_bar_set'):
            cats = sorted(stats.get('by_category', {}).items(),
                          key=lambda x: x[1], reverse=True)
            self._bar_set.remove(0, self._bar_set.count())
            categories = []
            for cat, count in cats[:8]:
                self._bar_set.append(count)
                categories.append(cat)
            self._bar_axis_x.clear()
            self._bar_axis_x.append(categories)
            max_val = max([c for _, c in cats[:8]], default=1)
            self._bar_axis_y.setRange(0, max_val * 1.2)

        # TOP 攻击源 IP
        lines = []
        for ip, count in stats.get('top_attack_sources', [])[:10]:
            lines.append("  {0}: {1} attacks".format(ip, count))
        self.text_top_src.setText('\n'.join(lines) if lines else "  No data")

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
        self.text_log.append("[{0}] {1}".format(timestamp, msg))
