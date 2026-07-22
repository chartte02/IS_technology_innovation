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
        QLabel, QComboBox, QLineEdit, QTextEdit,
        QGroupBox, QGridLayout, QHeaderView, QStatusBar, QMessageBox,
        QMenuBar, QAction, QFileDialog, QProgressBar, QCheckBox,
        QSpinBox, QFormLayout, QStackedWidget, QListWidget,
        QListWidgetItem, QFrame, QSizePolicy, QScrollArea,
    )
    from PyQt5.QtCore import (
        Qt, QTimer, pyqtSignal, QThread, QMargins, QSize,
    )
    from PyQt5.QtGui import QFont, QColor, QIcon, QPalette, QPainter, QBrush, QPen
    from PyQt5.QtWidgets import (
        QGraphicsScene, QGraphicsView, QGraphicsEllipseItem,
        QGraphicsLineItem, QGraphicsTextItem, QGraphicsRectItem,
    )
    from PyQt5.QtCore import QPointF, QRectF, QLineF
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False
    print("Warning: PyQt5 not installed. Run: pip install pyqt5 pyqtchart")

try:
    from PyQt5.QtChart import (
        QChart, QChartView, QPieSeries, QBarSeries, QBarSet,
        QHorizontalBarSeries, QLineSeries, QValueAxis, QBarCategoryAxis,
    )
    HAS_PYQTCHART = True
except ImportError:
    HAS_PYQTCHART = False
    print("Warning: PyQtChart not installed. Run: pip install pyqtchart")

# 主题系统 (独立模块, 可单独调试)
from gui.theme import LIGHT_THEME, DARK_THEME, build_stylesheet

# 流量生成器 (Demo 模式)
from tools.traffic_generator import TrafficGenerator


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
        self.demo_generator = None  # Demo 模式流量生成器
        self._current_theme = 'light'
        self._last_gen_sent = 0     # Demo PPS tracking

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
        self.setMinimumSize(1400, 900)

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
        # 仪表盘包裹在 QScrollArea 中
        dash_scroll = QScrollArea()
        dash_scroll.setWidgetResizable(True)
        dash_scroll.setWidget(self._create_dashboard_tab())
        dash_scroll.setObjectName("dashScroll")
        self.stack.addWidget(dash_scroll)                       # 0
        self.stack.addWidget(self._create_alert_tab())          # 1
        self.stack.addWidget(self._create_statistics_tab())     # 2
        self.stack.addWidget(self._create_signature_tab())      # 3
        self.stack.addWidget(self._create_attack_chain_tab())   # 4
        self.stack.addWidget(self._create_log_tab())            # 5
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
        sidebar.setFixedWidth(260)
        sidebar.setSpacing(0)

        # 导航项目: (显示文本, 页索引)
        items = [
            ("  ◉  Dashboard",      0),   # ◉
            ("  ⚠  Alerts",         1),   # ⚠
            ("  ▶  Statistics",     2),   # ▶
            ("  ☰  Signatures",     3),   # ☰
            ("  ◈  Attack Chain",   4),   # ◈
            ("  ☷  Log",            5),   # ☷
        ]
        for label, idx in items:
            item = QListWidgetItem(label)
            item.setSizeHint(QSize(240, 50))
            item.setData(Qt.UserRole, idx)
            sidebar.addItem(item)

        # 分隔符
        sep_item = QListWidgetItem("")
        sep_item.setSizeHint(QSize(240, 1))
        sep_item.setFlags(Qt.NoItemFlags)
        sidebar.addItem(sep_item)

        # 主题切换
        theme_item = QListWidgetItem("  ☀  Toggle Theme")   # ☀
        theme_item.setSizeHint(QSize(240, 50))
        theme_item.setData(Qt.UserRole, 99)
        sidebar.addItem(theme_item)

        sidebar.currentRowChanged.connect(self._on_sidebar_changed)
        return sidebar

    def _on_sidebar_changed(self, row: int):
        """侧边栏点击处理: 导航或主题切换"""
        total_pages = self.stack.count()  # dynamic: works with 5 or 6 tabs
        if row == total_pages + 1:  # Theme toggle (after N items + 1 separator)
            self._on_toggle_theme()
            self.sidebar.blockSignals(True)
            self.sidebar.setCurrentRow(self.stack.currentIndex())
            self.sidebar.blockSignals(False)
        elif 0 <= row < total_pages:
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

        # Demo 按钮 (动态流量生成)
        self.btn_demo = QPushButton("▶  Demo")
        self.btn_demo.setObjectName("ctrlBtn")
        self.btn_demo.clicked.connect(self._on_demo)
        layout.addWidget(self.btn_demo)
        self.btn_reset = QPushButton("Reset")
        self.btn_reset.setObjectName("ctrlBtn")
        self.btn_reset.clicked.connect(self._on_reset_session)
        layout.addWidget(self.btn_reset)

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
        title.setStyleSheet("font-size: 36px; font-weight: 700; padding-bottom: 4px;")
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

        # ─── 下方: 最近告警 + 实时流量 (上下两行) ───

        # 行 1: 最近告警 (高度 250px)
        alert_card = QFrame()
        alert_card.setObjectName("contentCard")
        alert_card_layout = QVBoxLayout(alert_card)
        alert_card_layout.setContentsMargins(12, 8, 12, 8)

        alert_title = QLabel("Recent Alerts")
        alert_title.setObjectName("sectionTitle")
        alert_title.setStyleSheet("font-size: 14px; font-weight: 700; padding-bottom: 2px;")
        alert_card_layout.addWidget(alert_title)

        self.table_recent = QTableWidget()
        self.table_recent.setColumnCount(6)
        self.table_recent.setHorizontalHeaderLabels(
            ["Time", "Severity", "Source", "Type", "Source IP", "Description"])
        self.table_recent.horizontalHeader().setStretchLastSection(True)
        self.table_recent.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)
        self.table_recent.setAlternatingRowColors(True)
        self.table_recent.setMinimumHeight(180)  # show 7 rows
        self.table_recent.cellDoubleClicked.connect(self._on_alert_double_click)
        alert_card_layout.addWidget(self.table_recent)
        layout.addWidget(alert_card)

        # 行 2: 实时流量 (折线图 + 指标 + TOP 来源)
        traffic_card = QFrame()
        traffic_card.setObjectName("contentCard")
        traffic_layout = QVBoxLayout(traffic_card)
        traffic_layout.setContentsMargins(16, 12, 16, 12)

        traffic_title = QLabel("Real-time Traffic")
        traffic_title.setObjectName("sectionTitle")
        traffic_layout.addWidget(traffic_title)

        # PPS/BPS 折线图
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
            self._pps_chart_view.setFixedHeight(240)
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
        self.lbl_ano = QLabel("Anomaly: 0")
        self.lbl_ml = QLabel("ML: not trained")
        self.lbl_gen = QLabel("Demo: OFF")
        # 基础标签循环
        for lbl in [self.lbl_pps, self.lbl_bps, self.lbl_conn,
                     self.lbl_hosts, self.lbl_streams]:
            lbl.setStyleSheet("font-size: 15px; padding: 4px 10px; "
                            "background-color: " +
                            (LIGHT_THEME['alternateBase'] if self._current_theme == 'light'
                             else DARK_THEME['alternateBase']) +
                            "; border-radius: 4px;")
            stats_row.addWidget(lbl)
        # C 模块标签 (醒目颜色区分)
        self.lbl_ano.setStyleSheet(
            "font-size: 15px; padding: 4px 12px; font-weight: bold; "
            "color: #FFFFFF; background-color: #FF9500; border-radius: 4px;")
        stats_row.addWidget(self.lbl_ano)
        self.lbl_ml.setStyleSheet(
            "font-size: 15px; padding: 4px 12px; font-weight: bold; "
            "color: #FFFFFF; background-color: #AF52DE; border-radius: 4px;")
        stats_row.addWidget(self.lbl_ml)
        self.lbl_gen.setStyleSheet(
            "font-size: 15px; padding: 4px 12px; font-weight: bold; "
            "color: #FFFFFF; background-color: #34C759; border-radius: 4px;")
        stats_row.addWidget(self.lbl_gen)
        stats_row.addStretch()
        traffic_layout.addLayout(stats_row)

        # TOP 攻击来源
        traffic_layout.addWidget(QLabel("Top Attack Sources:"))
        self.text_top_ip = QTextEdit()
        self.text_top_ip.setReadOnly(True)
        self.text_top_ip.setMaximumHeight(100)
        traffic_layout.addWidget(self.text_top_ip)

        layout.addWidget(traffic_card)

        return page

    # ─── Alerts 页 ───

    def _create_alert_tab(self) -> QWidget:
        """告警列表 — 卡片包裹"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title = QLabel("Alerts")
        title.setStyleSheet("font-size: 36px; font-weight: 700; padding-bottom: 4px;")
        layout.addWidget(title)

        card = QFrame()
        card.setObjectName("contentCard")
        card_layout = QVBoxLayout(card)

        # 筛选栏 (下拉变化即筛选, 无需 Filter 按钮)
        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("Severity:"))
        self.cmb_severity = QComboBox()
        self.cmb_severity.setObjectName("appleCombo")
        self.cmb_severity.addItems(["All", "critical", "high", "medium", "low"])
        self.cmb_severity.currentTextChanged.connect(self._on_filter_alerts)
        filter_bar.addWidget(self.cmb_severity)

        filter_bar.addWidget(QLabel("Category:"))
        self.cmb_category = QComboBox()
        self.cmb_category.setObjectName("appleCombo")
        self.cmb_category.addItems(
            ["All", "sql_injection", "xss", "web_attack",
             "brute_force", "backdoor", "scan", "dos"])
        self.cmb_category.currentTextChanged.connect(self._on_filter_alerts)
        filter_bar.addWidget(self.cmb_category)

        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self._on_filter_alerts)
        filter_bar.addWidget(self.btn_refresh)

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
        self.table_alerts.cellDoubleClicked.connect(self._on_alert_double_click)
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
        title.setStyleSheet("font-size: 36px; font-weight: 700; padding-bottom: 4px;")
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
            self._pie_chart.legend().setLabelColor(
                QColor(LIGHT_THEME['text'] if self._current_theme == 'light'
                       else DARK_THEME['text']))
            self._pie_chart.setBackgroundBrush(Qt.transparent)
            self._pie_chart_view = QChartView(self._pie_chart)
            self._pie_chart_view.setRenderHint(QPainter.Antialiasing)
            self._pie_chart_view.setMinimumSize(280, 250)
            pie_layout.addWidget(self._pie_chart_view)
            charts_row.addWidget(pie_card)
        else:
            self._pie_chart_view = None

        # 柱状图卡片 (横向)
        if HAS_PYQTCHART:
            bar_card = QFrame()
            bar_card.setObjectName("contentCard")
            bar_layout = QVBoxLayout(bar_card)
            bar_label = QLabel("Attack Categories")
            bar_label.setObjectName("sectionTitle")
            bar_layout.addWidget(bar_label)

            self._bar_set = QBarSet("")
            self._bar_set.setColor(QColor(255, 149, 0))
            self._bar_series = QHorizontalBarSeries()
            self._bar_series.append(self._bar_set)
            self._bar_chart = QChart()
            self._bar_chart.addSeries(self._bar_series)
            self._bar_chart.setAnimationOptions(QChart.SeriesAnimations)
            self._bar_chart.legend().hide()
            self._bar_chart.setBackgroundBrush(Qt.transparent)
            self._bar_chart.setMargins(QMargins(0, 0, 0, 0))
            self._bar_axis_val = QValueAxis()
            self._bar_axis_val.setLabelFormat("%d")
            self._bar_axis_cat = QBarCategoryAxis()
            self._bar_chart.addAxis(self._bar_axis_cat, Qt.AlignLeft)
            self._bar_chart.addAxis(self._bar_axis_val, Qt.AlignBottom)
            self._bar_series.attachAxis(self._bar_axis_val)
            self._bar_series.attachAxis(self._bar_axis_cat)
            self._bar_chart_view = QChartView(self._bar_chart)
            self._bar_chart_view.setRenderHint(QPainter.Antialiasing)
            self._bar_chart_view.setFixedSize(400, 240)
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

        self.list_top_src = QListWidget()
        self.list_top_src.setObjectName("topSrcList")
        self.list_top_src.setMaximumHeight(200)
        top_layout.addWidget(self.list_top_src)

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
        title.setStyleSheet("font-size: 36px; font-weight: 700; padding-bottom: 4px;")
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
        self.text_sig.setFont(QFont("Consolas", 14))
        card_layout.addWidget(self.text_sig)

        layout.addWidget(card)
        return page

    # ─── Attack Chain 页 ───

    def _create_attack_chain_tab(self) -> QWidget:
        """攻击链可视化面板 — QGraphicsView 节点-边图"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # 标题 + 图例
        header = QHBoxLayout()
        title = QLabel("Attack Chain Visualization")
        title.setStyleSheet("font-size: 36px; font-weight: 700; padding-bottom: 4px;")
        header.addWidget(title)
        header.addStretch()

        # 图例
        legend_colors = [
            ("Recon", QColor("#FFCC00")),
            ("Exploit", QColor("#FF9500")),
            ("C2/Persist", QColor("#FF3B30")),
            ("Lateral", QColor("#AF52DE")),
        ]
        for name, color in legend_colors:
            lbl = QLabel(" ■ " + name)
            lbl.setStyleSheet(
                "color: {0}; font-size: 14px; font-weight: 600; padding: 2px 8px;".format(
                    color.name()))
            header.addWidget(lbl)
        layout.addLayout(header)

        # QGraphicsView
        self._chain_scene = QGraphicsScene()
        self._chain_view = QGraphicsView(self._chain_scene)
        self._chain_view.setRenderHint(QPainter.Antialiasing)
        self._chain_view.setMinimumHeight(400)
        self._chain_view.setStyleSheet(
            "QGraphicsView { border: 1px solid #E5E5EA; border-radius: 8px; "
            "background-color: " +
            (LIGHT_THEME['base'] if self._current_theme == 'light'
             else DARK_THEME['base']) + "; }")
        layout.addWidget(self._chain_view)

        # 刷新按钮
        btn_row = QHBoxLayout()
        self.btn_refresh_chain = QPushButton("Refresh Attack Chain")
        self.btn_refresh_chain.clicked.connect(self._refresh_attack_chain)
        btn_row.addWidget(self.btn_refresh_chain)
        btn_row.addStretch()
        self.lbl_chain_info = QLabel("No attack chain data available")
        self.lbl_chain_info.setStyleSheet("font-size: 14px; padding: 4px 8px; color: #86868B;")
        btn_row.addWidget(self.lbl_chain_info)
        layout.addLayout(btn_row)

        return page

    def _refresh_attack_chain(self):
        """从告警数据绘制攻击链可视化"""
        self._chain_scene.clear()
        if self.engine is None:
            self.lbl_chain_info.setText("No engine connected")
            return

        # 获取最近告警，按 src_ip 分组
        alerts = self.engine.alert_mgr.get_alerts(limit=500)
        if not alerts:
            self.lbl_chain_info.setText("No alerts to visualize")
            return

        # 按 src_ip 分组，按时间排序
        from collections import defaultdict
        chains = defaultdict(list)
        for a in alerts:
            # 映射告警类别到 MITRE ATT&CK 阶段
            phase = self._map_category_to_phase(a.category)
            chains[a.src_ip].append({
                'time': a.timestamp,
                'dst': a.dst_ip,
                'category': a.category,
                'severity': a.severity,
                'phase': phase,
                'desc': a.description or a.signature_name,
            })

        # 过滤：至少 2 步的 src_ip 才画出
        active = {ip: steps for ip, steps in chains.items() if len(steps) >= 2}
        if not active:
            self.lbl_chain_info.setText("No multi-step attack chains found (need >=2 steps)")
            # Show note
            note = self._chain_scene.addText(
                "No attack chains detected yet.\n"
                "Attack chains appear when the same source IP triggers\n"
                "multiple different alert categories within the time window.",
                QFont("Segoe UI", 14))
            note.setDefaultTextColor(QColor("#86868B"))
            note.setPos(100, 150)
            return

        # 绘制
        phase_colors = {
            'recon': QColor("#FFCC00"),
            'exploit': QColor("#FF9500"),
            'c2': QColor("#FF3B30"),
            'lateral': QColor("#AF52DE"),
            'unknown': QColor("#86868B"),
        }

        y_start = 30
        x_start = 80
        x_step = 300
        y_step = 120

        for chain_idx, (src_ip, steps) in enumerate(sorted(active.items())):
            # 排序：按时间
            steps.sort(key=lambda s: s['time'])

            # 源 IP 节点 (左侧)
            src_x = x_start + chain_idx * x_step
            src_y = y_start

            # Source node
            src_ellipse = QGraphicsEllipseItem(QRectF(src_x - 30, src_y - 15, 60, 30))
            src_ellipse.setBrush(QBrush(QColor("#007AFF")))
            src_ellipse.setPen(QPen(QColor("#0055CC"), 2))
            self._chain_scene.addItem(src_ellipse)

            src_text = QGraphicsTextItem(src_ip)
            src_text.setDefaultTextColor(QColor("#FFFFFF"))
            src_text.setFont(QFont("Segoe UI", 9, QFont.Bold))
            src_text.setPos(src_x - 28, src_y - 10)
            self._chain_scene.addItem(src_text)

            prev_x = src_x
            prev_y = src_y + 15

            for step_idx, step in enumerate(steps):
                dest_x = prev_x
                dest_y = prev_y + y_step

                # 目标节点
                color = phase_colors.get(step['phase'], phase_colors['unknown'])
                dst_ellipse = QGraphicsEllipseItem(
                    QRectF(dest_x - 35, dest_y - 15, 70, 30))
                dst_ellipse.setBrush(QBrush(color))
                dst_ellipse.setPen(QPen(color.darker(120), 2))
                self._chain_scene.addItem(dst_ellipse)

                # 目标标签 (dst_ip + category)
                label_text = "{0}:{1}".format(
                    step['dst'][:15], step['category'][:12])
                dst_text = QGraphicsTextItem(label_text)
                dst_text.setDefaultTextColor(QColor("#1D1D1F"))
                dst_text.setFont(QFont("Segoe UI", 8))
                dst_text.setPos(dest_x - 30, dest_y - 10)
                self._chain_scene.addItem(dst_text)

                # 连线
                line = QGraphicsLineItem(
                    QLineF(QPointF(prev_x, prev_y),
                           QPointF(dest_x, dest_y)))
                line.setPen(QPen(color, 2, Qt.DashLine))
                self._chain_scene.addItem(line)

                # 时间标签
                time_str = time.strftime('%H:%M:%S',
                                         time.localtime(step['time']))
                time_text = QGraphicsTextItem(time_str)
                time_text.setDefaultTextColor(QColor("#86868B"))
                time_text.setFont(QFont("Segoe UI", 7))
                time_text.setPos(dest_x - 45, dest_y + 15)
                self._chain_scene.addItem(time_text)

                # 阶段标签
                phase_text = QGraphicsTextItem(step['phase'])
                phase_text.setDefaultTextColor(color)
                phase_text.setFont(QFont("Segoe UI", 8, QFont.Bold))
                phase_text.setPos(dest_x - 40, dest_y - 28)
                self._chain_scene.addItem(phase_text)

                prev_y = dest_y + 15
                prev_x = dest_x

            # 攻击链完成度
            unique_phases = len(set(s['phase'] for s in steps))
            chain_level = ("CRITICAL" if unique_phases >= 4 else
                           "HIGH" if unique_phases >= 3 else "MEDIUM")
            level_color = ("#FF3B30" if chain_level == "CRITICAL" else
                           "#FF9500" if chain_level == "HIGH" else "#FFCC00")
            level_text = QGraphicsTextItem(
                "Level: {0} ({1} phases)".format(chain_level, unique_phases))
            level_text.setDefaultTextColor(QColor(level_color))
            level_text.setFont(QFont("Segoe UI", 10, QFont.Bold))
            level_text.setPos(src_x + 80, src_y - 15)
            self._chain_scene.addItem(level_text)

        count = len(active)
        total_steps = sum(len(s) for s in active.values())
        max_phases = max(
            len(set(s['phase'] for s in st)) for st in active.values())
        self.lbl_chain_info.setText(
            "{0} chains | {1} steps | max {2} phases".format(
                count, total_steps, max_phases))

    @staticmethod
    def _map_category_to_phase(category: str) -> str:
        """将告警类别映射到 MITRE ATT&CK 攻击阶段"""
        mapping = {
            'scan': 'recon',
            'sql_injection': 'exploit',
            'xss': 'exploit',
            'web_attack': 'exploit',
            'webshell': 'exploit',
            'brute_force': 'exploit',
            'backdoor': 'c2',
            'dos': 'exploit',
        }
        return mapping.get(category, 'unknown')

    # ─── Log 页 ───

    def _create_log_tab(self) -> QWidget:
        """系统日志 — 卡片包裹"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title = QLabel("System Log")
        title.setStyleSheet("font-size: 36px; font-weight: 700; padding-bottom: 4px;")
        layout.addWidget(title)

        card = QFrame()
        card.setObjectName("contentCard")
        card_layout = QVBoxLayout(card)

        self.text_log = QTextEdit()
        self.text_log.setReadOnly(True)
        self.text_log.setFont(QFont("Consolas", 13))
        card_layout.addWidget(self.text_log)

        layout.addWidget(card)
        return page

    # ─── 统计卡片工厂 ───

    def _make_stat_card(self, title: str, value: str,
                         accent: str = "#007AFF") -> QFrame:
        """创建 Apple 风格统计卡片 (圆角白底 + 左侧色条)"""
        card = QFrame()
        card.setObjectName("statCard")
        card.setMinimumHeight(110)

        inner = QVBoxLayout(card)
        inner.setContentsMargins(16, 10, 12, 10)
        inner.setSpacing(4)

        # 数值 (大号粗体)
        lbl_value = QLabel(value)
        lbl_value.setObjectName("cardValue")
        lbl_value.setStyleSheet(
            "font-size: 48px; font-weight: 700; color: {0};".format(accent))
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

    def _on_demo(self):
        """Demo 模式: 启动/停止动态流量生成器, 实时产生攻击+正常混合流量"""
        if self.engine is None:
            self._log("[ERROR] No engine, cannot start demo")
            return

        gen = self.demo_generator
        if gen is not None and gen.is_running:
            gen.stop()
            self._log("Demo stopped: %d packets sent" % gen.get_stats()["sent"])
            self.btn_demo.setText("▶  Demo")
            return

        self.demo_generator = TrafficGenerator(self.engine)
        self.demo_generator.start(pps=2.0)
        self.btn_demo.setText("■  Stop Demo")
        self._log("Demo started: 2 pps attack+normal mixed traffic")

    def _on_reset_session(self):
        """Clear current GUI/session counters without reloading configuration."""
        if self.engine is None:
            return

        capture = getattr(self.engine, 'capture', None)
        if capture is not None and capture.is_running:
            QMessageBox.information(
                self, "Reset Session",
                "Stop the current capture or replay before resetting."
            )
            return

        demo = getattr(self, 'demo_generator', None)
        if demo is not None and getattr(demo, 'is_running', False):
            QMessageBox.information(
                self, "Reset Session",
                "Stop Demo before resetting."
            )
            return

        self.engine.alert_mgr.clear_all()

        if capture is not None:
            capture.packets_captured = 0
            capture.bytes_captured = 0
            capture.start_time = 0.0
            capture._last_stats_time = time.time()
            capture._pps_counter = 0
            capture._current_pps = 0.0
            capture.recent_packets.clear()
            capture.recent_alerts.clear()

        reassembler = getattr(self.engine, 'reassembler', None)
        if reassembler is not None:
            with reassembler._lock:
                reassembler._streams.clear()
                reassembler.total_streams_created = 0
                reassembler.total_streams_expired = 0
                reassembler.total_bytes_reassembled = 0

        anomaly = getattr(self.engine, 'anomaly_detector', None)
        if anomaly is not None:
            with anomaly._lock:
                anomaly._stats.clear()
                if hasattr(anomaly, '_beacon_flows'):
                    anomaly._beacon_flows.clear()
                anomaly.total_processed = 0
                anomaly.total_alerts = 0
                anomaly.window_start = time.time()
            if hasattr(self.engine, '_last_anomaly_check'):
                self.engine._last_anomaly_check = 0.0

        self._pps_history.clear()
        self._bps_history.clear()
        self._chart_time_counter = 0
        self._update_realtime_chart()
        self._refresh_statistics()

        self.table_recent.setRowCount(0)
        self.table_alerts.setRowCount(0)
        self.text_top_ip.setText("  No data")
        if hasattr(self, 'text_top_src'):
            self.text_top_src.setText("  No data")

        for card in [self.card_total_alerts, self.card_critical,
                     self.card_high, self.card_medium, self.card_low,
                     self.card_total_packets]:
            self._set_card_value(card, "0")

        self.lbl_pps.setText("PPS: 0")
        self.lbl_bps.setText("BPS: 0")
        self.lbl_conn.setText("Conn: 0")
        self.lbl_hosts.setText("Hosts: 0")
        self.lbl_streams.setText("TCP: 0")
        self.pps_label.setText("PPS: 0")
        self.alerts_label.setText("Alerts: 0")
        self.uptime_label.setText("Uptime: 00:00:00")
        self._log("Session statistics reset")

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

    def _on_alert_double_click(self, row: int, col: int):
        """双击告警表格行 → 弹窗显示完整告警详情 + 威胁情报"""
        table = self.sender()
        if table is None or self.engine is None:
            return

        # 从表格获取 alert_id
        if table is self.table_alerts:
            id_item = table.item(row, 0)
            if id_item is None:
                return
            alert_id = int(id_item.text())
            alert = self.engine.alert_mgr.get_alert_by_id(alert_id)
        elif table is self.table_recent:
            alerts = list(self.engine.alert_mgr.recent_alerts)
            if row >= len(alerts):
                return
            alert = alerts[-20 + row] if len(alerts) > 20 else alerts[row]
        else:
            return

        if alert is None:
            return

        # 查询威胁情报
        threat_info = self._query_threat_intel(alert.src_ip)

        # 构建详细内容
        sev_color = {'critical': '#FF3B30', 'high': '#FF9500',
                     'medium': '#FFCC00', 'low': '#007AFF'}.get(
                         alert.severity, '#86868B')

        detail_html = (
            "<hr style='border:1px solid #E5E5EA'>"
            "<table cellspacing=8>"
            "<tr><td><b>Alert ID:</b></td><td>{0}</td></tr>"
            "<tr><td><b>Time:</b></td><td>{1}</td></tr>"
            "<tr><td><b>Source:</b></td><td>{2}</td></tr>"
            "<tr><td><b>Category:</b></td><td>{3}</td></tr>"
            "<tr><td><b>Severity:</b></td><td><span style='color:{5};font-weight:bold'>{4}</span></td></tr>"
            "<tr><td><b>Signature ID:</b></td><td>{6}</td></tr>"
            "<tr><td><b>Src IP:</b></td><td>{7}</td></tr>"
            "<tr><td><b>Dst IP:</b></td><td>{8}:{9}</td></tr>"
            "<tr><td><b>Protocol:</b></td><td>{10}</td></tr>"
            "<tr><td><b>Matched Pattern:</b></td><td><code>{11}</code></td></tr>"
            "<tr><td><b>Matched Text:</b></td><td><code>{12}</code></td></tr>"
        ).format(
            alert.alert_id,
            time.strftime('%Y-%m-%d %H:%M:%S',
                          time.localtime(alert.timestamp)),
            alert.source, alert.category, alert.severity, sev_color,
            alert.signature_id, alert.src_ip, alert.dst_ip,
            alert.dst_port, alert.protocol or 'TCP',
            alert.matched_pattern[:150] if alert.matched_pattern else '-',
            alert.matched_text[:150] if alert.matched_text else '-',
        )

        # 威胁情报行
        if threat_info and threat_info.get('available'):
            risk_color = '#FF3B30' if threat_info.get('risk') == 'HIGH' else '#34C759'
            detail_html += (
                "<tr><td colspan='2'><hr style='border:1px solid #E5E5EA'>"
                "<b style='font-size:14px'>Threat Intelligence</b></td></tr>"
                "<tr><td><b>AbuseIPDB Score:</b></td><td>{t[abuseipdb_score]}/100</td></tr>"
                "<tr><td><b>OTX Pulses:</b></td><td>{t[otx_pulses]} community reports</td></tr>"
                "<tr><td><b>Combined Risk:</b></td><td><span style='color:{rc};font-weight:bold'>{t[combined_risk]}</span></td></tr>"
            ).format(
                t=threat_info,
                rc=risk_color,
            )
        else:
            detail_html += (
                "<tr><td colspan='2'><hr style='border:1px solid #E5E5EA'>"
                "<span style='color:#86868B'>Threat Intel: No known malicious reputation</span></td></tr>"
            )

        detail_html += "</table>"

        dlg = QMessageBox(self)
        dlg.setWindowTitle("Alert Detail")
        dlg.setIcon(QMessageBox.Information)
        dlg.setText("<b style='font-size:16px'>{0}</b>".format(
            alert.signature_name or alert.description))
        dlg.setInformativeText(detail_html)
        dlg.setStandardButtons(QMessageBox.Ok)
        dlg.exec_()

    def _query_threat_intel(self, src_ip: str) -> dict:
        """查询来源 IP 的威胁情报信息"""
        # 优先使用本地威胁情报模块
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
            from tools.threat_intel import ThreatIntel
            ti = ThreatIntel()
            result = ti.check_ip(src_ip)
            if result and result.get('score', 0) > 0:
                return {
                    'available': True,
                    'abuseipdb_score': result.get('score', 0),
                    'otx_pulses': result.get('pulse_count', 0),
                    'combined_risk': 'HIGH' if result.get('score', 0) > 50 else 'LOW',
                    'category': result.get('category', ''),
                }
        except Exception:
            pass

        # Fallback: 检查本地黑名单
        local_blacklist = {
            '10.0.0.55': 85, '10.0.0.99': 90,
            '10.0.0.77': 75,
        }
        if src_ip in local_blacklist:
            score = local_blacklist[src_ip]
            return {
                'available': True,
                'abuseipdb_score': score,
                'otx_pulses': 0,
                'combined_risk': 'HIGH' if score > 50 else 'LOW',
                'category': 'local_blacklist',
            }

        return {'available': False}

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

            # 更新仪表盘卡片 — 用累计统计(by_severity)而非仅最近60秒
            all_stats = self.engine.alert_mgr.get_statistics()
            sev = all_stats.get('by_severity', {})
            self._set_card_value(self.card_total_alerts,
                str(all_stats['total']))
            self._set_card_value(self.card_critical,
                str(sev.get('critical', 0)))
            self._set_card_value(self.card_high,
                str(sev.get('high', 0)))
            self._set_card_value(self.card_medium,
                str(sev.get('medium', 0)))
            self._set_card_value(self.card_low,
                str(sev.get('low', 0)))
            self._set_card_value(self.card_total_packets,
                str(status.get('packets_captured', 0)))

            # 更新流量统计 (Demo 模式下用生成器 PPS, 否则用抓包器 PPS)
            gen = self.demo_generator
            if gen is not None and gen._running:
                gs = gen.get_stats()
                now_sent = gs["sent"]
                current_pps = now_sent - self._last_gen_sent  # delta ~ PPS
                self._last_gen_sent = now_sent
                current_bps = current_pps * 512  # assume ~512 bytes/pkt
            else:
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

            # 从异常检测器获取主机数 + 异常告警数
            if self.engine and self.engine.anomaly_detector:
                ad = self.engine.anomaly_detector.get_statistics()
                self.lbl_hosts.setText(
                    "Hosts: {0}".format(ad.get('total_hosts_tracked', 0)))
                self.lbl_ano.setText(
                    "Anomaly: {0}".format(ad.get('total_alerts', 0)))
            else:
                self.lbl_hosts.setText("Hosts: 0")
                self.lbl_ano.setText("Anomaly: 0")

            # ML 检测器状态
            if self.engine and self.engine.ml_detector:
                ml_ready = self.engine.ml_detector.is_ready()
                if ml_ready:
                    ml_stats = self.engine.ml_detector.get_statistics()
                    self.lbl_ml.setText(
                        "ML: {0}/{1}".format(
                            ml_stats.get('anomalies', 0),
                            ml_stats.get('total_checked', 0)))
                else:
                    self.lbl_ml.setText("ML: not trained")
            else:
                self.lbl_ml.setText("ML: n/a")

            # Demo 模式生成器状态
            if gen is not None and gen._running:
                self.lbl_gen.setText(
                    "Demo: {0}pkt".format(gen.get_stats()["sent"]))
            else:
                self.lbl_gen.setText("Demo: OFF")

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
                # ★ Source 列: anomaly / misuse / tls / ml — 双引擎区分关键
                self.table_recent.setItem(i, 2,
                    QTableWidgetItem(alert.source))
                self.table_recent.setItem(i, 3,
                    QTableWidgetItem(alert.category))
                self.table_recent.setItem(i, 4,
                    QTableWidgetItem(alert.src_ip))
                self.table_recent.setItem(i, 5,
                    QTableWidgetItem(alert.description))

        except Exception:
            pass

        # 每 5 秒刷新统计图表 + 告警表格 + 攻击链
        if self._chart_time_counter % 5 == 0:
            self._refresh_statistics()
            if self.stack.currentIndex() == 1:
                self._on_filter_alerts()
            if self.stack.currentIndex() == 4:
                self._refresh_attack_chain()
                self._on_filter_alerts()

        # 每 10 秒刷新攻击链面板
        if self._chart_time_counter % 10 == 0 and self.stack.currentIndex() == 4:
            self._refresh_attack_chain()

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

        # 饼图/柱状图 图例颜色适配当前主题
        if HAS_PYQTCHART:
            txt_color = QColor(LIGHT_THEME['text'] if self._current_theme == 'light'
                               else DARK_THEME['text'])
            if hasattr(self, '_pie_chart'):
                self._pie_chart.legend().setLabelColor(txt_color)
            if hasattr(self, '_pps_chart'):
                self._pps_chart.legend().setLabelColor(txt_color)
                self._pps_chart.setTitleBrush(txt_color)

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

        # 类别柱状图 (横向)
        if HAS_PYQTCHART and hasattr(self, '_bar_set'):
            cats = sorted(stats.get('by_category', {}).items(),
                          key=lambda x: x[1], reverse=True)[:8]
            self._bar_set.remove(0, self._bar_set.count())
            cat_labels = []
            for cat, count in cats:
                self._bar_set.append(count)
                cat_labels.append(str(cat))
            self._bar_axis_cat.clear()
            self._bar_axis_cat.append(cat_labels)
            max_val = max([c for _, c in cats], default=1)
            self._bar_axis_val.setRange(0, max_val * 1.3)

        # TOP 攻击源 IP
        self.list_top_src.clear()
        for ip, count in stats.get('top_attack_sources', [])[:10]:
            self.list_top_src.addItem(
                "  {0}  —  {1} attacks".format(ip, count))

        # 告警降噪统计 (C模块: AlertFilter)
        if self.engine and self.engine.alert_filter:
            fs = self.engine.alert_filter.get_statistics()
            if fs.get('processed', 0) > 0:
                self.lbl_chain_info.setText(
                    "[Filter] {0} processed, {1} suppressed, {2} downgraded".format(
                        fs.get('processed', 0),
                        fs.get('suppressed', 0),
                        fs.get('downgraded', 0)))

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
