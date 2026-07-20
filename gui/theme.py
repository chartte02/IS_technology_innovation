# ============================================================
# 模块: Apple 风格主题系统 (theme.py)
# 功能: 配色方案 + QSS 样式表生成
# 负责人: 成员D
# ============================================================

"""Apple 风格主题 — 纯数据/函数, 无 Qt widget 依赖, 可独立导入调试。

使用:
    from gui.theme import LIGHT_THEME, DARK_THEME, build_stylesheet

    c = LIGHT_THEME                          # 取配色字典
    qss = build_stylesheet(c)                # 生成 QSS 字符串
    window.setStyleSheet(qss)                # 应用到窗口

修改主题时只需编辑此文件, 重新导入即生效, 无需重启整个应用。
"""

# ═══════════════════════════════════════════════════════════════
# 配色方案
# ═══════════════════════════════════════════════════════════════

LIGHT_THEME: dict = {
    'window':        '#F5F5F7',
    'windowText':    '#1D1D1F',
    'base':          '#FFFFFF',
    'alternateBase': '#F9F9FB',
    'text':          '#1D1D1F',
    'button':        '#FFFFFF',
    'buttonText':    '#1D1D1F',
    'highlight':     '#007AFF',
    'sidebar':       '#ECECF0',
    'sidebarBorder': '#D1D1D6',
    'sidebarHover':  '#E0E0E5',
    'card':          '#FFFFFF',
    'cardBorder':    '#E5E5EA',
    'grayText':      '#86868B',
    'grayText2':     '#AEAEB2',
    'separator':     '#E0E0E5',
    'green':         '#34C759',
    'red':           '#FF3B30',
    'orange':        '#FF9500',
    'yellow':        '#FFCC00',
    'purple':        '#AF52DE',
    'blue':          '#007AFF',
    'teal':          '#5AC8FA',
    'chartBg':       '#FFFFFF',
}

DARK_THEME: dict = {
    'window':        '#1C1C1E',
    'windowText':    '#F5F5F7',
    'base':          '#2C2C2E',
    'alternateBase': '#3A3A3C',
    'text':          '#F5F5F7',
    'button':        '#3A3A3C',
    'buttonText':    '#F5F5F7',
    'highlight':     '#0A84FF',
    'sidebar':       '#2C2C2E',
    'sidebarBorder': '#48484A',
    'sidebarHover':  '#3A3A3C',
    'card':          '#3A3A3C',
    'cardBorder':    '#48484A',
    'grayText':      '#98989D',
    'grayText2':     '#636366',
    'separator':     '#48484A',
    'green':         '#30D158',
    'red':           '#FF453A',
    'orange':        '#FF9F0A',
    'yellow':        '#FFD60A',
    'purple':        '#BF5AF2',
    'blue':          '#0A84FF',
    'teal':          '#64D2FF',
    'chartBg':       '#3A3A3C',
}


# ═══════════════════════════════════════════════════════════════
# 字号常量 (改一处, 全局生效)
# ═══════════════════════════════════════════════════════════════

FONT_BASE      = '20px'   # 全局默认
FONT_SIDEBAR   = '20px'   # 侧边栏
FONT_CARD_VAL  = '44px'   # 卡片数值
FONT_CARD_TTL  = '16px'   # 卡片标题
FONT_SECTION   = '20px'   # 内容区标题
FONT_BTN       = '18px'   # 按钮
FONT_TBL_HEAD  = '15px'   # 表头
FONT_STATUSBAR = '17px'   # 状态栏
FONT_GROUP_TTL = '15px'   # 分组框标题


# ═══════════════════════════════════════════════════════════════
# QSS 样式表生成
# ═══════════════════════════════════════════════════════════════

def build_stylesheet(c: dict) -> str:
    """根据配色字典生成 Apple 风格全局 QSS 样式表。"""
    return f"""
    /* ===== 全局 ===== */
    QMainWindow {{
        background-color: {c['window']};
    }}
    QWidget {{
        font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
        font-size: {FONT_BASE};
        color: {c['text']};
    }}

    /* ===== 顶部控制栏分隔线 ===== */
    QFrame#toolbarSeparator {{
        color: {c['sidebarBorder']};
        max-height: 1px;
    }}

    /* ===== 侧边栏 ===== */
    QListWidget#sidebar {{
        background-color: {c['sidebar']};
        border: none;
        border-right: 1px solid {c['sidebarBorder']};
        outline: none;
        font-size: {FONT_SIDEBAR};
        padding: 8px 0;
    }}
    QListWidget#sidebar::item {{
        border-radius: 8px;
        margin: 1px 10px;
        padding: 12px 16px;
        color: {c['text']};
    }}
    QListWidget#sidebar::item:selected {{
        background-color: {c['highlight']};
        color: #FFFFFF;
        font-weight: 600;
    }}
    QListWidget#sidebar::item:hover:!selected {{
        background-color: {c['sidebarHover']};
    }}

    /* ===== 内容区 ===== */
    QStackedWidget#contentStack {{
        background-color: {c['window']};
    }}

    /* ===== 统计卡片 ===== */
    QFrame#statCard {{
        background-color: {c['card']};
        border-radius: 10px;
        border: 1px solid {c['cardBorder']};
        padding: 16px 12px;
    }}
    QLabel#cardValue {{
        font-size: {FONT_CARD_VAL};
        font-weight: 700;
    }}
    QLabel#cardTitle {{
        font-size: {FONT_CARD_TTL};
        font-weight: 600;
        color: {c['grayText']};
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 2px;
    }}

    /* ===== 内容卡片 ===== */
    QFrame#contentCard {{
        background-color: {c['card']};
        border-radius: 10px;
        border: 1px solid {c['cardBorder']};
        padding: 16px;
    }}
    QLabel#sectionTitle {{
        font-size: {FONT_SECTION};
        font-weight: 700;
        color: {c['text']};
        padding-bottom: 8px;
    }}

    /* ===== 按钮 ===== */
    QPushButton {{
        background-color: {c['button']};
        color: {c['buttonText']};
        border: 1px solid {c['cardBorder']};
        border-radius: 8px;
        padding: 8px 20px;
        font-size: {FONT_BTN};
    }}
    QPushButton:hover {{
        background-color: {c['alternateBase']};
        border-color: {c['grayText2']};
    }}
    QPushButton:pressed {{
        background-color: {c['highlight']};
        color: white;
        border-color: {c['highlight']};
    }}

    /* 主操作按钮 — 启动/停止 */
    QPushButton#btnStart {{
        border: none;
        font-weight: 700;
        font-size: {FONT_BTN};
        padding: 10px 24px;
        border-radius: 8px;
    }}
    QPushButton#btnStart[state="stopped"] {{
        background-color: {c['green']};
        color: white;
    }}
    QPushButton#btnStart[state="stopped"]:hover {{
        background-color: {c['green']};
        opacity: 0.85;
    }}
    QPushButton#btnStart[state="running"] {{
        background-color: {c['red']};
        color: white;
    }}
    QPushButton#btnStart[state="running"]:hover {{
        background-color: {c['red']};
        opacity: 0.85;
    }}

    /* 控制栏次要按钮 */
    QPushButton#ctrlBtn {{
        background-color: transparent;
        border: 1px solid {c['cardBorder']};
        border-radius: 8px;
        padding: 8px 16px;
        font-size: {FONT_BTN};
    }}
    QPushButton#ctrlBtn:hover {{
        background-color: {c['alternateBase']};
    }}

    /* ===== 表格 ===== */
    QTableWidget {{
        background-color: {c['card']};
        alternate-background-color: {c['alternateBase']};
        border: 1px solid {c['cardBorder']};
        border-radius: 8px;
        gridline-color: {c['separator']};
        selection-background-color: {c['highlight']};
        selection-color: white;
    }}
    QTableWidget::item {{
        padding: 6px 12px;
    }}
    QHeaderView::section {{
        background-color: {c['sidebar']};
        color: {c['text']};
        border: none;
        border-bottom: 1px solid {c['separator']};
        padding: 10px 12px;
        font-weight: 700;
        font-size: {FONT_TBL_HEAD};
        text-transform: uppercase;
    }}

    /* ===== 下拉框 (Apple 风格) ===== */
    QComboBox {{
        background-color: {c['card']};
        border: 1px solid {c['cardBorder']};
        border-radius: 8px;
        padding: 8px 36px 8px 14px;
        color: {c['text']};
        font-size: {FONT_BTN};
        min-width: 100px;
    }}
    QComboBox:hover {{
        border-color: {c['highlight']};
        background-color: {c['alternateBase']};
    }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 32px;
        border: none;
        border-left: 1px solid {c['cardBorder']};
        border-top-right-radius: 7px;
        border-bottom-right-radius: 7px;
    }}
    QComboBox::down-arrow {{
        width: 10px;
        height: 10px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {c['card']};
        border: 1px solid {c['cardBorder']};
        border-radius: 8px;
        padding: 4px 0;
        margin-top: 4px;
        selection-background-color: {c['highlight']};
        selection-color: white;
        font-size: {FONT_BTN};
        outline: none;
    }}
    QComboBox QAbstractItemView::item {{
        padding: 8px 14px;
        min-height: 28px;
    }}
    QComboBox QAbstractItemView::item:hover {{
        background-color: {c['alternateBase']};
    }}

    /* 告警页面下拉框 (略宽) */
    QComboBox#appleCombo {{
        min-width: 130px;
    }}

    /* ===== 文本输入 ===== */
    QLineEdit {{
        background-color: {c['card']};
        border: 1px solid {c['cardBorder']};
        border-radius: 6px;
        padding: 8px 12px;
        color: {c['text']};
        font-size: {FONT_BTN};
    }}
    QLineEdit:focus {{
        border-color: {c['highlight']};
    }}

    /* ===== 文本区域 ===== */
    QTextEdit {{
        background-color: {c['card']};
        border: 1px solid {c['cardBorder']};
        border-radius: 8px;
        color: {c['text']};
        padding: 10px;
    }}

    /* ===== 分割器 ===== */
    QSplitter::handle {{
        background-color: {c['separator']};
        width: 1px;
    }}

    /* ===== 状态栏 ===== */
    QStatusBar#appStatusBar {{
        background-color: {c['sidebar']};
        border-top: 1px solid {c['sidebarBorder']};
        color: {c['grayText']};
        font-size: {FONT_STATUSBAR};
        padding: 4px 14px;
    }}
    QLabel#statusLabel {{
        color: {c['grayText']};
        font-size: {FONT_STATUSBAR};
    }}

    /* ===== 滚动条 ===== */
    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {c['cardBorder']};
        border-radius: 5px;
        min-height: 36px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {c['grayText2']};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar:horizontal {{
        background: transparent;
        height: 10px;
    }}
    QScrollBar::handle:horizontal {{
        background: {c['cardBorder']};
        border-radius: 5px;
        min-width: 36px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {c['grayText2']};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
    }}

    /* ===== 分组框 (保留用于兼容) ===== */
    QGroupBox {{
        font-weight: 700;
        border: 1px solid {c['cardBorder']};
        border-radius: 8px;
        margin-top: 8px;
        padding-top: 18px;
        color: {c['text']};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 6px;
        color: {c['grayText']};
        font-size: {FONT_GROUP_TTL};
        text-transform: uppercase;
    }}
    """
