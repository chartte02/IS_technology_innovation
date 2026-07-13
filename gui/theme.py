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
# QSS 样式表生成
# ═══════════════════════════════════════════════════════════════

def build_stylesheet(c: dict) -> str:
    """根据配色字典生成 Apple 风格全局 QSS 样式表。

    Args:
        c: 配色字典 (LIGHT_THEME 或 DARK_THEME)

    Returns:
        str: 完整的 QSS 样式表字符串 (~7400 字符)

    调试提示:
        >>> from gui.theme import LIGHT_THEME, build_stylesheet
        >>> qss = build_stylesheet(LIGHT_THEME)
        >>> print(qss[:200])   # 预览前 200 字符
        >>> # 修改配色后只需重新调用 build_stylesheet() 然后 setStyleSheet()
    """
    return """
    /* ===== 全局 ===== */
    QMainWindow {{
        background-color: {window};
    }}
    QWidget {{
        font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
        font-size: 15px;
        color: {text};
    }}

    /* ===== 顶部控制栏分隔线 ===== */
    QFrame#toolbarSeparator {{
        color: {sidebarBorder};
        max-height: 1px;
    }}

    /* ===== 侧边栏 ===== */
    QListWidget#sidebar {{
        background-color: {sidebar};
        border: none;
        border-right: 1px solid {sidebarBorder};
        outline: none;
        font-size: 15px;
        padding: 8px 0;
    }}
    QListWidget#sidebar::item {{
        border-radius: 8px;
        margin: 1px 10px;
        padding: 10px 14px;
        color: {text};
    }}
    QListWidget#sidebar::item:selected {{
        background-color: {highlight};
        color: #FFFFFF;
        font-weight: 600;
    }}
    QListWidget#sidebar::item:hover:!selected {{
        background-color: {sidebarHover};
    }}

    /* ===== 内容区 ===== */
    QStackedWidget#contentStack {{
        background-color: {window};
    }}

    /* ===== 统计卡片 ===== */
    QFrame#statCard {{
        background-color: {card};
        border-radius: 10px;
        border: 1px solid {cardBorder};
        padding: 14px 10px;
    }}
    QLabel#cardValue {{
        font-size: 32px;
        font-weight: 700;
    }}
    QLabel#cardTitle {{
        font-size: 13px;
        font-weight: 600;
        color: {grayText};
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}

    /* ===== 内容卡片 ===== */
    QFrame#contentCard {{
        background-color: {card};
        border-radius: 10px;
        border: 1px solid {cardBorder};
        padding: 16px;
    }}
    QLabel#sectionTitle {{
        font-size: 16px;
        font-weight: 700;
        color: {text};
        padding-bottom: 8px;
    }}

    /* ===== 按钮 ===== */
    QPushButton {{
        background-color: {button};
        color: {buttonText};
        border: 1px solid {cardBorder};
        border-radius: 6px;
        padding: 6px 16px;
        font-size: 15px;
    }}
    QPushButton:hover {{
        background-color: {alternateBase};
        border-color: {grayText2};
    }}
    QPushButton:pressed {{
        background-color: {highlight};
        color: white;
        border-color: {highlight};
    }}

    /* 主操作按钮 — 启动/停止 */
    QPushButton#btnStart {{
        border: none;
        font-weight: 700;
        font-size: 15px;
        padding: 8px 20px;
        border-radius: 8px;
    }}
    QPushButton#btnStart[state="stopped"] {{
        background-color: {green};
        color: white;
    }}
    QPushButton#btnStart[state="stopped"]:hover {{
        background-color: {green};
        opacity: 0.85;
    }}
    QPushButton#btnStart[state="running"] {{
        background-color: {red};
        color: white;
    }}
    QPushButton#btnStart[state="running"]:hover {{
        background-color: {red};
        opacity: 0.85;
    }}

    /* 控制栏次要按钮 */
    QPushButton#ctrlBtn {{
        background-color: transparent;
        border: 1px solid {cardBorder};
        border-radius: 6px;
        padding: 6px 14px;
    }}
    QPushButton#ctrlBtn:hover {{
        background-color: {alternateBase};
    }}

    /* ===== 表格 ===== */
    QTableWidget {{
        background-color: {card};
        alternate-background-color: {alternateBase};
        border: 1px solid {cardBorder};
        border-radius: 8px;
        gridline-color: {separator};
        selection-background-color: {highlight};
        selection-color: white;
    }}
    QTableWidget::item {{
        padding: 5px 10px;
    }}
    QHeaderView::section {{
        background-color: {sidebar};
        color: {text};
        border: none;
        border-bottom: 1px solid {separator};
        padding: 8px 10px;
        font-weight: 700;
        font-size: 13px;
        text-transform: uppercase;
    }}

    /* ===== 下拉框 ===== */
    QComboBox {{
        background-color: {card};
        border: 1px solid {cardBorder};
        border-radius: 6px;
        padding: 5px 10px;
        color: {text};
    }}
    QComboBox:hover {{
        border-color: {highlight};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {card};
        border: 1px solid {cardBorder};
        border-radius: 6px;
        selection-background-color: {highlight};
        selection-color: white;
    }}

    /* ===== 文本输入 ===== */
    QLineEdit {{
        background-color: {card};
        border: 1px solid {cardBorder};
        border-radius: 6px;
        padding: 6px 10px;
        color: {text};
    }}
    QLineEdit:focus {{
        border-color: {highlight};
    }}

    /* ===== 文本区域 ===== */
    QTextEdit {{
        background-color: {card};
        border: 1px solid {cardBorder};
        border-radius: 8px;
        color: {text};
        padding: 8px;
    }}

    /* ===== 分割器 ===== */
    QSplitter::handle {{
        background-color: {separator};
        width: 1px;
    }}

    /* ===== 状态栏 ===== */
    QStatusBar#appStatusBar {{
        background-color: {sidebar};
        border-top: 1px solid {sidebarBorder};
        color: {grayText};
        font-size: 14px;
        padding: 3px 12px;
    }}
    QLabel#statusLabel {{
        color: {grayText};
        font-size: 14px;
    }}

    /* ===== 滚动条 ===== */
    QScrollBar:vertical {{
        background: transparent;
        width: 8px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {cardBorder};
        border-radius: 4px;
        min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {grayText2};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar:horizontal {{
        background: transparent;
        height: 8px;
    }}
    QScrollBar::handle:horizontal {{
        background: {cardBorder};
        border-radius: 4px;
        min-width: 30px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {grayText2};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
    }}

    /* ===== 分组框 (保留用于兼容, 但新设计用 contentCard) ===== */
    QGroupBox {{
        font-weight: 700;
        border: 1px solid {cardBorder};
        border-radius: 8px;
        margin-top: 8px;
        padding-top: 16px;
        color: {text};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 6px;
        color: {grayText};
        font-size: 13px;
        text-transform: uppercase;
    }}
    """.format(**c)
