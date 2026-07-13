# 成员D 开发日志 — GUI 界面 + 告警管理 + 测试 + 文档

> **负责模块**: `gui/main_window.py`, `core/alert_manager.py`, `tests/`, `docs/`
> **角色**: 前端开发 + 测试 + 文档 + 演示
> **开始日期**: 2026-07-08

---

## Day 1 — 2026-07-08 (环境搭建 + GUI 基础修复 + 测试)

### 1. 今日进度

- [x] 搭建 Python 3.13.5 venv 环境，安装全部依赖（scapy, pyqt5, pyqtchart, pyahocorasick, sklearn 等）
- [x] GUI 窗口正常打开/关闭，确认 PyQt5 5.15.11 + PyQtChart 5.15.7 可用
- [x] `alert_manager.py` 独立测试全部通过（提交/去重/统计/JSON 导出/误报标记）
- [x] 修复 GUI 4 个 bug（emoji 崩溃、统计卡片引用、特征库按钮回调、**AC 自动机大小写 bug**）
- [x] 重写 `tests/test_signature_match.py`（全英文避免编码问题）
- [x] 测试准确率：**17/17 = 100%**（SQL注入/XSS/Web攻击/暴力破解 全部通过）

### 2. 遇到的问题与解决

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| emoji 导致 Windows cp1252 崩溃 (`_print_alert`) | colorama 将 emoji 写入 cp1252 编码的终端时失败 | 改用纯 ASCII 标记 `[CRIT]/[HIGH]/[MED]/[LOW]`，包裹 try/except |
| GUI 统计卡片 `findChild(QLabel)` 返回 GroupBox 的标题 label 而非数值 label | QGroupBox 标题也是 QLabel，`findChild` 返回第一个 | 在 `_make_stat_card` 中保存 `gb._value_label` 引用，新增 `_set_card_value` 方法精确更新 |
| 特征库管理 Tab 「查看」和「重载」按钮无回调 | 代码中只声明了按钮但未 `.clicked.connect()` | 新增 `_on_view_signature()` 和 `_on_reload_signatures()` 两个回调 |
| **成员A模块的 AC 自动机 bug**：暴力破解检测准确率 33% | `_build_indices` 直接用原始大小写 pattern 入 AC 自动机，但 `_match_ac` 用 `payload.lower()` 搜索 → 大小写不匹配 | 改为 `pattern.lower()` 入 AC 自动机，key 用 tuple 直接索引而非 `id()` → 暴力破解准确率 33%→100% |
| 测试文件在目录重构中丢失（`ids_detection_system/tests/` 层未随搬移） | 目录重构时文件未完全移动 | 重建 `tests/test_signature_match.py`，改为全英文 + 更完整的测试用例 |

### 3. Agent 协作记录

| 任务 | 是否用 Agent | 效果评估 |
|------|-------------|----------|
| 定位 emoji 崩溃的具体位置和原因 | ✅ | 2 分钟定位到 `_print_alert` 第 316 行 |
| 发现 AC 自动机大小写 bug | ✅ | 帮我写了 debug 脚本对比 `payload_lower` 和 AC 模式存储的内容，迅速定位根因 |
| 重写测试脚本 | ✅ | 从旧格式改为带详细输出的新格式，一次通过 |
| 环境搭建（pip install + 验证） | ✅ | 批量安装 15 个包，自动处理了 PyQtChart 包名不对的坑 |

### 4. 技术决策

| 决策 | 选项 A | 选项 B | 选择 | 理由 |
|------|--------|--------|------|------|
| 统计卡片更新方式 | `findChild(QLabel)` | `gb._value_label` 保存引用 | 引用 | `findChild` 不稳定，QGroupBox 的标题也是 QLabel |
| 图表库 | PyQtChart | matplotlib 嵌入 | PyQtChart | 原生 Qt 组件，与 PyQt5 无缝集成 |
| 终端输出编码 | emoji + Unicode | 纯 ASCII | 纯 ASCII | Windows 兼容性优先，emoji 只在 GUI 中用 |
| 测试脚本语言 | 中文注释 | 全英文 | 全英文 | 避免 Windows cp1252 编码问题 |

### 5. 性能/测试数据

| 测试项 | 结果 | 备注 |
|--------|------|------|
| GUI 窗口打开 | ✅ | PyQt5 5.15.11, 暗色主题正常 |
| 告警去重逻辑 | ✅ | 同 signature_id+src_ip+dst_ip 正确去重 |
| JSON 导出文件 | ✅ | alerts.json 存在，格式正确 |
| 误报标记 | ✅ | acknowledge + mark_false_positive 正常 |
| **特征匹配总准确率** | **100% (17/17)** | SQLi 6/6, XSS 4/4, Web 4/4, BruteForce 3/3 |
| 特征库规则数 | 58 条 | 7 个 YAML 文件 |

### 6. 参考项目借鉴

| 参考项目 | 借鉴内容 | 落地情况 |
|----------|----------|----------|
| （Day 2-3 计划）NetPortMon | PyQtChart 实时图表实现 | 待开始 |

### 7. 明日计划 (Day 2)

- [ ] 🔴 PDF必做：统计分析 Tab 增加 PyQtChart 图表（告警严重度饼图 + 攻击类别柱状图）
- [ ] 🔴 PDF必做：仪表盘增加实时流量折线图
- [ ] 🟡 下载 3 个 PCAP 攻击样本 → `tests/test_pcaps/`
- [ ] 🟡 统计整个项目代码行数（答辩用）

- [ ] 
- [ ] 

---

## Day 2 — 2026-07-13 (GUI 完善 + Bug 修复 + 端到端验证)

### 1. 今日进度

- [x] 验证 venv 环境全部依赖正常（Python 3.13.5, Scapy, PyQt5, PyQtChart, pyahocorasick）
- [x] 运行 `test_signature_match.py`：**17/17 = 100%** 准确率（确认 Day 1 回归无问题）
- [x] 验证 `alert_manager.py` 独立测试全部通过（提交/去重/统计/确认/误报标记）
- [x] 验证 GUI 窗口打开正常：5 个 Tab、3 个 PyQtChart 图表（饼图/柱状图/PPS折线图）、5 个统计卡片
- [x] **修复 Bug #5**：`get_status` 字段名不匹配 — GUI 用 `elapsed`，实际是 `elapsed_seconds`，导致运行时间始终 00:00:00
- [x] **修复 Bug #6**：暂停/恢复按钮逻辑错误 — `is_running` 暂停时返回 False，导致无法恢复
- [x] **修复 Bug #7**：告警列表 Tab 的「筛选」和「导出 JSON」按钮无回调函数
- [x] **新增功能**：告警列表 Tab 支持按严重度/类别筛选 + 筛选结果导出 JSON
- [x] **新增功能**：告警列表 Tab 每 5 秒自动刷新（切换到此 Tab 时）
- [x] 端到端验证：PCAP 回放 `synthetic_attacks.pcap` → 16 包 → 26 条告警覆盖 SQLi/XSS/Web/BruteForce
- [x] 统计项目代码行数：**4705 行 Python + 1166 行 YAML + 3630 行文档 = 9501 行**
- [x] 确认 PCAP 样本：3 个文件已就绪（`http.cap`, `synthetic_attacks.pcap`, `extended_attacks.pcap`）

### 2. 遇到的问题与解决

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 仪表盘运行时间始终显示 00:00:00 | `main_window.py` 中 `status.get('elapsed', 0)` 但 `PacketCapture.get_status()` 返回的 key 是 `elapsed_seconds` | 修改 `_refresh_ui` 中两处 `status.get('elapsed', ...)` → `status.get('elapsed_seconds', ...)` |
| 暂停后无法恢复（点击「恢复」无反应） | `_on_pause_resume` 入口检查 `self.engine.capture.is_running`，但暂停时 `is_running` 返回 `_running and not _paused = False` | 改为检查 `_running`（暂停时仍为 True），并通过 `_paused` 判断方向 |
| 告警列表 Tab 的筛选/导出按钮点击无反应 | 代码中只声明了按钮但未 `.clicked.connect()` | 新增 `_on_filter_alerts()` 和 `_on_export_alerts_tab()` 回调，并提取 `_populate_alert_table()` 复用方法 |
| 告警列表 Tab 表格始终为空 | `_refresh_ui` 只更新仪表盘最近告警表，未更新告警 Tab 的表格 | 每 5 秒自动调用 `_on_filter_alerts()`（仅在告警 Tab 激活时） |
| PCAP 回放控制台中文乱码（终端显示 `初` 等） | Windows 终端 Unicode 输出问题，不影响功能 | 功能正常，仅在 `--console` 模式下有显示问题，GUI 不受影响 |

### 3. Agent 协作记录

| 任务 | 是否用 Agent | 效果评估 |
|------|-------------|----------|
| 阅读项目代码并理解整体架构 | ✅ | 并行读取 10+ 个文件，快速了解全貌 |
| 定位 `elapsed` vs `elapsed_seconds` 字段名不一致 | ✅ | 对比 `packet_capture.py` 的 `get_status()` 和 GUI 的 `_refresh_ui` 迅速发现问题 |
| 发现暂停/恢复按钮的 `is_running` 逻辑陷阱 | ✅ | 分析了 `is_running` property 的实现逻辑，指出暂停时返回 False 的根因 |
| 实现告警筛选/导出功能 | ✅ | 生成 `_on_filter_alerts`、`_on_export_alerts_tab`、`_populate_alert_table` 三个方法 |
| 端到端 PCAP 回放验证 | ✅ | 一次运行就得到 26 条告警，证明全链路正常 |
| 统计代码行数 | ✅ | 一键统计 Python/YAML/Markdown 代码行数 |

### 4. 技术决策

| 决策 | 选项 A | 选项 B | 选择 | 理由 |
|------|--------|--------|------|------|
| 告警表格刷新策略 | 每 1 秒无条件刷新 | 每 5 秒 + 仅激活 Tab 时刷新 | 选项 B | 避免大量告警时每秒重建表格的 CPU 开销 |
| 筛选/导出函数设计 | 各写独立逻辑 | 提取 `_populate_alert_table` 复用 | 选项 B | 减少重复代码，便于维护 |
| 暂停恢复逻辑修复 | 修改 `PacketCapture` 增加 `is_paused` 属性 | 在 GUI 中避开 `is_running` 改用内部状态 | 选项 B | 不跨成员修改代码，符合 CLAUDE.md 模块归属规范 |

### 5. 性能/测试数据

| 测试项 | 结果 | 备注 |
|--------|------|------|
| GUI 窗口打开 | ✅ | PyQt5 5.15.11, 5 个 Tab, 3 个图表 |
| `test_signature_match.py` 通过率 | **100% (17/17)** | SQLi 6/6, XSS 4/4, Web 4/4, BruteForce 3/3 |
| `alert_manager.py` 独立测试 | ✅ 全部通过 | 提交/去重/统计/确认/误报标记 |
| 特征库规则数 | 91 条（新增到 9 个 YAML 文件） | Day 1 还是 58 条，成员A 新增了 imported_suricata.yaml 和 webshell.yaml |
| PCAP 回放检测 | 16 包 → **26 条告警** | SQLi(6) + XSS(6) + Web(7) + BruteForce(7) |
| 项目总代码行数 | **9501 行** | Python 4705 + YAML 1166 + 文档 3630 |
| GUI 刷新延迟 | < 50ms（估计） | 1 秒定时器，offscreen 测试无法精确测量 |

### 6. 参考项目借鉴

| 参考项目 | 借鉴内容 | 落地情况 |
|----------|----------|----------|
| PyQt5 官方 examples/widgets | QTableWidget 动态填充 + resizeColumnsToContents | 用于 `_populate_alert_table` 方法 |
| Suricata IDS | 告警规则分级（priority 1-3 → critical/high/medium/low） | 已通过 imported_suricata.yaml 集成 |

### 7. 明日计划 (Day 3)

- [ ] 🔴 PDF必做：下载更多 PCAP 样本（DDoS/端口扫描/后门通信类型），确保 5 种攻击类型覆盖
- [ ] 🔴 PDF必做：搭建演示环境方案（虚拟机 Kali+Metasploitable 或纯 PCAP 回放方案）
- [ ] 🟡 为异常检测模块编写模拟测试（端口扫描/暴力破解/DoS）
- [ ] 🟡 开始准备答辩 PPT 大纲 + 收集各成员技术贡献材料
- [ ] 🟡 GUI 细节优化：双击告警行查看详情、右键菜单（确认/标记误报）

---

### GUI 执行说明

> **以下是在本项目虚拟环境中运行 GUI 的步骤，供选择执行方式时参考：**

#### 方式 1：启动 GUI 主界面

```bash
# 在项目根目录下，使用 venv 的 Python 环境
cd D:\Document\CODE\School\IS_technology_innovation
.\venv\Scripts\python.exe main.py
```

启动后界面采用 **Apple 风格设计**：
- 左侧 **侧边栏导航** (5 项: Dashboard / Alerts / Statistics / Signatures / Log + 主题切换)
- 右侧 **卡片式内容区** (白色圆角卡片 + 全局 QSS 样式)
- 仪表盘 **6 张统计卡片** + 实时 PPS/BPS 双线折线图 + TOP 5 攻击来源
- 告警列表按严重度/类别筛选 + 导出 JSON
- 统计分析严重度饼图 + 攻击类别柱状图 + TOP 10 来源
- ☀ **亮/暗主题切换** (侧边栏底部)

#### 方式 2：命令行模式（不需要 GUI）

```bash
.\venv\Scripts\python.exe main.py --console
```

#### 方式 3：PCAP 回放模式（演示推荐）

```bash
# 回放预置的攻击样本
.\venv\Scripts\python.exe main.py --replay tests/test_pcaps/synthetic_attacks.pcap

# 其他可用 PCAP 文件：
#   tests/test_pcaps/http.cap              (256KB, HTTP 流量)
#   tests/test_pcaps/extended_attacks.pcap (扩展攻击样本)
```

#### 方式 4：运行测试套件

```bash
# 签名匹配准确率测试
.\venv\Scripts\python.exe tests/test_signature_match.py -v

# alert_manager 独立测试
.\venv\Scripts\python.exe -c "
from core.alert_manager import AlertManager
mgr = AlertManager()
# ... 测试逻辑见 alert_manager.py 文档
"
```

#### 启动前检查清单

| 检查项 | 命令 |
|--------|------|
| Python 环境 | `.\venv\Scripts\python.exe --version` |
| 依赖安装 | `.\venv\Scripts\python.exe -c "import scapy,yaml; from PyQt5.QtChart import QChart; print('OK')"` |
| 配置文件 | 确认 `config.yaml` 在项目根目录 |
| Npcap (Windows) | 需要管理员权限运行（仅在线抓包模式需要） |

> **注意**：PCAP 回放模式不需要 Npcap 和管理员权限，是演示时最稳定的方案。

---

## Day 3 — 2026-07-13 (Apple 风格 GUI 重新设计)

### 1. 今日进度

- [x] **GUI 全新设计**: 从 QTabWidget 暗色主题改为 Apple 风格 (侧边栏导航 + 卡片式布局 + 亮/暗主题切换)
- [x] 实现 `_apply_apple_theme()` / `_build_apple_stylesheet()` 主题系统 (亮色 #F5F5F7 / 暗色 #1C1C1E)
- [x] 创建侧边栏导航 (QListWidget + QStackedWidget) 替代顶部 Tab, 5 个导航项 + 主题切换按钮
- [x] 6 张 Apple 风格统计卡片 (白色圆角卡片 + 左侧色条 + 大字数值 + 小字标题)
- [x] 新增 `card_low` (Low 严重度卡片, 紫色), 仪表盘从 5 卡片升级为 6 卡片
- [x] 实时折线图增加 BPS 线 (绿色), 与 PPS 线 (蓝色) 同时显示, 修复 `_bps_history` 未绘制 bug
- [x] 修复 `text_top_ip` 仪表盘 TOP 攻击来源不更新 bug (在 `_refresh_ui` 中填充数据)
- [x] 修复 `lbl_conn`/`lbl_hosts`/`lbl_streams` 始终显示 0 bug (连接真实数据源: TCP 重组器 + 异常检测器)
- [x] 修复 Settings > View Config 菜单无回调 bug (新增 `_on_config` 方法)
- [x] 删除未使用的 `DetectionWorker` QThread 死代码 (43 行)
- [x] 全局 QSS 样式表 (7400+ 字符): 圆角按钮/输入框/表格/滚动条, Apple 字体栈, 主题色系统
- [x] 所有 inline `setStyleSheet()` 调用替换为 QSS class/property selector
- [x] 控制栏按钮状态: 用 Qt dynamic property `[state="running"]` / `[state="stopped"]` 切换红/绿色

### 2. 遇到的问题与解决

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `_create_sidebar()` 调用时 Qt 进程崩溃 (exit code 127) | `sidebar.setCurrentRow(0)` 触发 `_on_sidebar_changed` 信号, 但 `self.stack` 尚未创建 | 将 `setCurrentRow(0)` 从 `_create_sidebar` 移至 `_init_ui` 末尾 (stack 创建后) |
| QSS 在 widget 创建前应用导致 Qt C++ 层崩溃 | Qt CSS 引擎在解析复杂样式表时, 对尚未创建的 widget 类型可能触发内部错误 | 将所有 widget 创建移至 `_apply_apple_theme()` 之前, 主题在最后应用 |
| `\u{1F4C2}` unicode escape 语法错误 | Python `\u` 必须跟 4 位十六进制, `{` 不是合法十六进制字符 | 直接用字面量 emoji `📂` |
| 旧版 `_set_dark_theme` 使用 QPalette 但不足以覆盖所有 widget | QPalette 只影响默认绘图, 对 QSS 样式 widget 无效 | 全局 QSS + QPalette 双管齐下: QSS 控制 widget 外观, QPalette 控制默认颜色 |

### 3. Agent 协作记录

| 任务 | 是否用 Agent | 效果评估 |
|------|-------------|----------|
| 设计 Apple 风格 GUI 架构 | ✅ | Plan agent 产出 13 步完整方案, 包括侧边栏/QSS/配色/卡片设计 |
| 探索现有 GUI 结构和数据流 | ✅ | Explore agent 详尽列出 30 个方法/13 个信号/5 个 tab/已知 bug |
| 生成 7400 字符 QSS 样式表 | ✅ | Apple 风格样式表, 亮/暗双主题, 覆盖所有 widget 类型 |
| 调试 `_create_sidebar` Qt 崩溃 | ✅ | 逐步排除 QSS/Unicode/PyQtChart/方法调用链, 最终定位到信号顺序问题 |
| Bug 修复 (6 个) | ✅ | 一次性完成全部 6 个已知 bug 修复 |
| 端到端验证 | ✅ | PCAP 回放 + 测试套件 + 结构测试全部通过 |

### 4. 技术决策

| 决策 | 选项 A | 选项 B | 选择 | 理由 |
|------|--------|--------|------|------|
| 导航模式 | 保留 QTabWidget | QListWidget + QStackedWidget | 选项 B | Apple 侧边栏风格, 导航更清晰, 扩展性好 |
| 主题实现 | 仅 QPalette | QSS 全局样式表 | QSS | QPalette 无法控制圆角/阴影/悬停效果, QSS 功能完整 |
| 配色方案 | Material Design | Apple Human Interface | Apple | 更简洁现代, 亮色系默认更符合演示场景 |
| QSS 应用时机 | widget 创建前 | widget 创建后 | widget 创建后 | 避免 Qt CSS 引擎在 widget 未就绪时崩溃 |
| 统计卡片 | QGroupBox + border | QFrame + 左侧色条 | QFrame | 更接近 Apple 卡片风格: 白底/圆角/色条强调 |

### 5. 性能/测试数据

| 测试项 | 结果 | 备注 |
|--------|------|------|
| GUI 窗口创建 | ✅ | QMainWindow + 侧边栏 7 项 + 5 个内容页 |
| 亮/暗主题切换 | ✅ | 1 秒内完成, 所有 widget 即时更新 |
| `test_signature_match.py` 通过率 | **100% (17/17)** | 回归测试通过 |
| PCAP 回放检测 | ✅ | 16 包 → 26 条告警, 覆盖全部类别 |
| 端到端集成测试 | ✅ | Engine + AlertManager + GUI 全链路 |
| QSS 样式表大小 | 7,416 字符 | 覆盖 15+ widget 类型 |
| 代码变更 | -101 行, +373 行, 净增 ~272 行 | 最终文件 ~1110 行 |

### 6. 参考项目借鉴

| 参考项目 | 借鉴内容 | 落地情况 |
|----------|----------|----------|
| Apple Human Interface Guidelines | 侧边栏导航/卡片布局/色彩系统/字体层级 | 侧边栏 220px, 卡片圆角 10px, SF 字体栈 |
| macOS System Settings | 左侧 icon + label 列表, 右侧内容区 | QListWidget + QStackedWidget 实现 |
| PyQt5 官方 QSS 文档 | QSS 选择器语法/动态属性/伪状态 | `[state="running"]` 动态切换按钮颜色 |

### 7. 明日计划 (Day 4)

- [ ] 🔴 PDF必做: 下载/制作 5 个不同攻击类型 PCAP 样本 (DDoS/端口扫描/后门)
- [ ] 🔴 PDF必做: 搭建演示环境方案 (VirtualBox Kali+Metasploitable 或纯 PCAP)
- [ ] 🟡 为异常检测模块编写模拟测试
- [ ] 🟡 开始答辩 PPT 初稿 + 截图 (新 GUI 6 张截图)
- [ ] 🟡 双击告警行查看详情对话框 / 右键菜单确认和误报标记

---

## Day 4 — 2026-07-11

---

## Day 5 — 2026-07-12

---

## Day 6 — 2026-07-13

---

## Day 7 — 2026-07-14

---

## 答辩素材汇总（Day 7 填写）

### 我解决的 3 个最有价值的问题

1. 
2. 
3. 

### 我的 3 个关键技术贡献

1. 
2. 
3. 

### 我从开源项目中学到的 3 点

1. 
2. 
3. 

### 答辩时可以展示的性能数据

| 指标 | 数值 |
|------|------|
| GUI 界面 Tab 页数 | 5 个（可扩展到 8 个） |
| 实时图表个数 | 4 个（饼图/柱状图/折线图/排行） |
| 图表刷新频率 | 1 秒 |
| 测试用例总数 | ___ 个 |
| 测试通过率 | ___% |
| 告警去重有效率 | ___% |

### 我负责模块的截图（仪表盘 / 告警列表 / 统计分析 / 特征库管理 / 系统日志）

（粘贴每个 Tab 的截图在此）

### Agent 使用总结

- 总共使用 Agent 协助 __ 次
- 节省了约 __ 小时的开发时间
- 最有效的使用场景：______
