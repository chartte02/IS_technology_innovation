# NADS GUI 答辩演示指南

> **用途**: 答辩现场操作手册 — 按步骤执行即可完成完整演示
> **更新**: 2026-07-20 

---

## 目录

1. [启动前检查](#一启动前检查)
2. [启动 GUI](#二启动-gui)
3. [六大页面详解](#三六大页面详解)
4. [完整演示流程](#四完整演示流程)
5. [备用方案](#五备用方案)
6. [常见问题排查](#六常见问题排查)

---

## 一、启动前检查

### 1.1 环境确认

在项目根目录打开终端，逐项检查：

```bash
# 1. Python 版本
python --version                              # 需要 3.9+

# 2. 依赖完整
python -c "import scapy; print('scapy OK')"
python -c "import yaml; print('yaml OK')"
python -c "from PyQt5.QtWidgets import QApplication; print('PyQt5 OK')"
python -c "from PyQt5.QtChart import QChart; print('PyQtChart OK')"
python -c "import ahocorasick; print('ahocorasick OK')"
python -c "import cryptography; print('cryptography OK')"

# 3. 演示 PCAP 存在
ls tests/test_pcaps/demo_*.pcap              # 应有 5 个文件

# 4. 特征库可加载
python -c "
import sys; sys.path.insert(0,'.')
from core.misuse_detector import SignatureMatcher
m = SignatureMatcher('./signatures')
print(f'Loaded: {m.load_all()} rules')
print(f'AC patterns: {len(m._ac_sig_map)}, Regex: {len(m._regex_matchers)}')
"
# 期望输出: Loaded: 93 rules, AC patterns: 115, Regex: 192
```

### 1.2 如果依赖缺失

```bash
pip install scapy pyyaml pyqt5 pyqtchart pyahocorasick cryptography
```

---

## 二、启动 GUI

### 2.1 正常启动

```bash
cd D:\Document\CODE\School\IS_technology_innovation
python main.py
```

启动后看到 **Apple 风格亮色主题窗口**，标题栏显示 "NADS — 常见网络攻击检测系统"。

### 2.2 启动后的初始状态

```
┌─────────────────────────────────────────────────────────────┐
│  [▶ Start Detection] [⏸ Pause] │ Interface: [eth0 ▾]       │
│  BPF: [tcp] │ [☁ Learn Baseline] [📂 Replay PCAP] [▶ Demo] │
│                                          ○ Stopped          │
├──────────┬──────────────────────────────────────────────────┤
│ ◉ Dash.. │  Dashboard                                       │
│ ⚠ Alerts │  ┌──────┬──────┬──────┬──────┬──────┬──────┐   │
│ ▶ Stats  │  │Total │Crit  │High  │Med   │Low   │Pkts  │   │
│ ☰ Signs  │  │  0   │  0   │  0   │  0   │  0   │  0   │   │
│ ◈ Chain  │  └──────┴──────┴──────┴──────┴──────┴──────┘   │
│ ☷ Log    │  Recent Alerts (empty)                           │
│          │  Real-time Traffic (no data)                     │
├──────────┴──────────────────────────────────────────────────┤
│  Ready                              PPS: 0  Alerts: 0  ...  │
└─────────────────────────────────────────────────────────────┘
```

**此时状态栏显示 "Ready"** — 系统已初始化但未开始检测，所有统计卡片显示 0。

---

## 三、六大页面详解

### 3.1 Tab 0 — ◉ Dashboard（仪表盘）

**位置**: 侧边栏第 1 项，启动后默认显示

**包含内容及含义**:

| 区域 | 内容 | 含义 |
|------|------|------|
| **顶部标题** | "Dashboard" | 页面标识 |
| **统计卡片行** (6张) | Total Alerts / Critical / High / Medium / Low / Packets | 系统启动以来的告警累计数和抓包总数。Total Alerts = Critical+High+Medium+Low 的去重和 |
| **Recent Alerts 表** | Time / Severity / Type / Source IP / Description | 最近 20 条告警的实时滚动列表。最新的在最上面 |
| **Real-time Traffic 折线图** | PPS(蓝线) + BPS(绿线)，X轴=最近60秒 | 实时流量速率。PPS=Packets Per Second每秒包数，BPS=Bytes Per Second每秒字节数 |
| **文本指标行** | PPS / BPS / Conn / Hosts / TCP / Anomaly / Demo | 数值形式的实时指标。Hosts=活跃主机数，TCP=活跃TCP连接数 |
| **Top Attack Sources** | IP 地址列表 | 告警来源 IP 排名（告警数从多到少） |

**操作**: 无需操作，系统启动后自动刷新（每 1 秒更新折线图，每 5 秒更新卡片和表格）。

**答辩解说词**:
> "仪表盘是系统的总览页面——6 张统计卡片让你一眼看到当天有多少告警，红色 critical 和橙色 high 高亮显示需要立即处理的高危告警。下方 PPS/BPS 双线折线图实时展示网络流量速率，蓝色是每秒包数，绿色是每秒字节数。如果出现攻击流量尖峰，这里会立刻反映出来。"

---

### 3.2 Tab 1 — ⚠ Alerts（告警列表）

**位置**: 侧边栏第 2 项

**包含内容及含义**:

| 区域 | 内容 | 含义 |
|------|------|------|
| **筛选栏** | Severity 下拉 / Category 下拉 / Refresh / Export JSON | 按严重度或攻击类别筛选告警，一键导出 JSON |
| **告警表格** (8列) | ID / Time / Severity / Source / Category / Attack Name / Src IP / Dst IP:Port | 每条告警的完整信息。**双击任意行**弹出详情弹窗 |

**Severity 颜色含义**:

| 颜色 | 严重度 | 含义 | 应如何处理 |
|------|:--:|------|------|
| 🔴 红色 | critical | 确认的攻击行为 | 立即响应 |
| 🟠 橙色 | high | 高度可疑 | 优先排查 |
| 🟡 黄色 | medium | 可能异常 | 关注跟踪 |
| 🔵 蓝色 | low | 轻微可疑 | 记录观察 |

**操作**:
1. 点击 Severity 下拉选 "critical" → 只显示严重告警
2. 点击 Category 下拉选 "sql_injection" → 只显示 SQL 注入
3. **双击任意告警行** → 弹出详情弹窗（含威胁情报）
4. 点击 "Export JSON" → 导出告警为文件

**答辩解说词**:
> "告警列表是运维人员的主要工作界面——每条告警标明了严重度、攻击类别、来源和目标 IP。双击任意告警可以查看完整详情，包括匹配到的攻击载荷原文和威胁情报查询结果——系统会自动查询 AbuseIPDB 等平台，告诉你这个攻击来源 IP 是否在全球已知的恶意 IP 名单中。"

**告警详情弹窗内容**:

```
┌──────────────────────────────────────────────┐
│                 Alert Detail                 │
├──────────────────────────────────────────────┤
│  SQL Injection - UNION SELECT                │
│  ─────────────────────────────────────────── │
│  Alert ID:     42                            │
│  Time:         2026-07-20 10:23:42           │
│  Category:     sql_injection                 │
│  Severity:     CRITICAL (红色)               │
│  Src IP:       10.0.1.1                      │
│  Dst IP:       192.168.1.10:80               │
│  Matched Text: UNION SELECT user,password... │
│  ─────────────────────────────────────────── │
│  Threat Intelligence:                        │
│  AbuseIPDB:     85/100 (已知恶意)             │
│  Combined Risk: 🔴 HIGH                      │
│                                    [ OK ]    │
└──────────────────────────────────────────────┘
```

---

### 3.3 Tab 2 — ▶ Statistics（统计分析）

**位置**: 侧边栏第 3 项

**包含内容及含义**:

| 区域 | 内容 | 含义 |
|------|------|------|
| **Alert Severity Distribution** (饼图) | 红/橙/黄/蓝 四色扇形 | 各类严重度告警的占比。扇区越大 = 该类告警越多 |
| **Attack Category Distribution** (柱状图) | 横轴=攻击类别，纵轴=数量 | 哪种攻击最多。柱子越高 = 该类攻击越频繁 |
| **Top 10 Attack Source IPs** (文本列表) | IP: 攻击次数 | 排名前十的攻击来源 |
| **Refresh Statistics** 按钮 | 点击手动刷新 | 立即更新图表数据 |

**操作**:
1. 切换到 Statistics Tab → 图表自动显示当前统计数据
2. 点击 Refresh Statistics → 强制刷新

**答辩解说词**:
> "统计分析页面用图表直观展示告警的分布情况——饼图告诉你严重度占比，如果红色扇形很大说明今天发生了多次高危攻击。柱状图告诉你哪种攻击最常见，方便安全团队调整防御策略。这些图表每 5 秒自动刷新。"

---

### 3.4 Tab 3 — ☰ Signatures（特征库管理）

**位置**: 侧边栏第 4 项

**包含内容及含义**:

| 区域 | 内容 | 含义 |
|------|------|------|
| **特征库文件列表** | sql_injection.yaml / xss.yaml / web_attack.yaml / ... | 当前加载的 10 个 YAML 特征库文件 |
| **规则浏览区域** | 点击文件 → 展示该文件下所有规则 | 每条规则的 ID、名称、严重度、模式 |
| **Reload** 按钮 | 热更新 | 修改 YAML 后不重启系统加载新规则 |

**操作**:
1. 点击 "webshell.yaml" → 查看 7 条 WebShell 检测规则（蚁剑/冰蝎/哥斯拉）
2. 点击 "imported_suricata.yaml" → 查看从 Suricata 社区导入的 15 条规则

**答辩解说词**:
> "特征库管理页面展示了系统加载的全部攻击检测规则——共 10 个 YAML 文件，93 条规则。其中包括我们自研的 78 条规则和从 Suricata 社区导入的 15 条规则。点击任何文件可以看到具体每条规则的 ID、严重度和匹配模式。Reload 按钮支持热更新——修改 YAML 文件后无需重启系统，新规则即刻生效。"

---

### 3.5 Tab 4 — ◈ Attack Chain（攻击链可视化）

**位置**: 侧边栏第 5 项

**包含内容及含义**:

| 区域 | 内容 | 含义 |
|------|------|------|
| **攻击链图** (QGraphicsView) | 节点-边有向图 | 蓝色节点 = 攻击来源 IP，彩色节点 = 攻击目标/阶段。连线 = 攻击路径 |
| **图例** | 黄色=侦察, 橙色=利用, 红色=C2, 紫色=横向移动 | 四种攻击阶段对应 MITRE ATT&CK 模型 |
| **刷新按钮** | Refresh Attack Chain | 手动刷新可视化 |
| **统计行** | X chains / Y steps / max Z phases | 当前检测到的攻击链总数 / 总步数 / 最长攻击链的阶段数 |

**攻击阶段颜色含义**:

| 颜色 | MITRE ATT&CK 阶段 | 对应告警类型 | 含义 |
|------|------|------|------|
| 🟡 黄色 | Reconnaissance (侦察) | scan | 攻击者在探测网络——端口扫描、漏洞扫描器指纹 |
| 🟠 橙色 | Exploitation (利用) | sql_injection, xss, web_attack, brute_force, webshell | 攻击者在尝试入侵——SQL注入、XSS、暴力破解 |
| 🔴 红色 | C2 / Persistence (控制/持久化) | backdoor | 攻击者已建立后门连接——C2通信、木马 |
| 🟣 紫色 | Lateral Movement (横向移动) | (内网扫描、内网暴力破解) | 攻击者在内网扩散 |

**攻击链示例解读**:

```
  [10.0.5.1] ───(黄)──→ [192.168.1.50:多端口]  10:00:01  扫描侦察
       │
       ├───(橙)──→ [192.168.1.50:80]           10:00:05  SQL注入利用
       │
       └───(红)──→ [192.168.1.50:4444]         10:00:30  后门C2连接

  Level: HIGH (3 phases)
```

**解读**: 来源 IP `10.0.5.1` 在 10:00:01 开始扫描目标 (侦察)，10:00:05 发起 SQL 注入攻击 (利用)，10:00:30 建立后门连接 (C2)。这是一个典型的 **侦察→利用→持久化** 三步攻击链，威胁等级 HIGH。

**操作**:
1. 先回放含混合攻击的 PCAP（如 `demo_mixed.pcap`），让系统积累告警
2. 切换到 Attack Chain Tab
3. 点击 Refresh Attack Chain → 查看可视化结果
4. 指向图中的节点和连线，讲解攻击链含义

**答辩解说词**:
> "攻击链可视化面板是我们的一大特色——不同于传统的告警列表，它将同一来源 IP 的零散告警按照 MITRE ATT&CK 模型串联成可视化的攻击路径图。蓝色圆圈是攻击来源，黄色=侦察阶段比如端口扫描，橙色=利用阶段比如 SQL 注入，红色=持久化阶段比如后门连接。一条线串下来，攻击者的完整行动路线一目了然。下方显示威胁等级——3 阶段以上标记为 HIGH，4 阶段以上标记为 CRITICAL。"

---

### 3.6 Tab 5 — ☷ Log（系统日志）

**位置**: 侧边栏第 6 项

**包含内容及含义**:

| 区域 | 内容 | 含义 |
|------|------|------|
| **日志文本区** | `[HH:MM:SS] 消息内容` | 系统运行日志，按时间倒序 |
| **Clear 按钮** | 清空日志 | 重置日志显示 |

**日志消息含义**:

| 日志示例 | 含义 |
|----------|------|
| `[10:23:19] Theme switched to dark` | 用户切换了暗色主题 |
| `[10:23:42] [CRIT] SQLI-001: UNION SELECT from 10.0.1.1` | 检测到一条 critical 级 SQL 注入告警 |
| `[10:24:00] Demo started: 2 pps attack+normal mixed traffic` | Demo 模式已启动 |
| `[10:24:30] Demo stopped: 120 packets sent` | Demo 模式已停止 |

**答辩解说词**:
> "系统日志记录了所有运行事件——包括检测到的每条告警、用户操作记录和系统状态变化。答辩时不需要在这个页面停留太久，点到即可。"

---

## 四、完整演示流程

### 4.1 推荐演示顺序（共 8 幕，约 10-12 分钟）

```
第1幕: 启动展示 (30秒)
  操作: 启动 GUI → 展示窗口完整外观
  停留: Dashboard (Tab 0)
  讲解: "NADS 是一个基于混合检测架构的入侵检测系统..."

第2幕: SQL 注入检测 (90秒)
  操作: 点击 [📂 Replay PCAP] → 选择 demo_sqli.pcap
  效果: Dashboard 卡片跳动 → Alerts 表格新增行 → Log 滚动
  操作: 切换到 Alerts Tab (Tab 1) → 筛选 severity=critical
  操作: 双击一条告警 → 弹窗展示详情+威胁情报
  讲解: 每个告警字段含义 + 威胁情报查询结果

第3幕: XSS 检测 (60秒)
  操作: 点击 [📂 Replay PCAP] → 选择 demo_xss.pcap
  效果: 新告警出现
  切换: Statistics Tab (Tab 2) → 展示饼图和柱状图
  讲解: 图表含义

第4幕: Web 攻击 + 混合攻击 (90秒)
  操作: 回放 demo_webattack.pcap → 展示目录遍历/命令注入检出
  操作: 回放 demo_mixed.pcap → 展示扫描+SQLi+后门全检出
  切换: Attack Chain Tab (Tab 4) → 展示攻击链可视化
  讲解: 攻击链颜色含义 + 3步攻击路径

第5幕: **真实网络扫描检测** ⭐ (90秒)
  操作: 回放 kali_to_windows_scan.pcap → 展示真实 Kali→Windows 扫描检出
  效果: 误用检测(Nmap指纹) + 异常检测(端口扫描) 双引擎同时告警
  讲解: "这是真实虚拟机环境抓包，298个包"
  切换: Alert Tab → 筛选 anomaly → 展示异常检测告警
  切换: Attack Chain Tab → 展示扫描攻击链

第6幕: 特征库展示 (30秒)
  切换: Signatures Tab (Tab 3)
  讲解: 93条规则 / 10个YAML / Suricata导入

第7幕: Demo 模式 (30秒)
  操作: 点击 [▶ Demo] → 系统自动生成混合攻击流量
  效果: 仪表盘实时刷新、告警持续产生
  操作: 点击 [■ Stop Demo] 停止
  讲解: "Demo模式模拟真实攻击场景，无需PCAP文件"

第8幕: 主题切换 + 总结 (30秒)
  操作: 点击侧边栏 Toggle Theme → 切换到暗色主题
  讲解: "支持亮色/暗色双主题，适配不同工作环境"
```

### 4.2 各步骤详细操作

#### 第 1 步 — 启动展示

```
1. 打开终端，进入项目根目录
2. 执行: python main.py
3. 等待窗口弹出（约 3-5 秒）
4. 确认: 窗口标题 "NADS — 常见网络攻击检测系统"
5. 确认: 左侧 6 项导航菜单 + 底部 "Toggle Theme"
6. 确认: 顶部控制栏所有按钮可用
7. 确认: 状态栏显示 "Ready"
```

#### 第 2 步 — SQL 注入检测

```
1. 点击控制栏 [📂 Replay PCAP] 按钮
2. 在文件选择对话框中，导航到 tests/test_pcaps/
3. 选择 demo_sqli.pcap → 点击打开
4. 观察效果（约 3 秒）:
   a. Dashboard 的 Total Alerts 卡片数字跳动 (0 → 5)
   b. Critical 卡片显示红色数字
   c. Recent Alerts 表格新增行
   d. Log 区滚动显示 "[CRIT] SQLI-001: UNION SELECT..."
5. 点击侧边栏 "⚠ Alerts" 切换到告警列表
6. 右上角 Severity 下拉选择 "critical" → 只显示红色严重告警
7. 双击任意一行 → 弹窗显示完整详情
8. 指向弹窗中的:
   - Alert ID / Category / Severity
   - Matched Text: "UNION SELECT user,password FROM users--"
   - Threat Intelligence 区域
```

#### 第 3 步 — XSS 检测

```
1. 点击控制栏 [📂 Replay PCAP]
2. 选择 demo_xss.pcap
3. 观察 Alerts 表格新增 XSS 告警
4. 切换到 "▶ Statistics" 页
5. 点击 Refresh Statistics → 观察:
   - 饼图: 各严重度扇区比例
   - 柱状图: web_attack 和 xss 柱子最高
6. 讲解图表的含义
```

#### 第 4 步 — Web 攻击 + 攻击链

```
1. 回放 demo_webattack.pcap
2. 观察检出: 目录遍历 (WEB-001)、命令注入 (WEB-003)、文件包含 (WEB-002)
3. 回放 demo_mixed.pcap
4. 观察检出: Nikto 扫描 (SCAN-003) + SQL 注入 + 后门
5. 切换到 "◈ Attack Chain" 页
6. 点击 Refresh Attack Chain
7. 指向攻击链图:
   - 蓝色节点 = 10.0.5.1 (攻击来源)
   - 黄色节点 = 扫描 (侦察阶段)
   - 橙色节点 = SQL 注入 (利用阶段)
   - 红色节点 = 后门连接 (持久化阶段)
   - 底部 "Level: HIGH (3 phases)"
```

#### 第 5 步 ⭐ — 真实网络扫描检测（答辩亮点）

这是整个演示的亮点环节——展示系统对**真实网络环境流量**（非人工构造）的检测能力。

**PCAP 来源**:
```
VirtualBox Host-Only 网络真实抓包:
┌──────────────────┐    扫描    ┌──────────────────┐
│  Kali Linux      │ ────────→ │  Windows 10      │
│  192.168.71.128  │  298 个包  │  192.168.71.1    │
│  (攻击机)        │  58 秒     │  (靶机)          │
└──────────────────┘           └──────────────────┘
         ↑  NADS 在此宿主机上离线分析 PCAP

Kali 使用 Nmap 对 Windows 进行了端口扫描，
覆盖了 45+ 个不同端口 (SSH/HTTP/HTTPS/MySQL/RDP/...)
```

**操作**:
```
1. 点击控制栏 [📂 Replay PCAP]
2. 选择 kali_to_windows_scan.pcap → 点击打开
3. 等待约 5 秒（298 个包回放）→ 观察效果:
   a. Dashboard: Total Alerts 数字跳动
   b. Log 区滚动显示:
      "[MED] [anomaly] port_scan: 43 个不同端口 (阈值: 20)"
      "[MED] [misuse] SCAN-001: Port Scan - Nmap SYN Scan"
   c. Alerts 表格新增 3 条告警
4. 切换到 "⚠ Alerts" 页
5. 观察两条关键告警:
   - 异常检测: "port_scan: 43 个不同端口" (source=anomaly, 统计偏离触发)
   - 误用检测: "Port Scan - Nmap SYN Scan" (source=misuse, 特征匹配识破Nmap)
6. 指向两条告警的 Source 列 → 一个来自 "anomaly"，一个来自 "misuse"
7. 切换到 "◈ Attack Chain" 页 → 点击 Refresh
8. 观察攻击链图: Kali扫描 → 跨多个端口 → 侦察阶段

关键数据:
  总包数:     298 个
  回放时长:   58 秒（按原始间隔）
  误用检测:   2 条 (Nmap扫描指纹 + PHP误报)
  异常检测:   1 条 (端口扫描: 43端口)
  去重后:     3 条
```

**讲解词**:
> "接下来展示系统对真实网络流量的检测能力。这个 PCAP 不是我们手动构造的——它来自 VirtualBox 虚拟机环境的真实抓包：一台 Kali Linux 使用 Nmap 对 Windows 目标进行了端口扫描，共发起了 298 个探测包，涉及 45 个以上不同端口。
>
>回放后可以看到，我们的双引擎同时产生了告警——误用检测引擎识别出了 Nmap SYN 扫描的指纹特征，异常检测引擎通过统计偏离发现了单 IP 访问大量端口的异常行为。两条告警来自不同的检测维度，互相印证，这正是混合检测架构的优势所在。"

#### 第 6 步 — Demo 模式（如需额外展示）

```
1. 点击控制栏 [▶ Demo] 按钮
2. 观察: 系统自动以每秒 2 个包的速率生成混合攻击+正常流量
3. Dashboard 折线图出现 PPS 曲线
4. 告警持续产生
5. 30 秒后点击 [■ Stop Demo] 停止
```

### 4.3 演示时的关键讲解点

| 时机 | 讲解内容 |
|------|----------|
| GUI 打开时 | "Apple 风格设计，6 个功能页面，侧边栏导航" |
| 回放 PCAP 后 | "检测到了 X 条告警，包括 critical 级 SQL 注入和 high 级 XSS" |
| 双击告警弹窗时 | "每条告警不仅显示攻击载荷原文，还自动查询威胁情报——这个 IP 在 AbuseIPDB 得分 85/100，已知恶意" |
| 真实扫描演示时 ⭐ | "这不是手动构造的流量——来自 VirtualBox 虚拟机真实抓包。误用检测识破了 Nmap 指纹，异常检测通过统计偏离发现了端口扫描。双引擎互相印证——混合检测的核心优势" |
| Statistics 页 | "饼图展示严重度分布，柱状图展示攻击类别排名" |
| Attack Chain 页 | "这是我们的特色——将零散告警串联成攻击者行动地图" |
| Signatures 页 | "93 条规则，包括自研的 WebShell 检测和从 Suricata 社区导入的规则" |

---

## 五、备用方案

### 5.1 方案A：PCAP 回放（主力方案，推荐）

**优势**: 100% 成功率，不需要管理员权限，不需要真实网络攻击环境

**流程**: 按第四节步骤执行即可

**PCAP 文件清单**:

| 文件名 | 攻击类型 | 包数 | 预期告警 | 来源 |
|--------|----------|:--:|:--:|------|
| `demo_sqli.pcap` | SQL 注入 | 3 | 5 条 (critical+high) | Scapy 构造 |
| `demo_xss.pcap` | XSS 跨站脚本 | 3 | 6 条 (high+medium) | Scapy 构造 |
| `demo_webattack.pcap` | 目录遍历+命令注入+文件包含 | 4 | 7 条 (high+critical) | Scapy 构造 |
| `demo_mixed.pcap` | 扫描+SQL注入+后门 | 5 | 6 条 (含攻击链) | Scapy 构造 |
| `synthetic_attacks.pcap` | 综合攻击 | 16 | 24 条 | Scapy 构造 |
| `extended_attacks.pcap` | 扩展攻击(SSRF/XXE/SSTI/WebShell) | 12 | 15 条 | Scapy 构造 |
| **`kali_to_windows_scan.pcap`** | **真实 Kali→Windows 端口扫描** | **298** | **3 条 (1异常+2误用)** | **虚拟机真实抓包** |

### 5.2 方案B：命令行模式（GUI 故障时备用）

```bash
# 如果 GUI 无法启动，使用命令行模式
python main.py --replay tests/test_pcaps/demo_sqli.pcap

# 终端会直接输出所有检测到的告警，格式如下:
# [CRIT] [sql_injection] SQLI-001: UNION SELECT | 10.0.1.1:30001 -> 192.168.1.10:80
# [HIGH] [sql_injection] SQLI-002: Tautology (1=1) | 10.0.1.1:30002 -> 192.168.1.10:80
```

### 5.3 方案C：Demo 模式（无需 PCAP 文件时备用）

```bash
# 启动 GUI
python main.py

# 直接点击 [▶ Demo] 按钮
# 系统自动生成 SQL 注入/XSS/Web攻击/暴力破解/后门/扫描 混合流量
# 适合展示"实时检测"能力
```

### 5.4 方案D：预录视频（极端情况备用）

如果现场环境完全不可用（电源故障、投影仪故障等），播放预录的演示视频。
建议提前用 OBS 录制一段 5 分钟的完整操作视频。

---

## 六、常见问题排查

| 问题 | 原因 | 解决 |
|------|------|------|
| `ImportError: No module named 'PyQt5'` | PyQt5 未安装 | `pip install pyqt5 pyqtchart` |
| GUI 窗口打开后空白 | 初始化未完成 | 等待 3-5 秒，查看终端日志 |
| 点击 Start Detection 无反应 | 网卡未选择 | 在 Interface 下拉中选一个可用网卡 |
| PCAP 回放后无告警 | 文件路径错误 | 确认 PCAP 在 `tests/test_pcaps/` 下 |
| 饼图/折线图不显示 | PyQtChart 未安装 | `pip install PyQtChart` |
| 攻击链面板无内容 | 告警数不够 (需 ≥2 步) | 先回放 `demo_mixed.pcap` 再刷新 |
| 告警弹窗无威胁情报 | 本地黑名单未命中该 IP | 正常行为——只有已知恶意 IP 才会显示 |
| 终端显示 "pyahocorasick 未安装" | 缺少 C 扩展 | `pip install pyahocorasick`，不影响功能但会慢 |
| 主题切换后部分颜色异常 | QSS 缓存 | 重启 GUI |

---

## 附录：一句话话术速查

```
系统概述:
  "NADS 是一个基于混合检测架构的入侵检测系统，融合误用检测和异常检测双引擎。"

AC 自动机:
  "采用 Aho-Corasick 多模式匹配算法，250+ 条规则只需一次遍历，
   复杂度 O(n)，与规则数量无关。"

Suricata 规则导入:
  "自研规则导入器，兼容 Emerging Threats Open 社区 30000+ 条规则。"

TLS 加密流量检测:
  "JA3/JA4 指纹 + 证书异常 + C2 心跳三层防线，不解密也能发现 C2。"

攻击链可视化:
  "将零散告警按 MITRE ATT&CK 模型串联，颜色标记攻击阶段，
   安全运维人员一眼看出攻击者走了多远。"

Demo 模式:
  "一键生成混合攻击流量，无需 PCAP 文件，展示实时检测能力。"
```
