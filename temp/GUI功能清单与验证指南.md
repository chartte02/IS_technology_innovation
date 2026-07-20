# NADS GUI 功能清单与验证指南

> 最后更新: 2026-07-15 | 成员D

---

## 一、启动方式

```bash
cd D:\Document\CODE\School\IS_technology_innovation

# 方式 1：GUI 主界面（需要显示器）
.\venv\Scripts\python.exe main.py

# 方式 2：PCAP 回放（最稳定的演示方式，不需要管理员权限）
.\venv\Scripts\python.exe main.py --replay tests/test_pcaps/synthetic_attacks.pcap

# 方式 3：命令行模式（不需要 GUI）
.\venv\Scripts\python.exe main.py --console
```

**推荐演示流程**：先开 GUI（方式 1），然后在 GUI 里点「📂 Replay PCAP」选择测试文件，可以看到实时告警和图表变化。

---

## 二、GUI 5 个页面功能清单

### 页面 1 — Dashboard（仪表盘）

| 功能 | 描述 | 如何验证 |
|------|------|----------|
| **6 张统计卡片** | Total Alerts / Critical / High / Medium / Low / Packets | PCAP 回放时卡片数字实时增长，颜色区分严重度（红/橙/黄/紫/蓝/青） |
| **Recent Alerts 表格** | 最近 20 条告警（时间/严重度/类型/来源IP/描述） | 回放后表格自动填充，严重度行有颜色标识 |
| **Real-time PPS/BPS 折线图** | 蓝线 PPS + 绿线 BPS，60 秒滑动窗口 | 回放时有锯齿波动；**注意 Y 轴自适应缩放** |
| **Top Attack Sources** | TOP 5 攻击来源 IP | 回放后显示 IP:攻击次数，如 `192.168.1.100: 7 attacks` |
| **状态栏** | PPS / Alerts / Uptime 实时数字 | 回放时 PPS>0、Alerts>0、Uptime 在走 |

**验证检查点：**
- [ ] 回放 `synthetic_attacks.pcap` 后 Total Alerts = 21（去重后）
- [ ] Critical 卡片 ≥ 3，High 卡片 ≥ 10
- [ ] PPS 折线图有波动
- [ ] Top Attack Sources 显示 5 个 IP

---

### 页面 2 — Alerts（告警列表）

| 功能 | 描述 | 如何验证 |
|------|------|----------|
| **告警表格** | 8 列：ID / Time / Severity / Source / Category / Attack Name / Src IP / Dst IP:Port | 回放后表格填满，按时间排序 |
| **严重度筛选** | 下拉选 critical/high/medium/low | 选 "critical"，点 Filter，表格只显示严重告警 |
| **类别筛选** | 下拉选 sql_injection/xss/web_attack 等 | 选 "sql_injection"，点 Filter，表格只显示 SQL 注入告警 |
| **组合筛选** | 严重度 + 类别同时生效 | 选 "critical" + "sql_injection" → 精确命中 |
| **导出 JSON** | 将筛选结果导出为 JSON 文件 | 点 "Export JSON"，选择路径，检查文件内容 |

**验证检查点：**
- [ ] 筛选 "critical" → 表格行数减少到只有 critical 行
- [ ] 筛选 "xss" → 显示 3-4 条 XSS 告警
- [ ] 导出 JSON 文件包含筛选后的告警（不是全部）

---

### 页面 3 — Statistics（统计分析）

| 功能 | 描述 | 如何验证 |
|------|------|----------|
| **严重度饼图** | 红(critical) / 橙(high) / 黄(medium) / 蓝(low) 四色分布 | 回放后饼图有 3-4 个扇区，图例右对齐 |
| **类别柱状图** | TOP 8 攻击类别分布（橙色柱体） | 回放后 sql_injection / xss / web_attack / brute_force 类别有柱子 |
| **TOP 10 来源 IP** | 文本列出攻击次数最多的 10 个 IP | 与仪表盘的 TOP 5 数据一致（这里更多） |
| **Refresh 按钮** | 手动刷新统计 | 点击后图表重绘 |

**验证检查点：**
- [ ] 饼图至少显示 3 个扇区（critical/high/medium）
- [ ] 柱状图至少 3 个类别有柱体
- [ ] 数值与告警列表筛选结果一致

---

### 页面 4 — Signatures（特征库管理）

| 功能 | 描述 | 如何验证 |
|------|------|----------|
| **查看特征文件** | 下拉选择 .yaml 文件，点 View 查看内容 | 选 `sql_injection.yaml` → View → 右侧显示 YAML 源码 |
| **重载特征库** | 热更新，不重启系统 | 点 "Reload All" → 弹出对话框显示 "Successfully reloaded 93 rules" |
| **9 个特征文件** | sql_injection / xss / web_attack / brute_force / backdoor / scan / dos / webshell / imported_suricata | 下拉列表验证全部存在 |

**验证检查点：**
- [ ] 下拉框有 9 个文件
- [ ] 选任意文件 → View → 内容正确显示
- [ ] Reload All → 弹窗显示 93 条规则

---

### 页面 5 — Log（系统日志）

| 功能 | 描述 | 如何验证 |
|------|------|----------|
| **实时日志流** | 显示带时间戳的操作日志 | 做任何操作（回放/筛选/重载）都会追加日志行 |
| **自动滚动** | 新日志自动滚到底部 | 回放 PCAP 时日志持续增长 |

**验证检查点：**
- [ ] 启动回放后日志出现 "Replaying: ..." 条目
- [ ] 筛选告警后日志出现 "Filter: ..." 条目
- [ ] 重载特征库后日志出现 "Signatures reloaded: 93 rules"

---

## 三、全局功能

| 功能 | 描述 | 如何验证 |
|------|------|----------|
| **亮/暗主题切换** | 侧边栏底部 "☀ Toggle Theme" | 点击 → 全局切换暗色；再点 → 切回亮色 |
| **▶ Demo 动态检测** | 控制栏 Demo 按钮, 启动随机攻击流量生成器, 实时检测 | 点 Demo → 仪表盘卡片/图表实时跳动, 告警持续冒出来, 状态栏 PPS > 0；再点停止 |
| **📂 Replay PCAP** | 回放预录 PCAP 文件 | 选文件 → 终端输出告警, 仪表盘更新 |
| **菜单 > File > Export Alerts** | 导出全部告警 | 选路径保存，检查 JSON |
| **菜单 > Settings > View Config** | 查看 config.yaml 内容 | 弹窗显示配置文件 |
| **菜单 > Help > About NADS** | 关于对话框 | 显示项目名称和版本 |

### Demo 模式说明

Demo 模式是**最直观的动态演示方式**——不需要管理员权限，不需要真实攻击环境，不需要 PCAP 文件。点击按钮后：

1. 后台线程每秒发 2 个包（攻击 60% + 正常 40%）
2. 攻击包随机从 **SQLi / XSS / Web Attack / BruteForce / Backdoor / 端口扫描** 池中选取
3. 误用检测 + 异常检测同时工作，告警实时出现在告警列表和仪表盘
4. 异常检测器的 `check_all()` 每 5 秒自动触发，端口扫描等异常告警由 `source=anomaly` 标识
5. 流量面板新增 **Anomaly 计数** 和 **Demo 包数** 标签

```
Demo 运行后的数据流:
  TrafficGenerator (后台线程)
    ↓ _on_packet() 每个包
  ProtocolParser → MisuseDetector → [误用告警]
                 → AnomalyDetector → [异常告警, 每5秒]
                 → TCPReassembler → [流重组统计]
    ↓
  AlertManager → GUI 实时刷新
```

**验证检查点：**
- [ ] 点 Demo → 状态栏 PPS 从 0 变为非 0, 告警数开始增长
- [ ] 告警列表每 5 秒自动刷新, 能看到 xss/web_attack/sql_injection 等类别
- [ ] 筛选 `source=anomaly` 可看到异常检测告警（如果有端口扫描等高阈值操作触发）
- [ ] Demo 标签显示已发包数, 再点停止 → PPS 归零, 告警保持

---

## 四、核心检测功能验证（通过 PCAP 回放）

### 攻击检测覆盖

| 攻击类型 | 特征库规则数 | 验证方式 |
|----------|:---:|------|
| SQL 注入 | 17 条 | 回放 `synthetic_attacks.pcap` → 告警列表筛选 "sql_injection" → 应看到 UNION SELECT / Comment Bypass / Stacked Queries 等 |
| XSS | 10 条 | 筛选 "xss" → 应看到 Script Tag / Event Handler / IMG Onerror |
| Web 攻击 | 24 条 | 筛选 "web_attack" → 应看到 Directory Traversal / File Inclusion / PHP Code Execution / SQLMap |
| 暴力破解 | 9 条 | 筛选 "brute_force" → 应看到 SSH Brute Force Attempt |
| 后门/木马 | 10 条 | `extended_attacks.pcap` 中有 WebShell 样本 |
| DoS | 7 条 | 需要构造 SYN Flood 流量 |
| 扫描探测 | 9 条 | 需要模拟多端口访问 |
| WebShell | 7 条 | `extended_attacks.pcap` 中有蚁剑/冰蝎样本 |

### 可用的 PCAP 文件

```bash
tests/test_pcaps/synthetic_attacks.pcap  # 16 包，SQLi/XSS/Web/BruteForce（推荐）
tests/test_pcaps/extended_attacks.pcap   # 12 包，SSRF/XXE/SSTI/WebShell/NoSQL
tests/test_pcaps/http.cap                # HTTP 正常流量（256KB，验证无误报）
```

---

## 五、五步快速验证流程（推荐用于答辩演示）

```
第 1 步：启动 GUI
   .\venv\Scripts\python.exe main.py
   验证：窗口正常打开，侧边栏 5 项 + Toggle Theme

第 2 步：Demo 动态检测（★ 最直观）
   点控制栏 ▶ Demo → 仪表盘卡片数字实时跳动
   → 实时 PPS 折线图波动 → 告警列表逐渐填满
   → 运行 30 秒后点 ■ Stop Demo
   验证：>30 条告警，覆盖 SQLi/XSS/Web/BruteForce/Backdoor 多类

第 3 步：查看告警列表
   左侧点 Alerts → 等 5 秒自动刷新 → 表格显示告警
   筛选 severity=critical → 点 Filter → 仅显示严重告警
   筛选 category=xss → 确认 XSS 类型存在
   点 Export JSON → 导出筛选结果

第 4 步：查看统计分析
   左侧点 Statistics → 饼图显示严重度分布 → 柱状图显示类别分布
   验证：sql_injection/xss/web_attack 类别有柱体

第 5 步：PCAP 回放（备用演示）
   点 📂 Replay PCAP → 选 synthetic_attacks.pcap
   验证：21 条告警，覆盖 4 大类

第 6 步（可选）：切暗色主题展示
   左侧底部 "☀ Toggle Theme" → 全局变暗 → 再点切回亮色
```

---

## 六、模块接入状态

| 模块 | 负责人 | GUI 接入 | 展示方式 |
|------|:---:|:---:|------|
| 误用检测引擎 | A | ✅ | PCAP 回放 / Demo → 告警列表, 按类别筛选 |
| 数据包捕获 | B | ✅ | 在线抓包 → 状态栏 PPS/BPS |
| 协议解析 | B | ✅ | 透传, 输出 parsed_packet |
| TCP 流重组 | B | ✅ | 仪表盘 Conn/TCP 计数 |
| TLS 加密检测 | B | ✅ | 告警中 source=tls, 分类显示 |
| **异常检测** | **C** | **✅** | **Demo 模式端口扫描 → source=anomaly 告警; 仪表盘 Hosts/Anomaly 标签** |
| **基线学习** | **C** | **✅** | **点 Learn Baseline → 日志提示** |
| **流量生成器** | **D** | **✅** | **点 Demo → 实时动态攻击流量** |
| 告警管理 | D | ✅ | 去重/筛选/导出/统计 |
| GUI 界面 | D | ✅ | Apple 风格 5 页面 + 亮/暗主题 |
