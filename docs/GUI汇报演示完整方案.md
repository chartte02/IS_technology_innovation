# NADS GUI 汇报演示完整方案

> **日期**: 2026-07-22 | **目的**: 答辩现场 10-12 分钟完整演示脚本
> **前提**: 先完成本文档"第三章"列出的集成缺口修复（约 30 分钟工作），再按第四章脚本演示

---

## 第一章：现有 PCAP 文件与演示能力全景

### 1.1 可用 PCAP（12 个）

| PCAP | 包数 | 告警(去重) | 攻击链 | 演示价值 | 演示时长 |
|------|:--:|:--:|:--:|------|:--:|
| `demo_web_all.pcap` | 10 | 22 | 0 | ⭐⭐⭐ **一键展示** SQLi+XSS+WebAttack 三类Web攻击 | ~2s |
| `demo_mixed.pcap` | 5 | 6 | 1-2 | ⭐⭐⭐⭐⭐ **攻击链可视化**扫描→注入→后门三步链 | ~2s |
| `demo_tls_ja3.pcap` | 1 | 1(待修复) | 0 | ⭐⭐⭐⭐ **TLS加密C2检测**—JA3恶意指纹识别 | ~1s |
| `demo_c2_beacon.pcap` | 10 | 0(待修复) | 0 | ⭐⭐⭐⭐⭐ **C2心跳检测**—CV变异系数发现规律信标 | ~2s |
| `demo_bruteforce.pcap` | 8 | 1 | 0 | ⭐⭐⭐ **暴力破解检测**—HTTP 401异常检测触发 | ~1s |
| `synthetic_attacks.pcap` | 16 | 23 | 0 | ⭐⭐⭐ 早期综合样本 | ~3s |
| `extended_attacks.pcap` | 12 | 19 | 2 | ⭐⭐⭐⭐ **SSRF/XXE/SSTI/WebShell**四类高级攻击 | ~3s |
| `kali_to_windows_scan.pcap` | 837 | 7 | 1 | ⭐⭐⭐⭐ **真实网络扫描**—Kali→Windows双引擎检测（12种协议） | ~64s |
| **`demo_hybrid_detection.pcap`** | **55** | **13** | **1** | **⭐⭐⭐⭐⭐ 混合检测核心展示**—同一IP四阶段攻击，双引擎12+1告警 | **~3s** |
| `normal_real_browsing.pcap` | 930 | 16 FP | 0 | ⭐⭐⭐⭐ **正常流量误报率评估**—真实浏览流量，误报率1.72% | ~172s |
| `wednesday_subset.pcap` | 17,244 | 99 | 2 | ⭐⭐⭐⭐⭐ **CIC-IDS-2017学术数据集**—客观评估 | ~390s |
| `demo_sqli.pcap` | 3 | 4 | 0 | ⭐⭐ 已被 demo_web_all 覆盖 | — |
| `demo_xss.pcap` | 3 | 8 | 0 | ⭐⭐ 已被 demo_web_all 覆盖 | — |
| `demo_webattack.pcap` | 4 | 10 | 0 | ⭐⭐ 已被 demo_web_all 覆盖 | — |

### 1.2 各模块集成状态

| 模块 | 文件 | main.py 集成 | 备注 |
|------|------|:--:|------|
| PacketCapture | `core/packet_capture.py` | ✅ | PCAP回放+实时抓包 |
| ProtocolParser | `core/protocol_parser.py` | ✅ | 9协议解析 |
| TCPReassembler | `core/tcp_reassembler.py` | ✅ | 流重组 |
| MisuseDetector | `core/misuse_detector.py` | ✅ | 93规则+AC自动机 |
| AnomalyDetector | `core/anomaly_detector.py` | ✅ | 7检测器 |
| BaselineLearner | `core/baseline_learner.py` | ✅ | `--learn` 命令行模式 |
| TLSDetector (JA3) | `core/tls_detector.py` | ✅ | 集成在 `_on_packet()` step 3 |
| TLSDetector (C2 Beacon) | `core/tls_detector.py` | ⚠️ | JA3提取已集成，**恶意查询+C2间隔分析未显式调用** |
| MLAnomalyDetector | `core/ml_anomaly.py` | ✅ | 自动训练+预测 |
| AttackChainAnalyzer | `core/attack_chain.py` | ⚠️ | 代码已集成，**`config.yaml` 中 `enabled: false`** |
| ThreatIntel | `tools/threat_intel.py` | ❌ | **未集成到告警管线** |
| AlertFilter (降噪) | `core/alert_manager.py` | ✅ | 已集成 |
| TrafficGenerator (Demo) | `tools/traffic_generator.py` | ✅ | GUI Demo按钮已连接 |

---

## 第二章：集成缺口与修复方案

### 🔴 缺口1：`config.yaml` — attack_chain 未启用

**问题**: `config.yaml` L137 `attack_chain: enabled: false`

**修复**: 改为 `enabled: true`
```
# config.yaml L137
attack_chain:
  enabled: true    # ← 改这里
```

**影响**: 修复后攻击链面板在回放 `demo_mixed.pcap`、`extended_attacks.pcap`、`kali_to_windows_scan.pcap` 时自动有数据。

---

### 🔴 缺口2：TLS JA3 恶意指纹查询未显式调用

**问题**: `main.py` `_on_packet()` step 3 调用了 `analyze_client_hello()` 检测 TLS 异常，但**没有调用 `lookup_ja3()` 检查 JA3 指纹是否已知恶意**。导致 `demo_tls_ja3.pcap` 回放时不会触发 TLS 告警。

**修复位置**: `main.py` L238-257，在 `analyze_client_hello()` 之后增加：
```python
# 检查 JA3 指纹是否已知恶意
ja3 = result.get('ja3', '')
if ja3 and self.tls_detector.lookup_ja3(ja3):
    info = self.tls_detector.lookup_ja3(ja3)
    self.alert_mgr.submit({
        'signature_id': 'TLS-JA3-MALICIOUS',
        'signature_name': f"TLS Malicious JA3: {info.get('family','Unknown')}",
        'type': 'tls_anomaly',
        'category': 'backdoor',
        'severity': 'critical',
        'description': f"TLS fingerprint matches known malware family: {info.get('family')}",
        ... }, source='tls')
```

**影响**: 修复后 `demo_tls_ja3.pcap` 会触发 critical 级 TLS 告警。

---

### 🟡 缺口3：威胁情报 enrichment 未集成到告警管线

**问题**: `tools/threat_intel.py` 的 `enrich_alert()` / `enrich_alerts()` 在 GUI 告警详情弹窗中被调用（`_query_threat_intel()`），但**告警入库时没有自动 enrichment**。

**影响**: 弹窗可以展示威胁情报，但无法"自动上报"。**影响不大**——GUI 已有 fallback 本地黑名单，弹窗能正常展示。

**建议**: 暂不改动。GUI 弹窗 `_query_threat_intel()` 已经处理了 enrichment 展示。

---

### 🟡 缺口4：`wednesday_subset.pcap` 回放时间过长（~6.5分钟）

**问题**: 17,244 包按原始 57 PPS 回放需要 ~390 秒。

**方案A（推荐）**: 提前用命令行回放，截图保存结果，演示时直接展示截图。
```bash
python main.py --replay tests/test_pcaps/wednesday_subset.pcap > wed_result.txt 2>&1
```
**方案B**: 修改 `replay_pcap()` 支持倍速（已有 speed 参数支持）。
```python
# 演示时用 5x 倍速
engine.replay_pcap('tests/test_pcaps/wednesday_subset.pcap', speed=5.0)
```

---

### 汇总：必须修复 vs 建议修复

| 优先级 | 缺口 | 修复工作量 | 必须？ |
|:--:|------|:--:|:--:|
| 🔴 | `config.yaml` attack_chain enabled | 1行 | ✅ 必须 |
| 🔴 | TLS JA3 恶意查询显式调用 | ~15行 | ✅ 必须（否则TLS检测无法演示） |
| 🟡 | wednesday 回放太慢 | 改 speed 参数或截屏 | ✅ 建议 |
| 🟢 | 威胁情报 enrichment 自动集成 | 不改 | 不需要 |

---

## 第三章：演示前准备清单

### 3.1 环境确认
```bash
python -c "import scapy,yaml,ahocorasick,cryptography,sklearn;print('ALL OK')"
python -c "from PyQt5.QtWidgets import QApplication;from PyQt5.QtChart import QChart;print('GUI OK')"
ls tests/test_pcaps/demo_*.pcap normal_real_browsing.pcap kali_to_windows_scan.pcap | wc -l  # 应输出 11
```

### 3.2 修复集成缺口（需要你批准后执行）
- [ ] `config.yaml`: `attack_chain.enabled: true`
- [ ] `main.py`: TLS JA3 恶意指纹查询增加 ~15 行

### 3.3 预生成学术数据集演示截图
```bash
python main.py --replay tests/test_pcaps/wednesday_subset.pcap > demo_wed_result.txt 2>&1
# 截图保存为 wednesday_scan_demo.png（Statistics页饼图+柱状图）
```

### 3.4 提前验证关键 PCAP
```bash
# 确保每个演示 PCAP 都能正常检出
for pc in demo_web_all demo_mixed demo_tls_ja3 demo_c2_beacon demo_bruteforce extended_attacks demo_hybrid_detection; do
  python main.py --replay tests/test_pcaps/$pc.pcap 2>&1 | grep -c "CRIT\|HIGH"
done
```

---

## 第四章：完整演示脚本（10-12 分钟）

### 时间分配

| 幕 | 内容 | PCAP/模式 | 时长 |
|:--:|------|------|:--:|
| 1 | 启动 + 界面概览 | — | 30s |
| 2 | **一键Web攻击展示** | demo_web_all.pcap | 30s |
| 3 | **攻击链可视化** ⭐ | demo_mixed.pcap + extended_attacks.pcap | 90s |
| 4 | **混合检测双引擎展示** ⭐⭐ | demo_hybrid_detection.pcap | 90s |
| 5 | **真实网络扫描 + 误报率** ⭐ | kali_to_windows_scan.pcap + normal_real_browsing 截图 | 60s |
| 6 | **加密流量检测** ⭐ | demo_tls_ja3.pcap + demo_c2_beacon.pcap | 60s |
| 7 | **统计图表 + 特征库** | Statistics + Signatures Tab | 30s |
| 8 | **学术数据集** ⭐ | wednesday_subset 截屏展示 | 30s |
| 9 | Demo 模式实时检测 | [▶ Demo] 按钮 | 30s |
| 10 | 总结 | — | 30s |

---

### 第 1 幕：启动 + 界面概览（30 秒）

```
操作:
1. 终端执行: python main.py
2. 等待窗口弹出（3-5秒）
3. 确认: 标题 "NADS — 常见网络攻击检测系统"
4. 确认: 左侧 6 项导航（Dashboard/Alerts/Statistics/Signatures/Attack Chain/Log）

讲解词:
"NADS 是一个基于混合检测架构的入侵检测系统，融合了误用检测和异常检测双引擎。
界面采用 Apple 风格设计，6 个功能页面通过侧边栏导航。
系统初始化已完成，93 条检测规则加载完毕，包括自研的 78 条和
从 Suricata 社区导入的 15 条规则。"
```

---

### 第 2 幕：一键 Web 攻击展示（30 秒）

```
操作:
1. 点击 [📂 Replay PCAP] → 选择 demo_web_all.pcap
2. 观察（约2秒）:
   - Dashboard: Total Alerts 数字跳动 (0 → 22)
   - Critical 卡片出现数字 (红色)
   - Recent Alerts 表格新增行
   - Log 区滚动显示告警

检出内容:
  SQL注入:  UNION SELECT (SQLI-001), Tautology 1=1 (SQLI-002)
  XSS:      <script> 标签 (XSS-001), onerror 事件 (XSS-005), IMG标签 (XSS-006)
  Web攻击:  目录遍历 (WEB-001), 敏感文件 (WEB-002), 命令注入 (WEB-003)

讲解词:
"首先演示三类最常见的 Web 攻击——SQL 注入、XSS 跨站脚本和目录遍历/命令注入。
这个 PCAP 包含 10 个数据包，系统在 2 秒内全部检出，产生了 22 条去重告警。
Dashboard 卡片实时更新，Critical 红色高亮显示需要立即处理的高危告警。"
```

---

### 第 3 幕：攻击链可视化 ⭐（90 秒）

```
操作:
3a. 回放 demo_mixed.pcap
    - 点击 [📂 Replay PCAP] → 选择 demo_mixed.pcap
    - 观察 Alerts: 扫描(2) + SQL注入(3) + 后门(1) = 6条
    - 切换到 "◈ Attack Chain" Tab → 点击 Refresh
    - 查看: 蓝色节点(10.0.5.1) → 黄色(扫描) → 橙色(SQLi) → 红色(后门C2)
    - 底部显示: "1 chains | 3 steps | max 3 phases" / Level: HIGH

3b. 回放 extended_attacks.pcap（展示高级攻击类型）
    - 点击 [📂 Replay PCAP] → 选择 extended_attacks.pcap
    - 观察检出: SSRF(WEB-007) + XXE(WEB-008) + SSTI(WEB-009) + WebShell(蚁剑/菜刀)
    - 切换到 Alerts Tab → 筛选 severity=critical → 展示高级攻击全部被检出

讲解词:
"攻击链可视化是我们的一大特色。demo_mixed.pcap 模拟了一次完整的
攻击生命周期——同一来源 IP 先进行扫描侦察，发现漏洞后进行
SQL 注入利用，成功后安装后门维持持久化访问。三条独立告警
被自动串联为'侦察→利用→持久化'的三步攻击链。

接下来 extended_attacks.pcap 展示了系统对高级攻击的检出能力——
SSRF 服务端请求伪造、XXE XML外部实体注入、SSTI 模板注入，
以及蚁剑和中国菜刀两种国产 WebShell 的特征检测。"
```

---

### 第 4 幕：混合检测双引擎展示 ⭐⭐（90 秒）

**这是整个演示最重要的环节**——展示 NAD 的核心差异化优势。

```
操作:
1. 点击 [📂 Replay PCAP] → 选择 demo_hybrid_detection.pcap
2. 等待回放完成（约 3 秒，55 个包）
3. 观察 Dashboard: Total Alerts 数字跳动 (0 → 13)
4. 切换到 "⚠ Alerts" Tab
5. 观察 Source 列:

   Source       Category       Attack Name                   Severity
   ──────       ────────       ──────────────────────────    ────────
   anomaly      scan           port_scan (26个端口)          medium
   misuse       sql_injection  SQLI-001 UNION SELECT         critical
   misuse       sql_injection  SQLI-002 Tautology 1=1        high
   misuse       sql_injection  SQLI-004 DROP TABLE           critical
   misuse       sql_injection  SQLI-008 Stacked Queries      critical
   misuse       sql_injection  SQLI-010 SQLMap User-Agent    medium
   misuse       sql_injection  SQLI-011 MySQL Error Based    high
   misuse       web_attack     SUR-1000001 UNION SELECT      high
   misuse       web_attack     SUR-3000002 SQLMap Attack     high
   ... (共 13 条去重告警)

6. 手指向 "Source" 列的两行 → 重点强调:
   anomaly → port_scan (统计偏离触发)
   misuse  → SQLI-001/002/004/... (特征匹配触发)
```

**演示脚本结构**:

> "接下来是验证混合检测架构核心优势的演示。这个 PCAP 模拟了一次完整的网络攻击——
> 同一个来源 IP `10.0.7.77` 对目标 `192.168.1.100` 发动了四阶段攻击：
> 先进行端口扫描探测 25 个端口，然后发起 SQL 注入尝试窃取数据库，
> 接着尝试 SSH 暴力破解，最后建立后门连接维持持久化访问。
>
> 请大家注意告警列表的 **Source 列**——这是区分检测引擎的关键字段。
>
> 这条 `source=anomaly` 的告警，类型是 port_scan——
> 它是异常检测引擎通过统计偏离发现的：正常主机访问的端口数一般在
> 5 个以内，而这个 IP 在短时间内访问了 26 个不同端口，严重偏离基线，
> 触发了端口扫描告警。
>
> 这 12 条 `source=misuse` 的告警，包括 UNION SELECT、堆叠查询、
> SQLMap 指纹识别等——它们是误用检测引擎通过特征匹配发现的：
> 每条告警对应我们特征库中的一条检测规则。
>
> **同一次攻击事件，双引擎从不同维度同时产生了告警——**
> 异常检测发现"行为不正常"，误用检测告诉你"具体是什么攻击"。
> 两者互相印证，互补短板。异常检测可以发现未知的攻击模式，
> 误用检测可以精确告诉你攻击的类型和严重度。
> 这就是混合检测架构的设计理念。"

```
7. 可选的额外展示:
   - 双击一条 misuse 告警 → 弹窗展示匹配原文（如 "UNION SELECT user,password"）
   - 双击 anomaly 告警 → 弹窗展示统计详情（26 端口 / 阈值 20）
   - 切换到 Statistics Tab → 展示饼图/柱状图
   - 切换到 Attack Chain Tab → 显示同一个 IP 的四步攻击链
```

**解说词**:
> "这条 anomaly 告警——异常检测引擎通过统计偏离发现的：正常主机访问端口数在 5 个以内，这个 IP 在短时间内访问了 26 个不同端口。这 12 条 misuse 告警——误用检测引擎通过特征匹配：UNION SELECT 对应 SQLI-001 规则，SQLMap UA 对应 SQLI-010 规则。同一次攻击事件，双引擎从不同维度同时告警，互相印证，互补短板。"

---

### 第 5 幕：真实网络扫描 + 误报率评估 ⭐（60 秒）

**两个 PCAP 配合展示——一个证明检出能力，一个证明不误报。**

#### 5a. 真实 Kali 扫描（30秒）

```
操作:
1. 点击 [📂 Replay PCAP] → 选择 kali_to_windows_scan.pcap
2. 回放中观察 Log 滚动（12 种协议识别——HTTP/HTTPS/SSH/FTP/SMTP/POP3/IMAP/TELNET/DNS/MySQL/TLS）
3. 回放完成 → 切换到 Alerts Tab:

   关键告警:
     [anomaly] port_scan: 100 个不同端口 (阈值:20)    ← 异常检测
     [misuse]  SCAN-001: Nmap SYN Scan               ← 误用检测
     [misuse]  WEB-004: PHP Code Execution            ← 误用检测
     ... (共 7 条去重)

4. 指向 Source 列 → anomaly 和 misuse 同时出现
```

> "kali_to_windows_scan.pcap 来自 VirtualBox 真实抓包——
> Kali Linux 使用 Nmap 对 Windows 目标发起端口扫描。
> 系统正确识别了 12 种应用层协议，双引擎同时告警：
> 异常检测发现 100 个端口的统计偏离，误用检测识破 Nmap SYN 扫描指纹。"

#### 5b. 正常流量误报率展示（30秒）

```
操作:
1. 展示预先生成的正常流量检测结果截图（或快速回放）
2. 关键数据直接念
```

> "同时，我们用一段真实的网页浏览流量验证了系统的误报率——
> 930 个正常 HTTP 请求，包括访问网页、加载图片、API 调用等，全部是正常用户行为。
> 系统仅产生 16 条误报告警，误报率 1.72%。
> 误报集中在一条从 Suricata 社区导入的规则（SUR-1000302，匹配 'curl' 关键字）
> ——因为正常 HTTP 请求的 User-Agent 字符串中也可能包含 'curl'。
> 这说明**系统的自研规则误报率极低，而部分导入的社区规则需要根据实际网络环境调整**，
> 这也是为什么我们在误用检测引擎中增加了上下文过滤和位置感知降噪功能。"

---

### 第 6 幕：加密流量检测 ⭐（60 秒）

```
操作:
5a. TLS JA3 恶意指纹识别
    - 点击 [📂 Replay PCAP] → 选择 demo_tls_ja3.pcap
    - 观察 Alerts: critical 级 TLS 告警 "TLS Malicious JA3: C2 Demo"
    - 双击告警 → 弹窗展示 JA3 指纹完整值 + 匹配的恶意软件家族

5b. C2 Beacon 心跳检测（可选，如果 demo_c2_beacon 已集成检出）
    - 回放 demo_c2_beacon.pcap
    - 观察: CV 变异系数检测到固定间隔心跳（60s间隔, CV<0.05）

讲解词:
"加密流量检测是 PDF 要求的四项扩展功能之一。我们实现了
TLS JA3/JA4 指纹采集——即使不解密 HTTPS 载荷，
仅凭 ClientHello 握手中的加密套件顺序和扩展参数，
就可以识别出恶意 TLS 库的独特指纹。

demo_tls_ja3.pcap 中包含了一个模仿 C2 服务器 TLS 配置的
ClientHello——它的加密套件顺序与正常浏览器不同。
系统提取 JA3 指纹后与恶意指纹库匹配，发现这是一个已知的
C2 通信特征，触发 critical 级告警。

此外，我们还实现了基于变异系数的 C2 Beacon 心跳检测——
恶意软件C2通信的典型特征是固定间隔的心跳包。
通过统计连接时间间隔并计算 CV 值，CV<0.05 几乎可以确定是C2流量。
这种方法完全不需要解密 TLS 载荷。"
```

---

### 第 7 幕：统计图表 + 特征库（30 秒）

```
操作:
6a. Statistics Tab
    - 切换到 "▶ Statistics" Tab
    - 观察: 严重度饼图（红/橙/黄/蓝四色）+ 攻击类别柱状图
    - 点击 Refresh Statistics
    - 翻阅 Top Attack Source IPs 列表

6b. Signatures Tab
    - 切换到 "☰ Signatures" Tab
    - 点击 imported_suricata.yaml → 展示从Suricata社区导入的15条规则
    - 点击 webshell.yaml → 展示自研的7条WebShell检测规则

讲解词:
"Statistics 页用饼图和柱状图直观展示告警分布情况，
所有图表每 5 秒自动刷新。Signatures 页展示了系统的
93 条检测规则——包括自研的 78 条和从 Suricata 社区导入的 15 条。
点击任何文件可以看到具体每条规则的 ID、严重度和匹配模式。"
```

---

### 第 8 幕：学术数据集评估（30 秒）

```
操作:
- 展示预先生成的 wednesday_subset 检测结果截图
  (Statistics页 饼图/柱状图 + Attack Chain页)

关键数据（直接念）:
  "我们在 CIC-IDS-2017 数据集的 Wednesday DoS 子集上进行了评估——
  这是学术界最常用的 IDS 评估基准数据集之一。系统处理了 17,244 个
  网络包，检测到 99 条告警，覆盖 DoS、端口扫描、横向扫描、Web攻击
  四种类型，并发现了 2 条攻击链。"

讲解词:
"为了客观评估检测能力，我们使用了 CIC-IDS-2017——
加拿大新不伦瑞克大学发布的学术界标准评估数据集。
在 Wednesday DoS 子集上，系统处理了 17,244 个包，
检出 99 条告警，包括 50 条 DoS 告警、28 条扫描告警
和 21 条 Web 攻击告警。这个评估证明了系统在学术标准
数据集上的检测能力。"
```

---

### 第 9 幕：Demo 模式实时检测（30 秒）

```
操作:
1. 点击控制栏 [▶ Demo] 按钮
2. 观察:
   - Dashboard PPS/BPS 折线图出现实时流量曲线
   - 告警持续产生
   - Log 滚动显示实时告警
3. 约 20 秒后点击 [■ Stop Demo]

讲解词:
"Demo 模式可以一键生成混合攻击流量，无需 PCAP 文件。
系统自动以每秒 2 个包的速率产生 SQL 注入、XSS、
Web 攻击、暴力破解、后门和扫描等七类攻击的混合流量，
同时夹杂正常 HTTP 请求。适合演示系统的实时检测能力。"
```

---

### 第 10 幕：总结（30 秒）

```
操作: 点击侧边栏 Toggle Theme → 切换暗色主题（展示双主题支持）

讲解词:
"总结一下，NADS 实现了——
1. 误用检测：AC 自动机多模式匹配，93 条规则，准确率 96%，误报率 1.72%
2. 异常检测：7 种检测器，滑动时间窗口 + 动态阈值自适应
3. TLS 加密流量检测：JA3/JA4 指纹 + 证书异常 + C2 心跳三层防线
4. ML 未知攻击检测：Isolation Forest 无监督学习 + 两阶段精判
5. 攻击链关联分析：MITRE ATT&CK 七阶段串联
6. 威胁情报集成：AbuseIPDB + 本地黑名单双源查询
7. 真实流量验证：Kali→Windows 真实网络扫描，双引擎互印证
8. 正常流量验证：930 包真实浏览流量，误报率仅 1.72%
9. 友好用户界面：Apple 风格 6-Tab 设计，亮暗双主题

以上功能全部基于 30+ 个开源项目的调研和借鉴，
代码总量约 15,000 行。谢谢。"
```

---

## 第五章：PPT 建议结构

| 页码 | 标题 | 内容 | 来源 |
|:--:|------|------|------|
| 1 | 封面 | 项目名 + 团队 | D |
| 2 | 目录 | — | D |
| 3 | 系统架构 | 五层管道架构图 | D 绘制 |
| 4 | 数据流 | PCAP→解析→检测→告警→GUI 流程图 | B+D |
| 5 | 误用检测 | AC 自动机原理 + 三阶段匹配 + 规则数量对比 | A |
| 6 | 加密流量检测 | JA3 指纹计算原理 + CV C2 检测原理 | B |
| 7 | 异常检测 + ML | 7 种检测器 + IF 原理 + 两阶段检测流程 | C |
| 8 | 攻击链 + 威胁情报 | ATT&CK 阶段映射 + 情报集成架构 | C+D |
| 9 | GUI 仪表盘 | Dashboard 截图（6 卡片 + 折线图） | D 截图 |
| 10 | GUI 攻击链 | Attack Chain Tab 截图 + 说明 | D 截图 |
| 11 | 性能数据 | 准确率 96% + 误报率 1.72% + AC 加速 + 降噪率 + PPS | 全员 |
| 12 | 混合检测验证 | demo_hybrid_detection 双引擎数据 + kali真实扫描 | A+B+C |
| 13 | 学术评估 | CIC-IDS-2017 wednesday + normal_real_browsing 结果 | D 截图 |
| 14 | 开源项目调研 | 34 个项目总览表 | D 汇总 |
| 15 | 特色创新 | 6 大特色总结 | D 汇总 |
| 16 | 感谢 | Q&A | D |

---

## 第六章：风险预案

| 风险 | 预案 |
|------|------|
| GUI 无法启动 | 方案B：命令行 `python main.py --replay` 模式，终端直接输出告警 |
| 某个 PCAP 回放失败 | 跳过该步骤，继续下一个 PCAP |
| 攻击链面板无内容 | 手动点击 Refresh 按钮；如果仍无，展示截图 |
| Demo 模式不工作 | 用 PCAP 回放替代 |
| 投影仪/网络故障 | 方案D：预录 5 分钟演示视频 |