# NADS 项目完成情况与 GUI 最终功能说明

> **日期**: 2026-07-20
> **目的**: 基于当前代码仓库实际状态，分模块说明已完成工作、验证方式、以及 GUI 最终需实现的功能

---

## 一、项目整体状态

```
核心模块:     ████████████████████ 100%  8/8 模块完整实现
拓展功能:     ████████████████████ 100%  4/4 PDF必做项全部完成
特色方向:     ██████████████████░░  85%  5/6 已完成 (攻击链可视化待做)
GUI 前端:     ████████████████░░░░  80%  4/5 图表完成 (攻击链面板+告警详情弹窗待做)
测试验证:     ██████████░░░░░░░░░░  50%  需补充性能数据和联调验证
```

---

## 二、各模块完成情况

### 模块1：误用检测引擎（成员A）

| 文件 | 行数 | 状态 |
|------|------|:--:|
| `core/misuse_detector.py` | 919 | ✅ 完整 |
| `signatures/sql_injection.yaml` | - | ✅ |
| `signatures/xss.yaml` | - | ✅ |
| `signatures/web_attack.yaml` | - | ✅ |
| `signatures/brute_force.yaml` | - | ✅ |
| `signatures/backdoor.yaml` | - | ✅ |
| `signatures/scan.yaml` | - | ✅ |
| `signatures/dos.yaml` | - | ✅ |
| `signatures/webshell.yaml` | - | ✅ 新增 |
| `signatures/imported_suricata.yaml` | - | ✅ Suricata 规则已导入 |
| `tools/suricata_importer.py` | 15KB | ✅ Suricata 规则导入器完成 |

**已实现的核心能力**：
- Signature 数据结构：id/name/category/severity/patterns/threshold/protocols/ports/flowbits/match_position
- SignatureMatcher：AC 自动机 + 正则 + 阈值三阶段匹配
- 端口索引 (`_port_index`)、协议索引 (`_proto_index`)
- Flowbits 跨规则状态传递（Suricata 兼容）
- FlowStats 连接级统计
- 白名单 IP (`set_whitelist()`) + 内网 IP 前缀 (`set_internal_ranges()`)
- 特征库热更新 (`reload()`)
- **Suricata 规则导入器**：`tools/suricata_importer.py` 完整实现，含 classtype→severity 映射、content→patterns 转换，已产出 `imported_suricata.yaml`

**需要验证**：
- 七类攻击准确率统计（目标 ≥90%）：`python tests/test_signature_match.py`
- AC vs 暴力匹配性能对比（10000 包）：`python tools/perf_profiler.py`
- 流级别匹配验证（TCP 分片→重组→检出）

---

### 模块2：数据采集 + 协议解析 + TLS 检测（成员B）

| 文件 | 行数 | 状态 |
|------|------|:--:|
| `core/packet_capture.py` | 329 | ✅ 完整 |
| `core/protocol_parser.py` | 351 | ✅ 完整 |
| `core/tcp_reassembler.py` | 328 | ✅ 完整 |
| `core/tls_detector.py` | 30KB | ✅ TLS+证书+C2全部实现 |

**已实现的核心能力**：
- PacketCapture：AsyncSniffer 异步抓包、BPF 过滤、PCAP 回放、运行时统计（PPS）、网卡枚举
- ProtocolParser：IP/TCP 头解析、9 种协议识别（端口+指纹双策略）、HTTP 深度解析（method/URI/Host/UA）
- TCPStreamReassembler：StreamBuffer 严格 seq 排序（seq==next追加、seq<next重传忽略、seq>next乱序缓存）、LRU 淘汰、线程安全、重传统计
- **TLSDetector**（`core/tls_detector.py`，30KB）：
  - JA3 指纹提取（MD5 哈希：Version+Ciphers+Extensions+Curves+Formats）
  - JA4 指纹提取（SHA256 截断，GREASE 过滤）
  - 证书异常检测：自签名、过期、弱加密套件（RC4/DES/3DES/NULL）、CN 不匹配
  - **C2 Beaconing 检测**：已内置在 tls_detector.py 中，基于变异系数 CV 的心跳检测
  - 已知恶意 JA3 指纹库（Trickbot/Emotet/CobaltStrike/Meterpreter）
  - JA3S（Server Hello 指纹）提取
- CEF/Syslog 格式导出：`tools/cef_exporter.py`

**需要验证**：
- 协议识别准确率（>90%）：Wireshark 对比
- TCP 流重组完整性：构造 100 包含乱序/重传 → 验证字节级一致
- 抓包性能基准（100/1000/5000/10000 pps 丢包率）
- JA3 指纹正确性：用 ja3er.com 对比验证

---

### 模块3：异常检测 + 基线学习（成员C）

| 文件 | 行数 | 状态 |
|------|------|:--:|
| `core/anomaly_detector.py` | 539 | ✅ 完整 |
| `core/baseline_learner.py` | 406 | ✅ 完整 |

**已实现的核心能力**：
- HostStats：15 维统计画像（conn_count、syn_count、unique_dst_ips、unique_dst_ports、bytes_sent/received、login_failures 等）
- 7 种异常检测器：端口扫描、横向扫描、SYN Flood、暴力破解、高频流量、基线偏离、DDoS
- 滑动时间窗口（60s）+ 后台重置线程
- BaselineLearner：学习控制、基线计算、JSON 持久化保存/加载
- NetworkBaseline：全局指标 + 每主机基线 + 按小时流量模式

**需要验证**：
- 7 种检测器全覆盖验证（每类构造触发条件）
- 阈值参数调优（端口扫描 10/15/20/25/30 → 检出率 vs 误报率折线图）
- 基线偏离检测验证（学习基线 → 构造偏离流量 → 验证告警触发）
- 长时间运行稳定性（≥30 分钟，>10000 包，内存 < 100MB）

---

### 模块4：告警管理 + GUI（成员D）

| 文件 | 行数 | 状态 |
|------|------|:--:|
| `core/alert_manager.py` | 380 | ✅ 完整 |
| `gui/main_window.py` | 1168 | ✅ 主体完成 |
| `gui/theme.py` | 401 | ✅ 完整 |

**已实现的 GUI 功能**：
- Apple 风格亮/暗双主题（`gui/theme.py`，独立模块）
- 侧边栏导航（5 个 Tab：Dashboard/Alerts/Statistics/Signatures/Log）
- 顶部控制栏：Start/Pause、接口选择、BPF 过滤、Learn Baseline、Replay PCAP、**Demo 按钮**
- Dashboard：6 张统计卡片（Total/Critical/High/Medium/Low/Packets）+ 最近告警表 + **PPS/BPS 双线折线图**（实时刷新）+ TOP 攻击来源
- Alerts：表格（8 列） + 严重度/类别下拉筛选 + Export JSON
- Statistics：**告警严重度饼图** + **攻击类别柱状图**（PYQTCHART 实现完成）
- 状态栏：PPS/Alerts/Uptime 实时显示

**已实现的特色拓展**：
- `tools/traffic_generator.py`：动态流量生成器，7 大类攻击载荷（SQLi/XSS/Web/BruteForce/Backdoor/Scan/DoS），支持 Demo 模式实时模拟攻击
- `tools/threat_intel.py`：威胁情报集成（本地黑名单 + AbuseIPDB API + 恶意 JA3 指纹库）
- `tools/threat_intel.py` 已集成到 Demo 流量生成中
- `tools/report_generator.py`：检测报告自动生成
- `tools/rule_quality_check.py`：规则质量检查
- `tools/concurrent_bench.py`：并发性能基准测试
- `tools/fuzz_test.py`：模糊测试
- `tools/http_logger.py`：HTTP 日志记录器

---

### 模块5：主入口与集成（成员A）

| 文件 | 行数 | 状态 |
|------|------|:--:|
| `main.py` | 471 | ✅ 完整 |

**已实现**：IDSEngine 全链路回调、4 种运行模式（GUI/console/replay/learn）、配置文件驱动、安全关闭

---

### 模块6：测试

| 文件 | 状态 |
|------|:--:|
| `tests/test_signature_match.py` | ✅ 可用 |
| `tests/smoke_test.py` | ✅ 冒烟测试 |
| `tests/test_flowbits.py` | ✅ Flowbits 测试 |
| `tests/generate_test_pcap.py` | ✅ PCAP 生成器 |

---

## 三、仍需完成的工作

### 3.1 验证工作（各成员）

| 验证项 | 负责 | 验证方式 |
|--------|:--:|----------|
| 七类攻击准确率统计 | A | `python tests/test_signature_match.py` 输出统计 |
| AC vs 暴力性能对比 | A | `python tools/perf_profiler.py` |
| 协议识别准确率 | B | Wireshark 对比 |
| TCP 重组完整性 | B | 构造 100 包含乱序 → 验证字节级一致 |
| 抓包性能基准 | B | 不同 PPS 丢包率 |
| 7 种检测器全覆盖 | C | 每类构造触发条件 |
| 阈值参数调优 | C | 折线图 |
| 长时间稳定性 | C | ≥30min |
| 全链路端到端 | A | `python main.py --replay test.pcap` |
| GUI 响应性 + 内存 | D | 1000+告警不卡顿 |

### 3.2 GUI 待实现功能

#### 🔴 必须实现

**1. 攻击链可视化面板**（新 Tab #5）

在当前侧边栏 5 个 Tab 基础上，新增第 6 个 Tab "Attack Chain"：

```
侧边栏新增: "  ◈  Attack Chain"  → index=5
```

技术方案：`QGraphicsView` + `QGraphicsScene` 自定义绘制
- 节点：`QGraphicsEllipseItem`（圆形，标注 IP）
- 边：`QGraphicsLineItem`（箭头，标注攻击阶段 + 时间）
- 颜色：黄=侦察 → 橙=利用 → 红=C2 → 紫=横向移动
- 交互：点击节点 → 弹出该 IP 历史告警列表
- 数据来源：`alert_mgr.get_alerts()` 中按 `src_ip` 分组 + 时间段排序

**2. 告警详情弹窗**

双击告警表格行 → `QDialog` 弹窗，展示：
- 告警完整信息（规则 ID、严重度、来源/目标、匹配原文高亮）
- 威胁情报查询结果（AbuseIPDB 评分 + OTX pulses + 综合风险）
- "标记为误报"按钮 → `alert_mgr.mark_false_positive(id)`

**3. 攻击趋势面积图**（Dashboard 新增）

在 Dashboard 页面增加一个面积图（`QStackedAreaSeries` 或叠加 `QLineSeries`）：
- X 轴：过去 60 秒
- Y 轴：告警数量
- 每种攻击类型一条线（SQLi=红, XSS=橙, Scan=蓝）

#### 🟡 建议实现

**4. 告警声音提醒**
- critical 告警 → `QSound` 或 `winsound` 播放提示音

**5. 实时威胁等级指示灯**
- 状态栏右侧增加圆形指示灯：🟢无告警 / 🟡有告警 / 🔴有 critical
- 红色时闪烁动画

**6. PCAP 回放进度条 + 倍速控制**
- 进度条（已播放包数 / 总包数）
- 倍速选择下拉框（1x/2x/5x/10x）
- 暂停/继续按钮

---

## 四、GUI 最终完整功能清单

| 序号 | 功能 | 当前状态 | 对应代码位置 |
|:--:|------|:--:|------|
| 1 | 亮/暗双主题切换 | ✅ 完成 | `gui/theme.py`, `_apply_apple_theme()` |
| 2 | 侧边栏 5 Tab 导航 | ✅ 完成 | `_create_sidebar()` |
| 3 | 控制栏（Start/Pause/Interface/BPF/Learn/Replay/Demo） | ✅ 完成 | `_create_control_bar()` |
| 4 | Dashboard — 6 张统计卡片 | ✅ 完成 | `_make_stat_card()` × 6 |
| 5 | Dashboard — 最近告警表 | ✅ 完成 | `table_recent` |
| 6 | Dashboard — PPS/BPS 实时双线折线图 | ✅ 完成 | `_pps_series` + `_bps_series` |
| 7 | Dashboard — TOP 攻击来源 | ✅ 完成 | `text_top_ip` |
| 8 | Dashboard — 攻击趋势面积图 | ❌ 待实现 | 新增 `_attack_area_series` |
| 9 | Alerts — 告警表格 + 严重度/类别筛选 + JSON 导出 | ✅ 完成 | `table_alerts` + `cmb_severity/category` |
| 10 | Alerts — 告警详情弹窗（双击弹窗） | ❌ 待实现 | 新增 `AlertDetailDialog` 类 |
| 11 | Statistics — 告警严重度饼图 | ✅ 完成 | `_pie_chart` + `_pie_severity` |
| 12 | Statistics — 攻击类别柱状图 | ✅ 完成 | `_bar_chart` + `_bar_series` |
| 13 | Statistics — TOP 来源排行 | ✅ 完成 | （在 Dashboard 中） |
| 14 | Attack Chain — 攻击链可视化面板 | ❌ 待实现 | 新 Tab index=5, `_create_attack_chain_tab()` |
| 15 | 状态栏（PPS/Alerts/Uptime） | ✅ 完成 | `QStatusBar` |
| 16 | 实时威胁等级指示灯 | ❌ 待实现 | 状态栏新增 `threat_led` |
| 17 | Demo 模式（动态流量生成） | ✅ 完成 | `_on_demo()` + `traffic_generator.py` |
| 18 | PCAP 回放进度条 + 倍速 | ❌ 待实现 | `_on_replay_pcap()` 内新增 |
| 19 | 告警声音提醒 | ❌ 待实现 | `_on_alert_callback()` 内新增 |
| 20 | 威胁情报 GUI 展示 | ❌ 待实现 | 告警详情弹窗内 |

---

## 五、文件目录总览

```
NADS/
├── main.py                          # ✅ 主入口 (471行)
├── config.yaml                      # ✅ 全局配置
├── core/
│   ├── misuse_detector.py           # ✅ 误用检测 (919行, AC+正则+阈值)
│   ├── packet_capture.py            # ✅ 数据包捕获 (329行)
│   ├── protocol_parser.py           # ✅ 协议解析 (351行, 9种协议)
│   ├── tcp_reassembler.py           # ✅ TCP流重组 (328行, 严格seq排序)
│   ├── tls_detector.py              # ✅ TLS检测 (30KB, JA3/JA4+证书+C2)
│   ├── anomaly_detector.py          # ✅ 异常检测 (539行, 7种检测器)
│   ├── baseline_learner.py          # ✅ 基线学习 (406行)
│   └── alert_manager.py             # ✅ 告警管理 (380行)
├── gui/
│   ├── main_window.py               # ✅ GUI主体 (1168行, Apple风格)
│   └── theme.py                     # ✅ 主题系统 (401行)
├── signatures/ (10个YAML)           # ✅ 特征库
├── tools/ (12个工具脚本)             # ✅ 工具集
├── tests/ (4个测试文件)             # ✅ 测试
└── docs/ (6个文档)                   # ✅ 文档
```

**总代码量**: 核心 5292 行 + GUI 1569 行 + 工具 ~5000 行 + 测试 ~1000 行 ≈ **12000+ 行**
