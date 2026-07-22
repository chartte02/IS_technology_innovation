# NADS 演示 PCAP 文件说明与拓展建议

> **日期**: 2026-07-20 | **当前**: 9 个 PCAP 文件，覆盖人工构造 + 真实流量 + 学术数据集

---

## 一、现有 PCAP 文件清单

### 1.1 按生成方式分类

| 类别 | 文件数 | 总大小 | 总包数 |
|------|:--:|------|:--:|
| Scapy 人工构造 (demo_*) | 5 | ~3 KB | 23 |
| Scapy 人工构造 (synthetic/extended) | 2 | ~4 KB | 28 |
| 虚拟机真实抓包 | 1 | 176 KB | 837 |
| CIC-IDS-2017 学术数据集 | 1 | 20 MB | 17,244 |
| **合计** | **9** | **~20 MB** | **18,132** |

---

### 1.2 逐个详解

#### 🔧 demo_sqli.pcap — SQL 注入检测

| 属性 | 内容 |
|------|------|
| **生成方式** | Scapy 构造 `IP()/TCP()/Raw()` HTTP 请求包 |
| **包数** | 3 个 |
| **攻击内容** | `UNION SELECT user,password FROM users--`、`admin' OR '1'='1'--`、1 个正常包 |
| **目标端口** | 80 (HTTP) |
| **预期告警** | 4 条 (SQLI-001 UNION SELECT + SQLI-002 Tautology + 2 Suricata规则) |
| **代表什么** | **Web 应用层攻击**—攻击者通过在 URL 参数中注入 SQL 语句窃取数据库数据 |

---

#### 🔧 demo_xss.pcap — XSS 跨站脚本检测

| 属性 | 内容 |
|------|------|
| **生成方式** | Scapy 构造 HTTP 请求包 |
| **包数** | 3 个 |
| **攻击内容** | `<script>alert(1)</script>`、`<img src=x onerror=alert(document.cookie)>`、1 个正常包 |
| **目标端口** | 80 (HTTP) |
| **预期告警** | 8 条 (XSS-001 Script Tag + XSS-005 Event Handler + XSS-006 IMG Onerror + 5 Suricata规则) |
| **代表什么** | **Web 应用层攻击**—攻击者在评论区/搜索框注入恶意脚本，窃取用户 Cookie 或重定向到钓鱼页面 |

---

#### 🔧 demo_bruteforce.pcap — SSH 暴力破解检测

| 属性 | 内容 |
|------|------|
| **生成方式** | Scapy 构造 TCP 包（含 SSH banner + 登录失败消息） |
| **包数** | 8 个 |
| **攻击内容** | `SSH-2.0-OpenSSH` + `Failed password for root` × 8 次 |
| **目标端口** | 22 (SSH) |
| **预期告警** | **0 条**（原因：Scapy 构造的 TCP 包不含完整的 SSH 协议头，ProtocolParser 识别为 UNKNOWN → 误用检测跳过 SSH 规则。异常检测的 `_check_login_pattern` 可识别 "Failed password"，但 8 个包不足以触发 brute_force 阈值） |
| **代表什么** | **协议层攻击**—攻击者反复尝试 SSH 登录密码，试图猜解凭证 |

**⚠️ 已知问题**: 此 PCAP 在当前系统下检出率为 0。需要在演示时说明或改用真实 SSH 流量。

---

#### 🔧 demo_webattack.pcap — Web 攻击综合检测

| 属性 | 内容 |
|------|------|
| **生成方式** | Scapy 构造 HTTP 请求包 |
| **包数** | 4 个 |
| **攻击内容** | `../../../etc/passwd`（目录遍历）、`|cat /etc/passwd`（命令注入）、`php://filter/...`（文件包含）、`system('id')`（代码执行） |
| **目标端口** | 80 (HTTP) |
| **预期告警** | 10 条 (WEB-001 目录遍历 + WEB-002 敏感文件 + WEB-003 命令注入 + 7 Suricata规则) |
| **代表什么** | **Web 服务器漏洞利用**—攻击者利用文件包含漏洞读取系统敏感文件，利用命令注入执行系统命令 |

---

#### 🔧 demo_mixed.pcap — 多阶段攻击链演示 ⭐

| 属性 | 内容 |
|------|------|
| **生成方式** | Scapy 构造，同一个源 IP 发送多类攻击 |
| **包数** | 5 个 |
| **攻击内容** | Nikto 扫描器指纹 → 端口扫描 → SQL 注入 `DROP TABLE` → 后门 `eval($_POST)` |
| **目标端口** | 80, 22, 3306, 4444 |
| **预期告警** | 6 条 + **2 条攻击链** (scan → sql_injection → backdoor) |
| **代表什么** | **完整攻击生命周期**—攻击者先扫描侦察、发现漏洞后 SQL 注入利用、成功后安装后门维持持久化访问。这是演示攻击链可视化的最佳 PCAP |

---

#### 🔧 synthetic_attacks.pcap — 综合攻击样本

| 属性 | 内容 |
|------|------|
| **生成方式** | Scapy 构造（早期生成） |
| **包数** | 16 个 |
| **攻击内容** | SQL注入(UNION SELECT/注释绕过/堆叠查询) + XSS(Script/Event/IMG) + 目录遍历 + 文件包含 + SQLMap UA |
| **目标端口** | 80 (HTTP) |
| **预期告警** | 23 条 (sql_injection=6, web_attack=12, xss=5) |

---

#### 🔧 extended_attacks.pcap — 扩展攻击样本

| 属性 | 内容 |
|------|------|
| **生成方式** | `tests/generate_test_pcap.py` 自动生成 |
| **包数** | 12 个 |
| **攻击内容** | SSRF(Server-Side Request Forgery) + XXE(XML External Entity) + SSTI(Server-Side Template Injection) + WebShell(蚁剑/中国菜刀) + NoSQL注入 |
| **目标端口** | 80 (HTTP) |
| **预期告警** | 19 条 + **2 条攻击链** |

---

#### 🌐 kali_to_windows_scan.pcap — 真实网络扫描 ⭐

| 属性 | 内容 |
|------|------|
| **生成方式** | **VirtualBox 虚拟机真实抓包**—Kali 使用 Nmap 扫描 Windows 靶机 |
| **包数** | 837 个（TCP），298 个含 payload |
| **网络拓扑** | Kali (`192.168.71.128`) → Nmap 扫描 → Windows (`192.168.71.1`) |
| **协议分布** | UNKNOWN(135), TLS(78), HTTP(48), HTTPS(37) |
| **扫描端口** | 100+ 个不同端口（7070/443/8080/80/58940/...） |
| **预期告警** | 7 条 + 1 条攻击链 |
| **检测效果** | **误用检测**: Nmap SYN Scan 指纹识别 (SCAN-001) / **异常检测**: 端口扫描 100 个端口 |
| **代表什么** | **真实攻击场景**—这是最接近真实 IDS 部署环境的流量。答辩时重点展示"双引擎同时告警、互相印证" |

---

#### 📚 wednesday_subset.pcap — CIC-IDS-2017 学术数据集 ⭐⭐

| 属性 | 内容 |
|------|------|
| **生成方式** | **加拿大新不伦瑞克大学 CIC-IDS-2017 数据集** Wednesday 子集（学术界最常用的 IDS 评估基准数据集之一） |
| **文件大小** | 20 MB（完整数据集 80+ GB） |
| **包数** | 17,244 个 TCP 包 |
| **唯一 IP** | 36 个 |
| **协议分布** | HTTP(15,262), HTTPS(910), SSH(168), FTP(50), TLS(46), SMTP(46) |
| **标注攻击** | DoS/DDoS 攻击（Slowloris, Slowhttptest, Hulk, GoldenEye） |
| **NADS 检出** | **99 条去重告警** (DoS=50, scan=28, web_attack=21) + 2 条攻击链 |
| **告警类型** | `dos`, `high_frequency`, `horizontal_scan`, `port_scan`, `web_attack` |
| **代表什么** | **学术基准测试**—与国际标准数据集对比，客观评估检测能力。答辩时可说"在 CIC-IDS-2017 Wednesday DoS 子集上检出 99 条告警"。 |

---

## 二、覆盖矩阵

### 2.1 攻击类型覆盖

| 攻击类型 | 有对应的 PCAP | PCAP 名称 | 备注 |
|----------|:--:|------|------|
| SQL 注入 | ✅ | demo_sqli, synthetic, extended, demo_mixed | 6 种 SQLi 变体全部覆盖 |
| XSS 跨站脚本 | ✅ | demo_xss, synthetic | Script/Event/IMG/编码 全覆盖 |
| 目录遍历 | ✅ | demo_webattack, synthetic, extended | |
| 命令注入 (RCE) | ✅ | demo_webattack, extended | 含 Netcat 反弹 Shell |
| 文件包含 (LFI/RFI) | ✅ | demo_webattack, extended | |
| SSRF | ✅ | extended_attacks | |
| XXE | ✅ | extended_attacks | |
| SSTI | ✅ | extended_attacks | |
| WebShell | ✅ | extended_attacks | 蚁剑/中国菜刀 |
| NoSQL 注入 | ✅ | extended_attacks | |
| 暴力破解 (SSH) | ⚠️ | demo_bruteforce | PCAP 格式问题，检出率 0 |
| 端口扫描 | ✅ | kali_to_windows_scan, demo_mixed | 真实流量 + 人工构造 |
| 扫描器指纹 (Nikto/SQLMap) | ✅ | synthetic, extended, demo_mixed | |
| 后门/木马 C2 | ✅ | demo_mixed | |
| DoS/DDoS | ✅ | wednesday_subset | CIC-IDS-2017 学术标准数据集 |
| TLS 加密流量检测 | ❌ | 无 | **需要补充** |

### 2.2 演示场景覆盖

| 场景 | PCAP | 演示价值 |
|------|------|:--:|
| 单一攻击快速展示 | demo_sqli, demo_xss, demo_webattack | ⭐⭐⭐ |
| **多阶段攻击链** | **demo_mixed** | ⭐⭐⭐⭐⭐ |
| **真实网络流量** | **kali_to_windows_scan** | ⭐⭐⭐⭐⭐ |
| **学术数据集评估** | **wednesday_subset** | ⭐⭐⭐⭐⭐ |
| 双引擎互相印证 | kali_to_windows_scan | ⭐⭐⭐⭐⭐ |
| 误报率评估 | wednesday_subset | ⭐⭐⭐⭐ |

---

## 三、拓展建议

### 🥇 优先级1：补充 TLS 加密 C2 流量 PCAP（答辩核心）

**缺口**: 目前没有任何 PCAP 能演示 TLS JA3 指纹检测和 C2 Beacon 检测——这是 PDF 必做①和特色2的核心功能。

**方案**: 生成一个含已知恶意 JA3 指纹的 TLS ClientHello 测试 PCAP：

```python
# 1. 用 Scapy 构造含 TLS ClientHello 的包
# 2. ClientHello 参数模仿 Cobalt Strike 的 JA3 指纹 (37f463bf...)
# 3. 模拟固定间隔的心跳包（每 60 秒，CV < 0.05）
# 4. 目标：触发 TLSDetector 告警 + C2 Beacon 告警
```

**答辩价值**: "接下来演示加密流量检测——即使不解密 HTTPS，我们也能通过 TLS 握手阶段的 JA3 指纹识别出 Cobalt Strike C2 通信，并通过心跳时间间隔的变异系数发现规律 C2 信标。"

---

### 🥈 优先级2：修复/替换 demo_bruteforce.pcap

**缺口**: 当前 PCAP 因协议格式问题检出率为 0。

**方案A**: 重新构造符合 SSH 协议格式的登录失败包（包含完整 SSH banner → key exchange → auth failure 序列）。
**方案B**: 改用 HTTP 401 暴力破解（更简单，ProtocolParser 能正确识别 HTTP 协议）。

---

### 🥉 优先级3：合并 demo PCAP 为更大场景 PCAP

**现状**: demo_sqli (3包)、demo_xss (3包)、demo_webattack (4包) 各自独立，包数太少。

**方案**: 合并为一个 `demo_web_attacks.pcap`，含 20+ 包，混合 SQLi/XSS/WebAttack 三种攻击 + 正常流量。演示时可以一次回放展示三类 Web 攻击的检出能力。

---

### 4️⃣ 优先级4：优化异常检测动态阈值

**发现**: `wednesday_subset.pcap` 测试中，`_window_timer` 的 PPS 阈值从 10000 逐步降至 ~30，导致大量正常 Web 浏览被误报为"高频流量"。36 条 `high_frequency` 告警中有相当比例是误报。

**方案**: 
- 将 PPS 阈值下限设为合理值（如不低于 100），防止窗口重置时阈值降得过低
- 或在 `check_all()` 中增加"需连续 N 个窗口超阈值才告警"的过滤

---

### 5️⃣ 优先级5：增加正常流量 PCAP（误报率评估用）

**现状**: 所有 PCAP 都含攻击流量，没有纯正常流量的基准测试数据。

**方案**: 
- 用 Wireshark 录制 5 分钟正常网页浏览 + 邮件收发流量
- 用 NADS 回放 → 统计误报数 → 计算误报率
- 答辩时可以说"在 5 分钟正常流量中，误报率仅为 X%"

---

## 四、演示建议（结合当前 PCAP）

### 推荐演示顺序（按 PCAP）

```
1. demo_sqli.pcap        (30秒)  快速展示 SQL 注入检出
2. demo_webattack.pcap   (30秒)  展示 Web 攻击多类型检出
3. demo_mixed.pcap       (60秒)  ⭐ 展示攻击链可视化（核心亮点）
4. wednesday_subset.pcap (60秒)  ⭐ 展示学术数据集评估结果（17k包→99告警）
5. kali_to_windows_scan  (60秒)  ⭐ 展示真实流量双引擎检测（答辩核心）
6. [Demo模式]            (30秒)  展示实时检测能力
```

**演示时不需要逐个 PCAP 讲解攻击原理**——重点放在第 3、4、5 步的高价值展示上。前两步快速过，目的是让老师看到"系统能检出多种攻击"。第 3 步展示特色功能（攻击链可视化），第 4 步展示学术严谨性（国际标准数据集评估），第 5 步展示真实场景能力（真实网络流量双引擎检测）。

---

> **结论**: 当前 9 个 PCAP 已覆盖 15 种攻击类型，演示价值较高。核心缺口是 **TLS 加密 C2 流量 PCAP**——这是 PDF 必做①的演示关键，建议优先补充。wednesday_subset.pcap（CIC-IDS-2017）是意外惊喜，答辩时可作为学术严谨性的有力证明。
