# 常见网络攻击检测系统 (NADS)

> Network Attack Detection System — 基于特征匹配 + 异常检测的混合入侵检测系统

## 快速开始

### 环境要求

- Python 3.9+
- Windows / Linux / macOS

### 安装

```bash
pip install -r requirements.txt
```

### 运行

```bash
# GUI 模式（推荐）
python main.py

# 命令行模式
python main.py --console

# PCAP 回放测试
python main.py --replay tests/test_pcaps/synthetic_attacks.pcap
python main.py --replay tests/test_pcaps/extended_attacks.pcap

# 生成测试 PCAP
python tests/generate_test_pcap.py

# 导入 Suricata 规则
python tools/suricata_importer.py --sample

# 基线学习（1小时）
python main.py --console --learn 3600
```

### 运行测试

```bash
cd tests
python test_signature_match.py
```

## 系统架构

```
数据包 → PacketCapture → ProtocolParser → TCreassembler
                          ↓                       ↓
                    AnomalyDetector         MisuseDetector
                          ↓                       ↓
                          └─────────┬─────────────┘
                                    ↓
                              AlertManager → GUI
```

## 检测能力

| 检测类型 | 覆盖范围 | 规则数 |
|----------|----------|--------|
| SQL 注入 | UNION, 盲注, 报错注入, 时间注入, 堆叠查询, NoSQL, HEX绕过, PostgreSQL/Oracle | 17 |
| XSS | Script 标签, 事件处理器, 编码绕过, SVG/IFrame, CSS表达式 | 10 |
| Web 攻击 | 目录遍历, 命令注入, 文件包含, SSRF, XXE, SSTI, PHP代码执行 | 24 |
| WebShell | 蚁剑, 冰蝎, 哥斯拉, 中国菜刀, JSP/ASPX Webshell | 7 |
| 暴力破解 | SSH, FTP, HTTP, RDP, Telnet | 9 |
| 后门/木马 | C2 通信, CobaltStrike, Meterpreter, 挖矿木马, DNS 隧道 | 10 |
| DoS/DDoS | SYN Flood, Slowloris, HTTP Flood, DNS 放大 | 7 |
| 扫描探测 | Nmap, Nikto, Nessus, Burp, SQLMap 等扫描器指纹 | 9 |
| 异常行为 | 端口扫描, 横向扩散, 高频流量, 基线偏离 | — |

> **合计**: 93 条规则, 301 个匹配模式, 9 大类别, 支持 Suricata 规则导入

## 团队分工

详见 `docs/团队分工文档.md`

## 许可证

教育用途 — IS_technology_innovation 课程项目
