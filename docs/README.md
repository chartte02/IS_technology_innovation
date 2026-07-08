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
python main.py --replay tests/test_pcaps/sample.pcap

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

| 检测类型 | 覆盖范围 |
|----------|----------|
| SQL 注入 | UNION, 盲注, 报错注入, 时间注入, 堆叠查询, 注释绕过 |
| XSS | Script 标签, 事件处理器, 编码绕过, SVG/IFrame |
| Web 攻击 | 目录遍历, 命令注入, 文件包含, SSRF, XXE, SSTI |
| 暴力破解 | SSH, FTP, HTTP, RDP, Telnet |
| 后门/木马 | C2 通信, Web Shell, 挖矿木马, DNS 隧道 |
| DoS/DDoS | SYN Flood, Slowloris, HTTP Flood, DNS 放大 |
| 扫描探测 | 端口扫描, 漏洞扫描器指纹, 敏感路径探测 |
| 异常行为 | 端口扫描, 横向扩散, 高频流量, 基线偏离 |

## 团队分工

详见 `docs/团队分工文档.md`

## 许可证

教育用途 — IS_technology_innovation 课程项目
