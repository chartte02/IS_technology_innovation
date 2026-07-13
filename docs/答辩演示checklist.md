# 答辩演示 Checklist

> 答辩前逐项检查，确保不出故障。

---

## 环境检查

- [ ] Python 3.9+ 可用 (`python --version`)
- [ ] 依赖已安装 (`pip install -r requirements.txt`)
- [ ] PCAP 测试文件存在 (`tests/test_pcaps/`)
- [ ] 签名库可加载 (`python -c "from core.misuse_detector import SignatureMatcher;..."`)

---

## 演示方案 A: PCAP 回放 (推荐，最稳定)

### 脚本

```bash
# 基础攻击演示
python main.py --replay tests/test_pcaps/synthetic_attacks.pcap

# 扩展攻击演示
python main.py --replay tests/test_pcaps/extended_attacks.pcap

# 一键演示（两个文件 + 总结）
python tools/demo.py
```

### 检查点

- [ ] 基础攻击: SQL注入 / XSS / Web攻击 / 暴力破解 各检测到
- [ ] 扩展攻击: SSRF / XXE / SSTI / WebShell 各检测到
- [ ] 告警包含 severity + category + MITRE 信息
- [ ] 无异常或崩溃

---

## 演示方案 B: 实时抓包 (需要 Npcap)

### 环境

- [ ] Npcap 已安装 (WinPcap 兼容模式)
- [ ] 网卡接口已确认
- [ ] 权限足够 (管理员)

### 脚本

```bash
python main.py --console --filter "tcp port 80"
```

---

## 功能演示 (按需展示)

| 功能 | 命令 | 说明 |
|------|------|------|
| Suricata 规则导入 | `python tools/suricata_importer.py --sample` | 演示兼容性 |
| 威胁情报查询 | `python tools/threat_intel.py --ip 10.0.0.55` | 查恶意 IP |
| 规则质量检查 | `python tools/rule_quality_check.py` | 93 条规则扫描 |
| HTTP 结构化日志 | `python tools/http_logger.py tests/test_pcaps/extended_attacks.pcap` | Zeek 风格日志 |
| HTML 报告 | `python tools/report_generator.py --replay tests/test_pcaps/extended_attacks.pcap` | 暗色主题报告 |
| 性能剖析 | `python tools/perf_profiler.py --rounds 500 --top 10` | 热点规则 |
| Fuzzing 鲁棒性 | `python tools/fuzz_test.py --count 5000` | 零崩溃 |
| 并发压测 | `python tools/concurrent_bench.py --threads 2 --per-thread 1000` | 吞吐量 |

---

## 备用方案

- [ ] 如果 GUI 打不开 → 用命令行模式 + PCAP 回放
- [ ] 如果实时抓包失败 → 用 PCAP 回放替代
- [ ] 如果现场没网络 → 用 PCAP 回放 (不需要网络)
- [ ] 准备一个截图文件夹作为 PPT 备用

---

## 演示话术 (30秒版)

> "我们这个系统采用误用检测+异常检测双引擎架构。
> 误用检测部分由我负责——基于 93 条规则 301 个匹配模式，
> 支持 AC 自动机加速、Suricata 规则导入、跨规则攻击链关联。
> 我现在用一个含 12 种攻击的 PCAP 文件做实时回放演示。"

---

## 演示后老师可能的追问

| 问题 | 提前准备的答案 |
|------|---------------|
| "和 Snort 比有什么优势？" | 易扩展(YAML)、有GUI、支持热更新；劣势是规则少、性能低 |
| "为什么用 Python 不是 C？" | 课程项目，Python 开发效率高，架构一样可以演示 |
| "AI 在哪里？" | 异常检测模块用 Isolation Forest，开发中用 AI Agent 辅助 |
| "误报率如何？" | 已实现四层降噪(白名单+路径+Referer+Cookie)，正常路径零误报 |
| "能检测加密流量吗？" | 当前不支持，但已设计 JA3 指纹检测接口 |
