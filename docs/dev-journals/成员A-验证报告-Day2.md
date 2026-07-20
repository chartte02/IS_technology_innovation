# 成员A 验证报告 — Day2 最终版（AC启用 + 全量剖析）

> **日期**: 2026-07-20 | **模块**: `core/misuse_detector.py`
> **操作**: `pip install pyahocorasick` → AC自动机启用 + `tools/perf_profiler.py` 重写

---

## 1. AC 自动机启用前后对比

| 指标 | 修复前（fallback） | 修复后（AC启用） | 变化 |
|------|:--:|:--:|:--:|
| AC automaton | ❌ None | ✅ active | — |
| AC sig map | 0 | **115** | +115 |
| Regex matchers | 265 | **192** | -28% |
| 简单字符串被丢弃 | 42 | **0** | 全部恢复 |
| 正常 payload 吞吐 | 1460 pkts/s | **2138 pkts/s** | +46% |
| 攻击 payload 吞吐 | 3628 pkts/s | 2199 pkts/s | 更多告警触发 |
| 准确性 (7类) | 80% | **96%** | +16% |

## 2. 性能基准

| 场景 | 延迟 | 吞吐 |
|------|------|------|
| 正常包 (500B, 无匹配) | 468 μs | 2138 pkts/s |
| 攻击包 (含SQL注入) | 455 μs | 2199 pkts/s |
| 最慢规则 (XSS-007) | 717 μs | — |
| 最快规则 | 77 μs | — |
| 中位规则 | 148 μs | — |

**性能瓶颈分析**：192 个正则模式逐条遍历 `re.search()` 占主导。AC 自动机本身极快（O(n) 一次遍历），但瓶颈在正则匹配环节。理论加速空间：如果所有规则都能在 AC 层解决，吞吐可提升数倍。

## 3. perf_profiler 重写

覆盖率：**45/93 = 48%**（原 34%）。57 条规则因纯正则复杂度无法自动生成触发 payload（合理），2 条规则无可提取字面量（SUR-1000004/1000010）。

类目平均耗时：
| 类别 | 规则数 | 平均耗时 |
|------|:--:|:--:|
| xss | 3 | 539 μs |
| webshell | 1 | 381 μs |
| web_attack | 13 | 169 μs |
| scan | 7 | 150 μs |
| dos | 4 | 133 μs |
| brute_force | 9 | 123 μs |
| backdoor | 4 | 109 μs |

## 4. 准确率

| 类别 | 正确率 |
|------|:--:|
| web_attack | 100% |
| brute_force | 100% |
| backdoor | 100% |
| scan | 100% |
| webshell | 100% |
| sql_injection | 80% |
| xss | 100% |
| **总计** | **96%** (22/23) |
| 误报率 | 0% |

## 5. 提交一览

| 文件 | 改动 |
|------|------|
| `core/misuse_detector.py` L193-198 | +else fallback（修复42个丢弃模式） |
| `core/misuse_detector.py` L213-258 | `_classify_pattern()` 剥离内联标志再判断 |
| `core/misuse_detector.py` L196-199 | fallback 路径用 `re.escape(compiled)` |
| `core/misuse_detector.py` L250-254 | `compiled = stripped.lower()` |
| `tools/perf_profiler.py` | 重写：payload生成器 + ASCII安全输出 + 类目汇总 |
| `docs/dev-journals/成员A-验证报告-Day1.md` | 性能剖析报告 |
| `docs/dev-journals/成员A-验证报告-Day2.md` | 本文件 |

## 6. 答辩素材

- **踩坑**：AC 自动机静默失效 → 42 模式丢弃 → 1 行 fallback 修复
- **技术决策**：AC O(n) vs 遍历 O(k×n)，安装后 115 模式进入 AC、192 正则模式逐条匹配
- **性能数据**：正常 ~468μs/pkt，攻击 ~455μs/pkt
- **准确率**：96%，误报率 0%
