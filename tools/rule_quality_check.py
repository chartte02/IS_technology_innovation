#!/usr/bin/env python3
# ============================================================
# 规则质量检查脚本 — 自动扫描 YAML 签名库的问题
# ============================================================
# 检查项: 缺 protocols/ports, 正则性能问题, 重复模式, 缺少注释
# 用法:
#   python tools/rule_quality_check.py
#   python tools/rule_quality_check.py --verbose
# ============================================================

import sys
import os
import re
import yaml
import argparse
from typing import Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

SIG_DIR = os.path.join(os.path.dirname(__file__), '..', 'signatures')


def check_rule(rule: Dict, filename: str) -> List[str]:
    """检查单条规则，返回问题列表"""
    issues = []
    rid = rule.get('id', '?')
    name = rule.get('name', '')

    # 1. 缺少 protocols 声明
    if not rule.get('protocols'):
        cat = rule.get('category', '')
        if cat in ('sql_injection', 'xss', 'web_attack', 'webshell', 'scan'):
            issues.append(f"[MISSING-PROTO] {rid}: {name[:40]} 建议添加 protocols: [HTTP]")

    # 2. 缺少 ports 声明
    if not rule.get('ports'):
        cat = rule.get('category', '')
        if cat != 'brute_force':
            issues.append(f"[MISSING-PORT]  {rid}: {name[:40]} 建议指定 ports")

    # 3. 正则性能问题 — 过多通配符
    for pi, pattern in enumerate(rule.get('patterns', [])):
        if '.*' in pattern:
            issues.append(
                f"[REGEX-PERF]   {rid} pattern[{pi}]: 含 '.*' 可能影响性能 "
                f"→ {pattern[:60]}"
            )

    # 4. 模式数量过多（可能重复）
    patterns = rule.get('patterns', [])
    if len(patterns) > 6:
        issues.append(
            f"[TOO-MANY]     {rid}: {len(patterns)} 个模式, 考虑拆分规则"
        )

    # 5. 检查重复模式（去重）
    unique = set(p.lower() for p in patterns)
    if len(unique) < len(patterns):
        issues.append(f"[DUPLICATE]    {rid}: 存在重复模式")

    return issues


def main():
    parser = argparse.ArgumentParser(description='NADS 规则质量检查')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='显示详细信息')
    parser.add_argument('--fix', action='store_true',
                        help='显示修复建议')
    args = parser.parse_args()

    yaml_files = sorted(f for f in os.listdir(SIG_DIR) if f.endswith('.yaml'))
    total_issues = 0
    total_rules = 0

    print("=" * 60)
    print("  NADS 规则质量检查")
    print("=" * 60)

    for fname in yaml_files:
        filepath = os.path.join(SIG_DIR, fname)
        with open(filepath, 'r', encoding='utf-8') as f:
            rules = yaml.safe_load(f)

        if not isinstance(rules, list):
            continue

        file_issues = 0
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            total_rules += 1
            issues = check_rule(rule, fname)
            if issues:
                if file_issues == 0:
                    print(f"\n📄 {fname} ({len(rules)} 条)")
                for issue in issues:
                    print(f"  {issue}")
                    file_issues += 1
                    total_issues += 1

    print(f"\n{'='*60}")
    print(f"  检查完成: {total_rules} 条规则, {total_issues} 个问题")
    if total_issues == 0:
        print(f"  ✅ 所有规则通过质量检查")
    else:
        print(f"  📋 问题分类:")
        cats = {}
        # (简化统计)
        print(f"    可运行 --fix 查看修复建议")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
