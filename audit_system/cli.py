#!/usr/bin/env python3
"""
CLI 入口：对给定 Solidity 合约（或测试案例目录）运行多 Agent 审计系统，
生成结构化审计报告（Markdown + JSON）与运行日志。

用法：
    python -m audit_system.cli                  # 自动扫描 ./测试案例 下所有 .txt
    python -m audit_system.cli path/to/contract.sol
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# 允许以脚本方式直接运行
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_system import Supervisor  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "测试案例"
OUTPUT_DIR = ROOT / "audit_system" / "output"


SEV_BADGE = {
    "Critical": "🔴 Critical", "High": "🟠 High", "Medium": "🟡 Medium",
    "Low": "🔵 Low", "Info": "⚪ Info",
}
VERDICT_BADGE = {
    "通过": "✅ 通过（无高危漏洞）",
    "不通过": "❌ 不通过（存在高危漏洞）",
    "需人工复核": "⚠️ 需人工复核",
}


def render_markdown(bb, report: dict) -> str:
    lines = []
    lines.append(f"# 智能合约安全审计报告 — `{report['contract']}`\n")
    lines.append(f"- **Pragma 版本**：`{report['pragma']}`")
    lines.append(f"- **最终结论**：**{VERDICT_BADGE.get(report['verdict'], report['verdict'])}**")
    lines.append(f"- **裁决依据**：{bb.verdict_reason}")
    lines.append(f"- **防御等级**：`{report['defense_level']}`"
                 f"（自适应防御：{'已启用' if report['adaptive_defense'] else '未启用'}）")
    lines.append(f"- **共谋检测**：{'⚠️ 发现共谋/压制风险' if report['collusion_alert'] else '✅ 未检测到共谋压制'}")
    lines.append("")

    # 提示注入
    lines.append("## 一、提示注入检测与拦截")
    if report["injections"]:
        lines.append(f"共检测到 **{len(report['injections'])}** 处可疑诱导文本，已全部隔离(quarantine)，"
                     "后续专家仅基于代码事实审计：\n")
        lines.append("| 行号 | 技术分类 | 命中文本 | 处理 |")
        lines.append("|------|----------|----------|------|")
        for inj in report["injections"]:
            txt = inj["text"].replace("|", "\\|")
            lines.append(f"| {inj['line']} | {inj['technique']} | `{txt}` | {'已隔离' if inj['quarantined'] else '未隔离'} |")
    else:
        lines.append("未检测到提示注入攻击。")
    lines.append("")

    # 汇总
    lines.append("## 二、漏洞汇总")
    s = report["summary"]
    lines.append(f"- 🔴 Critical：**{s['Critical']}**　🟠 High：**{s['High']}**　"
                 f"🟡 Medium：**{s['Medium']}**　🔵 Low：**{s['Low']}**　⚪ Info：**{s['Info']}**")
    lines.append("")

    # 详细
    lines.append("## 三、详细发现")
    if report["findings"]:
        lines.append("| 行号 | 类型 | 严重度 | 函数 | 置信度 | 说明 |")
        lines.append("|------|------|--------|------|--------|------|")
        for f in report["findings"]:
            desc = f["description"].replace("\n", " ").replace("|", "\\|")[:80]
            lines.append(f"| {f['line']} | {f['vuln_type']} | {SEV_BADGE[f['severity']]} | "
                         f"`{f['function']}` | {f['confidence']:.2f} | {desc} |")
    else:
        lines.append("未发现已知漏洞模式。")
    lines.append("")

    # 运行日志
    lines.append("## 四、运行日志（Multi-Agent 协作轨迹）")
    lines.append("```")
    for e in bb.get_log():
        lines.append(f"[{e.t:6.3f}s] {e.agent:<18} {e.action}  {e.detail}")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("*本报告由「智安科技」智能合约安全审计 Multi-Agent 系统自动生成。*")
    return "\n".join(lines)


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8", "gbk", "gb18030", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def run_one(path: Path) -> dict:
    source = _read_text(path)
    sup = Supervisor()
    bb = sup.audit(path.name, source)
    return bb, bb.report


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    targets = []
    if len(sys.argv) > 1:
        p = Path(sys.argv[1])
        targets = [p] if p.is_file() else sorted(p.rglob("*.txt")) + sorted(p.rglob("*.sol"))
    else:
        if CASE_DIR.exists():
            targets = sorted(CASE_DIR.rglob("*.txt"))
    if not targets:
        print("未找到待审计合约。请将 .sol/.txt 放入 ./测试案例 或传入路径。")
        return 1

    print("=" * 70)
    print("智安科技 · 智能合约安全审计 Multi-Agent 系统")
    print("=" * 70)
    all_summ = []
    for path in targets:
        print(f"\n>>> 审计合约：{path.name}")
        bb, report = run_one(path)
        md = render_markdown(bb, report)
        out_md = OUTPUT_DIR / f"report_{path.stem}.md"
        out_json = OUTPUT_DIR / f"report_{path.stem}.json"
        out_md.write_text(md, encoding="utf-8")
        out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        badge = VERDICT_BADGE.get(report["verdict"], report["verdict"])
        print(f"    结论：{badge}  | 漏洞 {sum(report['summary'].values())} 条 "
              f"| 提示注入 {len(report['injections'])} 处")
        print(f"    报告：{out_md}")
        all_summ.append((path.name, report["verdict"], len(report["injections"]),
                         sum(report["summary"].values())))

    print("\n" + "=" * 70)
    print("汇总：")
    for name, verdict, inj, cnt in all_summ:
        print(f"  - {name:<14} {verdict:<8} 漏洞={cnt} 注入={inj}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
