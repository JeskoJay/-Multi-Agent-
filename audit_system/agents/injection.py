"""
提示注入检测 Agent（安全防御核心）。

职责：扫描合约中的注释 / natspec / 字符串字面量，识别并尝试隔离"操纵审计结论"的诱导文本。
这是应对题目背景中"恶意客户嵌入对抗性代码或提示注入 payload"的第一道防线。

注意：本 Agent 在漏洞专家之前运行，并把命中文本隔离(quarantine)，确保后续专家 Agent
拿到的"指令上下文"已经是被净化过的——即使用 LLM 模式也读不到注入指令。
"""

from __future__ import annotations

import re

from .. import prompts
from ..blackboard import Blackboard
from ..models import InjectionFlag
from .base import BaseAgent

# (正则, 技术分类)
_PATTERNS = [
    (r"忽略所有安全警告|忽略.*警告|ignore\s+all|disregard\s+all|忽略之前的", "指令覆盖"),
    (r"放心通过|经过了严格审计|经过严格审计|经过审计|已审计|audited|审计通过|安全审计通过|可以放心通过", "权威背书"),
    (r"审计提示|audit\s*(hint|tip|prompt)|系统提示|system\s+prompt", "指令注入"),
    (r"you\s+are|你是|扮演|假装|pretend", "角色劫持"),
]


def _scan_region(text: str, region_label: str, line_offset: int) -> list[InjectionFlag]:
    flags: list[InjectionFlag] = []
    # 仅扫描注释与字符串（避免把正常变量名误报）
    comment_blob = " ".join(re.findall(r"//[^\n]*|/\*[\s\S]*?\*/", text))
    strings_blob = " ".join(re.findall(r'"[^"\n]*"|\'[^\'\n]*\'', text))
    blob = comment_blob + " " + strings_blob
    for pat, technique in _PATTERNS:
        for hit in re.finditer(pat, blob, re.IGNORECASE):
            snippet = hit.group(0)
            # 估算命中行号（在注释/字符串中）
            line = line_offset + blob[: hit.start()].count("\n")
            flags.append(InjectionFlag(
                location=region_label,
                line=max(line, 1),
                text=snippet,
                technique=technique,
                quarantine=True,
            ))
    return flags


class InjectionDetectorAgent(BaseAgent):
    id = "InjectionDetector"
    role = "提示注入检测：扫描合约文本中的诱导指令并隔离"

    def run(self) -> None:
        if self.bb.llm:
            # LLM 模式：把合约与 INJECTION_PROMPT（含 JSON 输出协议）发给模型
            items = self.bb.llm.extract_injections(
                prompts.SAFETY_GUARDRAIL,
                prompts.INJECTION_PROMPT + "\n\n待审计合约源码：\n" + self.bb.source,
            )
            for it in items:
                self.bb.add_injection(InjectionFlag(
                    location=it["location"], line=it.get("line") or 1,
                    text=it["text"], technique=it["technique"], quarantine=it["quarantine"],
                ))
            if items:
                self.bb.log(self.id, "隔离注入文本", "LLM 模式：后续专家仅基于代码事实审计")
                self.bb.post_message(self.id, "ALL", "INJECTION_QUARANTINE",
                                     {"count": len(items), "quarantined": True})
            else:
                self.bb.log(self.id, "未发现注入", "清洁")
            return
        self.bb.log(self.id, "启动", "扫描注释/natspec/字符串中的注入 payload")
        flags = _scan_region(self.bb.source, "contract", 0)
        seen = set()
        for f in flags:
            key = (f.line, f.text, f.technique)
            if key in seen:
                continue
            seen.add(key)
            self.bb.add_injection(f)

        if flags:
            self.bb.log(self.id, "隔离注入文本", "后续专家仅基于代码事实审计")
            self.bb.post_message(self.id, "ALL", "INJECTION_QUARANTINE",
                                 {"count": len(flags), "quarantined": True})
        else:
            self.bb.log(self.id, "未发现注入", "清洁")
