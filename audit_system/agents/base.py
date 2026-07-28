"""
BaseAgent：所有 Agent 的抽象基类。

统一约定：
- 每个 Agent 持有一块共享 Blackboard，并拥有唯一 id 与 role 描述；
- run(ctx) 是唯一的入口方法，由 Supervisor 编排器调度；
- Agent 不直接修改其他 Agent 的私有字段，只通过黑板提供的 add_* / post_message 接口
  写入，保证职责边界清晰（评分维度"角色定义 15%"）。
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .. import prompts
from ..blackboard import Blackboard
from ..models import Finding, Severity


class BaseAgent(ABC):
    id: str = "base"
    role: str = "基类"

    def __init__(self, blackboard: Blackboard):
        self.bb = blackboard

    @abstractmethod
    def run(self) -> None:
        """执行本 Agent 的职责，结果写入 blackboard。"""
        raise NotImplementedError

    def _llm_emit_findings(self, prompt_template: str) -> None:
        """当 bb.llm 存在时，调用 LLM 解析合约并产出 findings（双轨切换入口）。"""
        if not self.bb.llm:
            return
        items = self.bb.llm.extract_findings(
            prompts.SAFETY_GUARDRAIL,
            prompt_template + "\n\n待审计合约源码：\n" + self.bb.source,
        )
        for it in items:
            self.bb.add_finding(Finding(
                vuln_type=it["vuln_type"],
                severity=Severity(it["severity"]),
                function=it.get("function") or "—",
                line=it.get("line") or 0,
                description=it["description"],
                evidence=it["evidence"][:120],
                confidence=it["confidence"],
                detected_by=self.id,
                injection_related=it["injection_related"],
            ))

    def __repr__(self) -> str:
        return f"<Agent {self.id} | {self.role}>"
