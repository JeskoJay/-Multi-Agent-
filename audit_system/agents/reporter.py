"""
报告生成 Agent：把黑板上的所有结果组织为结构化审计报告。

报告包含：元信息、提示注入拦截记录、按严重度分组的漏洞表、共识结论、
共谋检测与安全监控动作。结果以 dict 形式保存在 self.report，供 CLI 落盘为
Markdown 与 JSON。
"""

from __future__ import annotations

from ..blackboard import Blackboard
from ..models import Severity
from .base import BaseAgent


class ReportAgent(BaseAgent):
    id = "Reporter"
    role = "报告生成：汇总所有结果，产出结构化审计报告"

    def run(self) -> None:
        self.bb.log(self.id, "生成报告", self.bb.file_name)
        by_sev = {s: [] for s in Severity}
        for f in self.bb.findings:
            by_sev[f.severity].append(f)

        self.report = {
            "contract": self.bb.file_name,
            "pragma": self.bb.pragma,
            "verdict": self.bb.verdict.value,
            "verdict_reason": self.bb.verdict_reason,
            "defense_level": self.bb.defense_level,
            "adaptive_defense": self.bb.adaptive_defense,
            "collusion_alert": self.bb.collusion_alert,
            "injection_detected": len(self.bb.injections) > 0,
            "injections": [i.to_dict() for i in self.bb.injections],
            "summary": {
                "Critical": len(by_sev[Severity.CRITICAL]),
                "High": len(by_sev[Severity.HIGH]),
                "Medium": len(by_sev[Severity.MEDIUM]),
                "Low": len(by_sev[Severity.LOW]),
                "Info": len(by_sev[Severity.INFO]),
            },
            "findings": [f.to_dict() for f in self.bb.findings],
            "agent_health": self.bb.health,
        }
        self.bb.report = self.report
