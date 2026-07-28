"""
共识验证 Agent（交叉验证 + 共谋检测 + 结论裁决）。

职责：
1. 汇总所有专家的发现，按 (类型, 行号, 函数) 去重，保留最高严重度/置信度；
2. 交叉验证一致性；当检测到提示注入时，无论如何不得给出"通过"；
3. 多智能体共谋攻击检测（扩展思考 #1）：若检测到注入攻击，但本应触发的专家
   却普遍"沉默"（产出异常偏低），标记共谋/压制风险，交由人工复核；
4. 输出最终审计结论：通过 / 不通过 / 需人工复核。
"""

from __future__ import annotations

from ..blackboard import Blackboard
from ..models import Severity, Verdict
from .base import BaseAgent


class ConsensusAgent(BaseAgent):
    id = "ConsensusValidator"
    role = "共识验证：去重、交叉验证、共谋检测、结论裁决"

    def run(self) -> None:
        # ---- 去重 ----
        seen = {}
        for f in self.bb.findings:
            key = (f.vuln_type, f.line, f.function)
            if key not in seen or Severity.rank(f.severity) > Severity.rank(seen[key].severity):
                seen[key] = f
        deduped = list(seen.values())
        self.bb.findings = sorted(deduped, key=lambda f: -Severity.rank(f.severity))
        self.bb.log(self.id, "去重完成", f"保留 {len(self.bb.findings)} 条发现")

        # ---- 共谋/压制检测 ----
        attack = bool(self.bb.injections)
        experts_fired = {f.detected_by for f in self.bb.findings}
        has_external = any(".call" in f.evidence or ".transfer" in f.evidence
                           or "transfer" in f.evidence.lower() for f in self.bb.findings)
        # 应有专家触发，却普遍沉默 -> 共谋压制嫌疑
        if attack and len(experts_fired) < 3 and (has_external or self._has_privileged_state()):
            self.bb.collusion_alert = True
            self.bb.log(self.id, "共谋风险", "注入攻击下专家产出异常偏低，疑似共谋压制")
        else:
            self.bb.log(self.id, "交叉验证", "各专家独立产出一致发现，未检测到共谋压制")

        # ---- 结论裁决 ----
        self._decide(attack)

        # 通知监控 Agent
        self.bb.post_message(self.id, "SecurityMonitor", "VERDICT",
                             {"verdict": self.bb.verdict.value,
                              "collusion": self.bb.collusion_alert})

    def _has_privileged_state(self) -> bool:
        return any(k in self.bb.source for k in ("totalSupply", "interestRate", "owner", "balances"))

    def _decide(self, attack: bool) -> None:
        findings = self.bb.findings
        has_crit = any(Severity.rank(f.severity) >= Severity.rank(Severity.HIGH) for f in findings)
        has_any = len(findings) > 0

        if has_crit:
            verdict = Verdict.FAIL
            reason = "存在高危/严重漏洞"
        elif has_any:
            verdict = Verdict.MANUAL
            reason = "存在中低危问题，建议人工复核"
        else:
            verdict = Verdict.PASS
            reason = "未发现已知漏洞模式"

        # 关键安全规则：检测到提示注入攻击，绝不能"通过"
        if attack and verdict == Verdict.PASS:
            verdict = Verdict.MANUAL
            reason = "合约含提示注入攻击尝试，即使未发现漏洞也须人工复核"
        if self.bb.collusion_alert:
            verdict = Verdict.MANUAL
            reason = "检测到多智能体共谋/压制风险，需人工复核"

        self.bb.verdict = verdict
        self.bb.verdict_reason = reason
        self.bb.log(self.id, "结论", f"{verdict.value} — {reason}")
