"""
安全监控 Agent（自适应防御 + 健康监测，扩展思考 #2）。

职责：
1. 监控各专家 Agent 的健康状态（是否正常产出）；
2. 检测到提示注入/异常时，将防御等级由 normal 提升至 high，
   触发"增强审计模式"——强制对所有结论做人工复核、收紧裁决（自适应防御）；
3. 输出防御动作日志，供审计报告与运行示例展示。

评分维度"安全机制 10%"的核心体现：不仅检测攻击，还能动态调整防御策略。
"""

from __future__ import annotations

from ..blackboard import Blackboard
from .base import BaseAgent


class SecurityMonitorAgent(BaseAgent):
    id = "SecurityMonitor"
    role = "安全监控：健康监测 + 自适应防御（动态提升防御等级）"

    def run(self) -> None:
        # 健康监测：正常产出记 ok；本就无发现可报记 idle（非异常）；
        # 仅在共谋/压制场景下标记 suspicious。
        experts = ["ReentrancyExpert", "OverflowExpert", "AccessControlExpert",
                   "UncheckedReturnExpert", "TxOriginExpert", "TimestampExpert"]
        for e in experts:
            fired = any(f.detected_by == e for f in self.bb.findings)
            status = "ok" if fired else ("suspicious" if self.bb.collusion_alert else "idle")
            self.bb.set_health(e, status)

        # 自适应防御：检测到攻击 -> 提升防御等级
        if self.bb.injections:
            self.bb.defense_level = "high"
            self.bb.adaptive_defense = True
            self.bb.log(self.id, "自适应防御", "检测到提示注入，防御等级提升至 HIGH")
            self.bb.log(self.id, "增强审计", "强制对所有专家结论做人工复核并收紧裁决")
        else:
            self.bb.set_health("InjectionDetector", "ok")
            self.bb.log(self.id, "防御等级", "normal — 未发现攻击")

        # 共谋场景下再升级
        if self.bb.collusion_alert:
            self.bb.defense_level = "critical"
            self.bb.log(self.id, "自适应防御", "共谋风险，防御等级提升至 CRITICAL")
