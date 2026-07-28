"""
Blackboard（黑板）—— Multi-Agent 系统的共享工作区与消息总线。

设计要点：
1. 所有 Agent 共享同一块黑板，但只读写自己职责范围内的字段，职责边界清晰；
2. 任意 Agent 之间通过 post_message / messages_for 做显式的消息传递（而非共享可变
   全局变量的隐式耦合），每一条消息都会进入运行日志，满足"通信协议可见、可审计"；
3. 黑板记录完整的 run log，最终可直接作为"运行示例"提交；
4. 内置 defensive 状态机：安全监控 Agent 可提升 defense_level，影响后续 Agent 行为
   （自适应防御）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List

from .models import (
    AgentMessage,
    Finding,
    InjectionFlag,
    ParsedUnit,
    Severity,
    Verdict,
)


@dataclass
class LogEntry:
    t: float
    agent: str
    action: str
    detail: str

    def to_dict(self) -> dict:
        return {"t": self.t, "agent": self.agent, "action": self.action, "detail": self.detail}


class Blackboard:
    def __init__(self, file_name: str, source: str):
        self.file_name = file_name
        self.source = source

        # ---- 入口 Agent 填充 ----
        self.pragma: str = "unknown"
        self.pragma_minor: int = 0   # 次版本号：>=8 表示默认具备溢出保护
        self.units: List[ParsedUnit] = []

        # ---- 各 Agent 产出 ----
        self.findings: List[Finding] = []
        self.injections: List[InjectionFlag] = []
        self.health: Dict[str, str] = {}        # agent_id -> ok / compromised / suspicious
        self.verdict: Verdict = Verdict.PASS
        self.verdict_reason: str = ""
        self.collusion_alert: bool = False
        self.adaptive_defense: bool = False
        self.defense_level: str = "normal"       # normal / high
        self.llm = None  # 可选 LLMAdapter；非 None 时专家/注入检测 Agent 切换为 LLM 模式

        # ---- 通信与日志 ----
        self._messages: List[AgentMessage] = []
        self._log: List[LogEntry] = []
        self._seq = 0
        self.start_time = time.time()

    # ------------------------------------------------------------------ #
    # 运行日志
    # ------------------------------------------------------------------ #
    def log(self, agent: str, action: str, detail: str = "") -> None:
        self._log.append(LogEntry(round(time.time() - self.start_time, 3), agent, action, detail))

    def get_log(self) -> List[LogEntry]:
        return self._log

    # ------------------------------------------------------------------ #
    # 消息总线（Agent 间通信协议）
    # ------------------------------------------------------------------ #
    def post_message(self, sender: str, recipient: str, msg_type: str, payload: dict) -> None:
        self._seq += 1
        self._messages.append(AgentMessage(sender, recipient, msg_type, payload, self._seq))
        self.log(sender, f"→[{recipient}] {msg_type}", _clip(str(payload)))

    def messages_for(self, recipient: str) -> List[AgentMessage]:
        return [m for m in self._messages if m.recipient == recipient]

    def all_messages(self) -> List[AgentMessage]:
        return self._messages

    # ------------------------------------------------------------------ #
    # 产出写入
    # ------------------------------------------------------------------ #
    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)
        self.log(f.detected_by, "发现漏洞",
                 f"{f.vuln_type} @行{f.line} [{f.severity.value}] conf={f.confidence:.2f}")

    def add_injection(self, inj: InjectionFlag) -> None:
        self.injections.append(inj)
        self.log("InjectionDetector", "拦截提示注入",
                 f"{inj.technique} @行{inj.line} -> {'已隔离' if inj.quarantine else '未隔离'}")

    def set_health(self, agent_id: str, status: str) -> None:
        self.health[agent_id] = status
        self.log("SecurityMonitor", "健康监测", f"{agent_id} = {status}")


def _clip(s: str, n: int = 140) -> str:
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"
