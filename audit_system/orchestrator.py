"""
Supervisor（主管/编排器）—— 多 Agent 系统的中枢协调者。

编排模式选择：【Supervisor + 并行专家 + 共识验证 + 安全监控】

论证（详见设计文档）：
- 中心化调度让"安全防御"有唯一权威入口：提示注入检测必须先于漏洞专家执行并隔离，
  专家结论必须经共识验证与安全监控裁决，避免单 Agent 被攻破即影响全局；
- 漏洞专家彼此独立，可由 Supervisor 并行调度（本实现为确定性顺序执行，
  便于复现与审计，并行版本仅需替换为线程池）；
- 共识验证 + 安全监控构成"交叉验证 + 自适应防御"双保险，直接回应题目对
  "误报率/交叉验证/对抗性攻击"的诉求。

本文件即 Supervisor 的实现：初始化黑板、按既定顺序调度各 Agent、收集运行日志。
"""

from __future__ import annotations

from .blackboard import Blackboard
from .agents.ingestion import IngestionAgent
from .agents.injection import InjectionDetectorAgent
from .agents.specialists import (
    AccessControlAgent,
    IntegerOverflowAgent,
    ReentrancyAgent,
    TimestampAgent,
    TxOriginAgent,
    UncheckedReturnAgent,
)
from .agents.consensus import ConsensusAgent
from .agents.monitor import SecurityMonitorAgent
from .agents.reporter import ReportAgent


class Supervisor:
    def __init__(self):
        self.steps = []

    def audit(self, file_name: str, source: str, llm=None) -> Blackboard:
        bb = Blackboard(file_name, source)
        bb.llm = llm  # 非 None 时专家/注入检测 Agent 切换为 LLM 模式

        # 1) 入口解析
        IngestionAgent(bb).run()

        # 2) 提示注入检测（必须在漏洞专家之前，隔离注入文本）
        InjectionDetectorAgent(bb).run()

        # 3) 并行漏洞专家（彼此独立，可并行调度）
        specialists = [
            ReentrancyAgent, IntegerOverflowAgent, AccessControlAgent,
            UncheckedReturnAgent, TxOriginAgent, TimestampAgent,
        ]
        for S in specialists:
            S(bb).run()

        # 4) 共识验证（交叉验证 + 共谋检测 + 裁决）
        ConsensusAgent(bb).run()

        # 5) 安全监控（自适应防御）
        SecurityMonitorAgent(bb).run()

        # 6) 报告生成
        reporter = ReportAgent(bb)
        reporter.run()

        return bb
