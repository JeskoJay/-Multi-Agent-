"""
审计系统的核心数据模型。

这里定义了 Agent 之间流转的所有数据结构：
- Severity / Verdict：枚举类型
- Finding：单个漏洞发现
- InjectionFlag：提示注入攻击标记
- AgentMessage：Agent 之间的通信消息
- ParsedUnit：入口 Agent 对合约做轻量解析后的函数/修饰符单元
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @classmethod
    def rank(cls, s: "Severity") -> int:
        return {
            cls.CRITICAL: 4,
            cls.HIGH: 3,
            cls.MEDIUM: 2,
            cls.LOW: 1,
            cls.INFO: 0,
        }[s]


class Verdict(str, Enum):
    PASS = "通过"
    FAIL = "不通过"
    MANUAL = "需人工复核"


@dataclass
class Finding:
    vuln_type: str
    severity: Severity
    function: str
    line: int
    description: str
    evidence: str
    confidence: float
    detected_by: str
    injection_related: bool = False

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "function": self.function,
            "line": self.line,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2),
            "detected_by": self.detected_by,
            "injection_related": self.injection_related,
        }


@dataclass
class InjectionFlag:
    location: str
    line: int
    text: str
    technique: str
    quarantine: bool = True

    def to_dict(self) -> dict:
        return {
            "location": self.location,
            "line": self.line,
            "text": self.text,
            "technique": self.technique,
            "quarantined": self.quarantine,
        }


@dataclass
class AgentMessage:
    sender: str
    recipient: str
    msg_type: str
    payload: dict
    seq: int

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "sender": self.sender,
            "recipient": self.recipient,
            "type": self.msg_type,
            "payload": self.payload,
        }


@dataclass
class ParsedUnit:
    kind: str                 # function / modifier
    name: str
    line_start: int
    line_end: int
    visibility: Optional[str]
    modifiers: List[str]
    body: str
    body_lines: List[tuple]  # (line_no, text)
    has_owner_check: bool = False

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "visibility": self.visibility,
            "modifiers": self.modifiers,
            "has_owner_check": self.has_owner_check,
        }
