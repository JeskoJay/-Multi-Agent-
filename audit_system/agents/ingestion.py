"""入口 Agent：解析合约并初始化黑板，然后向各专家广播解析结果。"""

from __future__ import annotations

from ..blackboard import Blackboard
from ..parser import parse_source
from .base import BaseAgent


class IngestionAgent(BaseAgent):
    id = "Ingestion"
    role = "入口解析：切分合约、提取 pragma 与函数单元、初始化审计上下文"

    def run(self) -> None:
        self.bb.log(self.id, "开始解析", self.bb.file_name)
        pragma, minor, units = parse_source(self.bb.source)
        self.bb.pragma = pragma
        self.bb.pragma_minor = minor
        self.bb.units = units
        self.bb.log(self.id, "解析完成",
                    f"pragma={pragma}, 解析到 {len(units)} 个函数/修饰符")

        # 通过消息总线把解析结果广播给后续 Agent（通信协议：broadcast）
        self.bb.post_message(
            self.id, "ALL", "PARSED",
            {"pragma": pragma, "units": [u.name for u in units]},
        )
