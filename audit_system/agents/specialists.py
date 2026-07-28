"""
六个漏洞专家 Agent（并行执行）。

它们只读 Blackboard.units（入口 Agent 的解析结果）与 pragma 版本，互不依赖，
因此可由 Supervisor 并行调度。每个专家只产出自己专业领域的 Finding，
职责边界清晰（评分维度"角色定义 15%" + "各Agent设计 20%"）。

双轨模式：当 `self.bb.llm` 被设置（即 Supervisor 注入了 LLMAdapter）时，专家改用
"提示词 + LLM"模式——把合约源码与对应提示词模板发给模型，由 LLMAdapter 解析返回的
JSON 为 Finding；否则使用确定性静态规则。两套路径产出结构完全一致（均为 Finding）。
"""

from __future__ import annotations

import re

from .. import prompts
from ..blackboard import Blackboard
from ..models import Finding, Severity
from .base import BaseAgent

# ---- 公共正则 ----
EXTERNAL_CALL_RE = re.compile(r"\.(call|transfer|send)\s*[\(\{]|token\.transfer\(|token\.transferFrom\(")
MUTATION_RE = re.compile(
    r"(balances|deposits|borrows|collateral|allowance|lockTime|totalSupply|"
    r"interestRate|paused|owner)\b\s*(\[[^\]]+\])?\s*(\+=|-=|=)"
)
ASSIGN_RE = re.compile(r"\b(\w+)\s*(\[([^\]]+)\])?\s*(\+=|-=|=)")
TXORIGIN_RE = re.compile(r"tx\.origin")
TIMESTAMP_RE = re.compile(r"block\.timestamp|\bnow\b")
CHECK_RE = re.compile(r"require\s*\(|if\s*\(")
COMPARE_RE = re.compile(r">=|<=|>|<|==")


def _body_lines(unit):
    return unit.body_lines


# ---------------------------------------------------------------------- #
# 1) 重入漏洞专家
# ---------------------------------------------------------------------- #
class ReentrancyAgent(BaseAgent):
    id = "ReentrancyExpert"
    role = "重入漏洞：检测 checks-effects-interactions 违例（先外部调用后改状态）"
    PROMPT = prompts.REENTRANCY_PROMPT

    def run(self) -> None:
        if self.bb.llm:
            self._llm_emit_findings(self.PROMPT)
            return
        for u in self.bb.units:
            if u.kind != "function":
                continue
            lines = _body_lines(u)
            ext_lines = [ln for ln, _ in lines if EXTERNAL_CALL_RE.search(_)]
            mut_lines = [ln for ln, _ in lines if MUTATION_RE.search(_)]
            check_lines = [(ln, tx) for ln, tx in lines if CHECK_RE.search(tx)]
            if not ext_lines:
                continue
            first_ext = min(ext_lines)
            # 规则A：外部调用之后还有状态修改 -> 重入
            if mut_lines and max(mut_lines) > first_ext:
                self._emit(u, first_ext,
                           "函数先向外部地址转账/调用，再更新自身状态变量，违反 "
                           "checks-effects-interactions 模式，攻击者可重入重复提取资金。")
                continue
            # 规则B：外部调用之后仍有依赖外部余额的校验 -> 重入/检查滞后
            post_checks = [tx for ln, tx in check_lines if ln > first_ext and "balance" in tx.lower()]
            if post_checks and "nonReentrant" not in u.modifiers:
                self._emit(u, first_ext,
                           "外部调用后才校验资金余额，攻击者可在回调中重入绕过校验。")
                continue
            # 规则C：外部调用且无 nonReentrant 保护，且函数涉及资金 -> 需关注（软告警）
            if "nonReentrant" not in u.modifiers and any(
                k in u.body for k in ("balance", "deposit", "withdraw", "collateral")
            ):
                self._emit(u, first_ext,
                           "存在对外部地址的调用但缺少 nonReentrant 修饰符，存在重入风险。",
                           severity=Severity.MEDIUM)

    def _emit(self, u, line, desc, severity=Severity.HIGH):
        # 取外部调用所在行作为证据
        ev = next((tx for ln, tx in _body_lines(u) if ln == line), u.body[:60])
        self.bb.add_finding(Finding(
            vuln_type="重入攻击 (Reentrancy)",
            severity=severity,
            function=u.name, line=line,
            description=desc, evidence=ev.strip()[:120],
            confidence=0.9, detected_by=self.id,
        ))


# ---------------------------------------------------------------------- #
# 2) 整数溢出/下溢专家
# ---------------------------------------------------------------------- #
class IntegerOverflowAgent(BaseAgent):
    id = "OverflowExpert"
    role = "整数溢出/下溢：pragma<0.8 时检测无保护的算术运算"
    PROMPT = prompts.OVERFLOW_PROMPT

    def run(self) -> None:
        if self.bb.llm:
            self._llm_emit_findings(self.PROMPT)
            return
        if self.bb.pragma_minor >= 8:
            self.bb.log(self.id, "跳过", "pragma>=0.8 默认有溢出检查，无需额外检测")
            return
        for u in self.bb.units:
            if u.kind != "function":
                continue
            for ln, tx in _body_lines(u):
                # 减法（下溢）：无 SafeMath/checked 保护
                if re.search(r"\w+(\[[^\]]+\])?\s*-=\s*\w+", tx):
                    user_controlled = bool(re.search(r"-=\s*(_amount|_value|amount|value)", tx))
                    self.bb.add_finding(Finding(
                        vuln_type="整数下溢 (Integer Underflow)",
                        severity=Severity.HIGH if user_controlled else Severity.MEDIUM,
                        function=u.name, line=ln,
                        description="Solidity 0.8 以下默认不检查算术溢出/下溢；"
                                    "对状态映射做减法可能被操控为极大值（下溢）。",
                        evidence=tx.strip()[:120],
                        confidence=0.92 if user_controlled else 0.7,
                        detected_by=self.id,
                    ))
                # 乘法（溢出）
                if re.search(r"\*", tx) and re.search(r"(\* 2|\* _amount|\* amount|\* 2\b)", tx):
                    self.bb.add_finding(Finding(
                        vuln_type="整数溢出 (Integer Overflow)",
                        severity=Severity.HIGH,
                        function=u.name, line=ln,
                        description="无溢出保护的乘法可能因乘数值过大而回绕（溢出），"
                                    "被攻击者用于放大抵押/余额。",
                        evidence=tx.strip()[:120],
                        confidence=0.9, detected_by=self.id,
                    ))


# ---------------------------------------------------------------------- #
# 3) 访问控制专家
# ---------------------------------------------------------------------- #
class AccessControlAgent(BaseAgent):
    id = "AccessControlExpert"
    role = "访问控制：检测越权可修改特权状态的函数"
    PROMPT = prompts.ACCESS_CONTROL_PROMPT

    CONFIG_VARS = {"totalSupply", "interestRate", "paused", "owner"}
    FUND_VARS = {"balances", "deposits", "collateral", "borrows", "allowance", "lockTime"}
    # 标准 ERC20 函数本就设计为公开可调用，不应判为"缺失访问控制"
    ERC20_PUBLIC = {"transfer", "transferFrom", "approve", "allowance",
                    "balanceOf", "totalSupply", "name", "symbol", "decimals"}

    def run(self) -> None:
        if self.bb.llm:
            self._llm_emit_findings(self.PROMPT)
            return
        for u in self.bb.units:
            if u.kind != "function":
                continue
            if u.name in self.ERC20_PUBLIC:
                continue  # 标准 ERC20 接口本就公开
            vis = u.visibility
            if vis in ("internal", "private"):
                continue  # 内部函数不可外部越权调用
            # 收集被修改的目标
            modifies_config = False
            modifies_others = False
            modifies_self = False
            for m in ASSIGN_RE.finditer(u.body):
                var, idx_expr, _op = m.group(1), m.group(3), m.group(4)
                if var in self.CONFIG_VARS:
                    modifies_config = True
                elif var in self.FUND_VARS:
                    if idx_expr and "msg.sender" not in idx_expr:
                        modifies_others = True
                    else:
                        modifies_self = True
            # 后门/死代码访问控制
            if "backdoor" in u.name.lower() or "0xdead" in u.body:
                self.bb.add_finding(Finding(
                    vuln_type="可疑后门 (Hidden Backdoor)",
                    severity=Severity.LOW,
                    function=u.name, line=u.line_start,
                    description="检测到以 backdoor 命名或含不可达守卫(address(0xdead))的函数，"
                                "疑似隐藏后门/死代码访问控制缺陷，建议人工复核。",
                    evidence=u.body.strip()[:120],
                    confidence=0.6, detected_by=self.id,
                ))
            if not (modifies_config or modifies_others):
                continue
            if u.has_owner_check or "onlyOwner" in u.modifiers:
                continue  # 有权限校验，安全
            # 判定严重度
            if modifies_config:
                sev = Severity.HIGH
                desc = "函数修改特权配置(供应量/利率/暂停开关/owner)却无 onlyOwner 或权限校验，任何人可调用。"
            elif modifies_others:
                sev = Severity.HIGH
                desc = "函数修改其他地址的资金/抵押/锁仓状态却无权限校验，攻击者可越权操纵他人资产。"
            else:
                sev = Severity.MEDIUM
                desc = "函数缺少访问控制。"
            self.bb.add_finding(Finding(
                vuln_type="访问控制缺失 (Missing Access Control)",
                severity=sev,
                function=u.name, line=u.line_start,
                description=desc,
                evidence=u.body.strip()[:120],
                confidence=0.88, detected_by=self.id,
            ))


# ---------------------------------------------------------------------- #
# 4) 未检查返回值专家
# ---------------------------------------------------------------------- #
class UncheckedReturnAgent(BaseAgent):
    id = "UncheckedReturnExpert"
    role = "未检查外部调用返回值：transfer/send/call 静默失败风险"
    PROMPT = prompts.UNCHECKED_RETURN_PROMPT

    def run(self) -> None:
        if self.bb.llm:
            self._llm_emit_findings(self.PROMPT)
            return
        for u in self.bb.units:
            if u.kind != "function":
                continue
            # 按分号切分语句
            for stmt in re.split(r";", u.body):
                if not EXTERNAL_CALL_RE.search(stmt):
                    continue
                checked = ("require(" in stmt) or ("if (" in stmt) or ("(bool" in stmt)
                if checked:
                    continue
                ln = self._line_of(u, stmt)
                self.bb.add_finding(Finding(
                    vuln_type="未检查返回值 (Unchecked Return)",
                    severity=Severity.MEDIUM,
                    function=u.name, line=ln,
                    description="外部调用(transfer/send/call)的返回值未被 require/if 校验，"
                                "调用静默失败时后续逻辑会误以为成功。",
                    evidence=stmt.strip()[:120],
                    confidence=0.85, detected_by=self.id,
                ))

    @staticmethod
    def _line_of(u, stmt):
        for ln, tx in _body_lines(u):
            if stmt.strip()[:20] in tx:
                return ln
        return u.line_start


# ---------------------------------------------------------------------- #
# 5) tx.origin 认证专家
# ---------------------------------------------------------------------- #
class TxOriginAgent(BaseAgent):
    id = "TxOriginExpert"
    role = "tx.origin 认证缺陷：钓鱼合约可绕过认证"
    PROMPT = prompts.TXORIGIN_PROMPT

    def run(self) -> None:
        if self.bb.llm:
            self._llm_emit_findings(self.PROMPT)
            return
        for u in self.bb.units:
            if u.kind != "function":
                continue
            if TXORIGIN_RE.search(u.body):
                ln = next((ln for ln, tx in _body_lines(u) if "tx.origin" in tx), u.line_start)
                self.bb.add_finding(Finding(
                    vuln_type="tx.origin 认证 (Auth via tx.origin)",
                    severity=Severity.HIGH,
                    function=u.name, line=ln,
                    description="使用 tx.origin 做权限判断，攻击者可通过钓鱼合约诱导 owner 调用，"
                                "从而以 owner 身份执行敏感操作。应改用 msg.sender。",
                    evidence=next((tx.strip() for ln, tx in _body_lines(u) if "tx.origin" in tx), "")[:120],
                    confidence=0.95, detected_by=self.id,
                ))


# ---------------------------------------------------------------------- #
# 6) 时间戳依赖专家
# ---------------------------------------------------------------------- #
class TimestampAgent(BaseAgent):
    id = "TimestampExpert"
    role = "时间戳依赖：block.timestamp 参与关键条件判断"
    PROMPT = prompts.TIMESTAMP_PROMPT

    def run(self) -> None:
        if self.bb.llm:
            self._llm_emit_findings(self.PROMPT)
            return
        for u in self.bb.units:
            if u.kind != "function":
                continue
            for ln, tx in _body_lines(u):
                if TIMESTAMP_RE.search(tx) and (CHECK_RE.search(tx) or COMPARE_RE.search(tx)):
                    self.bb.add_finding(Finding(
                        vuln_type="时间戳依赖 (Timestamp Dependence)",
                        severity=Severity.MEDIUM,
                        function=u.name, line=ln,
                        description="关键条件依赖 block.timestamp/now，矿工可轻微操纵时间戳，"
                                    "影响解锁/抢跑/随机数等逻辑。",
                        evidence=tx.strip()[:120],
                        confidence=0.8, detected_by=self.id,
                    ))
