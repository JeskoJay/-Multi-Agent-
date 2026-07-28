"""
Solidity 轻量解析器（无第三方依赖）。

仅做"够用"的静态解析：
- 提取 pragma 版本（判断 < 0.8 默认无溢出检查）；
- 用括号匹配切出每个 function / modifier 的声明与函数体；
- 提取可见性、修饰符（onlyOwner / nonReentrant ...）；
- 识别函数体内是否包含 owner 权限校验（require(msg.sender == owner) 等）。

解析结果存入 Blackboard.units，供各专家 Agent 使用。
"""

from __future__ import annotations

import re

from .models import ParsedUnit

_FUNC_RE = re.compile(r"\b(function|modifier)\s+([A-Za-z_]\w*)\s*\(")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+\^?(\d+)\.(\d+)\.\d+")
_VIS_RE = re.compile(r"\b(public|external|internal|private)\b")
_OWNER_CHECK_RE = re.compile(
    r"require\s*\(\s*msg\.sender\s*==\s*(owner|_owner|admin|owner_)\b"
    r"|onlyOwner|onlyAdmin|onlyRole|requireAuth|auth\("
)
_MUTATION_RE = re.compile(
    r"(balances|deposits|borrows|collateral|allowance|lockTime|totalSupply|"
    r"interestRate|paused|owner)\b\s*(\[[^\]]+\])?\s*(\+=|-=|=)"
)


def _strip_comments(text: str) -> str:
    """去掉 // 行注释与 /* */ 块注释，避免注释文本干扰语义判断。"""
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    return text


def parse_source(source: str):
    pragma = "unknown"
    pragma_minor = 0
    m = _PRAGMA_RE.search(source)
    if m:
        pragma = f"{m.group(1)}.{m.group(2)}"
        # Solidity 0.8+ 默认带溢出检查，因此以"次版本号"判断是否具备 SafeMath 默认保护
        pragma_minor = int(m.group(2))

    units: list[ParsedUnit] = []
    for fm in _FUNC_RE.finditer(source):
        kind = fm.group(1)
        name = fm.group(2)
        # 接口/抽象声明以 ';' 结尾，跳过
        semi = source.find(";", fm.end())
        brace = source.find("{", fm.end())
        if brace == -1:
            continue
        if semi != -1 and semi < brace:
            continue

        decl = source[fm.start():brace]
        vis_match = _VIS_RE.search(decl)
        visibility = vis_match.group(1) if vis_match else None
        mods = re.findall(r"\b(onlyOwner|onlyAdmin|onlyRole|nonReentrant|whenNotPaused|auth|validated)\w*\b", decl)

        # 匹配函数体结束的 '}'
        depth = 0
        j = brace
        while j < len(source):
            ch = source[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1

        body = source[brace + 1: j]
        line_start = source.count("\n", 0, fm.start()) + 1
        line_end = source.count("\n", 0, j) + 1
        lines_all = source.splitlines()
        body_lines = [
            (line_start + idx, ln)
            for idx, ln in enumerate(lines_all[line_start - 1: line_end])
        ]
        # 注意：必须在"去掉注释"后的函数体上判断 owner 校验，
        # 否则注释里"缺少 onlyOwner 检查"这类文本会被误判为已有权限校验。
        has_owner_check = bool(_OWNER_CHECK_RE.search(_strip_comments(body))) or ("onlyOwner" in mods)

        units.append(
            ParsedUnit(
                kind=kind,
                name=name,
                line_start=line_start,
                line_end=line_end,
                visibility=visibility,
                modifiers=mods,
                body=body,
                body_lines=body_lines,
                has_owner_check=has_owner_check,
            )
        )

    return pragma, pragma_minor, units
