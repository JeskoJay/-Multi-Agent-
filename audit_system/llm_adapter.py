"""
LLM 适配层（LLMAdapter）—— 把"提示词模板"真正接通大模型。

设计要点：
1. 零额外依赖：用标准库 urllib 直连 OpenAI 兼容的 /v1/chat/completions 接口
   （兼容 OpenAI / DeepSeek / 通义 / 自建网关，只要填 base_url 即可）。
2. 容错解析：模型返回常常不是"干净 JSON"——可能包在 ```json 围栏里、前后带解释文字、
   severity 用中文/大小写混写。extract_findings / extract_injections 做多层兜底提取 +
   字段归一化，保证最终能被 Finding / InjectionFlag 正确构造。
3. 双轨切换：各 Agent 在 `self.bb.llm` 为真时才走本适配器；否则使用确定性规则。
4. 安全：默认 temperature=0 提升确定性；调用失败不抛异常（返回空），避免拖垮整条审计链路。
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error
from typing import Dict, List, Optional

# severity 归一化映射（兼容模型输出中文/英文/大小写）
_SEV_MAP = {
    "critical": "Critical", "严重": "Critical", "高危": "Critical", "致命": "Critical",
    "high": "High", "高": "High",
    "medium": "Medium", "中": "Medium",
    "low": "Low", "低": "Low",
    "info": "Info", "信息": "Info", "提示": "Info", "notice": "Info",
}


def _norm_sev(v) -> str:
    if v is None:
        return "Medium"
    return _SEV_MAP.get(str(v).strip().lower(), "Medium")


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _as_float(v, default=0.8):
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return default


def _extract_json(text: str):
    """多层兜底地从模型文本里抠出 JSON 对象/数组。"""
    if not text:
        return None
    s = text.strip()
    # 1) 整体已是合法 JSON
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    # 2) 去掉 ```json ... ``` / ``` ... ``` 围栏
    m = re.search(r"```(?:json)?\s*(.*?)```", s, re.DOTALL | re.IGNORECASE)
    if m:
        inner = m.group(1).strip()
        try:
            return json.loads(inner)
        except json.JSONDecodeError:
            pass
    # 3) 截取第一个 { ... } 或 [ ... ]（贪婪匹配，DOTALL）
    m = re.search(r"(\{.*\}|\[.*\])", s, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    return None


def _to_items(obj) -> List[dict]:
    """把解析结果统一为 dict 列表。"""
    if obj is None:
        return []
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        if "findings" in obj and isinstance(obj["findings"], list):
            return [x for x in obj["findings"] if isinstance(x, dict)]
        return [obj]  # 单条对象
    return []


def _norm_finding(it: dict) -> dict:
    return {
        "vuln_type": str(it.get("vuln_type") or it.get("type") or "未知漏洞"),
        "severity": _norm_sev(it.get("severity")),
        "function": it.get("function"),
        "line": _as_int(it.get("line")),
        "description": str(it.get("description") or ""),
        "evidence": str(it.get("evidence") or ""),
        "confidence": round(_as_float(it.get("confidence", 0.8)), 2),
        "injection_related": bool(it.get("injection_related", False)),
    }


def _norm_injection(it: dict) -> dict:
    return {
        "location": str(it.get("location") or "contract"),
        "line": _as_int(it.get("line")),
        "text": str(it.get("text") or ""),
        "technique": str(it.get("technique") or "指令注入"),
        "quarantine": bool(it.get("quarantine", True)),
    }


class LLMAdapter:
    def __init__(self, api_key: Optional[str] = None,
                 base_url: Optional[str] = None,
                 model: Optional[str] = None):
        self.api_key = api_key or os.getenv("LLM_API_KEY") or ""
        self.base_url = (base_url or os.getenv("LLM_BASE_URL")
                         or "https://api.openai.com/v1").rstrip("/")
        self.model = model or os.getenv("LLM_MODEL") or "gpt-4o-mini"

    def chat(self, system: str, user: str, temperature: float = 0.0) -> str:
        """调用 OpenAI 兼容 chat/completions，失败返回空串（不抛异常）。"""
        url = self.base_url + "/chat/completions"
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"] or ""
        except Exception as exc:  # noqa: BLE001
            # 网络/鉴权/超时等任意异常：打印告警，返回空（上层解析得空列表，不拖垮审计）
            print(f"[LLMAdapter] 调用失败：{exc}", flush=True)
            return ""

    # ---- 高层便捷方法：prompt 模板 + 源码 -> 已归一化的 dict 列表 ----
    def extract_findings(self, system: str, user_prompt: str) -> List[dict]:
        raw = self.chat(system, user_prompt)
        return [_norm_finding(i) for i in _to_items(_extract_json(raw))]

    def extract_injections(self, system: str, user_prompt: str) -> List[dict]:
        raw = self.chat(system, user_prompt)
        return [_norm_injection(i) for i in _to_items(_extract_json(raw))]
