"""
FastAPI 服务层 —— 把已有的「智能合约安全审计 Multi-Agent 系统」引擎暴露为 HTTP API，
并托管单文件前端（web/index.html）。

运行方式（在项目根目录 D:/Users/SXF-Admin/Desktop/multi-agent 下）：
    python -m audit_system.api
等价于：
    uvicorn audit_system.api:app --host 0.0.0.0 --port 8000

接口：
    GET  /                -> 前端页面
    GET  /api/health      -> 健康检查
    GET  /api/cases       -> 可用测试案例（名称 + 源码），便于前端一键演示
    POST /api/audit       -> 提交合约源码，返回完整结构化审计结果（含 Agent 流程 timeline）
        请求体（JSON）:        {"source": "...", "file_name": "x.sol"}
        或 multipart 上传:     file=<合约文件>
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# —— 让本模块可作为包运行，并能 import 兄弟模块 —— #
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from audit_system import Supervisor  # noqa: E402
from audit_system.models import Severity  # noqa: E402

CASE_DIR = ROOT / "测试案例"
WEB_DIR = Path(__file__).resolve().parent / "web"

app = FastAPI(title="智安科技 · 智能合约安全审计 Multi-Agent 系统", version="1.0.0")


# --------------------------------------------------------------------------- #
# 数据模型
# --------------------------------------------------------------------------- #
class AuditRequest(BaseModel):
    source: str
    file_name: str = "contract.sol"
    llm: Optional[dict] = None  # 可选：{api_key, base_url, model} 启用 LLM 会诊模式


# --------------------------------------------------------------------------- #
# Agent 元信息（用于前端「多 Agent 协作流程」可视化）
# --------------------------------------------------------------------------- #
# id -> (中文显示名, 阶段, 角色说明)
AGENT_META = {
    "IngestionAgent":     ("入口解析 Agent", 1, "解析合约：pragma / 函数 / 修饰符 / 状态变量"),
    "InjectionDetector":  ("提示注入检测 Agent", 2, "隔离合约中诱导性文本，防止被操纵"),
    "ReentrancyExpert":   ("重入漏洞专家", 3, "检测 checks-effects-interactions 违例 / 缺 nonReentrant"),
    "OverflowExpert":     ("整数溢出专家", 3, "检测下溢/溢出，并结合 pragma 判断保护"),
    "AccessControlExpert":("访问控制专家", 3, "检测特权函数权限校验缺失"),
    "UncheckedReturnExpert":("未检查返回值专家", 3, "检测 call/send/transfer 返回值被忽略"),
    "TxOriginExpert":     ("tx.origin 专家", 3, "检测鉴权误用 tx.origin"),
    "TimestampAgent":     ("时间戳依赖专家", 3, "检测 block.timestamp 可被矿工操控"),
    "ConsensusAgent":     ("共识验证 Agent", 4, "交叉验证 / 共谋检测 / 最终裁决"),
    "SecurityMonitor":    ("安全监控 Agent", 4, "自适应防御 / Agent 健康巡检"),
    "Reporter":           ("报告生成 Agent", 5, "汇总结构化审计报告"),
}


def _decode(raw: bytes) -> str:
    for enc in ("utf-8", "gbk", "gb18030", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def build_response(bb) -> dict:
    """把 Blackboard 转换为前端需要的结构化结果。"""
    report = bb.report

    # ---- 运行日志 / 时间线 ----
    timeline = [
        {"t": round(e.t, 3), "agent": e.agent, "action": e.action, "detail": e.detail}
        for e in bb.get_log()
    ]

    # ---- Agent 流程节点（含每 agent 的起止时间与产出计数）----
    agents = []
    for aid, (cn, stage, role) in AGENT_META.items():
        agent_logs = [e for e in timeline if e["agent"] == aid]
        started = agent_logs[0]["t"] if agent_logs else None
        finished = agent_logs[-1]["t"] if agent_logs else None
        if aid == "InjectionDetector":
            count = len(bb.injections)
        else:
            count = sum(1 for f in bb.findings if f.detected_by == aid)
        status = bb.health.get(aid, "done")
        agents.append({
            "id": aid,
            "name": cn,
            "stage": stage,
            "role": role,
            "status": status,            # ok / done / compromised / suspicious / idle
            "produced": count,
            "started": started,
            "finished": finished,
        })

    return {
        "contract": bb.file_name,
        "pragma": bb.pragma,
        "source": bb.source,
        "verdict": report["verdict"],
        "verdict_reason": report["verdict_reason"],
        "defense_level": report["defense_level"],
        "adaptive_defense": report["adaptive_defense"],
        "collusion_alert": report["collusion_alert"],
        "injection_detected": report["injection_detected"],
        "injections": report["injections"],
        "summary": report["summary"],
        "findings": report["findings"],
        "agent_health": report["agent_health"],
        "agents": agents,
        "timeline": timeline,
        "units": [u.to_dict() for u in bb.units],
    }


# --------------------------------------------------------------------------- #
# 路由
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "audit-multi-agent", "version": "1.0.0"}


@app.get("/api/cases")
def list_cases():
    """返回测试案例目录里的合约，便于前端一键载入演示。"""
    cases = []
    if CASE_DIR.exists():
        for p in sorted(CASE_DIR.rglob("*.txt")):
            cases.append({
                "name": p.stem,
                "file_name": p.name,
                "source": _decode(p.read_bytes()),
            })
    return {"cases": cases}


@app.post("/api/audit")
async def audit(req: AuditRequest):
    # 解析输入：JSON body（前端以 {source, file_name, llm?} 提交）
    if not req.source or not req.source.strip():
        return JSONResponse(status_code=400, content={"error": "缺少合约源码（source）"})

    try:
        llm = None
        if req.llm:
            from .llm_adapter import LLMAdapter
            llm = LLMAdapter(**{k: req.llm[k] for k in ("api_key", "base_url", "model") if k in req.llm})
        bb = Supervisor().audit(req.file_name, req.source, llm=llm)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"error": f"审计执行失败：{exc}"})

    return build_response(bb)


@app.get("/", response_class=HTMLResponse)
def index():
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html)


# 兜底：若 web 目录未创建，提供最小化提示
if not (WEB_DIR / "index.html").exists():
    @app.get("/")
    def _no_frontend():
        return JSONResponse(
            status_code=200,
            content={"hint": "前端文件 web/index.html 尚未生成，请访问 /api/health 与 /api/audit。"},
        )
