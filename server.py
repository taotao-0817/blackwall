# -*- coding: utf-8 -*-
"""
黑墙系统 BlackWall V1.2 · HTTP 网关
====================================

让任何语言、任何形态的 AI 程序**零改造**接入黑墙：把"改代码"变成"改地址"。

    # 启动（默认 127.0.0.1:8765）
    python server.py
    python server.py --port 8765 --token my-token --reset --auto-approve

    # 客户端（任何语言）只需 POST
    curl -X POST http://127.0.0.1:8765/v1/tool/call \
         -H "X-API-Token: blackwall-demo-token" -H "Content-Type: application/json" \
         -d '{"agent_id":"my-agent","tool":"read_file","args":{"path":"kb.md"}}'

API 一览：
    POST /v1/guard/input             输入护栏（消息进来时）
    POST /v1/tool/call               工具调用（策略 → 审批 → 执行）
    POST /v1/guard/output            输出护栏（回复出去时，自动脱敏）
    GET  /v1/agents/{id}/status      风险分 / 冻结状态
    POST /v1/agents/{id}/unfreeze    人工解冻
    GET  /v1/approvals               待审列表（值班安全员控制台用）
    POST /v1/approvals/{id}/decide   裁决 approve / reject
    GET  /v1/audit/events            审计查询（可按 agent/effect 过滤）
    GET  /v1/stats                   统计
    GET  /docs                       FastAPI 自带的交互式 API 文档

审批工作流（人工在环）：
    工具调用命中审批规则 → 请求**挂起等待**（默认 45s）→ 值班安全员经
    POST /v1/approvals/{id}/decide 裁决 → 原请求被唤醒并返回最终结果。
    超时未裁决按"安全默认拒绝"；已批准过的操作指纹在有效期内自动放行（重试即过）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover
    raise SystemExit("缺少依赖，请先安装：pip install fastapi uvicorn\n"
                     f"（原始错误：{exc}）")

import uvicorn

from bootstrap import build_box

# ==========================================================================
# 全局状态
# ==========================================================================

BOX = None                      # 在 main() 里装配
TOKENS: set[str] = set()
APPROVAL_WAIT = 45.0            # 审批等待秒数
APPROVED_CACHE_TTL = 300.0      # 批准指纹有效期（重试免审窗口）


@dataclass
class ApprovalTicket:
    id: str
    agent_id: str
    tool: str
    args: dict
    rule_id: str
    reason: str
    created_at: float
    fingerprint: str
    event: threading.Event = field(default_factory=threading.Event)
    verdict: Optional[str] = None          # approve / reject
    note: str = ""
    decided_at: Optional[float] = None


APPROVALS: dict[str, ApprovalTicket] = {}
_approvals_lock = threading.Lock()
_approved_cache: dict[str, float] = {}      # fingerprint -> 批准时间戳


def _fingerprint(agent_id: str, tool: str, args: dict) -> str:
    payload = json.dumps(args, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(f"{agent_id}|{tool}|{payload}".encode("utf-8")).hexdigest()[:16]


def gateway_approval(action, decision) -> tuple[str, str]:
    """黑墙审批回调：挂起请求 → 等待值班裁决 → 唤醒返回（在黑墙工作线程中调用）"""
    fp = _fingerprint(action.agent_id, action.tool, action.args)

    with _approvals_lock:
        cached_at = _approved_cache.get(fp)
        if cached_at and time.time() - cached_at < APPROVED_CACHE_TTL:
            return "approve", f"命中 {int(time.time() - cached_at)}s 前的批准（同操作指纹免审）"
        ticket = ApprovalTicket(
            id=f"AP-{uuid.uuid4().hex[:8]}", agent_id=action.agent_id, tool=action.tool,
            args=action.args, rule_id=decision.rule_id, reason=decision.reason,
            created_at=time.time(), fingerprint=fp,
        )
        APPROVALS[ticket.id] = ticket

    print(f"[黑墙] ‖ 挂起：{ticket.agent_id} 请求 {ticket.tool} → 待审 {ticket.id}"
          f"（{APPROVAL_WAIT:.0f}s 内裁决，否则安全默认拒绝）", flush=True)

    decided = ticket.event.wait(timeout=APPROVAL_WAIT)

    if not decided or ticket.verdict is None:
        ticket.verdict = "reject"
        ticket.note = "审批超时未裁决，按安全默认拒绝"
        ticket.decided_at = time.time()
        print(f"[黑墙] ⏱ {ticket.id} 超时 → 安全默认拒绝", flush=True)
        return "reject", ticket.note

    if ticket.verdict == "approve":
        with _approvals_lock:
            _approved_cache[fp] = time.time()
    verdict_cn = "批准" if ticket.verdict == "approve" else "驳回"
    print(f"[黑墙] {'√' if ticket.verdict == 'approve' else '×'} {ticket.id} 人工{verdict_cn}：{ticket.note}",
          flush=True)
    return ticket.verdict, ticket.note


# ==========================================================================
# FastAPI 应用
# ==========================================================================

app = FastAPI(title="黑墙系统 BlackWall V1.2 · 网关", version="1.2.0",
              description="企业 AI Agent 安全限制与监管隔离网关")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])


def require_token(x_api_token: str = Header(default="")) -> None:
    if not x_api_token or x_api_token not in TOKENS:
        raise HTTPException(status_code=401, detail="无效或缺失 X-API-Token")


class GuardReq(BaseModel):
    agent_id: str
    text: str


class ToolCallReq(BaseModel):
    agent_id: str
    tool: str
    args: dict[str, Any] = {}


class DecideReq(BaseModel):
    verdict: str                       # approve / reject
    note: str = ""


class UnfreezeReq(BaseModel):
    by: str = "安全员"
    note: str = ""


def _decision_payload(decision, agent_id: str) -> dict:
    return {
        "effect": decision.effect.value,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "risk": decision.risk,
        "findings": [f.as_dict() for f in decision.findings],
        "agent_risk": BOX.risk.score(agent_id),
        "frozen": BOX.risk.is_frozen(agent_id),
    }


# --------------------------------------------------------------------------
# 三扇门
# --------------------------------------------------------------------------

@app.post("/v1/guard/input")
def guard_input(req: GuardReq, _: None = Depends(require_token)):
    g = BOX.guard_input(req.agent_id, req.text)
    return {"passed": g.passed, "text": g.text, "decision": _decision_payload(g.decision, req.agent_id)}


@app.post("/v1/tool/call")
def tool_call(req: ToolCallReq, _: None = Depends(require_token)):
    """注意：命中审批时会在此请求内挂起等待（默认 45s），建议客户端超时 ≥ 60s"""
    r = BOX.call_tool(req.agent_id, req.tool, **req.args)
    return {
        "ok": r.ok,
        "data": r.data,
        "error": r.error,
        "decision": _decision_payload(r.decision, req.agent_id) if r.decision else None,
    }


@app.post("/v1/guard/output")
def guard_output(req: GuardReq, _: None = Depends(require_token)):
    g = BOX.guard_output(req.agent_id, req.text)
    return {"passed": g.passed, "text": g.text, "decision": _decision_payload(g.decision, req.agent_id)}


# --------------------------------------------------------------------------
# Agent 状态与人工接管
# --------------------------------------------------------------------------

@app.get("/v1/agents/{agent_id}/status")
def agent_status(agent_id: str, _: None = Depends(require_token)):
    return {
        "agent_id": agent_id,
        "risk": BOX.risk.score(agent_id),
        "frozen": BOX.risk.is_frozen(agent_id),
        "freeze_reason": BOX.risk.freeze_reason(agent_id) or None,
    }


@app.post("/v1/agents/{agent_id}/unfreeze")
def agent_unfreeze(agent_id: str, req: UnfreezeReq, _: None = Depends(require_token)):
    if not BOX.risk.is_frozen(agent_id):
        return {"status": "not_frozen", "agent_id": agent_id}
    BOX.unfreeze(agent_id, by=req.by, note=req.note)
    return {"status": "unfrozen", "agent_id": agent_id, "risk": BOX.risk.score(agent_id)}


# --------------------------------------------------------------------------
# 审批工作流
# --------------------------------------------------------------------------

def _ticket_dict(t: ApprovalTicket) -> dict:
    return {
        "id": t.id, "agent_id": t.agent_id, "tool": t.tool, "args": t.args,
        "rule_id": t.rule_id, "reason": t.reason,
        "status": t.verdict or "pending", "note": t.note,
        "created_at": t.created_at, "decided_at": t.decided_at,
        "waited_s": round((t.decided_at or time.time()) - t.created_at, 1),
    }


@app.get("/v1/approvals")
def list_approvals(status: str = "pending", _: None = Depends(require_token)):
    with _approvals_lock:
        items = [_ticket_dict(t) for t in APPROVALS.values()]
    if status != "all":
        items = [t for t in items if t["status"] == status]
    items.sort(key=lambda t: t["created_at"], reverse=True)
    return {"count": len(items), "approvals": items}


@app.post("/v1/approvals/{ticket_id}/decide")
def decide_approval(ticket_id: str, req: DecideReq, _: None = Depends(require_token)):
    if req.verdict not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="verdict 必须是 approve 或 reject")
    with _approvals_lock:
        t = APPROVALS.get(ticket_id)
        if t is None:
            raise HTTPException(status_code=404, detail=f"审批单 {ticket_id} 不存在")
        if t.verdict is not None:
            return {"status": "already_decided", **_ticket_dict(t)}
        t.verdict = req.verdict
        t.note = req.note
        t.decided_at = time.time()
    t.event.set()                        # 唤醒挂起中的工具调用
    return {"status": "decided", **_ticket_dict(t)}


# --------------------------------------------------------------------------
# 审计与统计
# --------------------------------------------------------------------------

@app.get("/v1/audit/events")
def audit_events(limit: int = 100, agent_id: str | None = None,
                 effect: str | None = None, _: None = Depends(require_token)):
    # limit 归一化：注意 Python 中 rows[-0:] == rows[0:]（会返回全量），
    # 必须显式处理 0 / 负数；另设上限防止单次拉走整库
    limit = max(0, min(int(limit), 1000))
    rows = BOX.audit.rows()
    if agent_id:
        rows = [r for r in rows if r["agent_id"] == agent_id]
    if effect:
        rows = [r for r in rows if r["effect"] == effect]
    return {"total": len(rows), "events": rows[-limit:] if limit else []}


@app.get("/v1/stats")
def stats(_: None = Depends(require_token)):
    return BOX.stats()


# ==========================================================================
# 启动
# ==========================================================================

def main() -> None:
    global BOX, APPROVAL_WAIT

    parser = argparse.ArgumentParser(description="黑墙系统 BlackWall V1.2 · HTTP 网关")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default="blackwall-demo-token",
                        help="API 访问令牌（请求头 X-API-Token）")
    parser.add_argument("--reset", action="store_true",
                        help="启动前清空审计库/业务库（演示用）")
    parser.add_argument("--auto-approve", action="store_true",
                        help="自动批准所有审批请求（无人值守演示用）")
    parser.add_argument("--approval-timeout", type=float, default=45.0,
                        help="审批等待超时秒数（超时按安全默认拒绝）")
    args = parser.parse_args()

    APPROVAL_WAIT = args.approval_timeout
    TOKENS.add(args.token)

    handler = ((lambda action, decision: ("approve", "自动批准（--auto-approve 演示模式）"))
               if args.auto_approve else gateway_approval)
    BOX = build_box(reset=args.reset, approval_handler=handler)

    print("═" * 68)
    print("  黑墙系统 BlackWall V1.2 · HTTP 网关已就绪")
    print(f"  地址   http://{args.host}:{args.port}      （交互文档 {args.host}:{args.port}/docs）")
    print(f"  令牌   X-API-Token: {args.token}")
    print(f"  审批   {'自动批准模式' if args.auto_approve else f'人工裁决（等待 {APPROVAL_WAIT:.0f}s，python duty_cli.py 操作）'}")
    print("  三扇门 POST /v1/guard/input · /v1/tool/call · /v1/guard/output")
    print("═" * 68, flush=True)

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
