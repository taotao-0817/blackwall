# -*- coding: utf-8 -*-
"""
黑墙系统 BlackWall V1.3 · HTTP 网关
====================================

让任何语言、任何形态的 AI 程序**零改造**接入黑墙：把"改代码"变成"改地址"。

    # 启动（默认 127.0.0.1:8765）
    python server.py
    python server.py --port 8765 --admin-token my-admin --agent-token my-agent --reset

    # 客户端（任何语言）只需 POST
    curl -X POST http://127.0.0.1:8765/v1/tool/call \
         -H "X-API-Token: my-agent" -H "Content-Type: application/json" \
         -d '{"tool":"read_file","args":{"path":"kb.md"}}'

V1.3 身份分域（修复"被监管方自己批准自己"）：
    管理凭证（admin token）   审批裁决 / 解冻 / 审计查询——只给安全员持有；
    Agent 凭证（agent token）三扇门工具流——发给被监管程序，且**绑定固定
    agent_id**（服务端强制覆盖请求体中的自报值，熔断不能靠"换名字"绕过）。

API 一览：
    POST /v1/guard/input             输入护栏（消息进来时）
    POST /v1/tool/call               工具调用（策略 → 审批 → 执行）
    POST /v1/guard/output            输出护栏（回复出去时，自动脱敏）
    GET  /v1/whoami                  凭证自检（返回凭证类型与绑定身份）
    GET  /v1/agents/{id}/status      风险分 / 冻结状态（agent 仅可查自己）
    POST /v1/agents/{id}/unfreeze    人工解冻              [admin]
    GET  /v1/approvals               待审列表              [admin]
    POST /v1/approvals/{id}/decide   裁决 approve/reject   [admin]
    GET  /v1/audit/events            审计查询              [admin]
    GET  /v1/audit/verify            审计哈希链校验        [admin]
    GET  /v1/stats                   统计                  [admin]

审批工作流（人工在环）：
    工具调用命中审批规则 → 请求**挂起等待**（默认 45s；并发挂起设上限保护）
    → 值班安全员经 POST /v1/approvals/{id}/decide 裁决 → 原请求被唤醒并返回。
    超时未裁决按"安全默认拒绝"；已批准过的操作指纹在有效期内自动放行（重试即过）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover
    raise SystemExit("缺少依赖，请先安装：pip install fastapi uvicorn\n"
                     f"（原始错误：{exc}）")

import uvicorn

from bootstrap import build_box

# ==========================================================================
# 全局状态
# ==========================================================================

BOX = None                              # 在 main() 里装配
ADMIN_TOKENS: set[str] = set()          # 管理凭证（可配置多个）
AGENT_TOKENS: dict[str, str] = {}       # Agent 凭证 → 绑定身份（token→agent_id）
APPROVAL_WAIT = 45.0                    # 审批等待秒数
APPROVED_CACHE_TTL = 300.0              # 批准指纹有效期（重试免审窗口）
TICKET_TTL = 3600.0                     # 工单保留时长（超期清理，防内存无界增长）
MAX_PENDING = 20                        # 并发挂起上限（防大批挂起拖垮执行池）
_pending_count = 0                      # 当前挂起中的审批数（_approvals_lock 保护）


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


def _purge_expired_locked() -> None:
    """清理超期工单与过期免审指纹（须在 _approvals_lock 内调用）"""
    now = time.time()
    for tid in [t.id for t in APPROVALS.values()
                if t.decided_at is not None and now - t.decided_at > TICKET_TTL]:
        APPROVALS.pop(tid, None)
    for fp in [k for k, at in _approved_cache.items() if now - at > APPROVED_CACHE_TTL]:
        _approved_cache.pop(fp, None)


def gateway_approval(action, decision) -> tuple[str, str]:
    """黑墙审批回调：挂起请求 → 等待值班裁决 → 唤醒返回（在黑墙工作线程中调用）

    V1.3 抗 DoS：
    - 并发挂起超过上限 → 立即安全拒绝（不占执行线程，防恶意 Agent 用挂起洪峰
      拖垮线程池、把控制面一起饿死）；
    - 工单与免审缓存按 TTL 清理（防内存无界增长）。
    """
    global _pending_count
    fp = _fingerprint(action.agent_id, action.tool, action.args)

    with _approvals_lock:
        _purge_expired_locked()
        cached_at = _approved_cache.get(fp)
        if cached_at and time.time() - cached_at < APPROVED_CACHE_TTL:
            return "approve", f"命中 {int(time.time() - cached_at)}s 前的批准（同操作指纹免审）"
        if _pending_count >= MAX_PENDING:
            return "reject", (f"审批通道繁忙（同时挂起已达上限 {MAX_PENDING}），"
                              "按安全默认拒绝——请待积压审批处理后再试")
        ticket = ApprovalTicket(
            id=f"AP-{uuid.uuid4().hex[:8]}", agent_id=action.agent_id, tool=action.tool,
            args=action.args, rule_id=decision.rule_id, reason=decision.reason,
            created_at=time.time(), fingerprint=fp,
        )
        APPROVALS[ticket.id] = ticket
        _pending_count += 1

    print(f"[黑墙] ‖ 挂起：{ticket.agent_id} 请求 {ticket.tool} → 待审 {ticket.id}"
          f"（{APPROVAL_WAIT:.0f}s 内裁决，否则安全默认拒绝）", flush=True)

    try:
        decided = ticket.event.wait(timeout=APPROVAL_WAIT)
    finally:
        with _approvals_lock:
            _pending_count -= 1

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
# 限流（控制面自保：防止单一来源把网关淹没）
# ==========================================================================

class RateLimiter:
    """极简滑动窗口限流（按凭证 / 来源计数）"""

    def __init__(self, per_minute: int = 300):
        self.per_minute = per_minute
        self._win: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            dq = self._win[key]
            dq.append(now)
            while dq and now - dq[0] > 60.0:
                dq.popleft()
            return len(dq) <= self.per_minute


_limiter = RateLimiter(per_minute=300)


# ==========================================================================
# FastAPI 应用
# ==========================================================================

app = FastAPI(title="黑墙系统 BlackWall V1.3 · 网关", version="1.3.0",
              description="企业 AI Agent 安全限制与监管隔离网关",
              # V1.3：/docs 与 /openapi.json 默认关闭（不对未认证请求暴露接口结构）；
              # 需要交互文档时用 --docs 启动（仅限内网演示）
              docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def rate_limit_mw(request, call_next):
    key = request.headers.get("x-api-token") or (
        request.client.host if request.client else "unknown")
    if not _limiter.allow(key):
        return JSONResponse(status_code=429,
                            content={"detail": "请求过于频繁（网关限流），请稍后重试"})
    return await call_next(request)


# --------------------------------------------------------------------------
# 凭证与身份（V1.3 核心：agent / admin 分域 + token→agent_id 强绑定）
# --------------------------------------------------------------------------

def _identify(token: str) -> tuple[str, str | None] | None:
    """识别凭证：("agent", 绑定 id) / ("admin", None) / None（未识别）"""
    if token and token in AGENT_TOKENS:
        return "agent", AGENT_TOKENS[token]
    if token and token in ADMIN_TOKENS:
        return "admin", None
    return None


def require_admin(x_api_token: str = Header(default="")) -> None:
    if _identify(x_api_token) != ("admin", None):
        raise HTTPException(status_code=401,
                            detail="需要管理凭证（admin token）——该接口不对被监管方开放")


def require_agent(x_api_token: str = Header(default="")) -> str:
    ident = _identify(x_api_token)
    if ident is None or ident[0] != "agent":
        raise HTTPException(status_code=401, detail="需要 Agent 凭证（agent token）")
    return ident[1] or "unknown-agent"


class GuardReq(BaseModel):
    text: str
    agent_id: str = ""      # 兼容字段：V1.3 起忽略（身份由凭证绑定，服务端强制生效）


class ToolCallReq(BaseModel):
    tool: str
    args: dict[str, Any] = {}
    agent_id: str = ""      # 兼容字段：V1.3 起忽略（身份由凭证绑定，服务端强制生效）


class DecideReq(BaseModel):
    verdict: str                       # approve / reject
    note: str = ""


class UnfreezeReq(BaseModel):
    by: str = ""                       # 兼容字段：V1.3 起忽略（操作者以管理凭证为准）
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
# 三扇门（Agent 凭证，身份=凭证绑定值）
# --------------------------------------------------------------------------

@app.post("/v1/guard/input")
def guard_input(req: GuardReq, agent_id: str = Depends(require_agent)):
    g = BOX.guard_input(agent_id, req.text)
    return {"passed": g.passed, "text": g.text, "agent_id": agent_id,
            "decision": _decision_payload(g.decision, agent_id)}


@app.post("/v1/tool/call")
def tool_call(req: ToolCallReq, agent_id: str = Depends(require_agent)):
    """注意：命中审批时会在此请求内挂起等待（默认 45s），建议客户端超时 ≥ 60s"""
    r = BOX.call_tool(agent_id, req.tool, **req.args)
    return {
        "ok": r.ok,
        "data": r.data,
        "error": r.error,
        "agent_id": agent_id,
        "decision": _decision_payload(r.decision, agent_id) if r.decision else None,
    }


@app.post("/v1/guard/output")
def guard_output(req: GuardReq, agent_id: str = Depends(require_agent)):
    g = BOX.guard_output(agent_id, req.text)
    return {"passed": g.passed, "text": g.text, "agent_id": agent_id,
            "decision": _decision_payload(g.decision, agent_id)}


# --------------------------------------------------------------------------
# 凭证自检（客户端启动时对齐配置用）
# --------------------------------------------------------------------------

@app.get("/v1/whoami")
async def whoami(x_api_token: str = Header(default="")):
    ident = _identify(x_api_token)
    if ident is None:
        raise HTTPException(status_code=401, detail="无效或缺失 X-API-Token")
    kind, bound = ident
    return {"kind": kind, "agent_id": bound}


# --------------------------------------------------------------------------
# Agent 状态与人工接管
# --------------------------------------------------------------------------

@app.get("/v1/agents/{agent_id}/status")
async def agent_status(agent_id: str, x_api_token: str = Header(default="")):
    ident = _identify(x_api_token)
    if ident is None:
        raise HTTPException(status_code=401, detail="无效或缺失 X-API-Token")
    if ident[0] == "agent" and ident[1] != agent_id:
        raise HTTPException(status_code=403,
                            detail="Agent 凭证只能查询自身状态（身份由凭证绑定）")
    return {
        "agent_id": agent_id,
        "risk": BOX.risk.score(agent_id),
        "frozen": BOX.risk.is_frozen(agent_id),
        "freeze_reason": BOX.risk.freeze_reason(agent_id) or None,
    }


@app.post("/v1/agents/{agent_id}/unfreeze")
async def agent_unfreeze(agent_id: str, req: UnfreezeReq, _: None = Depends(require_admin)):
    if not BOX.risk.is_frozen(agent_id):
        return {"status": "not_frozen", "agent_id": agent_id}
    # V1.3：操作者身份以管理凭证为准（请求体里的 by 不再被信任）
    BOX.unfreeze(agent_id, by="值班管理员（admin 凭证）", note=req.note)
    return {"status": "unfrozen", "agent_id": agent_id, "risk": BOX.risk.score(agent_id)}


# --------------------------------------------------------------------------
# 审批工作流（管理凭证）
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
async def list_approvals(status: str = "pending", _: None = Depends(require_admin)):
    with _approvals_lock:
        items = [_ticket_dict(t) for t in APPROVALS.values()]
    if status != "all":
        items = [t for t in items if t["status"] == status]
    items.sort(key=lambda t: t["created_at"], reverse=True)
    return {"count": len(items), "approvals": items}


@app.post("/v1/approvals/{ticket_id}/decide")
async def decide_approval(ticket_id: str, req: DecideReq, _: None = Depends(require_admin)):
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
# 审计与统计（管理凭证）
# --------------------------------------------------------------------------

@app.get("/v1/audit/events")
async def audit_events(limit: int = 100, agent_id: str | None = None,
                       effect: str | None = None, _: None = Depends(require_admin)):
    # limit 归一化：注意 Python 中 rows[-0:] == rows[0:]（会返回全量），
    # 必须显式处理 0 / 负数；另设上限防止单次拉走整库
    limit = max(0, min(int(limit), 1000))
    rows = BOX.audit.rows()
    if agent_id:
        rows = [r for r in rows if r["agent_id"] == agent_id]
    if effect:
        rows = [r for r in rows if r["effect"] == effect]
    return {"total": len(rows), "events": rows[-limit:] if limit else []}


@app.get("/v1/audit/verify")
async def audit_verify(_: None = Depends(require_admin)):
    """审计哈希链完整性校验（V1.3：记录被删/被改会在此暴露）"""
    return BOX.audit.verify_chain()


@app.get("/v1/stats")
async def stats(_: None = Depends(require_admin)):
    return BOX.stats()


# ==========================================================================
# 启动
# ==========================================================================

def main() -> None:
    global BOX, APPROVAL_WAIT

    parser = argparse.ArgumentParser(description="黑墙系统 BlackWall V1.3 · HTTP 网关")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--admin-token", default="blackwall-demo-token",
                        help="管理凭证（审批/解冻/审计——只给安全员持有）")
    parser.add_argument("--agent-token", default="blackwall-agent-token",
                        help="Agent 凭证（三扇门工具流——发给被监管程序）")
    parser.add_argument("--agent-id", default="demo-agent",
                        help="Agent 凭证绑定的身份（服务端强制生效，不接受客户端自报）")
    parser.add_argument("--reset", action="store_true",
                        help="启动前清空审计库/业务库（演示用）")
    parser.add_argument("--auto-approve", action="store_true",
                        help="自动批准所有审批请求（无人值守演示用）")
    parser.add_argument("--approval-timeout", type=float, default=45.0,
                        help="审批等待超时秒数（超时按安全默认拒绝）")
    parser.add_argument("--docs", action="store_true",
                        help="启用 /docs 交互文档（默认关闭，不对未认证请求暴露接口结构）")
    parser.add_argument("--data-dir", default=None,
                        help="数据目录（默认 ./data；测试隔离用）")
    args = parser.parse_args()

    APPROVAL_WAIT = args.approval_timeout
    ADMIN_TOKENS.add(args.admin_token)
    AGENT_TOKENS[args.agent_token] = args.agent_id

    handler = ((lambda action, decision: ("approve", "自动批准（--auto-approve 演示模式）"))
               if args.auto_approve else gateway_approval)
    BOX = build_box(reset=args.reset, approval_handler=handler, data_dir=args.data_dir)

    if args.docs:
        # 显式开启时才挂载（默认不暴露接口结构给未认证请求）
        from fastapi.openapi.docs import get_swagger_ui_html

        @app.get("/openapi.json", include_in_schema=False)
        async def _openapi_json():
            return JSONResponse(app.openapi())

        @app.get("/docs", include_in_schema=False)
        async def _docs_ui():
            return get_swagger_ui_html(openapi_url="/openapi.json",
                                       title="黑墙系统 BlackWall · 网关 API")

    print("═" * 68)
    print("  黑墙系统 BlackWall V1.3 · HTTP 网关已就绪")
    print("  （身份分域 + 内联输出护栏 + 能力化策略 + 审计哈希链）")
    print(f"  地址        http://{args.host}:{args.port}"
          + ("      （交互文档 /docs 已启用）" if args.docs else ""))
    print(f"  Agent 凭证  X-API-Token: {args.agent_token}   → 绑定身份：{args.agent_id}")
    print(f"  管理凭证    X-API-Token: {args.admin_token}   （审批/解冻/审计，仅安全员持有）")
    print(f"  审批        {'自动批准模式' if args.auto_approve else f'人工裁决（等待 {APPROVAL_WAIT:.0f}s，python duty_cli.py 操作）'}")
    print("  三扇门      POST /v1/guard/input · /v1/tool/call · /v1/guard/output")
    if args.admin_token == "blackwall-demo-token" or args.agent_token == "blackwall-agent-token":
        print("  ⚠ 正在使用演示默认令牌——生产部署请用 --admin-token / --agent-token 更换！")
    print("═" * 68, flush=True)

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
