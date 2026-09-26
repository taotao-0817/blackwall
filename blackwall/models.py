"""
黑墙系统 BlackWall · 核心数据模型
========================
设计原则：所有经过沙盒的东西都抽象成一个 **Action**（一次待审查的操作），
沙盒对它产出 **Decision**（策略裁决）并落一条 **Event**（审计事件）。

企业接入时不需要理解这些细节——直接用 `blackwall.BlackWall` 门面即可。
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Phase(str, Enum):
    """一次 AI 交互的生命周期阶段"""
    INPUT = "input"      # 用户/外部内容 → Agent（检查 prompt 注入等）
    TOOL = "tool"        # Agent → 工具调用（策略决策主战场）
    EXEC = "exec"        # 工具内部 → 受限执行沙盒（代码/命令）
    OUTPUT = "output"    # Agent → 用户（检查数据泄露，可脱敏）


class Effect(str, Enum):
    """策略裁决"""
    ALLOW = "allow"          # 放行
    SANITIZE = "sanitize"    # 脱敏后放行
    APPROVAL = "approval"    # 挂起，等待人工审批
    DENY = "deny"            # 拦截


#: 效果严格度：数值越大越严格，多规则命中时取最严格的一条
EFFECT_SEVERITY = {
    Effect.ALLOW: 0,
    Effect.SANITIZE: 1,
    Effect.APPROVAL: 2,
    Effect.DENY: 3,
}

EFFECT_ICON = {
    Effect.ALLOW: "√",
    Effect.SANITIZE: "◎",
    Effect.APPROVAL: "‖",
    Effect.DENY: "×",
}

EFFECT_LABEL = {
    Effect.ALLOW: "放行",
    Effect.SANITIZE: "脱敏放行",
    Effect.APPROVAL: "人工审批",
    Effect.DENY: "已拦截",
}


@dataclass
class Finding:
    """护栏的一条发现（证据）"""
    kind: str            # 家族：prompt_injection / pii / secret / dangerous_command / escape ...
    label: str           # 人类可读标签："Prompt 注入"、"手机号"
    detail: str = ""     # 具体描述
    severity: int = 5    # 1-10
    snippet: str = ""    # 命中片段（截断到 80 字符，用于审计取证）

    def as_dict(self) -> dict:
        return {
            "kind": self.kind, "label": self.label, "detail": self.detail,
            "severity": self.severity, "snippet": self.snippet,
        }


@dataclass
class Action:
    """一次待审查的操作"""
    agent_id: str
    phase: Phase
    tool: str = ""
    args: dict = field(default_factory=dict)
    content: str = ""
    meta: dict = field(default_factory=dict)
    action_id: str = field(default_factory=lambda: f"A-{uuid.uuid4().hex[:8]}")

    # ---- 供策略引擎/护栏使用的统一视图 ----

    def payload_text(self) -> str:
        """代表这次操作的完整文本（工具名 + 参数 + 内容），用于模式匹配"""
        parts = [self.tool]
        for k, v in self.args.items():
            parts.append(f"{k}={v}")
        if self.content:
            parts.append(self.content)
        return "\n".join(str(p) for p in parts)

    def path_args(self) -> list[str]:
        """参数里形如路径的值（策略做资源 jail 判断用）"""
        out = []
        for k, v in self.args.items():
            if k.lower() in ("path", "file", "filename", "target", "dir", "dst", "dest") and isinstance(v, str):
                out.append(v)
        return out

    def summary(self) -> str:
        """给人类看的一行描述"""
        if self.phase == Phase.TOOL:
            if not self.tool and not self.args:
                return _short(self.content, 110) if self.content else "（人工干预操作）"
            if self.args:
                inner = ", ".join(f"{k}={_short(v)}" for k, v in self.args.items())
            else:
                inner = ""
            return f"{self.tool}({inner})"
        return _short(self.content, 110)


def _short(value: Any, limit: int = 60) -> str:
    s = str(value).replace("\n", " ⏎ ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


@dataclass
class Decision:
    """策略裁决结果"""
    effect: Effect = Effect.ALLOW
    reason: str = ""
    rule_id: str = ""
    findings: list[Finding] = field(default_factory=list)
    risk: int = 0               # 本次操作的风险贡献（0-100）
    transformed: str = ""       # sanitize 之后的文本（其它情况为空）


@dataclass
class ToolResult:
    """工具调用回执（交给 agent 的）"""
    ok: bool
    data: Any = None
    error: str = ""
    decision: Decision | None = None


@dataclass
class Event:
    """审计事件（落 SQLite + 供大屏回放）"""
    ts: float
    agent_id: str
    phase: str
    tool: str
    effect: str
    rule_id: str
    reason: str
    risk: int
    findings: list[dict]
    summary: str
    action_id: str = ""
    latency_ms: float = 0.0
    actor: str = "agent"        # agent / guard / human
    note: str = ""
    agent_risk: int = 0         # 该时刻 agent 的累计风险分（0-100）

    @staticmethod
    def new(**kw) -> "Event":
        kw.setdefault("ts", time.time())
        return Event(**kw)

    def as_dict(self) -> dict:
        return {
            "ts": self.ts, "agent_id": self.agent_id, "phase": self.phase,
            "tool": self.tool, "effect": self.effect, "rule_id": self.rule_id,
            "reason": self.reason, "risk": self.risk, "findings": self.findings,
            "summary": self.summary, "action_id": self.action_id,
            "latency_ms": round(self.latency_ms, 2), "actor": self.actor, "note": self.note,
            "agent_risk": self.agent_risk,
        }
