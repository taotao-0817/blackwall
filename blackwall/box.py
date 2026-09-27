"""
黑墙系统 BlackWall · 沙盒门面（企业接入的唯一入口）
==========================================
对被监管的 AI Agent 来说，世界只剩三个动作：

    box.guard_input(agent_id, text)      # 收到用户/外部内容时
    box.call_tool(agent_id, tool, **kw)  # 想用工具/数据时
    box.guard_output(agent_id, text)     # 准备回复用户时

全部流量都从这三扇门走，策略、护栏、风险、审计在这三扇门后统一编排。
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog
from .guards import InputGuard, OutputGuard
from .models import (EFFECT_SEVERITY, Action, Decision, Effect, Event, Finding,
                     Phase, ToolResult)
from .policy_engine import PolicyEngine
from .risk import RiskEngine
from .sandbox_exec import SandboxViolation


@dataclass
class GuardResult:
    """输入/输出护栏的裁决 + 处理后的文本"""
    decision: Decision
    text: str

    @property
    def passed(self) -> bool:
        return self.decision.effect in (Effect.ALLOW, Effect.SANITIZE)


@dataclass
class ToolSpec:
    name: str
    fn: Callable[..., Any]
    description: str = ""
    #: V1.3 能力标签（read_fs / write_fs / exec / send_ext / db_read / pii …）
    capabilities: tuple[str, ...] = ()


class BlackWall:
    def __init__(
        self,
        policy_path: str | Path,
        db_path: str | Path,
        workdir: str | Path | None = None,
        freeze_threshold: int = 100,
        approval_handler: Callable[[Action, Decision], tuple[str, str]] | None = None,
        on_event: Callable[[Event], None] | None = None,
        enforce_output_guard: bool = True,
        high_freq_limit: int = 25,
    ):
        self.engine = PolicyEngine(policy_path)
        self.audit = AuditLog(db_path)
        self.risk = RiskEngine(freeze_threshold=freeze_threshold)
        self.input_guard = InputGuard()
        self.output_guard = OutputGuard()
        self.workdir = Path(workdir).resolve() if workdir else None
        self.approval_handler = approval_handler
        self.on_event = on_event
        self.tools: dict[str, ToolSpec] = {}
        #: V1.3：工具结果返回前强制过输出护栏（不再依赖 Agent"自觉调用"输出门）
        self.enforce_output_guard = enforce_output_guard
        #: V1.3：敏感工具调用频率上限（60 秒滑窗，防"少量多次"拖取）
        self.high_freq_limit = high_freq_limit
        #: 最近一次工具调用的结果（demo 展示用）
        self.last_tool_output: Any = None

    # ------------------------------------------------------------------
    # 工具注册（白名单：没注册的工具，Agent 根本够不着）
    # ------------------------------------------------------------------
    def register_tool(self, name: str, fn: Callable[..., Any], description: str = "",
                      capabilities: tuple[str, ...] | list[str] = ()) -> None:
        self.tools[name] = ToolSpec(name=name, fn=fn, description=description,
                                    capabilities=tuple(capabilities))

    # ------------------------------------------------------------------
    # 门一：输入护栏
    # ------------------------------------------------------------------
    def guard_input(self, agent_id: str, text: str) -> GuardResult:
        action = Action(agent_id=agent_id, phase=Phase.INPUT, content=text)

        if self.risk.is_frozen(agent_id):
            decision = Decision(
                effect=Effect.DENY, rule_id="RISK-FROZEN",
                reason=f"Agent 已被风控冻结（{self.risk.freeze_reason(agent_id)}），暂不接受新任务",
                risk=0,
            )
            self._emit(action, decision)
            self._register_risk(agent_id, decision.effect, action.summary())
            return GuardResult(decision, "")

        findings = self.input_guard.scan(text)
        injection = [f for f in findings if f.kind == "prompt_injection"]
        evasion = [f for f in findings if f.kind == "encoding_evasion"]

        if injection:
            guard_decision = Decision(
                effect=Effect.DENY, rule_id="GUARD-INPUT-INJECTION",
                reason="输入内容包含疑似 Prompt 注入指令，已阻断（消息不会进入 Agent 上下文）",
                findings=findings, risk=40,
            )
        elif evasion:
            guard_decision = Decision(
                effect=Effect.APPROVAL, rule_id="GUARD-INPUT-EVASION",
                reason="输入包含疑似编码绕过载荷，已挂起等待人工确认",
                findings=findings, risk=25,
            )
        else:
            guard_decision = Decision(effect=Effect.ALLOW, reason="输入检查通过",
                                      rule_id="GUARD-INPUT", findings=findings)

        # 双引擎：业务策略文本规则（如"试图修改/绕过监管配置"）在输入阶段同样生效
        policy_decision = self.engine.evaluate(action)
        if EFFECT_SEVERITY[policy_decision.effect] > EFFECT_SEVERITY[guard_decision.effect]:
            policy_decision.findings = policy_decision.findings + guard_decision.findings
            decision = policy_decision
        else:
            if policy_decision.effect != Effect.ALLOW:
                guard_decision.findings = guard_decision.findings + policy_decision.findings
                guard_decision.reason += f"（同时命中策略: {policy_decision.rule_id}）"
            decision = guard_decision

        self._emit(action, decision)
        self._register_risk(agent_id, decision.effect, action.summary())
        return GuardResult(decision, text)

    # ------------------------------------------------------------------
    # 门二：工具调用（策略主战场）
    # ------------------------------------------------------------------
    def call_tool(self, agent_id: str, tool: str, **args: Any) -> ToolResult:
        t0 = time.perf_counter()
        action = Action(agent_id=agent_id, phase=Phase.TOOL, tool=tool, args=dict(args))

        # 0) 熔断优先：被冻结的 Agent 一切操作直接拒
        if self.risk.is_frozen(agent_id):
            decision = Decision(
                effect=Effect.DENY, rule_id="RISK-FROZEN",
                reason=f"Agent 已被风控冻结（{self.risk.freeze_reason(agent_id)}），操作被拒",
            )
            self._emit(action, decision, latency=self._ms(t0))
            self._register_risk(agent_id, decision.effect, action.summary())
            return ToolResult(False, error=decision.reason, decision=decision)

        # 1) 工具白名单
        spec = self.tools.get(tool)
        if spec is None:
            decision = Decision(
                effect=Effect.DENY, rule_id="TOOL-UNKNOWN",
                reason=f"工具 `{tool}` 未在沙盒注册：Agent 只能使用白名单内的工具",
            )
            self._emit(action, decision, latency=self._ms(t0))
            self._register_risk(agent_id, decision.effect, action.summary())
            return ToolResult(False, error=decision.reason, decision=decision)

        # 1a) 能力标签注入（V1.3：策略按"能力"匹配，而非只认工具名）
        action.capabilities = list(spec.capabilities)

        # 2) 策略裁决
        decision = self.engine.evaluate(action)

        # 3) 人工审批流（风险分只对"最终负面裁决"计分：驳回=deny，批准=0）
        approved_by_human = False
        if decision.effect == Effect.APPROVAL:
            self._emit(action, decision, latency=self._ms(t0), note="已挂起，等待人工审批")
            verdict, note = "reject", "没有可用的审批通道，按安全默认拒绝"
            if self.approval_handler:
                verdict, note = self.approval_handler(action, decision)
            if verdict != "approve":
                self._emit(action, decision, latency=self._ms(t0), actor="human",
                           effect_override=Effect.DENY,
                           note=f"人工驳回：{note}")
                self._register_risk(agent_id, Effect.DENY, action.summary())
                return ToolResult(False, error=f"人工审批未通过：{note}", decision=decision)
            self._emit(action, decision, latency=self._ms(t0), actor="human",
                       effect_override=Effect.ALLOW, note=f"人工审批通过：{note}")
            approved_by_human = True

        # 4) 直接拦截
        if decision.effect == Effect.DENY:
            self._emit(action, decision, latency=self._ms(t0))
            self._register_risk(agent_id, decision.effect, action.summary())
            return ToolResult(False, error=decision.reason, decision=decision)

        # 4a) 高频调用检测（V1.3 · 防"少量多次"拖取全量数据）：
        # 单次查询本就限额（≤50 行），但循环调用能绕开——滑动窗口统计敏感工具
        # 调用频率，超限即拦截并累计风险分。
        if spec.capabilities:
            freq = self.risk.note_call(agent_id, tool)
            if freq > self.high_freq_limit:
                rate_decision = Decision(
                    effect=Effect.DENY, rule_id="RATE-HIGH-FREQUENCY",
                    reason=(f"60 秒内第 {freq} 次调用 `{tool}`：疑似批量拖取数据，"
                            "已触发频率熔断（拒绝本次并累计风险分）"),
                    risk=50,
                )
                self._emit(action, rate_decision, latency=self._ms(t0))
                self._register_risk(agent_id, rate_decision.effect, action.summary())
                return ToolResult(False, error=rate_decision.reason, decision=rate_decision)

        # 5) 执行（工具内部若触发 L2 沙盒，抛 SandboxViolation）
        try:
            data = spec.fn(**args)
            output_findings: list[Finding] = []
        except SandboxViolation as sv:
            exec_decision = Decision(
                effect=Effect.DENY, rule_id="SANDBOX-EXEC",
                reason=f"受限执行沙盒拦截：{sv.reason}",
                findings=sv.findings, risk=sv.risk,
            )
            self._emit(action, exec_decision, latency=self._ms(t0), note="由 L2 执行沙盒判定")
            self._register_risk(agent_id, exec_decision.effect, action.summary())
            return ToolResult(False, error=exec_decision.reason, decision=exec_decision)
        except Exception as exc:  # noqa: BLE001 —— 工具异常也要留痕
            self._emit(action, decision, latency=self._ms(t0), note=f"工具执行异常：{exc}")
            return ToolResult(False, error=f"工具执行异常：{exc}", decision=decision)

        # 6) 成功 —— 返回给 Agent 之前，工具结果强制过输出护栏（V1.3：
        # 隔离必须内联在数据通路上——不能是 Agent"自愿调用"的接口）
        output_findings: list[Finding] = []
        if self.enforce_output_guard and data is not None:
            data, output_findings = self._sanitize_tool_output(data)
            if output_findings:
                kinds = "、".join(sorted({f.label for f in output_findings}))
                decision = Decision(
                    effect=Effect.SANITIZE,
                    rule_id=(f"{decision.rule_id}+GUARD-OUTPUT-INLINE"
                             if decision.rule_id else "GUARD-OUTPUT-INLINE"),
                    reason=f"工具结果中发现敏感信息（{kinds}），已强制脱敏后再返回给 Agent",
                    findings=decision.findings + output_findings,
                    risk=30,
                )
        self.last_tool_output = data
        self._emit(action, decision, latency=self._ms(t0))
        risk_effect = decision.effect
        if approved_by_human and not output_findings:
            risk_effect = Effect.ALLOW   # 人工批准的操作本身不罚分（保持原语义）
        self._register_risk(agent_id, risk_effect, action.summary())
        return ToolResult(True, data=data, decision=decision)

    # ------------------------------------------------------------------
    # 工具结果的强制脱敏（V1.3 内联护栏）
    # ------------------------------------------------------------------
    def _sanitize_tool_output(self, value: Any) -> tuple[Any, list[Finding]]:
        """递归扫描工具结果里的字符串，命中高危敏感信息即脱敏

        输出护栏从"Agent 自愿调用的接口"变成"数据通路上的内联关卡"——
        即使恶意 Agent 从不调用 /v1/guard/output，结果里的 PII / 密钥
        在返回之前也已被强制处理，且事件留痕可审计。
        """
        findings: list[Finding] = []

        def walk(v: Any) -> Any:
            if isinstance(v, str):
                hits = [f for f in self.output_guard.scan(v) if f.severity >= 6]
                if not hits:
                    return v
                findings.extend(hits)
                return self.output_guard.redact(v, hits)
            if isinstance(v, dict):
                return {k: walk(x) for k, x in v.items()}
            if isinstance(v, list):
                return [walk(x) for x in v]
            if isinstance(v, tuple):
                return tuple(walk(x) for x in v)
            return v

        cleaned = walk(value)
        dedup: dict[tuple[str, str], Finding] = {}
        for f in findings:   # 去重：同一敏感值多处出现只留一条证据
            dedup.setdefault((f.label, f.snippet), f)
        return cleaned, list(dedup.values())

    # ------------------------------------------------------------------
    # 门三：输出护栏（柔性监管：脱敏放行）
    # ------------------------------------------------------------------
    def guard_output(self, agent_id: str, text: str) -> GuardResult:
        action = Action(agent_id=agent_id, phase=Phase.OUTPUT, content=text)
        findings = self.output_guard.scan(text)
        high = [f for f in findings if f.severity >= 6]

        if high:
            clean = self.output_guard.redact(text, findings)
            kinds = "、".join(sorted({f.label for f in high}))
            decision = Decision(
                effect=Effect.SANITIZE, rule_id="GUARD-OUTPUT",
                reason=f"输出中发现敏感信息（{kinds}），已自动脱敏后放行",
                findings=findings, risk=30,
            )
            self._emit(action, decision)
            self._register_risk(agent_id, decision.effect, action.summary())
            return GuardResult(decision, clean)

        decision = Decision(
            effect=Effect.ALLOW, rule_id="GUARD-OUTPUT",
            reason="输出检查通过" + (f"（提示：包含 {len(findings)} 处低风险信息）" if findings else ""),
            findings=findings,
        )
        self._emit(action, decision)
        self._register_risk(agent_id, decision.effect, action.summary())
        return GuardResult(decision, text)

    # ------------------------------------------------------------------
    # 人工接管
    # ------------------------------------------------------------------
    def unfreeze(self, agent_id: str, by: str = "安全员", note: str = "") -> None:
        self.risk.unfreeze(agent_id)
        action = Action(agent_id=agent_id, phase=Phase.TOOL, meta={"human": by},
                        content=f"安全员操作：解冻 Agent（{by}）")
        decision = Decision(
            effect=Effect.ALLOW, rule_id="HUMAN-UNFREEZE",
            reason=f"{by} 人工解冻：已完成事件复核，恢复该 Agent 服务",
        )
        self._emit(action, decision, actor="human", note=note or "解冻后风险分清零")

    def freeze(self, agent_id: str, by: str = "安全员", reason: str = "") -> None:
        self.risk.freeze(agent_id, reason or "人工冻结")
        action = Action(agent_id=agent_id, phase=Phase.TOOL, meta={"human": by},
                        content=f"安全员操作：冻结 Agent（{by}）")
        decision = Decision(effect=Effect.DENY, rule_id="HUMAN-FREEZE",
                            reason=f"{by} 人工冻结：{reason}")
        self._emit(action, decision, actor="human")

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    @staticmethod
    def _ms(t0: float) -> float:
        return (time.perf_counter() - t0) * 1000

    def _emit(self, action: Action, decision: Decision, latency: float = 0.0,
              actor: str = "agent", note: str = "",
              effect_override: Effect | None = None,
              findings_extra: list[Finding] | None = None) -> Event:
        findings = list(decision.findings) + list(findings_extra or [])
        event = Event.new(
            agent_id=action.agent_id,
            phase=action.phase.value,
            tool=action.tool,
            effect=(effect_override or decision.effect).value,
            rule_id=decision.rule_id,
            reason=decision.reason,
            risk=decision.risk,
            findings=[f.as_dict() for f in findings],
            summary=action.summary(),
            action_id=action.action_id,
            latency_ms=latency,
            actor=actor,
            note=note,
            agent_risk=self.risk.score(action.agent_id),
        )
        self.audit.log(event)
        if self.on_event:
            self.on_event(event)
        return event

    def _register_risk(self, agent_id: str, effect: Effect, context: str) -> None:
        score, just_frozen = self.risk.register(agent_id, effect)
        if just_frozen:
            event = Event.new(
                agent_id=agent_id, phase="risk", tool="", effect="deny",
                rule_id="RISK-FREEZE", reason=(
                    f"Agent 累计风险分达到 {score}/100，触发自动熔断："
                    "暂停该 Agent 的全部操作，等待安全员复核"),
                risk=100, findings=[], summary=f"自动熔断（触发于：{context}）",
                actor="guard", note="需人工解冻后方可恢复", agent_risk=score,
            )
            self.audit.log(event)
            if self.on_event:
                self.on_event(event)

    # ------------------------------------------------------------------
    def stats(self) -> dict:
        return self.audit.stats()

    def export_audit(self, path: str | Path) -> Path:
        return self.audit.export_json(path)
