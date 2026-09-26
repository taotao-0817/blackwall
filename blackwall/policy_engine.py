"""
黑墙系统 BlackWall · 策略引擎
====================
企业通过一份 JSON 策略包描述"谁、在什么阶段、对什么工具/资源、做什么 → 怎么办"。
引擎对每个 Action 逐条求值，取**最严格**的裁决（deny > approval > sanitize > allow）。

规则结构::

    {
      "id": "DENY-EXFIL-CUSTOMER",
      "description": "...",
      "effect": "deny",              # allow / sanitize / approval / deny
      "risk": 30,                    # 命中后对本次操作的风险贡献
      "reason": "人类可读的拦截原因",
      "match": {
        "phases": ["tool"],          # 阶段过滤（可省略=任意）
        "tools":  ["send_email", "http_*"],       # fnmatch 通配（可省略=任意）
        "arg_regex":     {"body": ["客户|身份证"]},# 每个 arg 都要命中（组内 OR、组间 AND）
        "arg_regex_not": {"to":   ["@company\\.com"]},  # arg 命中其中任一 → 规则不适用（白名单排除）
        "resource_globs": ["*salaries*"],          # 路径参数命中任一 glob 即适用
        "content_regex":  ["删除所有"]             # 对整段文本（工具名+参数+内容）匹配
      }
    }

匹配语义为"证据式"：命中越多的规则组合，风险分叠加。
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from .models import Action, Decision, Effect, EFFECT_SEVERITY, Finding


class Rule:
    def __init__(self, raw: dict):
        self.id: str = raw["id"]
        self.description: str = raw.get("description", "")
        self.effect = Effect(raw.get("effect", "allow"))
        self.risk: int = int(raw.get("risk", 0))
        self.reason: str = raw.get("reason", self.description)
        self.enabled: bool = raw.get("enabled", True)

        m = raw.get("match", {})
        self.tools: list[str] | None = m.get("tools")
        self.phases: list[str] | None = m.get("phases")
        self.arg_regex: dict[str, list[re.Pattern]] = {
            k: [re.compile(p, re.IGNORECASE) for p in v]
            for k, v in m.get("arg_regex", {}).items()
        }
        self.arg_regex_not: dict[str, list[re.Pattern]] = {
            k: [re.compile(p, re.IGNORECASE) for p in v]
            for k, v in m.get("arg_regex_not", {}).items()
        }
        self.resource_globs: list[str] = m.get("resource_globs", [])
        self.content_regex: list[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in m.get("content_regex", [])
        ]

    # ------------------------------------------------------------------
    def matches(self, action: Action) -> tuple[bool, list[str]]:
        """返回 (规则是否适用, 命中证据列表)"""
        if not self.enabled:
            return False, []

        if self.phases and action.phase.value not in self.phases:
            return False, []
        if self.tools and not any(fnmatch.fnmatch(action.tool, t) for t in self.tools):
            return False, []

        hits: list[str] = []
        str_args = {k: str(v) for k, v in action.args.items()}

        # 必中字段（AND）
        for arg, pats in self.arg_regex.items():
            value = str_args.get(arg, "")
            hit = next((m for p in pats for m in [p.search(value)] if m), None)
            if hit is None:
                return False, []
            hits.append(f"{arg}≈“{hit.group(0)[:40]}”")

        # 白名单排除字段（命中任一 → 规则不适用）
        for arg, pats in self.arg_regex_not.items():
            value = str_args.get(arg, "")
            if any(p.search(value) for p in pats):
                return False, []
            hits.append(f"{arg}=“{value[:40]}” 命中限制条件")

        # 路径 glob（任一路径参数匹配即适用；无路径参数则规则不适用）
        if self.resource_globs:
            paths = action.path_args()
            matched = next(
                (p for p in paths
                 for g in self.resource_globs
                 if fnmatch.fnmatch(p.lower(), g.lower())),
                None,
            )
            if matched is None:
                return False, []
            hits.append(f"path≈“{matched[:60]}”")

        # 全文正则（任一命中）
        if self.content_regex:
            text = action.payload_text()
            hit = next((m for p in self.content_regex for m in [p.search(text)] if m), None)
            if hit is None:
                return False, []
            hits.append(f"文本≈“{hit.group(0)[:40]}”")

        return True, hits


class PolicyEngine:
    """加载策略包并对 Action 求值"""

    def __init__(self, policy_path: str | Path):
        self.policy_path = Path(policy_path)
        self.name = "未命名策略包"
        self.version = "0"
        self.default_effect = Effect.ALLOW
        self.rules: list[Rule] = []
        self.load()

    def load(self) -> None:
        raw = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.name = raw.get("name", self.name)
        self.version = raw.get("version", self.version)
        self.default_effect = Effect(raw.get("default_effect", "allow"))
        self.rules = [Rule(r) for r in raw.get("rules", [])]

    # ------------------------------------------------------------------
    def evaluate(self, action: Action) -> Decision:
        matched: list[tuple[Rule, list[str]]] = []
        for rule in self.rules:
            ok, hits = rule.matches(action)
            if ok:
                matched.append((rule, hits))

        if not matched:
            return Decision(
                effect=self.default_effect,
                reason="未命中任何限制规则，按默认策略放行",
                rule_id="DEFAULT",
            )

        best_rule, _best_hits = max(matched, key=lambda t: EFFECT_SEVERITY[t[0].effect])
        risk = min(100, sum(r.risk for r, _ in matched))
        rule_ids = ",".join(r.id for r, _ in matched)

        reason = best_rule.reason
        if len(matched) > 1:
            others = ", ".join(r.id for r, _ in matched if r is not best_rule)
            reason += f"（同时命中: {others}）"

        findings = [
            Finding(
                kind="policy", label=rule.id,
                detail="命中证据：" + "；".join(hits),
                severity=max(3, min(10, rule.risk // 5)),
                snippet="；".join(hits)[:80],
            )
            for rule, hits in matched
        ]
        return Decision(
            effect=best_rule.effect,
            reason=reason,
            rule_id=rule_ids,
            risk=risk,
            findings=findings,
        )
