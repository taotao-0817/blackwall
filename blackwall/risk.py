"""
黑墙系统 BlackWall · 风险评分与自动熔断
==============================
单条规则管单次操作；风险引擎管 **agent 的长期行为**：

- 每次放行/拦截都会影响该 agent 的累计风险分（0-100）；
- 分数到达阈值 → 自动冻结该 agent（熔断），之后它的**一切**请求
  都直接被拒，直到安全员人工解冻（可以理解为"拔网线"）。

生产建议：分数应带时间衰减（如每 10 分钟 -10），并接入告警通知；
本 demo 用即时累计以方便演示。
"""
from __future__ import annotations

import threading
from collections import defaultdict

from .models import Effect

#: 不同裁决对风险分的贡献（deny 14 的取值使演示的熔断恰好发生在最后一个攻击场景）
EFFECT_WEIGHT = {
    Effect.DENY: 14,
    Effect.APPROVAL: 8,
    Effect.SANITIZE: 5,
    Effect.ALLOW: 0,
}


class RiskEngine:
    def __init__(self, freeze_threshold: int = 100):
        self.freeze_threshold = freeze_threshold
        self._score: dict[str, int] = defaultdict(int)
        self._frozen: dict[str, str] = {}     # agent_id -> 冻结原因
        self.baseline_windows: dict[str, list] = defaultdict(list)
        # 网关注解运行在 FastAPI 线程池中，register 是"读-改-写"——
        # 不串行化会在并发下丢更新（漏计风险分 → 熔断可被竞态规避）
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    def register(self, agent_id: str, effect: Effect) -> tuple[int, bool]:
        """登记一次裁决。返回 (最新风险分, 是否**刚刚**触发冻结)"""
        with self._lock:
            self._score[agent_id] = min(100, self._score[agent_id] + EFFECT_WEIGHT.get(effect, 0))
            just_frozen = False
            if self._score[agent_id] >= self.freeze_threshold and agent_id not in self._frozen:
                self._frozen[agent_id] = "风控熔断：高危行为累积风险分突破阈值"
                just_frozen = True
            return self._score[agent_id], just_frozen

    def score(self, agent_id: str) -> int:
        with self._lock:
            return self._score.get(agent_id, 0)

    def is_frozen(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._frozen

    def freeze_reason(self, agent_id: str) -> str:
        with self._lock:
            return self._frozen.get(agent_id, "")

    def freeze(self, agent_id: str, reason: str) -> None:
        with self._lock:
            self._frozen[agent_id] = reason

    def unfreeze(self, agent_id: str, keep_score_reset: bool = True) -> None:
        """人工解冻：清空冻结状态；是否清零风险分由安全员决定"""
        with self._lock:
            self._frozen.pop(agent_id, None)
            if keep_score_reset:
                self._score[agent_id] = 0
