"""
黑墙系统 BlackWall · 审计存储（SQLite）
=============================
每一次经过沙盒的动作——放行的、拦截的、脱敏的、审批的——都落一条不可省略的
审计记录。监管的本质是"可追溯"：出了事能回答"谁、何时、想做什么、系统怎么裁决"。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

from .models import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    agent_id   TEXT    NOT NULL,
    phase      TEXT    NOT NULL,
    tool       TEXT,
    effect     TEXT    NOT NULL,
    rule_id    TEXT,
    reason     TEXT,
    risk       INTEGER DEFAULT 0,
    agent_risk INTEGER DEFAULT 0,
    findings   TEXT,
    summary    TEXT,
    action_id  TEXT,
    latency_ms REAL DEFAULT 0,
    actor      TEXT DEFAULT 'agent',
    note       TEXT,
    prev_hash  TEXT,
    self_hash  TEXT
);
"""


class AuditLog:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False：网关（FastAPI 线程池）会跨线程访问同一连接；
        # 并发访问由 RLock 串行化（可重入，便于 export_json 等嵌套调用）
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._lock = threading.RLock()
        with self._lock:
            self.conn.execute(_SCHEMA)
            # V1.3 老库迁移：补哈希链列（幂等）
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(events)")}
            if "prev_hash" not in cols:
                self.conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT")
            if "self_hash" not in cols:
                self.conn.execute("ALTER TABLE events ADD COLUMN self_hash TEXT")
            self.conn.commit()

    # ------------------------------------------------------------------
    def log(self, event: Event) -> int:
        with self._lock:
            tup = (event.ts, event.agent_id, event.phase, event.tool, event.effect,
                   event.rule_id, event.reason, event.risk, event.agent_risk,
                   json.dumps(event.findings, ensure_ascii=False), event.summary,
                   event.action_id, event.latency_ms, event.actor, event.note)
            prev = self._last_hash()
            self_hash = self._chain_hash(prev, tup)      # V1.3：哈希链（防篡改）
            cur = self.conn.execute(
                """INSERT INTO events
                   (ts, agent_id, phase, tool, effect, rule_id, reason, risk, agent_risk,
                    findings, summary, action_id, latency_ms, actor, note,
                    prev_hash, self_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*tup, prev, self_hash),
            )
            self.conn.commit()
            return cur.lastrowid

    def _last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT self_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        return (row[0] or "") if row else ""

    @staticmethod
    def _chain_hash(prev: str, values: tuple) -> str:
        payload = json.dumps(list(values), ensure_ascii=False, default=str)
        return hashlib.sha256(f"{prev}|{payload}".encode("utf-8")).hexdigest()

    def verify_chain(self) -> dict:
        """校验审计哈希链完整性（V1.3 防篡改）

        每条记录的 self_hash = SHA256(前一条的 self_hash + 本条内容)：
        —— 删除/修改/重排任何一条记录都会在链上留下断点。
        返回 {"ok", "checked", "broken_at", "reason"}。
        """
        with self._lock:
            cur = self.conn.execute(
                """SELECT id, ts, agent_id, phase, tool, effect, rule_id, reason,
                          risk, agent_risk, findings, summary, action_id,
                          latency_ms, actor, note, prev_hash, self_hash
                   FROM events ORDER BY id""")
            prev = ""
            checked = 0
            for row in cur.fetchall():
                (row_id, ts, agent_id, phase, tool, effect, rule_id, reason, risk,
                 agent_risk, findings, summary, action_id, latency_ms, actor, note,
                 row_prev, row_self) = row
                if row_self is None:
                    continue     # V1.3 迁移前的旧记录（未参与链）
                tup = (ts, agent_id, phase, tool, effect, rule_id, reason, risk,
                       agent_risk, findings, summary, action_id, latency_ms, actor, note)
                if row_prev != prev:
                    return {"ok": False, "checked": checked, "broken_at": row_id,
                            "reason": f"#{row_id} 前序哈希不衔接（有记录被删除或置换）"}
                if row_self != self._chain_hash(prev, tup):
                    return {"ok": False, "checked": checked, "broken_at": row_id,
                            "reason": f"#{row_id} 内容校验失败（记录被篡改）"}
                prev = row_self
                checked += 1
            return {"ok": True, "checked": checked, "broken_at": None,
                    "reason": "哈希链完整"}

    def rows(self) -> list[dict]:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM events ORDER BY id")
            cols = [c[0] for c in cur.description]
            out = []
            for row in cur.fetchall():
                d = dict(zip(cols, row))
                d["findings"] = json.loads(d["findings"] or "[]")
                out.append(d)
            return out

    def stats(self) -> dict:
        with self._lock:
            cur = self.conn.execute(
                "SELECT effect, COUNT(*) FROM events GROUP BY effect")
            by_effect = dict(cur.fetchall())
            cur = self.conn.execute("SELECT COUNT(*) FROM events")
            total = cur.fetchone()[0]
            cur = self.conn.execute(
                """SELECT rule_id, COUNT(*) c FROM events
                   WHERE effect IN ('deny','approval') AND rule_id != 'DEFAULT'
                   GROUP BY rule_id ORDER BY c DESC LIMIT 10""")
            top_rules = cur.fetchall()
            cur = self.conn.execute(
                "SELECT COUNT(DISTINCT agent_id) FROM events WHERE effect='deny'")
            offenders = cur.fetchone()[0]
        return {
            "total": total,
            "by_effect": by_effect,
            "top_rules": [{"rule_id": r, "count": c} for r, c in top_rules],
            "agents_with_deny": offenders,
        }

    def export_json(self, path: str | Path) -> Path:
        with self._lock:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "exported_at": time.time(),
                "stats": self.stats(),
                "events": self.rows(),
            }
            path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
            return path

    def close(self) -> None:
        self.conn.close()
