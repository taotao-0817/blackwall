"""
黑墙系统 BlackWall · 审计存储（SQLite）
=============================
每一次经过沙盒的动作——放行的、拦截的、脱敏的、审批的——都落一条不可省略的
审计记录。监管的本质是"可追溯"：出了事能回答"谁、何时、想做什么、系统怎么裁决"。
"""
from __future__ import annotations

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
    note       TEXT
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
            self.conn.commit()

    # ------------------------------------------------------------------
    def log(self, event: Event) -> int:
        with self._lock:
            cur = self.conn.execute(
                """INSERT INTO events
                   (ts, agent_id, phase, tool, effect, rule_id, reason, risk, agent_risk,
                    findings, summary, action_id, latency_ms, actor, note)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.ts, event.agent_id, event.phase, event.tool, event.effect,
                    event.rule_id, event.reason, event.risk, event.agent_risk,
                    json.dumps(event.findings, ensure_ascii=False), event.summary,
                    event.action_id, event.latency_ms, event.actor, event.note,
                ),
            )
            self.conn.commit()
            return cur.lastrowid

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
