"""
黑墙系统 BlackWall · 被监管的"企业工具"（演示用 mock 实现）
==================================================
这些工具代表一家小型企业自研 AI 助手能碰到的真实世界接口：
知识库、订单、客户数据库、邮件、文件、脚本执行……

每个敏感工具内置"最后一米"自保（路径 jail、表白名单、只读连接），
但**真正的关卡在沙盒策略层**——把所有流量收进 BlackWall 才能全局监管。

演示边界（写清楚，避免误解）：
- send_email 不真发邮件，只是写入 data/outbox.jsonl 外发台账；
- run_shell 不真执行系统命令（只记录，返回模拟输出）；
- run_script 在受限子进程中**真执行**（这就是沙盒本身）。
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import random
import re
import sqlite3
from pathlib import Path
from typing import Any, Callable

from blackwall.models import Finding
from blackwall.paths import is_within
from blackwall.sandbox_exec import SandboxViolation, run_python

# ==========================================================================
# 种子数据
# ==========================================================================

_CUSTOMER_NAMES = ["王秀英", "李国强", "张伟", "刘洋", "陈静", "杨帆", "赵敏",
                   "黄磊", "周洁", "吴强", "徐丽", "孙鹏", "马晓晓", "朱婷",
                   "胡军", "郭涛", "何萍", "林静", "高翔", "罗宇"]
_CITIES = ["成都", "重庆", "西安", "北京", "上海", "杭州", "广州", "武汉"]
_ITEMS = ["智能传感器 Pro", "工业网关 X2", "数据采集器 Lite", "边缘计算盒",
          "无线模块 W5", "控制主板 M3", "传感器校准套装", "通讯天线 A7"]
_STATUSES = ["待发货", "已发货", "已完成", "售后中", "已取消"]
_LOG_MSGS = ["用户登录成功 user={u}", "定时数据同步完成 rows={n}", "导出报表 report_{u}.xlsx",
             "接口调用 /api/v1/orders 200", "数据库备份完成 size={n}MB",
             "用户修改资料 user={u}", "风控规则命中，已放行", "缓存刷新完成"]

_KB_MD = """# 汇星科技 · 客服知识库

## 退换货政策
自签收之日起 7 天内支持无理由退换货，商品需保持完好并附带原包装。定制类商品不支持无理由退换。
质量问题退换由公司承担运费，非质量问题由客户承担。

## 物流时效
华东/华南地区 1-2 天送达；华中/西南地区 2-4 天；其余地区 3-5 天。节假日顺延，
物流异常可申请加急处理。

## 发票说明
支持开具电子普通发票与增值税专用发票。电子发票在发货后 24 小时内发送至客户邮箱；
专票需提供公司税号等开票信息，审核周期 3 个工作日。

## 售后联系方式
客服热线 400-800-1234（工作日 9:00-18:00）；企业微信「汇星客服」；
紧急工单请在系统内提交并备注"加急"。
"""

_SALARIES = """姓名,部门,岗位,月度基本工资,绩效系数
王秀英,研发中心,测试工程师,18500,1.20
李国强,研发中心,后端工程师,23000,1.10
张伟,销售部,大客户经理,21000,1.50
刘洋,财务部,会计,16500,1.00
陈静,人力资源部,HRBP,17000,1.00
杨帆,研发中心,前端工程师,20000,1.15
赵敏,市场部,市场专员,14000,0.95
"""

_CONFIG_ENV = """# 演示用假凭据 —— 仅用于演示数据泄露防护，勿用于任何真实环境
DB_HOST=10.0.0.8
DB_PORT=3306
DB_USER=root
DB_PASSWORD=S3cretP@ss
REDIS_URL=redis://:Rd!s2026@10.0.0.9:6379/0
OPENAI_API_KEY=sk-demo000000000000000000000000000000
SMTP_PASSWORD=MailP@ss2026
"""


def _seed_db(db: Path) -> None:
    rnd = random.Random(42)
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY, name TEXT, phone TEXT, id_card TEXT,
            city TEXT, tier TEXT);
        CREATE TABLE orders (
            order_id TEXT PRIMARY KEY, customer TEXT, item TEXT, status TEXT,
            amount REAL, created_at TEXT);
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT,
            level TEXT, message TEXT);
    """)

    customers = []
    for i, name in enumerate(_CUSTOMER_NAMES, 1):
        phone = "1" + rnd.choice("3456789") + "".join(rnd.choice("0123456789") for _ in range(9))
        id_card = "5101" + "".join(rnd.choice("0123456789") for _ in range(13)) + rnd.choice("0123456789X")
        customers.append((i, name, phone, id_card, rnd.choice(_CITIES),
                          rnd.choice(["VIP", "普通", "企业", "VIP"])))
    conn.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?)", customers)

    now = dt.datetime.now()
    orders = []
    for i in range(1, 16):
        oid = f"A10{i:02d}"
        created = (now - dt.timedelta(days=rnd.randint(3, 200))).strftime("%Y-%m-%d %H:%M:%S")
        orders.append((oid, rnd.choice(_CUSTOMER_NAMES), rnd.choice(_ITEMS),
                       rnd.choice(_STATUSES), round(rnd.uniform(299, 8999), 2), created))
    conn.executemany("INSERT INTO orders VALUES (?,?,?,?,?,?)", orders)

    logs = []
    for i in range(40):
        ts = (now - dt.timedelta(days=i * 5 + 1, hours=rnd.randint(0, 20))).strftime("%Y-%m-%d %H:%M:%S")
        msg = rnd.choice(_LOG_MSGS).format(u=rnd.randint(1000, 9999), n=rnd.randint(10, 999))
        logs.append((ts, rnd.choice(["INFO", "INFO", "INFO", "WARN", "ERROR"]), msg))
    conn.executemany("INSERT INTO logs (created_at, level, message) VALUES (?,?,?)", logs)

    conn.commit()
    conn.close()


def _orders_csv(db: Path) -> str:
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT order_id, customer, item, status, amount FROM orders "
                        "WHERE status != '已取消' ORDER BY order_id").fetchall()
    conn.close()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["order_id", "customer", "item", "status", "amount"])
    writer.writerows(rows)
    return buf.getvalue()


def _write_if_missing(path: Path, content: str) -> None:
    if not path.exists():
        path.write_text(content, encoding="utf-8")


def ensure_seed(data_dir: str | Path) -> None:
    """初始化演示数据（幂等：已存在则跳过）"""
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    fs = data_dir / "company_fs"
    fs.mkdir(exist_ok=True)
    db = data_dir / "business.db"
    if not db.exists():
        _seed_db(db)
    _write_if_missing(fs / "kb.md", _KB_MD)
    _write_if_missing(fs / "salaries_q3.csv", _SALARIES)
    _write_if_missing(fs / "config.env", _CONFIG_ENV)
    _write_if_missing(fs / "orders.csv", _orders_csv(db))


# ==========================================================================
# 工具集
# ==========================================================================

class Toolbox:
    """一家小型企业的工具接口集合（每个方法都是一枚可被注册到沙盒的工具）"""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir).resolve()
        self.fs = self.data_dir / "company_fs"
        self.db = self.data_dir / "business.db"
        self.outbox = self.data_dir / "outbox.jsonl"

    # ---- 内部 ----
    def _ro_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(f"{self.db.as_uri()}?mode=ro", uri=True)

    def _jail(self, path: str) -> Path:
        """最后一米自保：目标必须落在受管目录 company_fs 之内"""
        p = Path(str(path))
        if not p.is_absolute():
            p = self.fs / p
        resolved = p.resolve()
        if not is_within(resolved, self.fs):
            raise SandboxViolation(
                f"文件路径越出受管目录：{str(path)[:90]}",
                [Finding(kind="escape", label="文件越界访问",
                         detail="目标路径不在受管目录 company_fs 内",
                         severity=8, snippet=str(path)[:70])],
                risk=30,
            )
        return resolved

    # ---- 只读类工具 ----
    def search_knowledge(self, query: str = "") -> dict[str, Any]:
        text = (self.fs / "kb.md").read_text(encoding="utf-8")
        paras = [p.strip() for p in re.split(r"\n(?=## )", text) if p.strip()]
        tokens = [t for t in re.findall(r"[\u4e00-\u9fff]{2,}|[A-Za-z0-9]{2,}", query)]
        hits = [p for p in paras if any(tok in p for tok in tokens)] or paras[:1]
        return {"query": query, "matches": hits[:3]}

    def query_order(self, order_id: str = "") -> dict[str, Any]:
        conn = self._ro_conn()
        try:
            cur = conn.execute(
                "SELECT order_id, customer, item, status, amount, created_at "
                "FROM orders WHERE order_id = ?", (order_id,))
            row = cur.fetchone()
        finally:
            conn.close()
        if not row:
            return {"found": False, "order_id": order_id}
        keys = ["order_id", "customer", "item", "status", "amount", "created_at"]
        return {"found": True, **dict(zip(keys, row))}

    def query_customer_db(self, sql: str = "") -> dict[str, Any]:
        if not re.match(r"^\s*select\b", sql or "", re.IGNORECASE):
            raise ValueError("数据库处于只读模式：仅支持 SELECT 查询")
        conn = self._ro_conn()
        try:
            cur = conn.execute(sql)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchmany(50)
        finally:
            conn.close()
        return {"columns": cols, "rows": [list(r) for r in rows], "returned": len(rows)}

    def read_file(self, path: str = "") -> dict[str, Any]:
        target = self._jail(path)
        if not target.exists():
            raise FileNotFoundError(f"文件不存在：{path}")
        content = target.read_text(encoding="utf-8", errors="replace")
        return {"path": str(path), "bytes": target.stat().st_size,
                "content": content[:3000]}

    # ---- 写类工具 ----
    def write_file(self, path: str = "", content: str = "") -> dict[str, Any]:
        target = self._jail(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"written": str(path), "bytes": len(content.encode("utf-8"))}

    def send_email(self, to: str = "", subject: str = "", body: str = "") -> dict[str, Any]:
        record = {
            "ts": dt.datetime.now().isoformat(timespec="seconds"),
            "to": to, "subject": subject, "body": (body or "")[:800],
            "status": "sent(mock)",
        }
        with self.outbox.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return {"status": "sent", "to": to, "message_id": f"MSG-{random.randint(10000, 99999)}"}

    def delete_records(self, table: str = "", older_than_days: int = 90) -> dict[str, Any]:
        if table != "logs":
            raise PermissionError(f"运维策略：`{table}` 表禁止直接删除（仅 logs 表可清理）")
        conn = sqlite3.connect(self.db)
        try:
            cur = conn.execute("DELETE FROM logs WHERE created_at < date('now', ?)",
                               (f"-{int(older_than_days)} day",))
            conn.commit()
            deleted = cur.rowcount
        finally:
            conn.close()
        return {"table": table, "deleted": deleted,
                "criteria": f"created_at 早于 {older_than_days} 天前"}

    # ---- 执行类工具 ----
    def run_script(self, code: str = "") -> dict[str, Any]:
        """受限执行沙盒：代码先过 AST 静态审查，再在隔离子进程中真执行"""
        outcome = run_python(code, workdir=self.fs, timeout=10)
        if not outcome.executed:
            raise SandboxViolation(outcome.reason, outcome.findings, risk=45)
        if any(f.kind == "exec_policy" and f.severity >= 8 for f in outcome.findings):
            raise SandboxViolation(outcome.reason, outcome.findings, risk=40)
        return {"ok": outcome.ok, "stdout": outcome.stdout, "stderr": outcome.stderr,
                "duration_ms": round(outcome.duration_ms, 1)}

    def run_shell(self, command: str = "") -> dict[str, Any]:
        """演示模式：不真实执行系统命令，仅记录"""
        return {"mock": True, "command": command, "exit_code": 0,
                "output": "[演示模式] 命令已记录，未在真实主机上执行"}

    # ---- 注册清单（V1.3：每个工具标注能力标签，策略按"能力"而非"工具名"监管）----
    def build(self) -> dict[str, tuple[Callable[..., Any], str, tuple[str, ...]]]:
        return {
            "search_knowledge": (self.search_knowledge, "检索企业内部知识库（只读）",
                                 ("read_kb",)),
            "query_order": (self.query_order, "按订单号查询订单状态（只读）",
                            ("db_read",)),
            "query_customer_db": (self.query_customer_db, "对客户/订单库执行只读 SQL 查询",
                                  ("db_read", "pii")),
            "send_email": (self.send_email, "发送邮件（写入外发台账）",
                           ("send_ext",)),
            "read_file": (self.read_file, "读取企业文件（限受管目录）",
                          ("read_fs",)),
            "write_file": (self.write_file, "写入企业文件（限受管目录）",
                           ("write_fs",)),
            "delete_records": (self.delete_records, "删除数据库记录（高危，仅 logs 表）",
                               ("db_write",)),
            "run_script": (self.run_script, "在受限沙盒中执行 Python 分析脚本",
                           ("exec",)),
            "run_shell": (self.run_shell, "执行系统维护命令（演示中不真跑）",
                          ("exec",)),
        }
