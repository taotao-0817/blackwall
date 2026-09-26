# -*- coding: utf-8 -*-
"""
黑墙系统 · AI 安全风控报告生成器
==================================
把审计库（data/audit.db）的数据自动生成一份**给管理层看**的中文风控报告
（自包含 HTML，浏览器打开可另存为 PDF / 直接打印）。

    python report.py                  # 全量数据 → data/reports/
    python report.py --days 30        # 仅最近 30 天
    python report.py --out D:/报告.html

设计定位：监控大屏（深色）给安全工程师看实时；
本报告（浅色、A4 排版友好）给管理层和客户看结论——"本月拦了多少、拦在哪、要不要动"。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import time
from collections import Counter, OrderedDict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "data" / "audit.db"
DEFAULT_OUT_DIR = ROOT / "data" / "reports"

EFFECT_CN = {"allow": "放行", "deny": "拦截", "approval": "审批", "sanitize": "脱敏"}
EFFECT_COLOR = {"allow": "#1a9d63", "deny": "#d3334b", "approval": "#d99a06", "sanitize": "#7a52d1"}
PHASE_CN = {"input": "输入", "tool": "工具", "exec": "执行", "output": "输出", "risk": "风控"}
PHASE_COLOR = {"input": "#2b6cd4", "tool": "#002FA7", "exec": "#7a52d1", "output": "#d99a06", "risk": "#d3334b"}

# ==========================================================================
# 数据
# ==========================================================================

def load_events(db_path: Path, days: int = 0) -> list[dict]:
    if not Path(db_path).exists():
        raise SystemExit(f"审计库不存在：{db_path}（先运行 python demo.py 或 python server.py 产生数据）")
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id")]
    conn.close()
    if days > 0:
        cutoff = time.time() - days * 86400
        rows = [r for r in rows if r["ts"] >= cutoff]
    for r in rows:
        try:
            r["findings"] = json.loads(r["findings"] or "[]")
        except (json.JSONDecodeError, TypeError):
            r["findings"] = []
    return rows


def analyze(events: list[dict]) -> dict:
    total = len(events)
    by_effect = Counter(e["effect"] for e in events)
    by_phase = Counter(e["phase"] for e in events)

    rules = Counter()
    for e in events:
        if e["effect"] in ("deny", "approval") and e["rule_id"]:
            for rid in str(e["rule_id"]).split(","):
                rid = rid.strip()
                if rid and rid != "DEFAULT":
                    rules[rid] += 1

    agents = Counter(e["agent_id"] for e in events)
    peak = max((e["agent_risk"] or 0 for e in events), default=0)
    freezes = sum(1 for e in events if e["rule_id"] == "RISK-FREEZE")
    unfreezes = sum(1 for e in events if e["rule_id"] == "HUMAN-UNFREEZE")

    human_events = [e for e in events if e["actor"] == "human"]
    approved = sum(1 for e in human_events if "批准" in (e["note"] or ""))
    rejected = sum(1 for e in human_events if "驳回" in (e["note"] or ""))

    lat = [e["latency_ms"] for e in events if e.get("latency_ms")]
    avg_lat = sum(lat) / len(lat) if lat else 0.0

    span = (max(e["ts"] for e in events) - min(e["ts"] for e in events)) if events else 0

    return {
        "total": total, "by_effect": by_effect, "by_phase": by_phase,
        "rules": rules, "agents": agents, "peak": peak,
        "freezes": freezes, "unfreezes": unfreezes,
        "human_count": len(human_events), "approved": approved, "rejected": rejected,
        "avg_lat": avg_lat, "span_s": span,
        "ts_min": min((e["ts"] for e in events), default=time.time()),
        "ts_max": max((e["ts"] for e in events), default=time.time()),
    }


# ==========================================================================
# HTML 片段
# ==========================================================================

def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _kpis_html(a: dict) -> str:
    deny_rate = (a["by_effect"].get("deny", 0) / a["total"] * 100) if a["total"] else 0
    items = [
        ("监管行为总量", f"{a['total']}", "次"),
        ("安全拦截", f"{a['by_effect'].get('deny', 0)}", f"占 {deny_rate:.1f}%"),
        ("自动脱敏放行", f"{a['by_effect'].get('sanitize', 0)}", "次"),
        ("人工干预", f"{a['human_count']}", f"批准 {a['approved']} / 驳回 {a['rejected']}"),
        ("风险峰值", f"{a['peak']}", "/ 100"),
        ("自动熔断", f"{a['freezes']}", f"解冻 {a['unfreezes']} 次"),
    ]
    return "\n".join(
        f'<div class="kpi"><div class="v">{v}</div><div class="l">{l}'
        f'{" · " + s if s else ""}</div></div>' for l, v, s in items)


def _ring_html(a: dict) -> tuple[str, str]:
    counts = {k: a["by_effect"].get(k, 0) for k in ("allow", "deny", "approval", "sanitize")}
    total = sum(counts.values()) or 1
    acc, segs = 0.0, []
    for k in ("allow", "deny", "approval", "sanitize"):
        s0 = acc
        acc += counts[k] / total * 360
        segs.append(f"{EFFECT_COLOR[k]} {s0:.1f}deg {acc:.1f}deg")
    ring = f'<div class="ring" style="background:conic-gradient({",".join(segs)})"><b>{total}</b></div>'
    legend = "".join(
        f'<li><i style="background:{EFFECT_COLOR[k]}"></i>{EFFECT_CN[k]}<b>{counts[k]}</b></li>'
        for k in ("allow", "deny", "approval", "sanitize"))
    return ring, legend


def _phase_bars_html(a: dict) -> str:
    total = a["total"] or 1
    rows = []
    for k in ("input", "tool", "exec", "output", "risk"):
        n = a["by_phase"].get(k, 0)
        if not n:
            continue
        rows.append(
            f'<div class="phase-row"><span class="pn">{PHASE_CN[k]}</span>'
            f'<span class="pb"><i style="width:{n / total * 100:.0f}%;background:{PHASE_COLOR[k]}"></i></span>'
            f'<span class="pc">{n}</span></div>')
    return "".join(rows) or '<div class="muted">无数据</div>'


def _risk_svg(events: list[dict]) -> str:
    rs = [e["agent_risk"] or 0 for e in events]
    if not rs:
        return ""
    W, H, PAD = 380, 110, 10
    n = len(rs)
    maxr = max(100, max(rs))
    pts = [(PAD + (W - 2 * PAD) * (i / (n - 1) if n > 1 else 0.5),
            H - PAD - (H - 2 * PAD) * (r / maxr)) for i, r in enumerate(rs)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    y100 = H - PAD - (H - 2 * PAD) * (100 / maxr)
    return f'''<svg viewBox="0 0 {W} {H}" class="risksvg">
  <line x1="{PAD}" y1="{y100:.1f}" x2="{W - PAD}" y2="{y100:.1f}" stroke="#d3334b" stroke-width="1" stroke-dasharray="4 4" opacity=".6"/>
  <text x="{W - PAD}" y="{y100 - 4:.1f}" text-anchor="end" font-size="9" fill="#d3334b">熔断线 100</text>
  <polygon points="{PAD},{H - PAD} {line} {W - PAD},{H - PAD}" fill="rgba(0,47,167,.10)"/>
  <polyline points="{line}" fill="none" stroke="#002FA7" stroke-width="2" stroke-linejoin="round"/>
</svg>'''


def _rules_html(a: dict) -> str:
    top = a["rules"].most_common(8)
    if not top:
        return '<div class="muted">本周期无拦截/审批记录</div>'
    mx = top[0][1]
    return "".join(
        f'<div class="rule-row"><span class="rn">{rid}</span>'
        f'<span class="rb"><i style="width:{n / mx * 100:.0f}%"></i></span>'
        f'<span class="rc">×{n}</span></div>' for rid, n in top)


def _detail_rows(events: list[dict], limit: int = 24) -> str:
    picks = [e for e in events if e["effect"] == "deny" or e["actor"] == "human"]
    picks = picks[-limit:]
    if not picks:
        return '<tr><td colspan="5" class="muted">无拦截/人工干预记录</td></tr>'
    rows = []
    for e in picks:
        eff = e["effect"] if e["actor"] != "human" else "human"
        badge = {"deny": '<span class="b b-deny">拦截</span>',
                 "human": '<span class="b b-human">人工</span>'}.get(eff, eff)
        actor = "值班员" if e["actor"] == "human" else e["agent_id"]
        summary = (e["summary"] or "").replace("<", "&lt;")[:88]
        reason = (e["reason"] or "").replace("<", "&lt;")[:96]
        rows.append(f'<tr><td class="t">{_fmt(e["ts"])}</td><td>{actor}</td>'
                    f'<td class="s">{summary}</td><td>{badge}</td><td class="r">{reason}</td></tr>')
    return "".join(rows)


def _advice(a: dict) -> list[str]:
    adv = []
    if a["rules"]:
        rid, n = a["rules"].most_common(1)[0]
        adv.append(f"拦截集中在规则 <b>{rid}</b>（{n} 次）。建议复核对应业务流程，确认是否存在诱导性输入、越权偏好或流程设计缺陷。")
    if a["by_effect"].get("sanitize", 0):
        adv.append(f"发生 {a['by_effect']['sanitize']} 次输出脱敏。建议检查业务系统的回复链路，确认是否携带了非必要的个人信息字段（如客户手机号、证件号）。")
    if a["freezes"]:
        adv.append(f"触发自动熔断 {a['freezes']} 次、人工解冻 {a['unfreezes']} 次。建议对相关消息入口加固输入过滤，并复盘防御链路响应时长。")
    if a["rejected"]:
        adv.append(f"存在 {a['rejected']} 次人工驳回记录。建议排查发起方账号与来源渠道，必要时临时冻结相关凭证。")
    if not adv:
        adv.append("本周期运行平稳，未出现需要处置的异常。建议保持现有策略，并关注月度趋势变化（拦截率突升往往先于安全事故）。")
    return adv


def _trend_html(events: list[dict]) -> tuple[str, bool]:
    if not events:
        return "", False
    t0, t1 = events[0]["ts"], events[-1]["ts"]
    if t1 - t0 < 3600 * 8:
        return "", False
    by_day = OrderedDict()
    day = datetime.fromtimestamp(t0).date()
    end = datetime.fromtimestamp(t1).date()
    while day <= end:
        by_day[day] = [0, 0]
        day += timedelta(days=1)
    for e in events:
        d = datetime.fromtimestamp(e["ts"]).date()
        if d in by_day:
            by_day[d][0] += 1
            if e["effect"] in ("deny", "approval"):
                by_day[d][1] += 1
    mx = max((v[0] for v in by_day.values()), default=1) or 1
    bars = []
    for d, (tot, risk) in by_day.items():
        hb = tot / mx * 100
        hr = (risk / tot * 100) if tot else 0
        bars.append(
            f'<div class="day"><div class="stack">'
            f'<i class="risk" style="height:{hb * hr / 100:.1f}%"></i>'
            f'<i class="ok" style="height:{hb * (1 - hr / 100):.1f}%"></i></div>'
            f'<span>{d.strftime("%m-%d")}</span></div>')
    return f'<div class="days">{"".join(bars)}</div>', True


# ==========================================================================
# 模板
# ==========================================================================

TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ · 黑墙系统</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#eef2f8;color:#1c2536;font:14px/1.75 system-ui,"Segoe UI","Microsoft YaHei",sans-serif}
  .page{max-width:920px;margin:28px auto;background:#fff;padding:46px 54px 40px;
        box-shadow:0 4px 30px rgba(18,40,90,.10);border-radius:4px}
  .topbar{height:4px;background:linear-gradient(90deg,#002FA7,#2b8ce0 70%,#22d0e0);border-radius:2px}
  header{margin:20px 0 6px}
  .brand{font-size:12.5px;color:#5a6b8c;letter-spacing:.5px}
  .brand b{color:#002FA7;font-size:14px}
  h1{font-size:25px;color:#12234d;margin:10px 0 8px;letter-spacing:1px}
  .meta{font-size:12px;color:#7b89a6;border-bottom:1px solid #e4eaf4;padding-bottom:16px}
  .meta span{margin-right:18px}
  .kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:22px 0 6px}
  .kpi{border:1px solid #e4eaf4;border-radius:10px;padding:14px 16px;background:#fbfcfe}
  .kpi .v{font-size:26px;font-weight:800;color:#002FA7;font-family:Consolas,monospace}
  .kpi .l{font-size:12px;color:#6b7a99;margin-top:2px}
  h2{font-size:15px;color:#002FA7;margin:34px 0 14px;padding-bottom:8px;border-bottom:1px solid #e4eaf4}
  .summary{background:#f4f7fd;border-left:4px solid #002FA7;border-radius:0 10px 10px 0;
           padding:15px 20px;color:#26344f}
  .summary b{color:#c0243d}
  .cols{display:grid;grid-template-columns:250px 1fr;gap:26px;align-items:center}
  .ring-wrap{display:flex;flex-direction:column;align-items:center;gap:12px}
  .ring{width:150px;height:150px;border-radius:50%;position:relative;display:grid;place-items:center}
  .ring::after{content:"";position:absolute;inset:32px;border-radius:50%;background:#fff}
  .ring b{position:relative;z-index:1;font-size:22px;font-family:Consolas,monospace;color:#12234d}
  ul.legend{list-style:none;font-size:12.5px;color:#4a5a7c;width:100%}
  ul.legend li{display:flex;align-items:center;gap:8px;margin:4px 0}
  ul.legend i{width:10px;height:10px;border-radius:3px}
  ul.legend b{margin-left:auto;color:#12234d;font-family:Consolas,monospace}
  .phase-row{display:flex;align-items:center;gap:10px;margin:8px 0;font-size:12.5px}
  .pn{width:36px;color:#4a5a7c;flex:0 0 auto}
  .pb{flex:1;height:10px;background:#eef2f9;border-radius:5px;overflow:hidden}
  .pb i{display:block;height:100%;border-radius:5px}
  .pc{width:32px;text-align:right;color:#12234d;font-family:Consolas,monospace}
  .risksvg{width:100%;max-width:430px;display:block;margin:8px auto 0}
  .rule-row{display:flex;align-items:center;gap:10px;margin:8px 0;font-size:12.5px}
  .rn{flex:0 0 210px;color:#33415e;font-family:Consolas,monospace;font-size:11.5px;
      white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .rb{flex:1;height:10px;background:#eef2f9;border-radius:5px;overflow:hidden}
  .rb i{display:block;height:100%;border-radius:5px;background:linear-gradient(90deg,#002FA7,#2b8ce0)}
  .rc{width:36px;text-align:right;font-family:Consolas,monospace;color:#c0243d}
  table{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}
  th{background:#f4f7fd;color:#33415e;text-align:left;padding:8px 10px;font-weight:600;
     border-bottom:1px solid #e4eaf4}
  td{padding:7px 10px;border-bottom:1px solid #f0f4fa;vertical-align:top}
  td.t{color:#7b89a6;font-family:Consolas,monospace;font-size:11px;white-space:nowrap}
  td.s{color:#12234d;max-width:250px}
  td.r{color:#8a5a00;max-width:250px}
  .b{font-size:11px;padding:1px 8px;border-radius:20px;white-space:nowrap}
  .b-deny{background:#fdeef1;color:#c0243d;border:1px solid #f6c9d4}
  .b-human{background:#fff6e6;color:#a06a00;border:1px solid #f5ddb0}
  ul.advice{list-style:none;counter-reset:adv}
  ul.advice li{counter-increment:adv;position:relative;padding:9px 0 9px 34px;
               border-bottom:1px dashed #e9eef7;color:#26344f}
  ul.advice li:last-child{border-bottom:none}
  ul.advice li::before{content:counter(adv);position:absolute;left:0;top:10px;width:21px;height:21px;
    border-radius:50%;background:#eaf1ff;color:#002FA7;font-size:12px;font-weight:700;
    display:grid;place-items:center}
  ul.advice b{color:#002FA7}
  .muted{color:#9aa7c0;font-size:12.5px}
  footer{margin-top:34px;padding-top:14px;border-top:1px solid #e4eaf4;
         font-size:11px;color:#9aa7c0;line-height:1.9}
  @media print{
    body{background:#fff}
    .page{box-shadow:none;margin:0;max-width:none;border-radius:0;padding:18px 6px}
    h2{break-after:avoid} section{break-inside:avoid}
  }
  @media (max-width:760px){.cols{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="page">
  <div class="topbar"></div>
  <header>
    <div class="brand">◆ <b>黑墙系统 BlackWall</b> · AI 安全监管与隔离墙 —— 自动生成报告</div>
    <h1>__TITLE__</h1>
    <div class="meta">
      <span>报告编号 <b>__RPT_NO__</b></span>
      <span>统计周期 __PERIOD__</span>
      <span>生成时间 __GENERATED__</span>
    </div>
  </header>

  <section class="kpis">__KPIS__</section>

  <section>
    <h2>一、执行摘要</h2>
    <div class="summary">__SUMMARY__</div>
  </section>

  <section>
    <h2>二、行为分布</h2>
    <div class="cols">
      <div class="ring-wrap">__RING__<ul class="legend">__LEGEND__</ul></div>
      <div>
        <div style="font-size:12.5px;color:#5a6b8c;margin-bottom:6px">按监管阶段分布</div>
        __PHASE_BARS__
        __RISK_SVG__
      </div>
    </div>
    __TREND__
  </section>

  <section>
    <h2>三、风险来源排行</h2>
    __RULES__
  </section>

  <section>
    <h2>四、拦截与人工干预明细</h2>
    <table>
      <thead><tr><th>时间</th><th>发起方</th><th>请求动作</th><th>处置</th><th>裁决理由</th></tr></thead>
      <tbody>__DETAIL_ROWS__</tbody>
    </table>
  </section>

  <section>
    <h2>五、结论与建议</h2>
    <ul class="advice">__ADVICE__</ul>
  </section>

  <footer>
    本报告由黑墙系统 BlackWall 根据审计库（data/audit.db）自动生成，全部数据可回溯至原始事件。<br>
    审计范围：AI Agent 的输入 / 工具调用 / 受限执行 / 输出 全链路 ｜ 生成器版本 V1.1
  </footer>
</div>
</body>
</html>
"""


# ==========================================================================
# 构建
# ==========================================================================

def build_report(db_path: Path | str | None = None, out_path: Path | str | None = None,
                 days: int = 0, title: str | None = None) -> Path:
    db_path = Path(db_path or DEFAULT_DB)
    events = load_events(db_path, days)
    if not events:
        raise SystemExit("审计库中没有事件，先跑 python demo.py 或通过网关产生流量。")

    a = analyze(events)
    now = datetime.now()

    if title is None:
        title = "AI 安全风控报告（最近 30 天）" if days else "AI 安全风控报告（全量数据）"

    period = f"{_fmt(a['ts_min'])} 至 {_fmt(a['ts_max'])}"
    rpt_no = f"BW-{now.strftime('%Y%m%d')}-{hashlib.md5(str(a['total']).encode()).hexdigest()[:4].upper()}"

    # 摘要
    deny = a["by_effect"].get("deny", 0)
    allow = a["by_effect"].get("allow", 0)
    san = a["by_effect"].get("sanitize", 0)
    appr = a["by_effect"].get("approval", 0)
    pct = allow / a["total"] * 100 if a["total"] else 0
    top_rule_txt = ""
    if a["rules"]:
        rid, n = a["rules"].most_common(1)[0]
        top_rule_txt = f"拦截集中于规则 {rid}（{n} 次）；"
    summary = (f"报告周期内，黑墙系统共监管 <b>{a['total']}</b> 次 AI 行为："
               f"放行 {allow} 次（{pct:.1f}%）、安全拦截 <b>{deny}</b> 次、"
               f"转人工审批 {appr} 次、自动脱敏 {san} 次。"
               f"{top_rule_txt}风险峰值 {a['peak']}/100"
               + (f"，触发自动熔断 {a['freezes']} 次并完成人工复核。" if a["freezes"] else "。")
               + "所有高风险请求均在抵达业务系统之前被处置。")

    ring, legend = _ring_html(a)
    trend_html, has_trend = _trend_html(events)

    html = (TEMPLATE
            .replace("__TITLE__", title)
            .replace("__RPT_NO__", rpt_no)
            .replace("__PERIOD__", period)
            .replace("__GENERATED__", now.strftime("%Y-%m-%d %H:%M:%S"))
            .replace("__KPIS__", _kpis_html(a))
            .replace("__SUMMARY__", summary)
            .replace("__RING__", ring)
            .replace("__LEGEND__", legend)
            .replace("__PHASE_BARS__", _phase_bars_html(a))
            .replace("__RISK_SVG__", _risk_svg(events))
            .replace("__TREND__", trend_html)
            .replace("__RULES__", _rules_html(a))
            .replace("__DETAIL_ROWS__", _detail_rows(events))
            .replace("__ADVICE__", "".join(f"<li>{x}</li>" for x in _advice(a))))

    out_path = Path(out_path) if out_path else (DEFAULT_OUT_DIR / f"blackwall_report_{now.strftime('%Y%m%d_%H%M')}.html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="黑墙系统 · AI 安全风控报告生成器")
    parser.add_argument("--db", default=None, help=f"审计库路径（默认 {DEFAULT_DB}）")
    parser.add_argument("--out", default=None, help="输出 HTML 路径")
    parser.add_argument("--days", type=int, default=0, help="仅统计最近 N 天（默认 0=全量）")
    args = parser.parse_args()
    out = build_report(args.db, args.out, args.days)
    print(f"报告已生成：{out}")
