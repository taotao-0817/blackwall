# -*- coding: utf-8 -*-
"""
黑墙系统 BlackWall · 监管大屏生成器
==========================
把审计导出（data/audit_export.json）渲染成一份**自包含**的深色监管面板
（dashboard/index.html）：双击即可离线打开，含 KPI、事件全量回放、风险分
走势、裁决构成、规则命中排行与 Agent 状态。

    python build_dashboard.py [导出JSON路径] [输出HTML路径]
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>黑墙系统 BlackWall · 安全监管中心</title>
<style>
  :root{
    --bg:#070b14; --panel:#0d1424; --panel2:#111a2e; --border:#1d2a46;
    --text:#e8eefc; --dim:#8b98b8; --dim2:#5c6a8a;
    --blue:#4d7cff; --klein:#002FA7; --cyan:#22e0ff;
    --green:#2ee6a8; --red:#ff4d6d; --yellow:#ffc53d; --violet:#b87bff;
    --mono:"Cascadia Code","JetBrains Mono",Consolas,monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{background:
    radial-gradient(1100px 500px at 85% -10%, rgba(0,47,167,.28), transparent 60%),
    radial-gradient(900px 420px at -10% 0%, rgba(34,224,255,.08), transparent 55%),
    var(--bg);
    color:var(--text);font:14px/1.6 system-ui,"Segoe UI","Microsoft YaHei",sans-serif;}
  .topline{height:3px;background:linear-gradient(90deg,var(--klein),var(--blue),var(--cyan));}
  header{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;
    max-width:1560px;margin:0 auto;padding:22px 24px 10px;}
  .brand{display:flex;gap:14px;align-items:center}
  .logo{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;
    font-size:22px;color:#fff;background:linear-gradient(135deg,var(--klein),var(--blue) 60%,var(--cyan));
    box-shadow:0 6px 22px rgba(0,47,167,.45);}
  h1{font-size:21px;letter-spacing:.5px}
  h1 span{color:var(--dim);font-weight:500;font-size:15px;margin-left:8px}
  .sub{color:var(--dim2);font-size:12px}
  .meta{display:flex;gap:22px;font-size:12px;color:var(--dim);text-align:right}
  .meta b{color:var(--text);font-weight:600}
  .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;
    max-width:1560px;margin:8px auto 0;padding:0 24px;}
  .kpi{position:relative;background:linear-gradient(180deg,rgba(19,28,48,.92),rgba(13,20,36,.92));
    border:1px solid var(--border);border-radius:12px;padding:13px 15px;overflow:hidden;
    backdrop-filter:blur(8px);}
  .kpi::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:var(--kc,var(--blue));opacity:.9}
  .kpi .v{font-size:26px;font-weight:700;font-family:var(--mono);}
  .kpi .l{font-size:12px;color:var(--dim)}
  main{display:grid;grid-template-columns:minmax(0,1fr) 396px;gap:16px;
    max-width:1560px;margin:16px auto;padding:0 24px;}
  .panel{background:linear-gradient(180deg,rgba(17,26,46,.85),rgba(13,20,36,.9));
    border:1px solid var(--border);border-radius:14px;padding:14px 16px;backdrop-filter:blur(10px);}
  .panel h2{font-size:13px;color:var(--dim);font-weight:600;letter-spacing:1px;
    margin-bottom:10px;display:flex;align-items:center;gap:8px}
  .panel h2::before{content:"";width:3px;height:12px;border-radius:2px;background:var(--cyan)}
  .panelhead{display:flex;justify-content:space-between;align-items:center}
  .controls button{background:rgba(77,124,255,.12);color:var(--text);border:1px solid rgba(77,124,255,.4);
    border-radius:8px;padding:5px 12px;font-size:12px;cursor:pointer;margin-left:8px;transition:.2s}
  .controls button:hover{background:rgba(77,124,255,.28)}
  .timeline{overflow-y:auto;max-height:73vh;padding-right:6px;scrollbar-width:thin;scrollbar-color:#24314f transparent}
  .ev{border-left:3px solid var(--border);background:var(--panel2);border-radius:9px;
    padding:9px 13px;margin-bottom:8px;opacity:0;transform:translateX(-12px);
    transition:opacity .3s ease,transform .3s ease;}
  .ev.show{opacity:1;transform:none}
  .ev.e-allow{border-left-color:var(--green)}
  .ev.e-deny{border-left-color:var(--red);box-shadow:inset 0 0 30px rgba(255,77,109,.05)}
  .ev.e-approval{border-left-color:var(--yellow)}
  .ev.e-sanitize{border-left-color:var(--violet)}
  .evhead{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:3px}
  .tno{font-family:var(--mono);font-size:11px;color:var(--dim2)}
  .t{font-family:var(--mono);font-size:11px;color:var(--dim)}
  .badge{font-size:11px;padding:1px 8px;border-radius:20px;border:1px solid transparent;white-space:nowrap}
  .ph-cyan{color:var(--cyan);border-color:rgba(34,224,255,.4);background:rgba(34,224,255,.07)}
  .ph-blue{color:#94b4ff;border-color:rgba(77,124,255,.4);background:rgba(77,124,255,.08)}
  .ph-violet{color:var(--violet);border-color:rgba(184,123,255,.4);background:rgba(184,123,255,.07)}
  .ph-gold{color:var(--yellow);border-color:rgba(255,197,61,.4);background:rgba(255,197,61,.07)}
  .ph-red{color:var(--red);border-color:rgba(255,77,109,.45);background:rgba(255,77,109,.08)}
  .ef-green{color:var(--green);border-color:rgba(46,230,168,.4);background:rgba(46,230,168,.07)}
  .ef-red{color:var(--red);border-color:rgba(255,77,109,.45);background:rgba(255,77,109,.08)}
  .ef-gold{color:var(--yellow);border-color:rgba(255,197,61,.4);background:rgba(255,197,61,.07)}
  .ef-violet{color:var(--violet);border-color:rgba(184,123,255,.4);background:rgba(184,123,255,.07)}
  .hum{color:#ffd9e2;border-color:rgba(255,77,109,.5);background:rgba(255,77,109,.16)}
  .pill{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--dim)}
  .sum{font-size:13px;color:var(--text);word-break:break-all}
  .reason{font-size:12px;color:var(--yellow);margin-top:2px}
  .find{font-size:12px;color:var(--dim);margin-top:2px}
  .note{font-size:12px;color:var(--cyan);margin-top:2px}
  .chips{margin-top:5px;display:flex;gap:6px;flex-wrap:wrap}
  .chip{font-family:var(--mono);font-size:10.5px;color:#9fb2dd;background:rgba(77,124,255,.1);
    border:1px solid rgba(77,124,255,.28);border-radius:6px;padding:1px 7px}
  .side{display:flex;flex-direction:column;gap:16px}
  #riskline{width:100%;height:110px;display:block}
  .cap{font-size:11px;color:var(--dim2);margin-top:4px;text-align:center}
  .donutwrap{display:flex;align-items:center;gap:18px}
  #donut{width:128px;height:128px;border-radius:50%;position:relative;flex:0 0 auto;
    filter:drop-shadow(0 0 14px rgba(77,124,255,.25))}
  #donut::after{content:"";position:absolute;inset:26px;border-radius:50%;background:#0d1424;}
  #donut-center{position:absolute;inset:0;display:grid;place-items:center;
    font-family:var(--mono);font-size:20px;font-weight:700}
  .donutwrap .inner{position:relative;display:grid;place-items:center}
  #legend{list-style:none;font-size:12px;color:var(--dim);flex:1}
  #legend li{display:flex;align-items:center;gap:8px;margin:5px 0}
  #legend i{width:9px;height:9px;border-radius:3px;display:inline-block}
  #legend b{color:var(--text);font-family:var(--mono);margin-left:auto}
  .rule-row{display:flex;align-items:center;gap:9px;margin:7px 0;font-size:11.5px}
  .rn{font-family:var(--mono);color:#9fb2dd;flex:0 0 150px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .rb{flex:1;height:8px;border-radius:4px;background:rgba(77,124,255,.1);overflow:hidden}
  .rb i{display:block;height:100%;border-radius:4px;background:linear-gradient(90deg,var(--blue),var(--cyan));
    transition:width .9s cubic-bezier(.2,.9,.3,1)}
  .rc{font-family:var(--mono);color:var(--dim)}
  #agentstate .row{display:flex;justify-content:space-between;align-items:center;
    padding:8px 2px;border-bottom:1px dashed rgba(60,80,130,.35);font-size:13px}
  #agentstate .row:last-child{border-bottom:none}
  .st{font-weight:700}
  .st-ok{color:var(--green)} .st-bad{color:var(--red)} .st-warn{color:var(--yellow)}
  footer{max-width:1560px;margin:6px auto 28px;padding:0 24px;font-size:11.5px;color:var(--dim2)}
  @media (max-width:1180px){ main{grid-template-columns:1fr} .kpis{grid-template-columns:repeat(3,1fr)} }
  @media (prefers-reduced-motion:reduce){
    .ev{transition:none;opacity:1 !important;transform:none !important}
    .rb i{transition:none}
  }
</style>
</head>
<body>
<div class="topline"></div>
<header>
  <div class="brand">
    <div class="logo">&#9670;</div>
    <div>
      <h1>黑墙系统 BlackWall <span>安全监管中心 · AI Agent 行为审计</span></h1>
      <div class="sub">全部调度流量经沙盒三扇门（输入 / 工具 / 输出）· 本页数据来自审计导出，离线自包含</div>
    </div>
  </div>
  <div class="meta">
    <div>策略包<br><b>__POLICY__</b></div>
    <div>被监管对象<br><b>__AGENT__</b></div>
    <div>生成时间<br><b>__GENERATED__</b></div>
  </div>
</header>
<section class="kpis" id="kpis"></section>
<main>
  <section class="panel">
    <div class="panelhead">
      <h2 style="margin-bottom:0">事件时间线 · 全量回放</h2>
      <div class="controls"><button id="btn-replay">&#9654; 重新回放</button><button id="btn-all">&#9193; 全部展开</button></div>
    </div>
    <div class="timeline" id="timeline" style="margin-top:12px"></div>
  </section>
  <aside class="side">
    <section class="panel"><h2>风险分走势</h2><svg id="riskline"></svg>
      <div class="cap">Agent 累计风险分 · 到达 100 触发自动熔断</div></section>
    <section class="panel"><h2>裁决构成</h2>
      <div class="donutwrap">
        <div class="inner"><div id="donut"></div><div id="donut-center"></div></div>
        <ul id="legend"></ul>
      </div></section>
    <section class="panel"><h2>规则命中排行</h2><div id="rules"></div></section>
    <section class="panel"><h2>Agent 状态</h2><div id="agentstate"></div></section>
  </aside>
</main>
<footer>黑墙系统 BlackWall V1.1 · 审计事件 data/audit_export.json · 每一次放行/拦截/脱敏/审批都可追溯</footer>
<script>
const DATA = __DATA__;
const EV = DATA.events || [];
const ST = DATA.stats || {};
const AGENT = EV.length ? EV[0].agent_id : "-";
const STATIC = location.hash === "#all";   /* #all = 跳过回放动画，直接全量展示 */

const PHASE_META = { input:["输入","cyan"], tool:["工具","blue"], exec:["执行","violet"],
                     output:["输出","gold"], risk:["风控","red"] };
const EFF_META = { allow:["\u221A 放行","green"], deny:["\u00D7 拦截","red"],
                   approval:["\u2016 审批","gold"], sanitize:["\u25CE 脱敏","violet"] };

function esc(s){ return String(s==null?"":s).replace(/[&<>"]/g,
  c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function clip(s,n){ s=String(s==null?"":s); return s.length>n ? s.slice(0,n-1)+"\u2026" : s; }
function fmtTime(ts){ const d=new Date(ts*1000); return isNaN(d)?"":d.toLocaleTimeString("zh-CN",{hour12:false}); }

/* ---------- KPI ---------- */
(function(){
  const c={allow:0,deny:0,approval:0,sanitize:0};
  let human=0, peak=0, frozen=0;
  EV.forEach(e=>{ if(c[e.effect]!=null)c[e.effect]++;
    if(e.actor==="human")human++;
    peak=Math.max(peak,e.agent_risk||0);
    if(e.rule_id==="RISK-FREEZE")frozen++; });
  const defs=[
    ["事件总量", EV.length, "var(--cyan)"],
    ["安全拦截", c.deny, "var(--red)"],
    ["脱敏放行", c.sanitize, "var(--violet)"],
    ["人工干预", human, "var(--yellow)"],
    ["风险峰值", peak+"/100", "var(--red)"],
    ["自动熔断", frozen, "var(--red)"],
  ];
  const wrap=document.getElementById("kpis");
  defs.forEach(([l,v,col])=>{
    const d=document.createElement("div"); d.className="kpi"; d.style.setProperty("--kc",col);
    d.innerHTML=`<div class="v"></div><div class="l"></div>`;
    d.querySelector(".l").textContent=l; wrap.appendChild(d);
    const el=d.querySelector(".v");
    if(typeof v==="number"){ if(STATIC){ el.textContent=v; } else { countUp(el,v); } } else { el.textContent=v; }
  });
})();
function countUp(el,target,dur){
  dur=dur||750; const t0=performance.now();
  (function step(now){
    const p=Math.min(1,(now-t0)/dur);
    el.textContent=Math.round(target*(1-Math.pow(1-p,3)));
    if(p<1)requestAnimationFrame(step);
  })(performance.now());
}

/* ---------- 时间线 ---------- */
const timeline=document.getElementById("timeline");
function renderEvent(ev,i){
  const pm=PHASE_META[ev.phase]||["事件","blue"];
  const em=EFF_META[ev.effect]||["-","blue"];
  const chips=(ev.rule_id&&ev.rule_id!=="DEFAULT")
    ? ev.rule_id.split(",").map(r=>`<span class="chip">${esc(r)}</span>`).join("") : "";
  const finds=(ev.findings||[]).slice(0,2)
    .map(f=>`<div class="find">\u00B7 [${esc(f.label)}] ${esc(clip(f.detail,76))}</div>`).join("");
  const note=ev.note?`<div class="note">${esc(clip(ev.note,110))}</div>`:"";
  const hum=ev.actor==="human"?`<span class="badge hum">人工</span>`:"";
  return `<div class="ev e-${esc(ev.effect)}">
    <div class="evhead">
      <span class="tno">#${String(i+1).padStart(2,"0")}</span>
      <span class="t">${fmtTime(ev.ts)}</span>
      <span class="badge ph-${pm[1]}">${pm[0]}</span>
      <span class="badge ef-${em[1]}">${em[0]}</span>${hum}
      <span class="pill">风险 ${ev.agent_risk}</span>
    </div>
    <div class="sum">${esc(clip(ev.summary,116))}</div>
    <div class="reason">${esc(clip(ev.reason,160))}</div>
    ${finds}${note}
    ${chips?`<div class="chips">${chips}</div>`:""}
  </div>`;
}
EV.forEach((ev,i)=>timeline.insertAdjacentHTML("beforeend",renderEvent(ev,i)));
const nodes=[...timeline.querySelectorAll(".ev")];

let playing=false;
function replay(){
  if(playing||!nodes.length)return;
  if(STATIC||matchMedia("(prefers-reduced-motion: reduce)").matches){ showAll(); return; }
  playing=true;
  nodes.forEach(n=>n.classList.remove("show"));
  let i=0;
  const timer=setInterval(()=>{
    if(i>=nodes.length){ clearInterval(timer); playing=false; return; }
    nodes[i].classList.add("show");
    timeline.scrollTop=timeline.scrollHeight;
    i++;
  },105);
}
function showAll(){ nodes.forEach(n=>n.classList.add("show")); }
document.getElementById("btn-replay").addEventListener("click",replay);
document.getElementById("btn-all").addEventListener("click",showAll);
replay();

/* ---------- 风险曲线 ---------- */
(function(){
  const svg=document.getElementById("riskline");
  const W=360,H=105,PAD=10;
  const rs=EV.map(e=>e.agent_risk||0);
  const n=rs.length;
  svg.setAttribute("viewBox",`0 0 ${W} ${H}`);
  if(!n)return;
  const maxR=Math.max(100,...rs);
  const xy=rs.map((r,i)=>[PAD+(W-2*PAD)*(n===1?0.5:i/(n-1)), H-PAD-(H-2*PAD)*(r/maxR)]);
  const line=xy.map(p=>p.map(x=>x.toFixed(1)).join(",")).join(" ");
  const y100=(H-PAD-(H-2*PAD)*(100/maxR)).toFixed(1);
  svg.innerHTML=`
    <defs><linearGradient id="rg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#4d7cff" stop-opacity=".5"/>
      <stop offset="1" stop-color="#4d7cff" stop-opacity="0"/>
    </linearGradient></defs>
    <line x1="${PAD}" y1="${y100}" x2="${W-PAD}" y2="${y100}"
      stroke="#ff4d6d" stroke-width="1" stroke-dasharray="4 4" opacity=".55"/>
    <text x="${W-PAD}" y="${y100-4}" text-anchor="end" font-size="9" fill="#ff4d6d" opacity=".8">熔断线 100</text>
    <polygon points="${PAD},${H-PAD} ${line} ${W-PAD},${H-PAD}" fill="url(#rg)"/>
    <polyline points="${line}" fill="none" stroke="#22e0ff" stroke-width="2"
      stroke-linejoin="round" stroke-linecap="round"/>`;
})();

/* ---------- 裁决构成 ---------- */
(function(){
  const counts={allow:0,deny:0,approval:0,sanitize:0};
  EV.forEach(e=>{ if(counts[e.effect]!=null)counts[e.effect]++; });
  const total=Object.values(counts).reduce((a,b)=>a+b,0)||1;
  const colors={allow:"#2ee6a8",deny:"#ff4d6d",approval:"#ffc53d",sanitize:"#b87bff"};
  const names={allow:"放行",deny:"拦截",approval:"审批挂起",sanitize:"脱敏放行"};
  let acc=0; const segs=[];
  for(const k of ["allow","deny","approval","sanitize"]){
    const s0=acc; acc+=counts[k]/total*360;
    segs.push(`${colors[k]} ${s0.toFixed(1)}deg ${acc.toFixed(1)}deg`);
  }
  document.getElementById("donut").style.background=`conic-gradient(${segs.join(",")})`;
  document.getElementById("donut-center").textContent=total;
  document.getElementById("legend").innerHTML=
    ["allow","deny","approval","sanitize"].map(k=>
      `<li><i style="background:${colors[k]}"></i>${names[k]}<b>${counts[k]}</b></li>`).join("");
})();

/* ---------- 规则排行 ---------- */
(function(){
  const rules=(ST.top_rules||[]).slice(0,6);
  const max=Math.max(1,...rules.map(r=>r.count));
  document.getElementById("rules").innerHTML=rules.length?rules.map(r=>`
    <div class="rule-row">
      <span class="rn" title="${esc(r.rule_id)}">${esc(r.rule_id)}</span>
      <span class="rb"><i style="width:${Math.round(r.count/max*100)}%"></i></span>
      <span class="rc">\u00D7${r.count}</span>
    </div>`).join(""):"<div class='cap'>无拦截事件</div>";
})();

/* ---------- Agent 状态 ---------- */
(function(){
  let froze=0,unf=0,last=0,lastDeny="";
  EV.forEach(e=>{ if(e.rule_id==="RISK-FREEZE")froze++;
    if(e.rule_id==="HUMAN-UNFREEZE")unf++;
    last=e.agent_risk||0;
    if(e.effect==="deny"&&e.rule_id)lastDeny=e.rule_id; });
  let st,cls;
  if(froze>0&&unf>0&&froze===unf){ st="已恢复（人工解冻）"; cls="st-ok"; }
  else if(froze>unf){ st="已熔断 · 待人工复核"; cls="st-bad"; }
  else if(lastDeny){ st="正常运行（有拦截记录）"; cls="st-warn"; }
  else { st="正常运行"; cls="st-ok"; }
  document.getElementById("agentstate").innerHTML=`
    <div class="row"><span>Agent</span><b class="mono">${esc(AGENT)}</b></div>
    <div class="row"><span>当前状态</span><span class="st ${cls}">${st}</span></div>
    <div class="row"><span>累计风险分（末次）</span><b>${last}/100</b></div>
    <div class="row"><span>熔断 / 解冻</span><b>${froze} 次 / ${unf} 次</b></div>
    <div class="row"><span>最近拦截规则</span><span class="mono" style="font-size:11px">${esc(lastDeny||"—")}</span></div>`;
})();
</script>
</body>
</html>
"""

def build_dashboard(export_path: str | Path | None = None,
                    out_path: str | Path | None = None,
                    policy_name: str = "小型企业默认策略 v1.0") -> Path:
    export_path = Path(export_path or (ROOT / "data" / "audit_export.json"))
    out_path = Path(out_path or (ROOT / "dashboard" / "index.html"))

    data = json.loads(export_path.read_text(encoding="utf-8"))
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    agent_ids = sorted({e.get("agent_id", "-") for e in data.get("events", [])}) or ["-"]

    html = (TEMPLATE
            .replace("__DATA__", payload)
            .replace("__POLICY__", policy_name)
            .replace("__AGENT__", "、".join(agent_ids))
            .replace("__GENERATED__", time.strftime("%Y-%m-%d %H:%M:%S")))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else None
    dst = sys.argv[2] if len(sys.argv) > 2 else None
    print("生成:", build_dashboard(src, dst))
