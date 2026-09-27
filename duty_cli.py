# -*- coding: utf-8 -*-
"""
黑墙系统 · 值班安全员控制台（审批裁决）
========================================
黑墙把高风险操作挂起后，值班安全员用本工具查看和裁决——「人工在环」的操作台。
（生产环境可替换为企业 IM 卡片：钉钉/企微/飞书里点"批准/驳回"，回调同一个 decide 接口。）

    python duty_cli.py list                        # 查看待审请求
    python duty_cli.py show   <审批单号>            # 查看详情
    python duty_cli.py approve <审批单号> [备注]     # 批准
    python duty_cli.py reject  <审批单号> [备注]     # 驳回
    python duty_cli.py unfreeze <agent_id> [备注]   # 人工解冻被熔断的 Agent

V1.3 权限说明：本工具持有**管理凭证（admin token）**——审批与解冻只认
管理凭证，被监管的 Agent（agent token）无法自己批准/解冻自己。

环境变量：BLACKWALL_URL（默认 http://127.0.0.1:8765）
          BLACKWALL_TOKEN（管理凭证，默认 blackwall-demo-token；
                           生产部署请与 server.py --admin-token 保持一致）
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("BLACKWALL_URL", "http://127.0.0.1:8765")
TOKEN = os.environ.get("BLACKWALL_TOKEN", "blackwall-demo-token")


def api(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json", "X-API-Token": TOKEN},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"[错误] HTTP {e.code}: {e.read().decode('utf-8', 'replace')}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[错误] 无法连接黑墙网关 {BASE}：{e.reason}\n（先启动 python server.py）")
        sys.exit(1)


def _print_ticket(t: dict) -> None:
    status_cn = {"pending": "待裁决", "approve": "已批准", "reject": "已驳回"}.get(t["status"], t["status"])
    print(f"┌─ {t['id']}  [{status_cn}]  已等待 {t['waited_s']}s")
    print(f"│  发起方   {t['agent_id']}")
    print(f"│  操作     {t['tool']}({json.dumps(t['args'], ensure_ascii=False)[:110]})")
    print(f"│  命中规则 {t['rule_id']}")
    print(f"│  挂起理由 {t['reason']}")
    if t.get("note"):
        print(f"│  裁决备注 {t['note']}")
    print("└" + "─" * 66)


def cmd_list() -> None:
    data = api("GET", "/v1/approvals?status=pending")
    if not data["count"]:
        print("（当前无待审请求）")
        return
    print(f"待审 {data['count']} 件：\n")
    for t in data["approvals"]:
        _print_ticket(t)
        print()
    print("裁决：python duty_cli.py approve <单号> [备注]  /  reject <单号> [备注]")


def cmd_show(ticket_id: str) -> None:
    _print_ticket(_find(ticket_id))


def _find(ticket_id: str) -> dict:
    data = api("GET", "/v1/approvals?status=all")
    for t in data["approvals"]:
        if t["id"] == ticket_id:
            return t
    print(f"[错误] 找不到审批单 {ticket_id}")
    sys.exit(1)


def cmd_decide(verdict: str, ticket_id: str, note: str) -> None:
    t = _find(ticket_id)
    if t["status"] != "pending":
        print(f"该单已处于「{t['status']}」状态，无需重复裁决。")
        return
    result = api("POST", f"/v1/approvals/{ticket_id}/decide",
                 {"verdict": verdict, "note": note or ("值班批准" if verdict == "approve" else "值班驳回")})
    if result.get("status") == "decided":
        done = "√ 已批准" if verdict == "approve" else "× 已驳回"
        print(f"{done}：{ticket_id}（备注：{result.get('note', '')}）")
        print("原挂起的工具调用已唤醒，将按裁决结果继续。")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_unfreeze(agent_id: str, note: str) -> None:
    result = api("POST", f"/v1/agents/{agent_id}/unfreeze", {"note": note or "值班解冻"})
    if result.get("status") == "unfrozen":
        print(f"√ 已解冻：{agent_id}（风险分已重置，恢复服务）")
    elif result.get("status") == "not_frozen":
        print(f"该 Agent 当前未被冻结：{agent_id}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))


def main() -> None:
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return
    cmd, rest = argv[0], argv[1:]
    if cmd == "list":
        cmd_list()
    elif cmd == "show" and rest:
        cmd_show(rest[0])
    elif cmd == "approve" and rest:
        cmd_decide("approve", rest[0], " ".join(rest[1:]))
    elif cmd == "reject" and rest:
        cmd_decide("reject", rest[0], " ".join(rest[1:]))
    elif cmd == "unfreeze" and rest:
        cmd_unfreeze(rest[0], " ".join(rest[1:]))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
