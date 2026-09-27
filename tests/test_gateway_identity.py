# -*- coding: utf-8 -*-
"""
黑墙系统 · 网关身份分域回归（V1.3）
====================================
启动一个真实的网关子进程（独立数据目录），验证"被监管方不能管自己"：

    1. agent 凭证 → 三扇门可用、身份为凭证绑定值（自报 agent_id 被忽略）
    2. agent 凭证 → 审批列表 / 裁决 / 解冻 / 审计 / 统计 一律 401
    3. admin 凭证 → 管理面可用（审批列表 / 统计 / 解冻 / 审计哈希链）
    4. 无凭证 / 错误凭证 → 401
    5. whoami 正确报告凭证类型与绑定身份

用法：py -3.12 tests/test_gateway_identity.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = ROOT / "data" / "_gateway_test_tmp"
PORT = 8799
BASE = f"http://127.0.0.1:{PORT}"
ADMIN = "test-admin-token"
AGENT = "test-agent-token"
AGENT_ID = "test-agent-01"

results: list[tuple[str, bool]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond))
    mark = "√ PASS" if cond else "× FAIL"
    print(f"  {mark}  {name}" + (f"   {detail}" if detail else ""))


def api(method: str, path: str, body: dict | None = None, token: str | None = None,
        timeout: float = 15) -> tuple[int, dict]:
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json",
                 **({"X-API-Token": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}


def main() -> int:
    print(f"黑墙系统 · 网关身份分域回归（{BASE}）")
    shutil.rmtree(TMP, ignore_errors=True)
    TMP.mkdir(parents=True, exist_ok=True)
    log_path = TMP / "server.log"

    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "server.py"),
         "--port", str(PORT), "--admin-token", ADMIN, "--agent-token", AGENT,
         "--agent-id", AGENT_ID, "--data-dir", str(TMP / "data"),
         "--auto-approve"],
        cwd=str(ROOT), stdout=open(log_path, "wb"), stderr=subprocess.STDOUT,
    )
    try:
        # 等就绪（uvicorn 冷启动 + 装配 ~3s）
        ready = False
        for _ in range(60):
            try:
                code, _body = api("GET", "/v1/whoami", token=AGENT, timeout=2)
                if code == 200:
                    ready = True
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.5)
        if not ready:
            print("× 网关未就绪，日志尾部：")
            print(log_path.read_text(encoding="utf-8", errors="replace")[-2000:])
            return 1

        # 1. whoami
        code, body = api("GET", "/v1/whoami", token=AGENT)
        check("whoami(agent) 返回绑定身份", code == 200 and body.get("kind") == "agent"
              and body.get("agent_id") == AGENT_ID, str(body))
        code, body = api("GET", "/v1/whoami", token=ADMIN)
        check("whoami(admin) 类型正确", code == 200 and body.get("kind") == "admin", str(body))

        # 2. agent 自报身份被忽略（服务端强制覆盖）
        code, body = api("POST", "/v1/tool/call",
                         {"tool": "query_order", "args": {"order_id": "A1002"},
                          "agent_id": "fake-name-999"}, token=AGENT)
        check("agent 自报 agent_id 被服务端覆盖",
              code == 200 and body.get("agent_id") == AGENT_ID,
              f"返回身份={body.get('agent_id')}")

        # 3. agent 凭证不能碰管理面（P0-1 修复的核心断言）
        code, _ = api("GET", "/v1/approvals", token=AGENT)
        check("agent 读审批列表 → 401", code == 401)
        code, _ = api("POST", "/v1/approvals/AP-xxxx/decide",
                      {"verdict": "approve", "note": ""}, token=AGENT)
        check("agent 裁决审批 → 401", code == 401)
        code, _ = api("POST", f"/v1/agents/{AGENT_ID}/unfreeze", {"note": ""}, token=AGENT)
        check("agent 自我解冻 → 401", code == 401)
        code, _ = api("GET", "/v1/audit/events?limit=5", token=AGENT)
        check("agent 读审计 → 401", code == 401)
        code, _ = api("GET", "/v1/stats", token=AGENT)
        check("agent 读统计 → 401", code == 401)

        # 4. agent 只能看自己的状态
        code, _ = api("GET", "/v1/agents/other-agent/status", token=AGENT)
        check("agent 查他人状态 → 403", code == 403)
        code, _ = api("GET", f"/v1/agents/{AGENT_ID}/status", token=AGENT)
        check("agent 查自身状态 → 200", code == 200)

        # 5. admin 管理面可用
        code, _body = api("GET", "/v1/approvals", token=ADMIN)
        check("admin 读审批列表 → 200", code == 200)
        code, body = api("GET", "/v1/stats", token=ADMIN)
        check("admin 读统计 → 200", code == 200 and "total" in body)
        code, body = api("GET", "/v1/audit/verify", token=ADMIN)
        check("admin 审计哈希链校验 → ok", code == 200 and body.get("ok") is True,
              f"checked={body.get('checked')}")
        code, body = api("POST", "/v1/agents/some-other/unfreeze", {"note": "t"}, token=ADMIN)
        check("admin 解冻接口可达", code == 200, str(body.get("status")))

        # 6. 无凭证 / 错误凭证
        code, _ = api("POST", "/v1/tool/call", {"tool": "query_order", "args": {}})
        check("无凭证调用三扇门 → 401", code == 401)
        code, _ = api("GET", "/v1/stats", token="wrong-token")
        check("错误凭证 → 401", code == 401)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    passed = sum(1 for _, c in results if c)
    total = len(results)
    print(f"\n  {passed}/{total} 项通过")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
