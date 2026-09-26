# -*- coding: utf-8 -*-
"""
黑墙系统 · Windows 硬隔离实测（Job Object）
============================================
验证资源限额真的生效——不是"代码里写了"，而是"物理上拦得住"：

    1. Job Object 可用性
    2. 内存炸弹：分配超过 256MB → 被限额拦截（MemoryError）
    3. 进程炸弹：Job 内进程数封顶 → 超额进程创建/收编被拒
    4. 死循环：硬超时强制终止
    5. 回归：正常脚本照常执行

用法（Windows）：py -3.12 test_sandbox_limits.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from blackwall import console as C                      # noqa: E402
from blackwall.sandbox_exec import run_python           # noqa: E402
from blackwall.win_job import WindowsJobLimits          # noqa: E402

WORKDIR = Path(__file__).resolve().parent / "data" / "company_fs"
WORKDIR.mkdir(parents=True, exist_ok=True)

results: list[tuple[str, bool]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond))
    icon = C.c("√ PASS", "bright_green") if cond else C.c("× FAIL", "bright_red")
    line = f"  {icon}  {name}"
    if detail:
        line += "   " + C.c(detail, "dim")
    print(line)


def main() -> int:
    print()
    C.banner("黑墙系统 BlackWall · Windows 硬隔离实测", "Job Object 资源限额 · 物理层防线")
    print()

    # ---------------------------------------------------------------- 1
    with WindowsJobLimits() as job:
        check("Job Object 可用", job.available, job.error or "CreateJobObject + SetInformation 正常")

    # ---------------------------------------------------------------- 2
    CODE_MEM = """
blob = []
try:
    for i in range(40):                      # 尝试吃掉 640MB
        blob.append(bytearray(16 * 1024 * 1024))
    print("ALLOCATED-640MB")                 # 不该出现
except MemoryError:
    used = len(blob) * 16
    print(f"MEMORY-LIMITED-AT-{used}MB")
"""
    r1 = run_python(CODE_MEM, WORKDIR, timeout=40, memory_mb=256)
    limited = "MEMORY-LIMITED" in r1.stdout
    at_mb = ""
    if limited:
        frag = r1.stdout.split("MEMORY-LIMITED-AT-")[-1].strip().split("MB")[0]
        at_mb = f"在已分配 {frag}MB 时被拦截（上限 256MB）"
    check("内存炸弹被限额拦截", limited and "ALLOCATED-640MB" not in r1.stdout,
          at_mb or f"未拦截！stdout={r1.stdout[:80]!r}")

    # ---------------------------------------------------------------- 3
    # 注意：这里直接测 Job 原语——走 run_python 的话，AST 层会先把
    # `import subprocess` 拦下（这本身就是第一道防线）。
    with WindowsJobLimits(memory_mb=512, max_processes=3) as job:
        kids: list[subprocess.Popen] = []
        blocked = ""
        for i in range(1, 9):
            try:
                p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(8)"])
            except OSError as e:
                blocked = f"第 {i} 个子进程创建即被拒（{e.__class__.__name__}）"
                break
            if not job.assign(p):
                p.kill()
                p.wait()
                blocked = f"第 {i} 个子进程收编被拒（Job 已达进程数上限 3）"
                break
            kids.append(p)
        for k in kids:
            k.kill()
            k.wait()
    check("进程炸弹被封顶（上限 3 个）", bool(blocked),
          blocked or "未拦截：连续拉起 8 个进程都成功")

    # ---------------------------------------------------------------- 4
    CODE_LOOP = "print('start')\nwhile True:\n    pass\n"
    r4 = run_python(CODE_LOOP, WORKDIR, timeout=2)
    check("死循环被硬超时终止", (not r4.ok) and ("超时" in r4.reason),
          f"{r4.reason}（{r4.duration_ms:.0f}ms）")

    # ---------------------------------------------------------------- 5
    CODE_OK = "print('hello from sandbox')\nprint(2 + 2)"
    r5 = run_python(CODE_OK, WORKDIR, timeout=10)
    check("正常脚本照常执行（无回归）", r5.ok and "4" in r5.stdout,
          f"stdout={r5.stdout.strip()!r}  {r5.duration_ms:.0f}ms")

    # ---------------------------------------------------------------- 汇总
    passed = sum(1 for _, c in results if c)
    total = len(results)
    print()
    color = "bright_green" if passed == total else "bright_red"
    print(C.c(f"  {passed}/{total} 项通过", color, "bold"))
    print()
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
