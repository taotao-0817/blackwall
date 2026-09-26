"""
黑墙系统 BlackWall · 受限执行沙盒（纵深防御 L2）
========================================
策略引擎管"要不要跑"，本模块管"跑起来之后能碰到什么"。

两层防护：
1. **静态审查（AST）**：代码运行前解析语法树，狙击网络通信、进程创建、
   系统调用、越界文件访问等危险意图 —— 逃逸代码在第一行执行之前就被拿下。
2. **受限执行**：通过的子任务放进子进程运行——工作目录 jail、环境变量白名单
   （杜绝代码偷读服务器上的密钥）、硬超时、输出截断。
3. **物理限额（V1.2 新增）**：Windows Job Object 硬隔离——内存上限（防内存炸弹）、
   进程数上限（防 fork 炸弹）、随沙盒回收（防残留进程）；即使代码骗过了静态审查，
   也逃不出物理配额。

生产可进一步：容器化 / Windows AppContainer / seccomp / 只读挂载。
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding
from .win_job import WindowsJobLimits

#: 危险模块导入 → (风险说明, 严重度)
BLOCKED_IMPORTS: dict[str, tuple[str, int]] = {
    "socket": ("网络通信", 9),
    "requests": ("网络通信", 9),
    "httpx": ("网络通信", 9),
    "urllib": ("网络通信", 9),
    "urllib3": ("网络通信", 9),
    "http": ("网络通信", 9),
    "ftplib": ("网络通信", 9),
    "telnetlib": ("网络通信", 9),
    "xmlrpc": ("网络通信", 9),
    "smtplib": ("外发邮件", 8),
    "imaplib": ("邮件协议", 8),
    "poplib": ("邮件协议", 8),
    "subprocess": ("创建系统进程", 9),
    "multiprocessing": ("创建系统进程", 9),
    "pty": ("终端控制", 9),
    "ctypes": ("绕过解释器直接调用系统接口", 9),
    "winreg": ("修改 Windows 注册表", 8),
    "_winreg": ("修改 Windows 注册表", 8),
    "pickle": ("反序列化执行风险", 7),
    "marshal": ("反序列化执行风险", 7),
    "shutil": ("高危文件操作", 7),
    "webbrowser": ("唤起外部程序", 6),
}

#: 危险函数调用 → (风险说明, 严重度)
BLOCKED_CALLS: dict[str, tuple[str, int]] = {
    "os.system": ("执行系统命令", 10),
    "os.popen": ("执行系统命令", 10),
    "os.execv": ("替换进程映像", 10),
    "os.execve": ("替换进程映像", 10),
    "os.execvp": ("替换进程映像", 10),
    "os.execl": ("替换进程映像", 10),
    "os.spawnv": ("创建系统进程", 9),
    "os.spawnl": ("创建系统进程", 9),
    "os.remove": ("删除文件", 8),
    "os.unlink": ("删除文件", 8),
    "os.rmdir": ("删除目录", 8),
    "os.kill": ("结束进程", 9),
    "shutil.rmtree": ("递归删除目录", 9),
    "shutil.move": ("移动文件", 6),
    "eval": ("动态执行代码", 8),
    "exec": ("动态执行代码", 8),
    "compile": ("动态编译代码", 7),
    "__import__": ("动态导入模块", 7),
    "ctypes.CDLL": ("加载动态库", 9),
    "ctypes.WinDLL": ("加载动态库", 9),
}

#: 判定为"硬拒绝"的严重度阈值（静态审查阶段）
HARD_BLOCK_SEVERITY = 7


class SandboxViolation(Exception):
    """受限执行沙盒的拒绝信号（由工具层抛出，网关转成 deny 裁决）"""

    def __init__(self, reason: str, findings: list[Finding] | None = None, risk: int = 40):
        super().__init__(reason)
        self.reason = reason
        self.findings = findings or []
        self.risk = risk


@dataclass
class ExecOutcome:
    executed: bool                  # 是否真正进入执行（False = 静态审查阶段被拒）
    ok: bool
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    reason: str = ""
    findings: list[Finding] = field(default_factory=list)


# --------------------------------------------------------------------------
# 静态审查
# --------------------------------------------------------------------------

def _dotted(node: ast.AST) -> str | None:
    """把语法树节点还原成 a.b.c 形式的点号名"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _jail_check(path_str: str, workdir: Path) -> str | None:
    """检查文件路径是否逃出沙盒目录。返回违规描述或 None"""
    p = path_str.strip().replace("\\", "/")
    if p.startswith("~"):
        return "试图访问用户主目录"
    if ".." in p.split("/"):
        return "路径包含 `..`，试图突破沙盒目录"
    # Windows 盘符绝对路径 / UNC 路径 → 必须在 jail 内
    if (len(p) >= 2 and p[1] == ":") or p.startswith("//"):
        try:
            resolved = str(Path(path_str).resolve()).lower().replace("\\", "/")
        except (OSError, ValueError):
            return f"非法路径: {path_str[:80]}"
        jail = str(workdir.resolve()).lower().replace("\\", "/")
        if not resolved.startswith(jail):
            return f"绝对路径越出沙盒目录: {path_str[:80]}"
    return None


def audit_code(code: str, workdir: str | Path) -> list[Finding]:
    """静态审查：解析 AST，找出危险导入 / 调用 / 越界文件访问"""
    workdir = Path(workdir)
    findings: list[Finding] = []

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [Finding(
            kind="exec_policy", label="代码无法解析",
            detail=f"语法错误（第 {e.lineno} 行）——可疑载荷可能被混淆或截断",
            severity=6,
        )]

    for node in ast.walk(tree):
        # --- 危险 import ---
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in BLOCKED_IMPORTS:
                    desc, sev = BLOCKED_IMPORTS[root]
                    findings.append(Finding(
                        kind="escape", label="危险模块导入",
                        detail=f"导入 `{alias.name}`：{desc}",
                        severity=sev, snippet=f"import {alias.name}",
                    ))
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in BLOCKED_IMPORTS:
                desc, sev = BLOCKED_IMPORTS[root]
                findings.append(Finding(
                    kind="escape", label="危险模块导入",
                    detail=f"导入 `{node.module}`：{desc}",
                    severity=sev, snippet=f"from {node.module} import ...",
                ))

        # --- 危险调用 / 越界 open ---
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name:
                if name in BLOCKED_CALLS:
                    desc, sev = BLOCKED_CALLS[name]
                    findings.append(Finding(
                        kind="escape", label="危险函数调用",
                        detail=f"调用 `{name}()`：{desc}",
                        severity=sev, snippet=f"{name}(...)",
                    ))
                elif name in ("open", "io.open") and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        violation = _jail_check(first.value, workdir)
                        if violation:
                            findings.append(Finding(
                                kind="escape", label="文件越界访问",
                                detail=violation, severity=8,
                                snippet=f"open({first.value[:60]!r})",
                            ))
    return findings


# --------------------------------------------------------------------------
# 受限执行
# --------------------------------------------------------------------------

def _minimal_env(tmpdir: Path) -> dict[str, str]:
    """最小环境变量集：只保留解释器启动必需项，杜绝密钥被任务代码读到"""
    keep = {}
    for key in ("SYSTEMROOT", "PATH", "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"):
        if key in os.environ:
            keep[key] = os.environ[key]
    keep.update({
        "TEMP": str(tmpdir),
        "TMP": str(tmpdir),
        "HOME": str(tmpdir),
        "USERPROFILE": str(tmpdir),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        # 注意：绝不传入 API Key / 数据库口令等任何业务密钥
    })
    return keep


def run_python(code: str, workdir: str | Path, timeout: float = 10,
               max_output: int = 4000, memory_mb: int = 256,
               max_processes: int = 4) -> ExecOutcome:
    """在受限子进程中执行一段 Python 代码

    流程：静态审查 → 写临时脚本 → 子进程运行（jail 工作目录 + 环境白名单 +
    硬超时 + Windows Job Object 内存/进程数硬限额）。
    """
    workdir = Path(workdir).resolve()
    findings = audit_code(code, workdir)

    hard = [f for f in findings if f.severity >= HARD_BLOCK_SEVERITY]
    if hard:
        return ExecOutcome(
            executed=False, ok=False,
            reason=f"静态审查拦截 {len(hard)} 处危险构造",
            findings=findings,
        )

    tmpdir = workdir / ".sandbox_tmp"
    tmpdir.mkdir(parents=True, exist_ok=True)
    script = tmpdir / f"job_{int(time.time() * 1000)}.py"
    script.write_text(code, encoding="utf-8")

    t0 = time.perf_counter()
    job = WindowsJobLimits(memory_mb=memory_mb, max_processes=max_processes)
    try:
        with job:   # 非 Windows 时空操作；销毁时强制回收残留子进程
            proc = subprocess.Popen(
                [sys.executable, "-s", "-u", str(script)],
                cwd=str(workdir),
                env=_minimal_env(tmpdir),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
            )
            job.assign(proc)   # 把子进程收进资源限额 Job
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                duration = (time.perf_counter() - t0) * 1000
                return ExecOutcome(
                    executed=True, ok=False,
                    stdout=stdout[-max_output:], stderr=stderr[-max_output:],
                    reason=f"执行超时（>{timeout}s），进程已被强制终止",
                    duration_ms=duration,
                    findings=findings + [Finding(
                        kind="exec_policy", label="执行超时",
                        detail="任务运行时间超出配额，已强制终止（可能为死循环或挖矿等资源滥用）",
                        severity=8,
                    )],
                )

        duration = (time.perf_counter() - t0) * 1000
        ok = proc.returncode == 0
        reason = "" if ok else f"任务退出码 {proc.returncode}"
        if not ok:
            findings = findings + [Finding(
                kind="exec_error", label="任务异常退出",
                detail=f"退出码 {proc.returncode}", severity=3,
                snippet=(stderr or "")[-200:],
            )]
        return ExecOutcome(
            executed=True, ok=ok,
            stdout=stdout[-max_output:], stderr=stderr[-max_output:],
            duration_ms=duration, reason=reason, findings=findings,
        )
    finally:
        script.unlink(missing_ok=True)
