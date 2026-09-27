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
from .paths import is_within
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
    "importlib": ("动态导入模块（可绕过静态审查）", 9),
    "runpy": ("动态执行模块代码", 9),
    "builtins": ("访问解释器内建命名空间（可绕过拦截）", 8),
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

#: V1.3 受控文件名特征——代码中出现即硬拦（封堵"用脚本读取小抄"绕过资源策略）
SENSITIVE_FILE_HINTS = (
    "salaries", "payroll", "薪资", "工资", "config.env", ".env",
    "secret", "credential", "password", "passwd", "id_rsa", ".pem", ".key",
)

#: V1.3 getattr 动态属性访问的高危目标模块（取点号名首段判定）
_SENSITIVE_MODULE_ROOTS = {"os", "sys", "subprocess", "ctypes", "builtins",
                           "importlib", "shutil", "socket", "posix"}

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
    # （用路径段求值 is_within，而非字符串前缀——`company_fs_old` 能骗过前缀匹配）
    if (len(p) >= 2 and p[1] == ":") or p.startswith("//"):
        try:
            resolved = Path(path_str).resolve()
        except (OSError, ValueError):
            return f"非法路径: {path_str[:80]}"
        if not is_within(resolved, workdir):
            return f"绝对路径越出沙盒目录: {path_str[:80]}"
    return None


def audit_code(code: str, workdir: str | Path) -> list[Finding]:
    """静态审查：解析 AST，找出危险导入 / 危险函数引用 / 越界与受控文件访问

    V1.3 升级（对抗"动态构造"规避写法；注意本层是快速筛查、不是执行边界）：
    - 危险函数从"仅调用"扩到"**引用即拦**"（`s = os.system; s("calc")` 别名写法命中）；
    - open()/Path() 字面量路径做 jail + 受控文件名双检查；open() 参数为动态
      表达式（变量/拼接/间接路径）时直接硬拦——无法静态确认目标的读写不放行；
    - getattr / __builtins__ / `from os import system` 等动态取用手法纳入审查；
    - importlib / runpy 等动态导入模块列入黑名单。
    终极兜底是 OS 级隔离（见 README 生产化路线）——本层负责"低成本拿下绝大多数"。
    """
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

    def add(label: str, detail: str, sev: int, snippet: str = "") -> None:
        findings.append(Finding(kind="escape", label=label, detail=detail,
                                severity=sev, snippet=snippet))

    for node in ast.walk(tree):
        # --- 危险 import ---
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in BLOCKED_IMPORTS:
                    desc, sev = BLOCKED_IMPORTS[root]
                    add("危险模块导入", f"导入 `{alias.name}`：{desc}", sev,
                        f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in BLOCKED_IMPORTS:
                desc, sev = BLOCKED_IMPORTS[root]
                add("危险模块导入", f"导入 `{node.module}`：{desc}", sev,
                    f"from {node.module} import ...")
            if root == "os":    # from os import system / popen / remove …（别名直取高危函数）
                for alias in node.names:
                    if alias.name in ("system", "popen", "execv", "execve", "execvp",
                                      "execl", "execlp", "remove", "unlink", "rmdir",
                                      "kill", "spawnv", "spawnl"):
                        add("危险函数导入",
                            f"从 os 直接导入高危函数 `{alias.name}`（别名绕过的常见手法）",
                            9, f"from os import {alias.name}")

        # --- 危险函数：引用即拦（`s = os.system` 之类的别名同样命中）---
        elif isinstance(node, ast.Attribute):
            name = _dotted(node)
            if name in BLOCKED_CALLS:
                desc, sev = BLOCKED_CALLS[name]
                add("危险函数引用", f"引用 `{name}`：{desc}（赋值/传参别名同样拦截）",
                    sev, name)
        elif isinstance(node, ast.Name):
            if node.id in BLOCKED_CALLS:
                desc, sev = BLOCKED_CALLS[node.id]
                add("危险函数引用", f"引用 `{node.id}`：{desc}", sev, node.id)
            elif node.id == "__builtins__":
                add("危险引用", "访问 __builtins__ 命名空间（意图绕过解释器限制）", 8,
                    "__builtins__")

        # --- 文件访问 / 动态属性 ---
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if not name:
                continue
            if name in ("open", "io.open", "pathlib.Path", "Path"):
                target = node.args[0] if node.args else None
                if isinstance(target, ast.Constant) and isinstance(target.value, str):
                    pval = str(target.value)
                    violation = _jail_check(pval, workdir)
                    if violation:
                        add("文件越界访问", violation, 8, f"{name}({pval[:60]!r})")
                    low = pval.lower().replace("\\", "/")
                    hit = next((h for h in SENSITIVE_FILE_HINTS if h in low), None)
                    if hit:
                        add("受控文件访问",
                            f"代码试图打开受控文件（文件名特征命中 `{hit}`）：{pval[:60]}",
                            8, f"{name}({pval[:60]!r})")
                elif name in ("open", "io.open"):
                    add("动态文件路径",
                        "open() 参数为动态表达式，无法静态审查目标路径——沙盒内仅允许"
                        "字面量路径（确实需要动态路径时请走人工审批）", 7, "open(<expr>)")
                else:
                    add("动态路径构造",
                        "Path() 参数为动态表达式，建议改为字面量路径以便静态审查",
                        5, "Path(<expr>)")
            elif name == "getattr":
                base = node.args[0] if node.args else None
                attr = node.args[1] if len(node.args) > 1 else None
                base_name = _dotted(base) if base is not None else None
                if base_name and base_name.split(".")[0] in _SENSITIVE_MODULE_ROOTS:
                    add("动态属性访问",
                        f"getattr 目标为敏感模块 `{base_name}`（动态取属性可绕过静态拦截）",
                        8, "getattr(...)")
                elif not (isinstance(attr, ast.Constant) and isinstance(attr.value, str)):
                    add("动态属性访问",
                        "getattr 属性名为动态表达式（拼接/变量），无法静态审查",
                        8, "getattr(...)")
                else:
                    add("动态属性访问",
                        f"getattr({base_name or '?'}, {attr.value!r}) —— 留痕审查",
                        5, "getattr(...)")
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


def _tail_text(path: Path, max_chars: int) -> str:
    """从文件尾部读取至多 max_chars 个字符

    按字节定位后只读尾部（utf-8 单字符最多 4 字节，留少量余量），
    避免把子进程的海量输出整读进父进程内存。
    """
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    take = max_chars * 4 + 8
    with open(path, "rb") as f:
        f.seek(max(0, size - take))
        data = f.read(take)
    return data.decode("utf-8", errors="replace")[-max_chars:]


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

    out_file = tmpdir / f"{script.stem}.out"
    err_file = tmpdir / f"{script.stem}.err"

    t0 = time.perf_counter()
    job = WindowsJobLimits(memory_mb=memory_mb, max_processes=max_processes)
    soft_findings: list[Finding] = []
    try:
        with job:   # 非 Windows 时空操作；销毁时强制回收残留子进程
            # 子进程输出落到临时文件（而非内存管道）：即使子进程疯狂打印，
            # 也只占磁盘；读取时仅取尾部 max_output 字符，父进程内存恒定。
            with open(out_file, "wb") as fo, open(err_file, "wb") as fe:
                proc = subprocess.Popen(
                    [sys.executable, "-s", "-u", str(script)],
                    cwd=str(workdir),
                    env=_minimal_env(tmpdir),
                    stdout=fo, stderr=fe,
                )
                if job.available and not job.assign(proc):
                    # 限额指派失败不能静默（否则"资源限额生效"的宣称失去担保）——
                    # 留痕到审计，由上层风险策略决定是否从严
                    soft_findings.append(Finding(
                        kind="exec_policy", label="资源限额未生效",
                        detail=f"Job Object 指派子进程失败：{job.error or '原因未知'}",
                        severity=5,
                    ))
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    duration = (time.perf_counter() - t0) * 1000
                    return ExecOutcome(
                        executed=True, ok=False,
                        stdout=_tail_text(out_file, max_output),
                        stderr=_tail_text(err_file, max_output),
                        reason=f"执行超时（>{timeout}s），进程已被强制终止",
                        duration_ms=duration,
                        findings=findings + soft_findings + [Finding(
                            kind="exec_policy", label="执行超时",
                            detail="任务运行时间超出配额，已强制终止（可能为死循环或挖矿等资源滥用）",
                            severity=8,
                        )],
                    )

        duration = (time.perf_counter() - t0) * 1000
        stdout = _tail_text(out_file, max_output)
        stderr = _tail_text(err_file, max_output)
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
            stdout=stdout, stderr=stderr,
            duration_ms=duration, reason=reason, findings=findings + soft_findings,
        )
    finally:
        script.unlink(missing_ok=True)
        out_file.unlink(missing_ok=True)
        err_file.unlink(missing_ok=True)
