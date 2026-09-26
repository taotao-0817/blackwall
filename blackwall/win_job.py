# -*- coding: utf-8 -*-
"""
黑墙系统 BlackWall · Windows Job Object 资源限额（硬隔离增强）
==============================================================
AST 静态审查管"意图"，Job Object 管"物理上限"——这是一道**即使代码骗过
静态审查也依然生效**的兜底防线：

- 内存硬上限：子进程分配超过配额直接失败（防内存炸弹 / 挖矿程序）；
- 进程数硬上限：Job 内同时存在的进程数封顶（防 fork 炸弹 / 扫地兵进程）；
- 随沙盒回收：沙盒对象销毁时，Job 内所有进程被强制终止（防残留后门进程）。

纯标准库（ctypes 调用 kernel32）。非 Windows 平台自动降级为空操作。

    with WindowsJobLimits(memory_mb=256, max_processes=4) as job:
        proc = subprocess.Popen(cmd)
        job.assign(proc)
        proc.wait()
"""
from __future__ import annotations

import ctypes
import subprocess
import sys

_IS_WINDOWS = sys.platform == "win32"

# Job Object 信息类别 / 限制标志（Windows SDK 常量）
_JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

if _IS_WINDOWS:
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    # 注意：HANDLE 是 64 位指针，必须显式声明 restype/argtypes，
    # 否则 ctypes 默认按 32 位 int 截断，句柄会坏掉。
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


class WindowsJobLimits:
    """Windows Job Object 资源限额上下文管理器（非 Windows 为空操作）

    参数：
        memory_mb      进程及 Job 的内存硬上限（MB）
        max_processes  Job 内同时存在的进程数上限
    """

    def __init__(self, memory_mb: int = 256, max_processes: int = 4):
        self.memory_mb = int(memory_mb)
        self.max_processes = int(max_processes)
        self.available = _IS_WINDOWS
        self.error = ""
        self._job = None

    def __enter__(self) -> "WindowsJobLimits":
        if not _IS_WINDOWS:
            return self
        self._job = _kernel32.CreateJobObjectW(None, None)
        if not self._job:
            self.available = False
            self.error = f"CreateJobObjectW 失败（err={ctypes.get_last_error()}）"
            return self

        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        info.BasicLimitInformation.ActiveProcessLimit = self.max_processes
        limit_bytes = self.memory_mb * 1024 * 1024
        info.ProcessMemoryLimit = limit_bytes
        info.JobMemoryLimit = limit_bytes

        ok = _kernel32.SetInformationJobObject(
            self._job, _JobObjectExtendedLimitInformation,
            ctypes.byref(info), ctypes.sizeof(info))
        if not ok:
            self.available = False
            self.error = f"SetInformationJobObject 失败（err={ctypes.get_last_error()}）"
            _kernel32.CloseHandle(self._job)
            self._job = None
        return self

    def assign(self, proc: "subprocess.Popen") -> bool:
        """把已启动的子进程收进 Job（失败返回 False，调用方按"无限额"降级）"""
        if not self._job:
            return False
        try:
            return bool(_kernel32.AssignProcessToJobObject(self._job, int(proc._handle)))
        except (AttributeError, ValueError, OSError):
            return False

    def __exit__(self, *exc_info) -> bool:
        if self._job:
            # KILL_ON_JOB_CLOSE：销毁 Job → 内部所有进程被强制回收
            _kernel32.CloseHandle(self._job)
            self._job = None
        return False
