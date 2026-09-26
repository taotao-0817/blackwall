# -*- coding: utf-8 -*-
"""
黑墙系统 BlackWall · 路径归属判定（单一实现，消除同源缺陷）
==========================================================
安全审计（2026-09-27）发现：沙盒（sandbox_exec）与工具层（enterprise_tools）
各自手写了一份"路径是否越界"检查，且**两份都用字符串前缀匹配**：

    str(resolved).startswith(str(jail))
    "C:\\x\\company_fs_old"  startswith "C:\\x\\company_fs"  → True（不应通过！）

字符串前缀 ≠ 目录归属。本模块提供唯一正确实现，两处共用。
"""
from __future__ import annotations

from pathlib import Path


def is_within(target: str | Path, root: str | Path) -> bool:
    """target 是否位于 root 目录之内（含 root 本身；解析符号链接）。

    - 用路径段求值（relative_to），而非字符串前缀；
    - 任意解析失败按"越界"处理（fail-closed）。
    """
    try:
        Path(target).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False
