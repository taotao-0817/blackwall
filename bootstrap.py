# -*- coding: utf-8 -*-
"""
黑墙系统 BlackWall · 引导装配
==============================
demo.py（每次从干净状态演示）与 server.py（持续运行、数据留存）共用的装配逻辑：

    build_box(reset=True)   → 演示用：清空审计库/业务库后重建
    build_box(reset=False)  → 网关用：保留历史数据，续接运行
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable

from blackwall import BlackWall
from tools_impl.enterprise_tools import Toolbox, ensure_seed

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"


def build_box(
    *,
    reset: bool = False,
    approval_handler: Callable[..., Any] | None = None,
    freeze_threshold: int = 100,
) -> BlackWall:
    """装配黑墙沙盒：种子数据 →（可选清库）→ 创建沙盒 → 注册企业工具"""
    ensure_seed(DATA_DIR)

    if reset:
        for f in (DATA_DIR / "audit.db", DATA_DIR / "business.db", DATA_DIR / "outbox.jsonl"):
            f.unlink(missing_ok=True)
        tmp = DATA_DIR / "company_fs" / ".sandbox_tmp"
        if tmp.exists():
            shutil.rmtree(tmp)
        ensure_seed(DATA_DIR)  # 重建业务库

    box = BlackWall(
        ROOT / "policies" / "default_policy.json",
        DATA_DIR / "audit.db",
        workdir=DATA_DIR / "company_fs",
        freeze_threshold=freeze_threshold,
        approval_handler=approval_handler,
    )
    toolbox = Toolbox(DATA_DIR)
    for name, (fn, desc) in toolbox.build().items():
        box.register_tool(name, fn, desc)
    return box
