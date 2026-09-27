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
    data_dir: str | Path | None = None,
) -> BlackWall:
    """装配黑墙沙盒：种子数据 →（可选清库）→ 创建沙盒 → 注册企业工具

    data_dir：数据目录（默认 ./data）——测试可用独立目录隔离主演示数据。
    """
    data_dir = Path(data_dir) if data_dir else DATA_DIR
    ensure_seed(data_dir)

    if reset:
        for f in (data_dir / "audit.db", data_dir / "business.db", data_dir / "outbox.jsonl"):
            f.unlink(missing_ok=True)
        tmp = data_dir / "company_fs" / ".sandbox_tmp"
        if tmp.exists():
            shutil.rmtree(tmp)
        ensure_seed(data_dir)  # 重建业务库

    box = BlackWall(
        ROOT / "policies" / "default_policy.json",
        data_dir / "audit.db",
        workdir=data_dir / "company_fs",
        freeze_threshold=freeze_threshold,
        approval_handler=approval_handler,
    )
    toolbox = Toolbox(data_dir)
    for name, (fn, desc, caps) in toolbox.build().items():
        box.register_tool(name, fn, desc, capabilities=caps)
    return box
