"""
黑墙系统 BlackWall · 终端输出（ANSI 彩色）
=================================
跑 demo 时的控制台观感：场景叙述、裁决行、风险分进度。
尊重 NO_COLOR 环境变量；重定向到文件时自动降级为纯文本。
"""
from __future__ import annotations

import os
import sys

_ENABLED = ("NO_COLOR" not in os.environ) and (
    sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1"
)

_R = "\033[0m"
_STYLES = {
    "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "gray": "\033[90m", "bright_red": "\033[91m", "bright_green": "\033[92m",
    "bright_yellow": "\033[93m", "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m", "bright_cyan": "\033[96m",
}


def c(text: str, *styles: str) -> str:
    if not _ENABLED or not styles:
        return text
    prefix = "".join(_STYLES.get(s, "") for s in styles)
    return f"{prefix}{text}{_R}"


def rule(char: str = "─", width: int = 74, color: str = "gray") -> str:
    return c(char * width, color)


def banner(title: str, subtitle: str = "", width: int = 74) -> None:
    bar = "═" * width
    print()
    print(c(bar, "bright_blue"))
    print(c("  " + title, "bold", "bright_blue") +
          ("    " + c(subtitle, "dim") if subtitle else ""))
    print(c(bar, "bright_blue"))


def scene(idx: int, total: int, title: str, desc: str = "") -> None:
    print()
    print(c(f"▌ 场景 {idx:02d}/{total:02d} · ", "bold", "bright_cyan") + c(title, "bold"))
    if desc:
        for line in desc.split("\n"):
            print(c("   " + line, "gray"))


def step(label: str, value: str) -> None:
    print(c(f"   {label} ", "dim") + value)


def verdict(effect: str, rule_id: str = "", reason: str = "") -> None:
    icons = {"allow": ("√ 放行", "bright_green"), "deny": ("× 已拦截", "bright_red"),
             "approval": ("‖ 挂起待审", "bright_yellow"), "sanitize": ("◎ 脱敏放行", "bright_magenta")}
    text, color = icons.get(effect, (effect, "white"))
    out = c(f"   │ 裁决 > {text}", "bold", color)
    if rule_id:
        out += c(f"  [{rule_id}]", "dim")
    print(out)
    if reason:
        print(c("   │ 理由 > ", "dim") + c(reason, "yellow"))


def riskbar(score: int, note: str = "") -> None:
    blocks = 20
    filled = round(score / 100 * blocks)
    color = "bright_green" if score < 40 else ("bright_yellow" if score < 90 else "bright_red")
    bar = "█" * filled + "░" * (blocks - filled)
    print(c("   │ 风险 > ", "dim") + c(bar, color) + c(f" {score}/100", color) +
          (c(f"  {note}", "dim") if note else ""))


def result_line(text: str, color: str = "green") -> None:
    print(c("   └ 结果 > ", "dim") + c(text, color))
