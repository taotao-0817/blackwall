"""
黑墙系统 BlackWall V1.2 · AI Agent 安全隔离墙
==============================
为小型企业自研的 AI Agent / 程序提供安全限制与监管服务。

快速接入::

    from blackwall import BlackWall

    box = BlackWall("policies/default_policy.json", "data/audit.db")
    box.register_tool("send_email", my_send_email_fn)

    # Agent 的三扇门
    r = box.guard_input("my-agent", user_text)     # 收消息时
    r = box.call_tool("my-agent", "send_email", to=..., body=...)  # 用工具时
    r = box.guard_output("my-agent", draft_reply)  # 回复时

模块地图：
    models        数据模型（Action / Decision / Event）
    policy_engine 策略引擎（JSON 策略包的加载与求值）
    guards        输入/输出内容护栏（注入检测、PII/密钥检测、脱敏）
    sandbox_exec  受限执行沙盒（AST 静态审查 + 隔离子进程）
    risk          风险评分与自动熔断
    audit         SQLite 审计存储
    box           沙盒门面（三者编排，企业接入点）
"""
from .box import BlackWall, GuardResult, ToolSpec
from .models import (Action, Decision, Effect, Event, Finding, Phase,
                     ToolResult)
from .sandbox_exec import SandboxViolation, audit_code, run_python

__version__ = "1.2.0"
__all__ = [
    "BlackWall", "GuardResult", "ToolSpec",
    "Action", "Decision", "Effect", "Event", "Finding", "Phase", "ToolResult",
    "SandboxViolation", "audit_code", "run_python",
]
