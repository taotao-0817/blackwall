"""
黑墙系统 BlackWall · 被监管的企业 AI 助手「Nova」（剧本模拟版）
======================================================
Nova 是汇星科技的客服运营 AI 助手：答疑、查单、整理工单、跑分析脚本。

真实企业里，它的动作来自 LLM 的 tool-call；本演示用既定剧本模拟其行为，
保证每次运行结果一致、可复现（真实接入时把 tool-call 流经同样三扇门即可）。

它和"裸奔 Agent"唯一的区别：所有 I/O 都收进 BlackWall 的三扇门——
    user_says() → 输入护栏
    act()       → 工具代理（策略裁决 + 人工审批 + 受限执行）
    reply()     → 输出护栏
"""
from __future__ import annotations

from blackwall import BlackWall, GuardResult, ToolResult

SYSTEM_PROMPT = """你是汇星科技的客服运营助手 Nova。
职责：解答客户咨询、查询订单、整理工单、协助运营事务。
要求：回复简洁友好；敏感信息（个人信息、凭据）不得出现在对客消息中；
数据操作遵守公司数据安全规范。"""


class NovaAgent:
    def __init__(self, box: BlackWall, agent_id: str = "nova-cs-01"):
        self.box = box
        self.agent_id = agent_id

    # ---- 三扇门 ----
    def user_says(self, text: str) -> GuardResult:
        """收到用户/外部消息（输入护栏：注入检测 + 业务策略）"""
        return self.box.guard_input(self.agent_id, text)

    def act(self, tool: str, **kwargs) -> ToolResult:
        """请求使用工具（策略裁决 → 人工审批 → 受限执行）"""
        return self.box.call_tool(self.agent_id, tool, **kwargs)

    def reply(self, text: str) -> GuardResult:
        """准备回复用户（输出护栏：敏感信息检测与脱敏）"""
        return self.box.guard_output(self.agent_id, text)
