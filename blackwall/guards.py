"""
黑墙系统 BlackWall · 内容护栏（输入 / 输出双向）
======================================
InputGuard  : 拦截 Prompt 注入 / 越狱话术 / 编码绕过（含"间接注入"——
              外部客户消息里夹带的指令同样逃不过）。
OutputGuard : 检测 PII、API 密钥、内部路径等泄露，提供**脱敏**能力，
              让"柔性监管"成为可能（不放行不行，直接拦截又太粗暴）。

这两层是纯模式匹配 + 规则，可解释、可审计；生产中可叠加语义模型做二道防线。
"""
from __future__ import annotations

import re

from .models import Finding

# --------------------------------------------------------------------------
# 输入侧：Prompt 注入 / 越狱
# --------------------------------------------------------------------------

INJECTION_PATTERNS: list[tuple[str, str, int]] = [
    # (正则, 说明, 严重度)
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
     "英文经典注入短语", 9),
    (r"disregard\s+(your|all|any)\s+(instructions?|rules?|guidelines?|constraints?)",
     "英文无视指令短语", 9),
    (r"forget\s+(your|all|everything)[^.\n]{0,30}(instructions?|rules?|prompt)",
     "遗忘指令短语", 8),
    (r"(reveal|show|print|output|repeat|dump)\s+(me\s+)?(your\s+|the\s+)?(system\s+|initial\s+)?(prompt|instructions?)",
     "探测系统提示词", 8),
    (r"忽略(以上|上面|之前|先前|所有|前面)[^。\n]{0,8}(指令|规则|要求|提示|设定)",
     "中文忽略指令", 9),
    (r"(输出|告诉我|重复|展示|打印|复述)[^。\n]{0,8}(你的)?(系统|初始|隐藏)[^。\n]{0,4}(提示词?|指令|设定)",
     "中文探测系统提示词", 8),
    (r"(进入|开启|激活)[^。\n]{0,4}(开发者|调试|上帝|超级)[^。\n]{0,2}(模式|权限)",
     "伪模式提权话术", 8),
    (r"你现在是[^。\n]{0,10}(不受限|无限制|没有限制|不受任何约束)",
     "角色扮演绕过", 8),
    (r"(扮演|假装)[^。\n]{0,10}(黑客|没有道德|不受限制|不讲道德)",
     "角色扮演绕过", 7),
    (r"jailbreak|DAN\s*mode|do\s+anything\s+now",
     "越狱关键词", 9),
]

#: 超长 Base64 块（编码绕过嫌疑）
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")

#: 需要警惕的"注入载荷搭配词"——光有指令词还不够，配合这些才算实锤
#（本 demo 保持简单：命中即报，生产可做组合加权）


class InputGuard:
    """输入护栏：看的是"进来打算让 Agent 干什么" """

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        if not text:
            return findings

        for pattern, desc, severity in INJECTION_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                findings.append(Finding(
                    kind="prompt_injection",
                    label="Prompt 注入",
                    detail=desc,
                    severity=severity,
                    snippet=m.group(0)[:80],
                ))

        m = _BASE64_BLOB.search(text)
        if m:
            findings.append(Finding(
                kind="encoding_evasion",
                label="编码绕过嫌疑",
                detail="输入包含超长 Base64 编码块，可能用于隐藏指令或窃取数据",
                severity=4,
                snippet=m.group(0)[:40] + "…",
            ))

        return findings


# --------------------------------------------------------------------------
# 输出侧：数据泄露检测 + 脱敏
# --------------------------------------------------------------------------

PII_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), 6),
    ("身份证号", re.compile(r"(?<!\w)\d{17}[\dXx](?!\w)"), 8),
    ("银行卡号", re.compile(r"(?<!\d)(?:\d{4}[ -]){3}\d{4}(?![\d-])|(?<!\d)\d{16,19}(?!\d)"), 8),
    ("邮箱地址", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), 3),
]

SECRET_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("API 密钥(sk-)", re.compile(r"sk-[A-Za-z0-9]{16,}"), 10),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), 10),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), 10),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}"), 10),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), 10),
    ("私钥文件内容", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 10),
    ("数据库连接串", re.compile(
        r"(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s:@/]+@[^\s\"']+"), 9),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), 9),
]

PATH_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("内部 Windows 路径", re.compile(r"[A-Za-z]:\\Users\\[^\s\"'<>|,，。]+"), 5),
    ("内部 Unix 路径", re.compile(r"/(?:etc|home|root|var/log)/[^\s\"'<>|,，。]*"), 5),
]

#: 强制脱敏的类别（邮箱只提示、不遮——客服场景里邮箱未必是敏感物）
_REDACT_KINDS = {"手机号", "身份证号", "银行卡号", "API 密钥(sk-)", "AWS Access Key",
                 "GitHub Token", "Google API Key", "Slack Token", "私钥文件内容",
                 "数据库连接串", "JWT Token"}


class OutputGuard:
    """输出护栏：看的是"Agent 打算把什么送出去" """

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        if not text:
            return findings

        # 按类别优先顺序扫描，并对重叠区域去重
        #（避免 18 位身份证号被银行卡正则重复归类）
        spans: list[tuple[int, int]] = []
        candidates = (
            [(label, p, sev, "pii") for label, p, sev in PII_PATTERNS]
            + [(label, p, sev, "secret") for label, p, sev in SECRET_PATTERNS]
            + [(label, p, sev, "internal_path") for label, p, sev in PATH_PATTERNS]
        )
        for label, pattern, severity, kind in candidates:
            for m in list(pattern.finditer(text))[:3]:      # 每类最多取证 3 处
                s, e = m.span()
                if any(not (e <= s0 or s >= e0) for s0, e0 in spans):
                    continue                                # 与已确认的敏感区域重叠
                spans.append((s, e))
                findings.append(Finding(
                    kind=kind,
                    label=label,
                    detail=f"输出中发现{label}",
                    severity=severity,
                    snippet=m.group(0)[:60],
                ))
        return findings

    def redact(self, text: str, findings: list[Finding] | None = None) -> str:
        """对高价值敏感内容做遮盖；邮箱等低价值类别只告警不遮盖"""
        out = text
        for label, pattern, _severity in PII_PATTERNS + SECRET_PATTERNS:
            if label not in _REDACT_KINDS:
                continue
            out = pattern.sub(f"[已脱敏:{label}]", out)
        return out
