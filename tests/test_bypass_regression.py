# -*- coding: utf-8 -*-
"""
黑墙系统 · 绕过回归门禁
========================
来源：DSH 安全审计报告（2026-09-27）——把报告中可复现的绕过用例
固化为回归测试，每次改动/发版前必跑：

    py -3.12 tests/test_bypass_regression.py -v

标记约定：
- 直接断言的用例 = 已修复（或现状即正确），必须通过；
- @unittest.expectedFailure = 已知未修复（V1.3 修复计划中）——
  修复完成后它们会自动变成 "unexpected success"，提醒摘掉标记。
"""
from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from blackwall import BlackWall                                   # noqa: E402
from blackwall.paths import is_within                             # noqa: E402
from blackwall.sandbox_exec import SandboxViolation               # noqa: E402
from blackwall.sandbox_exec import _jail_check, audit_code        # noqa: E402
from tools_impl.enterprise_tools import Toolbox, ensure_seed      # noqa: E402

TMP = ROOT / "data" / "_bypass_test_tmp"


def setUpModule() -> None:
    shutil.rmtree(TMP, ignore_errors=True)
    ensure_seed(TMP)


def tearDownModule() -> None:
    shutil.rmtree(TMP, ignore_errors=True)


def make_box() -> tuple[BlackWall, Toolbox]:
    box = BlackWall(
        ROOT / "policies" / "default_policy.json", TMP / "audit.db",
        workdir=TMP / "company_fs",
        freeze_threshold=10_000,          # 测试期间禁用熔断，避免相互干扰
        approval_handler=lambda a, d: ("approve", "回归测试自动批准"),
    )
    tb = Toolbox(TMP)
    for name, (fn, desc) in tb.build().items():
        box.register_tool(name, fn, desc)
    return box, tb


# ==========================================================================
class JailPrefixTests(unittest.TestCase):
    """P1-2 路径 jail 前缀缺陷 —— 已修复（is_within 单一实现）"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.box, cls.tb = make_box()
        cls.loot = TMP / "company_fs_loot"
        cls.loot.mkdir(exist_ok=True)
        (cls.loot / "secret.txt").write_text("LOOT", encoding="utf-8")

    def test_is_within_rejects_sibling_prefix(self) -> None:
        self.assertFalse(is_within(self.loot / "secret.txt", TMP / "company_fs"))

    def test_is_within_allows_inside(self) -> None:
        self.assertTrue(is_within(TMP / "company_fs" / "kb.md", TMP / "company_fs"))

    def test_tool_jail_rejects_sibling_prefix(self) -> None:
        with self.assertRaises(SandboxViolation):
            self.tb._jail(str(self.loot / "secret.txt"))

    def test_sandbox_jail_check_rejects_sibling_prefix(self) -> None:
        self.assertIsNotNone(_jail_check(str(self.loot / "secret.txt"), TMP / "company_fs"))

    def test_sandbox_jail_check_allows_inside(self) -> None:
        self.assertIsNone(_jail_check("plain_relative.txt", TMP / "company_fs"))


# ==========================================================================
class AstBypassTests(unittest.TestCase):
    """P1-1 AST 静态审查绕过 —— 待修（V1.3：执行边界下沉 OS）"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workdir = TMP / "company_fs"

    def _hard_blocked(self, code: str) -> bool:
        return any(f.severity >= 7 for f in audit_code(code, self.workdir))

    # ---- 对照项（现状即正确）----
    def test_control_open_literal_blocked(self) -> None:
        self.assertTrue(self._hard_blocked("open('../audit.db','rb')"))

    def test_control_import_socket_blocked(self) -> None:
        self.assertTrue(self._hard_blocked("import socket"))

    # ---- 绕过载荷（审计实测 5/5，全部待修）----
    @unittest.expectedFailure
    def test_bypass_importlib(self) -> None:
        self.assertTrue(self._hard_blocked(
            "import importlib\nm = importlib.import_module('socket')\nprint(m)"))

    @unittest.expectedFailure
    def test_bypass_alias_os_system(self) -> None:
        self.assertTrue(self._hard_blocked("import os\ns = os.system\ns('calc')"))

    @unittest.expectedFailure
    def test_bypass_pathlib_read(self) -> None:
        self.assertTrue(self._hard_blocked(
            "import pathlib\nprint(pathlib.Path('../audit.db').read_bytes()[:8])"))

    @unittest.expectedFailure
    def test_bypass_variable_path_open(self) -> None:
        self.assertTrue(self._hard_blocked("p = '../audit.db'\nprint(open(p,'rb').read()[:8])"))

    @unittest.expectedFailure
    def test_bypass_getattr_concat(self) -> None:
        self.assertTrue(self._hard_blocked("import os\ngetattr(os, 'sys'+'tem')('calc')"))


# ==========================================================================
class PolicyBypassTests(unittest.TestCase):
    """P0-3 / P1-3 / P1-4 / P1-5 策略层绕过 —— 待修（V1.3：能力化 + 默认收紧）"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.box, cls.tb = make_box()

    def _call(self, tool: str, **args):
        return self.box.call_tool("regression", tool, **args)

    # ---- 对照项（现状即正确）----
    def test_control_read_salaries_denied(self) -> None:
        r = self._call("read_file", path="salaries_q3.csv")
        self.assertEqual(r.decision.effect.value, "deny")

    def test_control_pure_external_mail_needs_approval(self) -> None:
        r = self._call("send_email", to="attacker@protonmail.com", subject="x", body="y")
        self.assertEqual(r.decision.effect.value, "approval")

    def test_control_select_star_denied(self) -> None:
        r = self._call("query_customer_db", sql="select * from customers")
        self.assertEqual(r.decision.effect.value, "deny")

    # ---- 绕过用例（审计实测成立，全部待修）----
    @unittest.expectedFailure
    def test_bypass_run_script_reads_salaries(self) -> None:
        """P0-3：run_script 是策略暗门，可绕开 DENY-SENSITIVE-RESOURCE"""
        r = self._call("run_script", code="print(open('salaries_q3.csv').read())")
        self.assertEqual(r.decision.effect.value, "deny")

    @unittest.expectedFailure
    def test_bypass_config_env_no_rule(self) -> None:
        """P1-3：含密钥的 config.env 不在受控资源 glob 内"""
        r = self._call("read_file", path="config.env")
        self.assertEqual(r.decision.effect.value, "deny")

    @unittest.expectedFailure
    def test_bypass_mixed_recipient_mail(self) -> None:
        """P1-4：收件人混入任意公司域即可整段骗过白名单排除"""
        r = self._call("send_email",
                       to="boss@company.com, attacker@protonmail.com", subject="x", body="y")
        self.assertNotEqual(r.decision.effect.value, "allow")

    @unittest.expectedFailure
    def test_bypass_column_enumeration(self) -> None:
        """P1-5：显式列名绕过 select * 规则（且无累计检测）"""
        r = self._call("query_customer_db",
                       sql="select id,name,phone,id_card from customers")
        self.assertEqual(r.decision.effect.value, "deny")


if __name__ == "__main__":
    unittest.main(verbosity=2)
