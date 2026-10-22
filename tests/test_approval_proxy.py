from __future__ import annotations

import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


PROXY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "approval_proxy.py"
SPEC = importlib.util.spec_from_file_location("approval_proxy_ui_tests", PROXY_PATH)
proxy = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(proxy)


class ApprovalRequestTests(unittest.TestCase):
    def test_message_only_requests_remain_compatible(self) -> None:
        request = json.dumps({"message": "  complete operation details  "})
        self.assertEqual(proxy.read_request(io.StringIO(request)), "complete operation details")
        self.assertEqual(proxy.parse_request(io.StringIO(request)), ("complete operation details", None))

    def test_chinese_intent_is_validated_and_preserved(self) -> None:
        request = {"message": "systemctl restart app", "intent_zh": "重启应用服务，使新配置生效。"}
        self.assertEqual(
            proxy.parse_request(io.StringIO(json.dumps(request))),
            (request["message"], request["intent_zh"]),
        )
        self.assertEqual(proxy.validate_intent("中" * 500), "中" * 500)

    def test_invalid_requests_fail_closed_without_opening_window(self) -> None:
        invalid = [None, [], {}, {"message": True}, {"message": " "}, {"message": "x" * 24_001}]
        invalid_intents = [None, True, 123, [], "", " ", "restart application", "中" * 501,
                           "删除\n文件", "删除\t文件", "删除\x00文件", "删除\u202e文件", "删除\u200b文件",
                           "删除\u2028文件", "删除\u2029文件"]
        invalid.extend({"message": "command", "intent_zh": value} for value in invalid_intents)
        for value in invalid:
            with self.subTest(request=value), patch.object(proxy.sys, "stdin", io.StringIO(json.dumps(value))), \
                    patch.object(proxy.sys, "stdout", new_callable=io.StringIO) as output, \
                    patch.object(proxy, "ask_user") as ask:
                self.assertEqual(proxy.main(), 2)
                self.assertEqual(json.loads(output.getvalue()), {"approved": False})
                ask.assert_not_called()

    def test_main_forwards_intent_and_handles_gui_failure(self) -> None:
        request = json.dumps({"message": "command", "intent_zh": "重启服务。"})
        for failure in (False, True):
            with self.subTest(gui_failure=failure), patch.object(proxy.sys, "stdin", io.StringIO(request)), \
                    patch.object(proxy.sys, "stdout", new_callable=io.StringIO) as output, \
                    patch.object(proxy, "ask_user", return_value=True) as ask:
                if failure:
                    ask.side_effect = RuntimeError("private environment detail")
                self.assertEqual(proxy.main(), 2 if failure else 0)
                ask.assert_called_once_with("command", intent_zh="重启服务。")
                self.assertEqual(json.loads(output.getvalue()), {"approved": not failure})
                self.assertNotIn("private", output.getvalue())


class ApprovalDialogTests(unittest.TestCase):
    def _show_mock_dialog(self, decision: str, intent: str | None = "重启应用服务，使新配置生效。"):
        # 完全替换 Tk，测试绝不创建真实窗口，也不自动点击用户的审批窗口。
        root = MagicMock()
        commands = {}
        approved = {"value": False}
        boolean = MagicMock()
        boolean.get.side_effect = lambda: approved["value"]
        boolean.set.side_effect = lambda value: approved.update(value=value)

        def button_factory(*args, **kwargs):
            commands[kwargs["text"]] = kwargs["command"]
            return MagicMock()

        def decide():
            if decision == "close":
                root.protocol.call_args.args[1]()
            else:
                commands[decision]()

        root.wait_window.side_effect = decide
        message = "Target: example-host\nCommand:\nsystemctl restart app\nNext exact line"
        with patch.object(proxy.tk, "Tk", return_value=root), \
                patch.object(proxy.tk, "BooleanVar", return_value=boolean) as variable, \
                patch.object(proxy.tk, "Label") as labels, patch.object(proxy.tk, "Text") as text, \
                patch.object(proxy.ttk, "Frame"), patch.object(proxy.ttk, "Label"), \
                patch.object(proxy.ttk, "Scrollbar") as scrollbar, \
                patch.object(proxy.ttk, "Button", side_effect=button_factory):
            result = proxy.ask_user(message, intent_zh=intent)
        variable.assert_called_once_with(value=False)
        root.protocol.assert_called_once_with("WM_DELETE_WINDOW", root.destroy)
        root.destroy.assert_called_once_with()
        text.return_value.insert.assert_called_once_with("1.0", message)
        text.return_value.configure.assert_any_call(state="disabled")
        scrollbar.assert_called_once_with(
            unittest.mock.ANY, orient="vertical", command=text.return_value.yview,
        )
        text.return_value.configure.assert_any_call(yscrollcommand=scrollbar.return_value.set)
        return result, labels.call_args_list

    def test_chinese_intent_is_prominent_red_bold_and_command_is_preserved(self) -> None:
        result, labels = self._show_mock_dialog("确认并执行")
        self.assertTrue(result)
        self.assertEqual(labels[0].kwargs["text"], "请确认操作意图")
        self.assertEqual(labels[1].kwargs["text"], "重启应用服务，使新配置生效。")
        for label in labels:
            self.assertEqual(label.kwargs["foreground"], "#b91c1c")
            self.assertIn("bold", label.kwargs["font"])
            self.assertGreaterEqual(label.kwargs["font"][1], 13)

    def test_close_and_reject_do_not_approve(self) -> None:
        for decision in ("close", "拒绝"):
            with self.subTest(decision=decision):
                result, _ = self._show_mock_dialog(decision)
                self.assertFalse(result)

    def test_legacy_requests_show_generic_chinese_warning(self) -> None:
        result, labels = self._show_mock_dialog("拒绝", intent=None)
        self.assertFalse(result)
        self.assertEqual(labels[1].kwargs["text"], proxy.DEFAULT_INTENT_ZH)
        self.assertEqual(labels[1].kwargs["foreground"], "#b91c1c")

    def test_invalid_intent_does_not_create_window(self) -> None:
        with patch.object(proxy.tk, "Tk") as create_window, self.assertRaises(ValueError):
            proxy.ask_user("command", intent_zh="restart service")
        create_window.assert_not_called()


if __name__ == "__main__":
    unittest.main()
