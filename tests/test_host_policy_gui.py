"""主机审批策略 GUI 回归：模拟 Tk，不启动窗口、读取凭据或连接 SSH。"""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("scb_host_policy_gui", PLUGIN_ROOT / "scripts" / "ssh_manager_gui.py")
assert SPEC and SPEC.loader
gui = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gui)


class FakeVariable:
    def __init__(self, value=None, **_kwargs):
        self.value = value
        self.callbacks = []

    def get(self):
        return self.value

    def set(self, value):
        self.value = value
        for callback in self.callbacks:
            callback("variable", "", "write")

    def trace_add(self, _mode, callback):
        self.callbacks.append(callback)
        return str(len(self.callbacks))


class FakeWidget:
    def __init__(self, *_args, **kwargs):
        self.options = kwargs
        self.items = {}
        self.tags = {}
        self.columns = {}
        self.selected = ()

    def grid(self, **_kwargs):
        pass

    def pack(self, **_kwargs):
        pass

    def bind(self, *_args):
        pass

    def configure(self, **kwargs):
        self.options.update(kwargs)

    def heading(self, column, **kwargs):
        self.columns[column] = kwargs

    def column(self, *_args, **_kwargs):
        pass

    def tag_configure(self, tag, **kwargs):
        self.tags[tag] = kwargs

    def insert(self, _parent, _index, *, iid, **kwargs):
        self.items[iid] = kwargs

    def get_children(self):
        return tuple(self.items)

    def delete(self, item):
        self.items.pop(item)

    def selection(self):
        return self.selected

    def selection_set(self, alias):
        self.selected = (alias,)

    def focus(self, *_args):
        pass

    def see(self, *_args):
        pass

    def yview(self, *_args):
        pass

    def set(self, *_args):
        pass

    def add(self, *_args, **_kwargs):
        pass


def host_entry(**overrides):
    return {"host": "192.0.2.10", "port": 2222, "username": "fixture-user",
        "host_key_sha256": "SHA256:" + "A" * 43,
        "credential_target": "SecureCredentialBridge/ssh/fixture-host", **overrides}


class HostPolicyGUITests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for base in (gui.tk.Tk, gui.tk.Toplevel):
            self.stack.enter_context(patch.object(base, "__init__", return_value=None))
            for method in ("title", "geometry", "minsize", "resizable", "transient", "grab_set",
                           "wait_visibility", "focus_set", "wait_window", "destroy", "after"):
                self.stack.enter_context(patch.object(base, method, return_value=None))
        self.stack.enter_context(patch.object(gui.tk, "StringVar", FakeVariable))
        self.stack.enter_context(patch.object(gui.tk, "BooleanVar", FakeVariable))
        for widget in ("Frame", "Label", "Entry", "Button", "Checkbutton", "Combobox", "Notebook", "Treeview", "Scrollbar"):
            self.stack.enter_context(patch.object(gui.ttk, widget, FakeWidget))
        self.errors = self.stack.enter_context(patch.object(gui.messagebox, "showerror"))
        self.stack.enter_context(patch.object(gui.messagebox, "showinfo"))
        self.stack.enter_context(patch.object(gui, "default_config_path", return_value=PLUGIN_ROOT / "test" / "fixture-host-policy.json"))
        self.stack.enter_context(patch.object(gui, "load_config", return_value={}))
        for owner, name in ((gui, "store_secret"), (gui, "delete_credential"), (gui.bridge, "read_credential"),
                            (gui.socket, "create_connection")):
            self.stack.enter_context(patch.object(owner, name, side_effect=AssertionError("offline GUI test must not access credentials or SSH")))

    def dialog(self, **overrides):
        return gui.HostDialog(Mock(), {"_alias": "fixture-host", **host_entry(**overrides)})

    def test_new_and_legacy_hosts_default_to_write_confirmation(self):
        new = gui.HostDialog(Mock())
        self.assertEqual(new.environment.get(), "未指定")
        self.assertEqual(new.approval_policy.get(), "写操作确认")
        self.assertEqual(new.policy_box.options["values"], ("写操作确认",))
        legacy = self.dialog()
        legacy._accept()
        self.assertEqual(legacy.result["entry"]["environment"], "unspecified")
        self.assertEqual(legacy.result["entry"]["approval_policy"], "confirm_writes")
        self.assertEqual(legacy.result["entry"]["credential_target"], host_entry()["credential_target"])
        self.errors.assert_not_called()

    def test_edit_preserves_valid_environment_and_both_policy_choices(self):
        for environment, policy in (("unspecified", "confirm_writes"), ("production", "confirm_writes"),
                                    ("test", "confirm_writes"), ("test", "test_all_commands")):
            with self.subTest(environment=environment, policy=policy):
                dialog = self.dialog(environment=environment, approval_policy=policy)
                dialog._accept()
                self.assertEqual(dialog.result["entry"]["environment"], environment)
                self.assertEqual(dialog.result["entry"]["approval_policy"], policy)
        self.errors.assert_not_called()

    def test_explicit_test_selection_allows_preauthorization_and_can_be_revoked(self):
        dialog = self.dialog()
        dialog.environment.set("测试环境")
        self.assertEqual(dialog.approval_policy.get(), "写操作确认")
        self.assertEqual(dialog.policy_box.options["values"], ("写操作确认", "全部操作预授权"))
        dialog.approval_policy.set("全部操作预授权")
        dialog._accept()
        self.assertEqual(dialog.result["entry"]["approval_policy"], "test_all_commands")
        dialog.approval_policy.set("写操作确认")
        dialog._accept()
        self.assertEqual(dialog.result["entry"]["approval_policy"], "confirm_writes")

    def test_every_connection_identity_change_resets_then_allows_fresh_selection(self):
        for field, value in (("alias", "other-host"), ("host", "192.0.2.20"), ("port", "2200"),
                             ("username", "other-user"), ("fingerprint", "SHA256:" + "B" * 43)):
            with self.subTest(field=field):
                dialog = self.dialog(environment="test", approval_policy="test_all_commands")
                getattr(dialog, field).set(value)
                self.assertEqual(dialog.approval_policy.get(), "写操作确认")
                self.assertIn("已重置为写操作确认", dialog.policy_status.get())
                dialog._accept()
                self.assertEqual(dialog.result["entry"]["approval_policy"], "confirm_writes")
                dialog.approval_policy.set("全部操作预授权")
                dialog._accept()
                self.assertEqual(dialog.result["entry"]["approval_policy"], "test_all_commands")

    def test_identical_fingerprint_does_not_revoke_an_unchanged_identity(self):
        dialog = self.dialog(environment="test", approval_policy="test_all_commands")
        dialog.fingerprint.set(host_entry()["host_key_sha256"])
        self.assertEqual(dialog.approval_policy.get(), "全部操作预授权")

    def test_reverting_an_identity_edit_does_not_restore_old_preauthorization(self):
        dialog = self.dialog(environment="test", approval_policy="test_all_commands")
        dialog.host.set("192.0.2.20")
        dialog.host.set("192.0.2.10")
        self.assertEqual(dialog.approval_policy.get(), "写操作确认")

    def test_credential_dialog_toggle_shows_or_masks_both_entries(self):
        dialog = object.__new__(gui.CredentialDialog)
        dialog.first = Mock()
        dialog.second = Mock()
        dialog.show_secret = FakeVariable(False)

        dialog._toggle_visibility()
        dialog.first.configure.assert_called_once_with(show="•")
        dialog.second.configure.assert_called_once_with(show="•")

        dialog.first.configure.reset_mock()
        dialog.second.configure.reset_mock()
        dialog.show_secret.set(True)
        dialog._toggle_visibility()
        dialog.first.configure.assert_called_once_with(show="")
        dialog.second.configure.assert_called_once_with(show="")

    def test_worker_tests_entered_credential_without_saving_it(self):
        manager = object.__new__(gui.SSHManager)
        manager._test_results = gui.queue.Queue(maxsize=1)
        host = {**host_entry(), "credential_target": "SecureCredentialBridge/ssh/fixture-host"}

        with patch.object(gui, "store_secret") as save_secret, patch.object(
            gui, "test_ssh_authentication", side_effect=gui.bridge.BridgeError("auth failed")
        ) as test_auth:
            manager._test_connection_worker("fixture-host", host, "test-secret")
        test_auth.assert_called_once_with(host, credential_override="test-secret")
        save_secret.assert_not_called()
        self.assertFalse(manager._test_results.get_nowait()[1])

        with patch.object(gui, "test_ssh_authentication") as test_auth, patch.object(gui, "store_secret") as save_secret:
            manager._test_connection_worker("fixture-host", host, "test-secret")
        test_auth.assert_called_once_with(host, credential_override="test-secret")
        save_secret.assert_not_called()
        self.assertTrue(manager._test_results.get_nowait()[1])

    def test_successful_credential_test_saves_host_reference_to_config(self):
        manager = object.__new__(gui.SSHManager)
        manager._test_results = gui.queue.Queue(maxsize=1)
        manager._test_results.put(("fixture-host", True, "SSH 连接和认证成功；口令已保存，没有执行任何远端命令。"))
        manager._testing_alias = "fixture-host"
        manager._pending_secret = "test-secret"
        manager._pending_credential_target = "SecureCredentialBridge/ssh/fixture-host"
        manager.config_data = {"ssh_hosts": {"fixture-host": {"host": "192.0.2.10"}}}
        manager.config_path = PLUGIN_ROOT / "test" / "fixture-config.json"
        manager._test_status = FakeVariable("")

        with patch.object(gui.SSHManager, "winfo_exists", return_value=True), patch.object(gui, "write_config") as save_config, patch.object(gui, "store_secret") as save_secret:
            manager._poll_test_result()

        self.assertEqual(manager.config_data["ssh_hosts"]["fixture-host"]["credential_target"],
                         "SecureCredentialBridge/ssh/fixture-host")
        save_config.assert_called_once_with(manager.config_path, manager.config_data)
        save_secret.assert_called_once_with("SecureCredentialBridge/ssh/fixture-host", "test-secret")

    def test_failed_credential_test_does_not_save_secret_or_config(self):
        manager = object.__new__(gui.SSHManager)
        manager._test_results = gui.queue.Queue(maxsize=1)
        manager._test_results.put(("fixture-host", False, "auth failed"))
        manager._testing_alias = "fixture-host"
        manager._pending_secret = "test-secret"
        manager._pending_credential_target = "SecureCredentialBridge/ssh/fixture-host"
        manager.config_data = {"ssh_hosts": {"fixture-host": {"host": "192.0.2.10"}}}
        manager.config_path = PLUGIN_ROOT / "test" / "fixture-config.json"
        manager._test_status = FakeVariable("")

        with patch.object(gui.SSHManager, "winfo_exists", return_value=True), patch.object(gui, "write_config") as save_config, patch.object(gui, "store_secret") as save_secret:
            manager._poll_test_result()

        self.assertNotIn("credential_target", manager.config_data["ssh_hosts"]["fixture-host"])
        save_config.assert_not_called()
        save_secret.assert_not_called()

    def test_first_time_password_can_be_tested_before_credential_reference_exists(self):
        manager = object.__new__(gui.SSHManager)
        manager._testing_alias = None
        manager.config_data = {"ssh_hosts": {"fixture-host": {"host": "192.0.2.10"}}}
        manager.host_tree = Mock()
        manager._test_status = FakeVariable("")
        manager._set_testing_controls = Mock()
        manager.after = Mock()
        dialog = Mock()
        dialog.secret = "test-secret"
        thread = Mock()

        with patch.object(gui.SSHManager, "_selected", return_value="fixture-host"), \
             patch.object(gui, "CredentialDialog", return_value=dialog) as credential_dialog, \
             patch.object(gui.threading, "Thread", return_value=thread) as create_thread:
            manager._save_secret()

        credential_dialog.assert_called_once_with(
            manager, "测试 SSH 并保存密码/私钥口令", require_secret=True
        )
        args = create_thread.call_args.kwargs["args"]
        self.assertEqual(args[0], "fixture-host")
        self.assertEqual(args[1]["credential_target"], "SecureCredentialBridge/ssh/fixture-host")
        self.assertEqual(args[2], "test-secret")
        thread.start.assert_called_once_with()
        manager._set_testing_controls.assert_called_once_with(False)
        manager.after.assert_called_once_with(100, manager._poll_test_result)

    def test_leaving_test_environment_revokes_and_does_not_restore_preauthorization(self):
        for environment in ("未指定", "生产环境"):
            with self.subTest(environment=environment):
                dialog = self.dialog(environment="test", approval_policy="test_all_commands")
                dialog.environment.set(environment)
                self.assertEqual(dialog.approval_policy.get(), "写操作确认")
                self.assertEqual(dialog.policy_box.options["values"], ("写操作确认",))
                dialog.environment.set("测试环境")
                self.assertEqual(dialog.approval_policy.get(), "写操作确认")

    def test_save_rejects_invalid_policy_values_and_preauthorized_production(self):
        for environment, policy in (("生产环境", "全部操作预授权"), ("未指定", "全部操作预授权"),
                                    ("other", "写操作确认"), ("测试环境", "other")):
            with self.subTest(environment=environment, policy=policy):
                dialog = self.dialog()
                dialog.environment.set(environment)
                dialog.approval_policy.set(policy)
                dialog._accept()
                self.assertIsNone(dialog.result)
        self.assertEqual(self.errors.call_count, 4)

    def test_invalid_initial_policy_fails_closed_in_editor(self):
        dialog = self.dialog(environment="production", approval_policy="test_all_commands")
        self.assertEqual(dialog.environment.get(), "未指定")
        self.assertEqual(dialog.approval_policy.get(), "写操作确认")
        self.assertIn("原环境或审批策略无效", dialog.policy_status.get())

    def test_import_resets_candidate_and_same_alias_existing_policy(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                manager = gui.SSHManager()
                candidate = host_entry(environment="test", approval_policy="test_all_commands")
                if existing:
                    manager.config_data["ssh_hosts"]["fixture-host"] = copy.deepcopy(candidate)
                with patch.object(gui, "HostDialog", return_value=Mock(result=None)) as dialog:
                    manager._apply_discovered_candidate("fixture-host", candidate)
                initial = dialog.call_args.args[1]
                self.assertEqual(initial["environment"], "unspecified")
                self.assertEqual(initial["approval_policy"], "confirm_writes")
                self.assertEqual(candidate["approval_policy"], "test_all_commands")
                if existing:
                    self.assertEqual(manager.config_data["ssh_hosts"]["fixture-host"]["approval_policy"], "test_all_commands")

    def test_edit_passes_existing_policy_without_mutating_it_when_cancelled(self):
        manager = gui.SSHManager()
        manager.config_data["ssh_hosts"]["fixture-host"] = host_entry(environment="test", approval_policy="test_all_commands")
        manager.host_tree.selection_set("fixture-host")
        with patch.object(gui, "HostDialog", return_value=Mock(result=None)) as dialog:
            manager._edit_host()
        self.assertEqual(dialog.call_args.args[1]["approval_policy"], "test_all_commands")

    def test_list_uses_chinese_policy_labels_and_distinct_blue_orange_tags(self):
        manager = gui.SSHManager()
        manager.config_data["ssh_hosts"] = {
            "legacy": host_entry(),
            "production": host_entry(environment="production", approval_policy="confirm_writes"),
            "test": host_entry(environment="test", approval_policy="test_all_commands"),
            "invalid": host_entry(environment="production", approval_policy="test_all_commands"),
        }
        manager._refresh()
        tree = manager.host_tree
        self.assertEqual(tree.columns["policy"]["text"], "审批策略")
        self.assertEqual(tree.items["legacy"]["values"][-2:], ("未指定", "写操作确认"))
        self.assertEqual(tree.items["production"]["values"][-2:], ("生产环境", "写操作确认"))
        self.assertEqual(tree.items["test"]["values"][-2:], ("测试环境", "全部操作预授权"))
        self.assertEqual(tree.items["legacy"]["tags"], ("confirm_writes",))
        self.assertEqual(tree.items["test"]["tags"], ("test_all_commands",))
        self.assertEqual(tree.tags["confirm_writes"]["foreground"], "#2457a7")
        self.assertEqual(tree.tags["test_all_commands"]["foreground"], "#b85c00")
        self.assertEqual(tree.items["invalid"]["tags"], ("invalid_policy",))
        self.assertIn("不可执行", tree.items["invalid"]["values"][-1])

    def test_atomic_fixture_save_preserves_other_adapters_and_rejects_invalid_update(self):
        test_root = PLUGIN_ROOT / "test"
        test_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="host-policy-gui-", dir=test_root) as directory:
            path = Path(directory) / "fixture.json"
            for policy in ("confirm_writes", "test_all_commands"):
                fixture = {"ssh_hosts": {"fixture-host": host_entry(environment="test", approval_policy=policy)},
                    "ssh_actions": {"legacy": {"fixture": "unchanged"}}}
                gui.write_config(path, fixture)
                self.assertEqual(json.loads(path.read_text(encoding="utf-8")), fixture)
            saved = path.read_bytes()
            invalid = copy.deepcopy(fixture)
            invalid["ssh_hosts"]["fixture-host"]["environment"] = "production"
            with self.assertRaises(gui.bridge.BridgeError):
                gui.write_config(path, invalid)
            self.assertEqual(path.read_bytes(), saved)
            self.assertEqual(sorted(item.name for item in Path(directory).iterdir()), ["fixture.json"])


if __name__ == "__main__":
    unittest.main()
