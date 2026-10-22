from __future__ import annotations

import importlib.util
import base64
import hashlib
import json
import os
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = PLUGIN_ROOT / "mcp" / "server.py"
SPEC = importlib.util.spec_from_file_location("bridge_server", SERVER_PATH)
bridge = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(bridge)
GUI_SPEC = importlib.util.spec_from_file_location("ssh_manager_gui", PLUGIN_ROOT / "scripts" / "ssh_manager_gui.py")
ssh_gui = importlib.util.module_from_spec(GUI_SPEC)
assert GUI_SPEC and GUI_SPEC.loader
GUI_SPEC.loader.exec_module(ssh_gui)
import manage_credential as credential_manager  # noqa: E402


class ConfigAndToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = json.loads((PLUGIN_ROOT / "config" / "bridge.example.json").read_text(encoding="utf-8"))

    def test_example_config_is_valid(self) -> None:
        bridge.validate_config(self.cfg)

    def test_rejects_unpinned_ssh_host(self) -> None:
        cfg = json.loads(json.dumps(self.cfg))
        del cfg["ssh_hosts"]["staging"]["host_key_sha256"]
        with self.assertRaises(bridge.BridgeError):
            bridge.validate_config(cfg)

    def test_rejects_unscoped_credential_reference(self) -> None:
        cfg = json.loads(json.dumps(self.cfg))
        cfg["email"]["credential_target"] = "other-plugin/mail"
        with self.assertRaises(bridge.BridgeError):
            bridge.validate_config(cfg)

    def test_rejects_write_or_multiple_sql_statements(self) -> None:
        self.assertFalse(bridge.is_single_read_query("DELETE FROM jobs"))
        self.assertFalse(bridge.is_single_read_query("SELECT 1; DELETE FROM jobs"))
        self.assertTrue(bridge.is_single_read_query("SELECT id FROM jobs;"))

    def test_email_draft_is_not_sent_and_is_held_in_memory(self) -> None:
        before = set(bridge.DRAFTS)
        result = bridge.email_create_draft({"to": "operator@example.invalid", "subject": "Review", "body": "Draft body"}, self.cfg)
        self.assertIn("draft_created_not_sent", result["content"][0]["text"])
        self.assertEqual(set(bridge.DRAFTS) - before, {result["structuredContent"]["draft_id"]})

    def test_mcp_stdio_lists_only_configured_tools(self) -> None:
        import tempfile

        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ)
            environment["SCB_CONFIG"] = str(Path(directory) / "does-not-exist.json")
            completed = subprocess.run([sys.executable, str(SERVER_PATH)], input="\n".join(map(json.dumps, messages)) + "\n", text=True, capture_output=True, check=True, timeout=10, env=environment)
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "secure-credential-bridge")
        self.assertEqual(
            [tool["name"] for tool in responses[1]["result"]["tools"]],
            ["bridge_status", "ssh_discover_hosts", "ssh_connect", "ssh_run_command"],
        )
        self.assertEqual(completed.stderr, "")

    def test_retired_fixed_ssh_action_is_not_executable_even_if_legacy_config_contains_it(self) -> None:
        cfg = {
            "ssh_hosts": {},
            "ssh_actions": {"legacy": {"command": "whoami", "host": "removed-host"}},
        }
        bridge.validate_config(cfg)
        self.assertNotIn("ssh_run_action", [tool["name"] for tool in bridge.tools_for(cfg)])
        with self.assertRaisesRegex(bridge.BridgeError, "Unknown tool"):
            bridge.tool_call("ssh_run_action", {"action": "legacy"}, cfg)

    def test_ssh_run_command_schema_is_stable_without_configured_hosts(self) -> None:
        tool = next(tool for tool in bridge.tools_for({}) if tool["name"] == "ssh_run_command")
        self.assertEqual(set(tool["inputSchema"]["properties"]), {"alias", "command", "timeout_seconds", "intent_zh"})
        self.assertEqual(tool["inputSchema"]["required"], ["alias", "command"])
        self.assertNotIn("enum", tool["inputSchema"]["properties"]["alias"])
        self.assertFalse(tool["inputSchema"]["additionalProperties"])

    def test_config_is_reread_after_local_configuration_changes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "bridge.json"
            host = {"host": "192.0.2.10", "port": 22, "username": "test-user", "host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "credential_target": "SecureCredentialBridge/ssh/test-host"}
            with patch.object(bridge, "CONFIG_PATH", config_path):
                config_path.write_text(json.dumps({"ssh_hosts": {"first": host}}), encoding="utf-8")
                first = bridge.config()
                config_path.write_text(json.dumps({"ssh_hosts": {"second": host}}), encoding="utf-8")
                second = bridge.config()
        self.assertEqual(list(first["ssh_hosts"]), ["first"])
        self.assertEqual(list(second["ssh_hosts"]), ["second"])

    def test_ssh_connect_alias_is_optional_in_tool_schema(self) -> None:
        tool = next(tool for tool in bridge.tools_for({}) if tool["name"] == "ssh_connect")
        self.assertNotIn("alias", tool["inputSchema"].get("required", []))
        self.assertEqual(set(tool["inputSchema"]["properties"]), {"alias"})

    def test_discover_ssh_hosts_reads_literal_aliases_without_network_access(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            ssh_config = Path(directory) / "config"
            ssh_config.write_text(
                "Host test-host\n  HostName 192.0.2.10\n  User test-user\n  Port 22\n"
                "Host *.internal\n  User ignored\n"
                "Match exec true\n  HostName should-not-be-read\n",
                encoding="utf-8",
            )
            discovered = bridge.discover_ssh_hosts(ssh_config)
        self.assertEqual(discovered, {"test-host": {"host": "192.0.2.10", "port": 22, "username": "test-user"}})

    def test_ssh_connect_unknown_alias_opens_manager_without_authentication(self) -> None:
        cfg = {"ssh_hosts": {}, "ssh_actions": {}}
        with patch.object(bridge, "discover_ssh_hosts", return_value={}), patch.object(bridge, "launch_ssh_manager", return_value=True), patch.object(bridge, "verify_ssh_authentication") as verify, self.assertRaises(bridge.BridgeError):
            bridge.ssh_connect({"alias": "missing"}, cfg)
        verify.assert_not_called()

    def test_discovery_tool_redacts_private_key_path(self) -> None:
        candidate = {"host": "192.0.2.10", "port": 22, "username": "test-user", "private_key_file": "C:/private/key"}
        with patch.object(bridge, "discover_ssh_hosts", return_value={"test-host": candidate}):
            result = bridge.tool_call("ssh_discover_hosts", {}, {"ssh_hosts": {}, "ssh_actions": {}})
        self.assertEqual(result["structuredContent"]["candidates"][0], {
            "alias": "test-host",
            "private_key_available": True, "configured_in_bridge": False,
        })
        self.assertNotIn("192.0.2.10", result["content"][0]["text"])
        self.assertNotIn("test-user", result["content"][0]["text"])
        self.assertNotIn("private_key_file", result["content"][0]["text"])

    def test_ssh_connect_success_skips_approval_and_runs_no_remote_command(self) -> None:
        host = {"host": "192.0.2.10", "port": 22, "username": "test-user", "host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "credential_target": "SecureCredentialBridge/ssh/test-host"}
        with patch.object(bridge, "request_confirmation") as approval, patch.object(bridge, "verify_ssh_authentication") as verify:
            result = bridge.ssh_connect({"alias": "test-host"}, {"ssh_hosts": {"test-host": host}, "ssh_actions": {}})
        approval.assert_not_called()
        verify.assert_called_once_with(host)
        self.assertEqual(result["structuredContent"], {"alias": "test-host", "connected": True, "remote_command_executed": False})

    def test_arbitrary_ssh_command_requires_approval_with_exact_target_and_command(self) -> None:
        host = {"host": "192.0.2.10", "port": 22, "username": "test-user", "host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "credential_target": "SecureCredentialBridge/ssh/test-host"}
        command = "systemctl restart nginx"
        intent = "重启 nginx 服务以加载配置"
        with patch.object(bridge, "request_confirmation", side_effect=bridge.BridgeError("denied")) as approval:
            with self.assertRaises(bridge.BridgeError):
                bridge.ssh_run_command({"alias": "test-host", "command": command, "intent_zh": intent}, {"ssh_hosts": {"test-host": host}})
        message = approval.call_args.args[0]
        self.assertIn("test-user@192.0.2.10:22", message)
        self.assertIn(command, message)
        self.assertEqual(approval.call_args.kwargs, {"intent_zh": intent})

    def test_approved_ssh_command_uses_exact_command_and_returns_bounded_result(self) -> None:
        host_key = b"mock server host key"
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(host_key).digest()).decode("ascii").rstrip("=")
        host = {"host": "192.0.2.10", "port": 22, "username": "test-user", "host_key_sha256": fingerprint, "credential_target": "SecureCredentialBridge/ssh/test-host"}
        events: list[object] = []

        class FakeHostKey:
            @staticmethod
            def asbytes() -> bytes:
                return host_key

        class FakeChannel:
            consumed = False

            def recv_ready(self) -> bool:
                return not self.consumed

            def recv(self, _size: int) -> bytes:
                self.consumed = True
                return b"ok\n"

            @staticmethod
            def recv_stderr_ready() -> bool:
                return False

            def exit_status_ready(self) -> bool:
                return self.consumed

            @staticmethod
            def recv_exit_status() -> int:
                return 0

            @staticmethod
            def close() -> None:
                pass

        channel = FakeChannel()

        class FakeClient:
            def set_missing_host_key_policy(self, policy: object) -> None:
                self.policy = policy

            def connect(self, **_kwargs: object) -> None:
                events.append("connect")
                self.policy.missing_host_key(self, "192.0.2.10", FakeHostKey())

            @staticmethod
            def get_transport() -> object:
                return types.SimpleNamespace(get_remote_server_key=lambda: FakeHostKey())

            def exec_command(self, command: str, **_kwargs: object) -> tuple[None, object, object]:
                events.append(("execute", command))
                return None, types.SimpleNamespace(channel=channel), types.SimpleNamespace(channel=channel)

            @staticmethod
            def close() -> None:
                pass

        fake_paramiko = types.ModuleType("paramiko")
        fake_paramiko.MissingHostKeyPolicy = type("MissingHostKeyPolicy", (), {})
        fake_paramiko.SSHClient = FakeClient
        command = "systemctl restart nginx"
        intent = "重启 nginx 服务以加载配置"

        def approve(message: str, *, intent_zh: str) -> None:
            self.assertIn(command, message)
            self.assertEqual(intent_zh, intent)
            events.append("approved")

        with patch.dict(sys.modules, {"paramiko": fake_paramiko}), patch.object(bridge, "request_confirmation", side_effect=approve), patch.object(bridge, "read_credential", return_value="mock-secret"):
            result = bridge.ssh_run_command({"alias": "test-host", "command": command, "intent_zh": intent}, {"ssh_hosts": {"test-host": host}})

        self.assertEqual(events, ["approved", "connect", ("execute", command)])
        self.assertEqual(result["structuredContent"]["stdout"], "ok\n")
        self.assertEqual(result["structuredContent"]["exit_code"], 0)
        self.assertTrue(result["structuredContent"]["approval_required"])
        self.assertFalse(result["structuredContent"]["read_only"])

    def test_arbitrary_ssh_command_rejects_invalid_host_command_and_timeout_before_approval(self) -> None:
        host = {"host": "192.0.2.10", "port": 22, "username": "test-user", "host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "credential_target": "SecureCredentialBridge/ssh/test-host"}
        cfg = {"ssh_hosts": {"test-host": host}}
        for args, expected_error in (
            ({"alias": "unknown", "command": "whoami"}, "not configured"),
            ({"alias": "test-host", "command": "  "}, "non-empty"),
            ({"alias": "test-host", "command": "whoami", "timeout_seconds": 0}, "between 1 and 300"),
        ):
            with self.subTest(args=args), patch.object(bridge, "request_confirmation") as approval, patch.object(bridge, "read_credential") as credential, self.assertRaisesRegex(bridge.BridgeError, expected_error):
                bridge.ssh_run_command(args, cfg)
            approval.assert_not_called()
            credential.assert_not_called()

    def test_ssh_connect_omitted_alias_selects_only_configured_host(self) -> None:
        host = {"host": "192.0.2.10", "port": 22, "username": "test-user", "host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "credential_target": "SecureCredentialBridge/ssh/test-host"}
        cfg = {"ssh_hosts": {"test-host": host}, "ssh_actions": {}}
        with patch.object(bridge, "request_confirmation") as approval, patch.object(bridge, "verify_ssh_authentication") as verify, patch.object(bridge, "launch_ssh_manager") as launch:
            result = bridge.ssh_connect({}, cfg)
        approval.assert_not_called()
        verify.assert_called_once_with(host)
        launch.assert_not_called()
        self.assertEqual(result["structuredContent"], {"alias": "test-host", "connected": True, "remote_command_executed": False})

    def test_ssh_connect_rejects_host_details_as_tool_arguments(self) -> None:
        cfg = {"ssh_hosts": {}, "ssh_actions": {}}
        with self.assertRaises(bridge.BridgeError):
            bridge.ssh_connect({"target": "192.0.2.10"}, cfg)
        with self.assertRaises(bridge.BridgeError):
            bridge.ssh_connect({"alias": "test-host", "username": "test-user"}, cfg)

    def test_ssh_connect_omitted_alias_refuses_to_choose_between_configured_hosts(self) -> None:
        host = {"host": "192.0.2.10", "port": 22, "username": "test-user", "host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "credential_target": "SecureCredentialBridge/ssh/test-host"}
        cfg = {"ssh_hosts": {"test-host": host, "other": dict(host, host="192.0.2.11")}, "ssh_actions": {}}
        with patch.object(bridge, "request_confirmation") as approval, patch.object(bridge, "verify_ssh_authentication") as verify, self.assertRaises(bridge.BridgeError) as caught:
            bridge.ssh_connect({}, cfg)
        approval.assert_not_called()
        verify.assert_not_called()
        self.assertIn("select one local alias", str(caught.exception))
        self.assertIn("test-host", str(caught.exception))
        self.assertIn("other", str(caught.exception))

    def test_ssh_connect_without_config_prefills_sole_discovered_host_without_authentication(self) -> None:
        with patch.object(bridge, "discover_ssh_hosts", return_value={"test-host": {"host": "192.0.2.10", "port": 22, "username": "test-user"}}), patch.object(bridge, "launch_ssh_manager", return_value=True) as launch, patch.object(bridge, "verify_ssh_authentication") as verify, self.assertRaises(bridge.BridgeError) as caught:
            bridge.ssh_connect({}, {"ssh_hosts": {}, "ssh_actions": {}})
        launch.assert_called_once_with("test-host")
        verify.assert_not_called()
        self.assertIn("Found the only literal alias", str(caught.exception))
        self.assertIn("No SSH authentication", str(caught.exception))

    def test_ssh_connect_unknown_local_alias_prefills_manager(self) -> None:
        with patch.object(bridge, "discover_ssh_hosts", return_value={"test-host": {"host": "192.0.2.10", "port": 22, "username": "test-user"}}), patch.object(bridge, "launch_ssh_manager", return_value=True) as launch, patch.object(bridge, "verify_ssh_authentication") as verify, self.assertRaises(bridge.BridgeError) as caught:
            bridge.ssh_connect({"alias": "test-host"}, {"ssh_hosts": {}, "ssh_actions": {}})
        launch.assert_called_once_with("test-host")
        verify.assert_not_called()
        self.assertIn("Found this alias", str(caught.exception))

    def test_ssh_connect_without_config_opens_manager_for_manual_choice_when_multiple_discovered(self) -> None:
        candidates = {
            "test-host": {"host": "192.0.2.10", "port": 22, "username": "test-user"},
            "staging": {"host": "192.0.2.11", "port": 22, "username": "deploy"},
        }
        with patch.object(bridge, "discover_ssh_hosts", return_value=candidates), patch.object(bridge, "launch_ssh_manager", return_value=True) as launch, patch.object(bridge, "verify_ssh_authentication") as verify, self.assertRaises(bridge.BridgeError) as caught:
            bridge.ssh_connect({}, {"ssh_hosts": {}, "ssh_actions": {}})
        launch.assert_called_once_with(None)
        verify.assert_not_called()
        self.assertIn("Multiple literal aliases", str(caught.exception))
        self.assertIn("No SSH authentication", str(caught.exception))

    def test_ssh_connect_auth_failure_opens_prefilled_manager(self) -> None:
        host = {"host": "192.0.2.10", "port": 22, "username": "test-user", "host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "credential_target": "SecureCredentialBridge/ssh/test-host"}
        with patch.object(bridge, "request_confirmation"), patch.object(bridge, "verify_ssh_authentication", side_effect=bridge.BridgeError("SSH authentication failed.")), patch.object(bridge, "launch_ssh_manager", return_value=True) as launch, self.assertRaises(bridge.BridgeError) as caught:
            bridge.ssh_connect({"alias": "test-host"}, {"ssh_hosts": {"test-host": host}, "ssh_actions": {}})
        launch.assert_called_once_with("test-host")
        self.assertIn("configuration window was opened", str(caught.exception))

    def test_local_approval_accepts_only_boolean_true(self) -> None:
        approved = subprocess.CompletedProcess([], 0, '{"approved": true}\n', "")
        with patch.object(bridge.subprocess, "run", return_value=approved) as run:
            bridge.request_local_approval("Run the configured action")
        self.assertEqual(run.call_args.args[0][-1], str(bridge.APPROVAL_PROXY_PATH))
        self.assertNotIn("password", run.call_args.kwargs["input"].lower())

    def test_local_approval_decline_and_malformed_response_fail_closed(self) -> None:
        for stdout in ('{"approved": false}\n', '{"approved": "true"}\n', "not-json\n"):
            with self.subTest(stdout=stdout), patch.object(
                bridge.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, stdout, ""),
            ), self.assertRaises(bridge.BridgeError):
                bridge.request_local_approval("Run the configured action")

    def test_local_approval_timeout_fails_closed(self) -> None:
        with patch.object(bridge.subprocess, "run", side_effect=subprocess.TimeoutExpired("approval", 120)), self.assertRaises(bridge.BridgeError):
            bridge.request_local_approval("Run the configured action")

    def test_local_approval_proxy_request_parser_rejects_invalid_input(self) -> None:
        proxy_spec = importlib.util.spec_from_file_location("approval_proxy", PLUGIN_ROOT / "scripts" / "approval_proxy.py")
        proxy = importlib.util.module_from_spec(proxy_spec)
        assert proxy_spec and proxy_spec.loader
        proxy_spec.loader.exec_module(proxy)
        with self.assertRaises(ValueError):
            proxy.read_request(types.SimpleNamespace(read=lambda: '{"message": true}'))


class SSHManagerConfigTests(unittest.TestCase):
    def test_credential_status_output_is_safe_without_console(self) -> None:
        with patch.object(credential_manager.sys, "stdout", None):
            credential_manager.report_cli_status("credential stored")

    def test_gui_config_writer_validates_and_preserves_other_adapters(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bridge.json"
            config = json.loads((PLUGIN_ROOT / "config" / "bridge.example.json").read_text(encoding="utf-8"))
            ssh_gui.write_config(path, config)
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["email"], config["email"])

            original = path.read_bytes()
            invalid = json.loads(json.dumps(config))
            del invalid["ssh_hosts"]["staging"]["host_key_sha256"]
            with self.assertRaises(ssh_gui.bridge.BridgeError):
                ssh_gui.write_config(path, invalid)
            self.assertEqual(path.read_bytes(), original)

    def test_credential_reference_rejects_unsafe_alias(self) -> None:
        self.assertEqual(ssh_gui.credential_ref("staging"), "SecureCredentialBridge/ssh/staging")
        with self.assertRaises(ValueError):
            ssh_gui.credential_ref("../outside")

    def test_fingerprint_read_does_not_authenticate(self) -> None:
        public_key = b"example ssh host public key"
        transport_state = {"started": False, "closed": False}

        class FakeKey:
            @staticmethod
            def asbytes() -> bytes:
                return public_key

            @staticmethod
            def get_name() -> str:
                return "ssh-ed25519"

        class FakeTransport:
            def __init__(self, sock: object):
                self.sock = sock

            def start_client(self, timeout: float) -> None:
                transport_state["started"] = True

            @staticmethod
            def get_remote_server_key() -> FakeKey:
                return FakeKey()

            def close(self) -> None:
                transport_state["closed"] = True

        with patch.dict(sys.modules, {"paramiko": types.SimpleNamespace(Transport=FakeTransport)}), patch.object(
            ssh_gui.socket, "create_connection", return_value=object()
        ):
            fingerprint, key_type = ssh_gui.read_ssh_fingerprint("example.com", 22)

        expected = base64.b64encode(hashlib.sha256(public_key).digest()).decode("ascii").rstrip("=")
        self.assertEqual(fingerprint, f"SHA256:{expected}")
        self.assertEqual(key_type, "ssh-ed25519")
        self.assertTrue(transport_state["started"])
        self.assertTrue(transport_state["closed"])


if __name__ == "__main__":
    unittest.main()
