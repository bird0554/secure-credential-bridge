"""测试主机预授权边界；仅使用合成配置与替身，不读取真实配置、凭据或网络。"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


_FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "scb_host_preauthorization_fixtures", Path(__file__).with_name("test_ssh_policy_integration.py")
)
assert _FIXTURE_SPEC and _FIXTURE_SPEC.loader
_fixtures = importlib.util.module_from_spec(_FIXTURE_SPEC)
_FIXTURE_SPEC.loader.exec_module(_fixtures)
bridge = _fixtures.bridge
PLUGIN_ROOT = Path(__file__).resolve().parents[1]

TEST_POLICY = {"environment": "test", "approval_policy": "test_all_commands"}
DEFAULT_POLICY = {"environment": "unspecified", "approval_policy": "confirm_writes"}
INTENT = "执行测试环境维护命令并修改远端状态"

# 包含写入、未识别命令、混合查询/写入和复杂 shell；预授权不伪造只读分类。
WRITE_COMMANDS = (
    "systemctl restart nginx",
    "custom-maintenance --mode audit",
    "whoami; touch /tmp/example",
    "whoami\ntouch /tmp/example",
    "whoami || touch /tmp/example",
    "cat /etc/hosts | sort -o /tmp/example",
    "cat /etc/hosts > /tmp/example",
    "find /var/log -delete",
    "ip route flush table main",
    "docker volume rm example",
    "docker exec example sh -c 'touch /tmp/example'",
    "python -c 'print(1)'",
    "cat $(touch /tmp/example)",
    "cat `touch /tmp/example`",
)


class HostPreauthorizationTests(unittest.TestCase):
    # 复用 fixture 方法，避免继承旧 TestCase 导致重复收集整组测试。
    setUp = _fixtures.SSHPolicyIntegrationTests.setUp
    mock_ssh = _fixtures.SSHPolicyIntegrationTests.mock_ssh
    run_command = _fixtures.SSHPolicyIntegrationTests.run_command

    def enable_test_policy(self) -> None:
        self.host.update(TEST_POLICY)

    def test_safe_defaults_and_exact_valid_policy_combinations(self) -> None:
        cases = (
            ({}, DEFAULT_POLICY),
            ({"environment": "unspecified"}, DEFAULT_POLICY),
            ({"approval_policy": "confirm_writes"}, DEFAULT_POLICY),
            (DEFAULT_POLICY, DEFAULT_POLICY),
            ({"environment": "test"}, {"environment": "test", "approval_policy": "confirm_writes"}),
            ({"environment": "production"}, {"environment": "production", "approval_policy": "confirm_writes"}),
            ({"environment": "test", "approval_policy": "confirm_writes"}, {"environment": "test", "approval_policy": "confirm_writes"}),
            ({"environment": "production", "approval_policy": "confirm_writes"}, {"environment": "production", "approval_policy": "confirm_writes"}),
            (TEST_POLICY, TEST_POLICY),
        )
        for fields, expected in cases:
            with self.subTest(fields=fields):
                host = {**self.host, **fields}
                before = dict(host)
                self.assertEqual(bridge.ssh_host_policy(host), expected)
                self.assertEqual(host, before, "读取默认策略不能隐式改写配置")
                bridge.validate_config({"ssh_hosts": {"test-host": host}})

    def test_invalid_policy_types_values_and_combinations_fail_before_ssh(self) -> None:
        invalid = []
        for field in ("environment", "approval_policy"):
            for value in (None, True, False, 1, 0, 1.0, [], {}, "", " ", "TEST", " test", "test ", "other"):
                invalid.append({**TEST_POLICY, field: value})
        invalid.extend((
            {"approval_policy": "test_all_commands"},
            {"environment": "unspecified", "approval_policy": "test_all_commands"},
            {"environment": "production", "approval_policy": "test_all_commands"},
            {"environment": "test", "approval_policy": "TEST_ALL_COMMANDS"},
            {"environment": "test", "approval_policy": "test_all_commands "},
            {"environment": "test", "approval_policy": "always_allow"},
        ))
        for fields in invalid:
            with self.subTest(fields=fields):
                cfg = {"ssh_hosts": {"test-host": {**self.host, **fields}}}
                with self.assertRaises(bridge.BridgeError):
                    bridge.ssh_host_policy(cfg["ssh_hosts"]["test-host"])
                with self.assertRaises(bridge.BridgeError):
                    bridge.validate_config(cfg)
                # 直接执行入口也必须防御坏配置，不能依赖调用方先调用 validate_config。
                for command in ("whoami", "systemctl restart nginx"):
                    with self.subTest(command=command), self.mock_ssh() as (fake, credential), patch.object(
                        bridge, "request_confirmation"
                    ) as approval, self.assertRaises(bridge.BridgeError):
                        bridge.ssh_run_command({"alias": "test-host", "command": command, "intent_zh": INTENT}, cfg)
                    approval.assert_not_called()
                    credential.assert_not_called()
                    fake.module.SSHClient.assert_not_called()

    def test_legacy_test_and_production_defaults_still_require_confirmation(self) -> None:
        for fields in ({}, {"environment": "test"}, {"environment": "production"}, DEFAULT_POLICY,
                       {"environment": "test", "approval_policy": "confirm_writes"}):
            for command in ("systemctl restart nginx", "custom-maintenance", "whoami; touch /tmp/example"):
                with self.subTest(fields=fields, command=command):
                    cfg = {"ssh_hosts": {"test-host": {**self.host, **fields}}}
                    with self.mock_ssh() as (fake, credential), patch.object(
                        bridge, "request_confirmation", side_effect=bridge.BridgeError("fixture declined")
                    ) as approval, self.assertRaisesRegex(bridge.BridgeError, "fixture declined"):
                        bridge.ssh_run_command({"alias": "test-host", "command": command, "intent_zh": INTENT}, cfg)
                    approval.assert_called_once()
                    credential.assert_not_called()
                    fake.module.SSHClient.assert_not_called()

    def test_preauthorized_writes_unknown_and_mixed_commands_skip_only_confirmation(self) -> None:
        self.enable_test_policy()
        for command in WRITE_COMMANDS:
            with self.subTest(command=command), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation", side_effect=AssertionError("test-host is preauthorized")
            ) as approval:
                self.assertFalse(bridge.classify_command(command).read_only)
                result = self.run_command(command, intent_zh=INTENT)["structuredContent"]
            approval.assert_not_called()
            credential.assert_called_once_with(self.host["credential_target"])
            self.assertEqual(fake.events, ["new_client", "credential", "connect", ("execute", command)])
            self.assertEqual(result["command"], command)
            self.assertEqual(result["executed_command"], command)
            self.assertEqual(result["approval_basis"], "host_preauthorized")
            self.assertFalse(result["read_only"])
            self.assertFalse(result["approval_required"])
            self.assertEqual({key: result[key] for key in TEST_POLICY}, TEST_POLICY)
            self.assertTrue(fake.client_closed)

    def test_readonly_results_keep_classification_and_normalization_on_all_hosts(self) -> None:
        for fields in ({}, {"environment": "production"}, TEST_POLICY):
            cfg = {"ssh_hosts": {"test-host": {**self.host, **fields}}}
            for tool in (bridge.ssh_read_command, bridge.ssh_run_command):
                for command in ("whoami", "rg -n ERROR /var/log/app.log", "systemctl status nginx"):
                    with self.subTest(fields=fields, tool=tool.__name__, command=command), self.mock_ssh() as (
                        fake, _
                    ), patch.object(bridge, "request_confirmation") as approval:
                        result = tool({"alias": "test-host", "command": command}, cfg)["structuredContent"]
                    approval.assert_not_called()
                    self.assertTrue(result["read_only"])
                    self.assertFalse(result["approval_required"])
                    self.assertEqual(result["approval_basis"], "read_only")
                    self.assertEqual({key: result[key] for key in TEST_POLICY}, bridge.ssh_host_policy(cfg["ssh_hosts"]["test-host"]))
                    self.assertEqual(result["executed_command"], bridge.classify_command(command).execution_command)
                    self.assertIn(("execute", result["executed_command"]), fake.events)

    def test_confirmed_mutations_report_user_confirmation_and_policy(self) -> None:
        for fields in ({}, {"environment": "test"}, {"environment": "production"}):
            cfg = {"ssh_hosts": {"test-host": {**self.host, **fields}}}
            with self.subTest(fields=fields), self.mock_ssh() as (fake, _):
                def approve(message: str, *, intent_zh: str) -> None:
                    self.assertEqual(fake.events, [])
                    self.assertEqual(intent_zh, INTENT)
                    self.assertIn("systemctl restart nginx", message)
                    fake.events.append("approved")

                with patch.object(bridge, "request_confirmation", side_effect=approve) as approval:
                    result = bridge.ssh_run_command(
                        {"alias": "test-host", "command": "systemctl restart nginx", "intent_zh": INTENT}, cfg
                    )["structuredContent"]
            approval.assert_called_once()
            self.assertEqual(fake.events[0], "approved")
            self.assertEqual(result["approval_basis"], "user_confirmation")
            self.assertFalse(result["read_only"])
            self.assertTrue(result["approval_required"])
            self.assertEqual({key: result[key] for key in TEST_POLICY}, bridge.ssh_host_policy(cfg["ssh_hosts"]["test-host"]))

    def test_same_endpoint_other_alias_does_not_inherit_preauthorization(self) -> None:
        self.enable_test_policy()
        for alias, fields in (("legacy", {}), ("test-default", {"environment": "test"}),
                              ("production", {"environment": "production"})):
            # 所有坐标和 credential target 完全一致，授权仍只能来自指定别名。
            other_host = {key: value for key, value in self.host.items() if key not in TEST_POLICY}
            self.cfg["ssh_hosts"][alias] = {**other_host, **fields}
            with self.subTest(alias=alias), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation", side_effect=bridge.BridgeError("fixture declined")
            ) as approval, self.assertRaisesRegex(bridge.BridgeError, "fixture declined"):
                bridge.ssh_run_command({"alias": alias, "command": "systemctl restart nginx", "intent_zh": INTENT}, self.cfg)
            approval.assert_called_once()
            self.assertIn(alias, approval.call_args.args[0])
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_preauthorization_does_not_relax_readonly_tool(self) -> None:
        self.enable_test_policy()
        for command in WRITE_COMMANDS:
            with self.subTest(command=command), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation"
            ) as approval, self.assertRaisesRegex(bridge.BridgeError, "read-only"):
                bridge.ssh_read_command({"alias": "test-host", "command": command}, self.cfg)
            approval.assert_not_called()
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_callers_cannot_override_policy_or_bypass_approval_via_arguments(self) -> None:
        self.enable_test_policy()
        for extra in ({"approved": True}, {"skip_approval": True}, {"read_only": True},
                      {"environment": "test"}, {"approval_policy": "test_all_commands"},
                      {"approval_basis": "host_preauthorized"}, {"host_preauthorized": True},
                      {"read_only_required": False}, {"host": dict(self.host)}):
            for tool in (bridge.ssh_run_command, bridge.ssh_read_command):
                with self.subTest(extra=extra, tool=tool.__name__), self.mock_ssh() as (fake, credential), patch.object(
                    bridge, "request_confirmation"
                ) as approval, self.assertRaises(bridge.BridgeError):
                    tool({"alias": "test-host", "command": "whoami", **extra}, self.cfg)
                approval.assert_not_called()
                credential.assert_not_called()
                fake.module.SSHClient.assert_not_called()

    def test_tool_argument_schemas_and_annotations_remain_unchanged(self) -> None:
        self.enable_test_policy()
        tools = {tool["name"]: tool for tool in bridge.tools_for(self.cfg)}
        for name, properties in (
            ("ssh_run_command", {"alias", "command", "timeout_seconds", "intent_zh"}),
            ("ssh_read_command", {"alias", "command", "timeout_seconds"}),
        ):
            self.assertEqual(set(tools[name]["inputSchema"]["properties"]), properties)
            self.assertEqual(tools[name]["inputSchema"]["required"], ["alias", "command"])
            self.assertFalse(tools[name]["inputSchema"]["additionalProperties"])
        self.assertFalse(tools["ssh_run_command"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["ssh_run_command"]["annotations"]["destructiveHint"])
        self.assertTrue(tools["ssh_read_command"]["annotations"]["readOnlyHint"])

    def test_preauthorized_nonreadonly_still_requires_valid_chinese_intent(self) -> None:
        self.enable_test_policy()
        intents = ({}, *({"intent_zh": value} for value in (
            None, "", "   ", "restart nginx", "重启\n服务", "重启\r服务", "重启\t服务",
            "重启\u202e服务", "重启\u2028服务", "重启\x00服务", "中" * 501, True, 1, {}, [],
        )))
        for intent in intents:
            for command in ("systemctl restart nginx", "custom-maintenance"):
                with self.subTest(intent=intent, command=command), self.mock_ssh() as (fake, credential), patch.object(
                    bridge, "request_confirmation"
                ) as approval, self.assertRaisesRegex(bridge.BridgeError, "intent_zh"):
                    self.run_command(command, **intent)
                approval.assert_not_called()
                credential.assert_not_called()
                fake.module.SSHClient.assert_not_called()

    def test_invalid_optional_intent_on_readonly_is_not_ignored(self) -> None:
        self.enable_test_policy()
        with self.mock_ssh() as (fake, credential), patch.object(
            bridge, "request_confirmation"
        ) as approval, self.assertRaisesRegex(bridge.BridgeError, "intent_zh"):
            self.run_command("whoami", intent_zh="English only")
        approval.assert_not_called()
        credential.assert_not_called()
        fake.module.SSHClient.assert_not_called()

    def test_preauthorized_command_keeps_original_whitespace_quotes_and_newlines(self) -> None:
        self.enable_test_policy()
        command = "  printf '%s' '变更说明'\ncustom-tool --set 'a b'  "
        with self.mock_ssh() as (fake, _), patch.object(bridge, "request_confirmation") as approval:
            result = self.run_command(command, intent_zh=INTENT)["structuredContent"]
        approval.assert_not_called()
        self.assertEqual(result["command"], command)
        self.assertEqual(result["executed_command"], command)
        self.assertIn(("execute", command), fake.events)

    def test_preauthorized_host_does_not_require_available_confirmation_transport(self) -> None:
        self.enable_test_policy()
        with self.mock_ssh(), patch.object(bridge, "APPROVAL_MODE", "native"), patch.object(
            bridge, "CLIENT_ELICITATION", False
        ), patch.object(bridge, "send") as send, patch.object(bridge, "request_local_approval") as local:
            result = self.run_command("systemctl restart nginx", intent_zh=INTENT)["structuredContent"]
        send.assert_not_called()
        local.assert_not_called()
        self.assertEqual(result["approval_basis"], "host_preauthorized")

    def test_preauthorization_keeps_callback_and_transport_fingerprint_checks(self) -> None:
        self.enable_test_policy()
        for options, message in (
            ({"key": b"untrusted-test-key"}, "fingerprint"),
            ({"check_callback": False, "transport_key": b"untrusted-test-key"}, "fingerprint"),
            ({"transport_key": None}, "did not provide a host key"),
        ):
            with self.subTest(options=options), self.mock_ssh(_fixtures.FakeSSH(**options)) as (
                fake, _
            ), patch.object(bridge, "request_confirmation") as approval, self.assertRaisesRegex(bridge.BridgeError, message):
                self.run_command("systemctl restart nginx", intent_zh=INTENT)
            approval.assert_not_called()
            self.assertFalse(any(isinstance(event, tuple) for event in fake.events))
            self.assertTrue(fake.client_closed)

    def test_preauthorization_keeps_timeout_limits_and_connection_options(self) -> None:
        self.enable_test_policy()
        for timeout in (1, 300):
            with self.subTest(timeout=timeout), self.mock_ssh() as (fake, _):
                self.run_command("systemctl restart nginx", timeout_seconds=timeout, intent_zh=INTENT)
            self.assertEqual(fake.execute_options, {"timeout": timeout, "get_pty": False})
            for key in ("timeout", "banner_timeout", "auth_timeout"):
                self.assertEqual(fake.options[key], min(timeout, 30))
            self.assertFalse(fake.options["allow_agent"])
            self.assertFalse(fake.options["look_for_keys"])
        for timeout in (0, 301, -1, True, "60", 1.0, None):
            with self.subTest(timeout=timeout), self.mock_ssh() as (fake, credential), self.assertRaises(bridge.BridgeError):
                self.run_command("systemctl restart nginx", timeout_seconds=timeout, intent_zh=INTENT)
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_preauthorization_keeps_runtime_deadline_and_closes_timed_out_channel(self) -> None:
        self.enable_test_policy()
        fake = _fixtures.FakeSSH(stdout=b"")
        with self.mock_ssh(fake), patch.object(fake, "exit_status_ready", return_value=False), patch.object(
            bridge.time, "monotonic", side_effect=[100.0, 102.0, 102.0]
        ), self.assertRaisesRegex(bridge.BridgeError, "timed out"):
            self.run_command("systemctl restart nginx", timeout_seconds=1, intent_zh=INTENT)
        self.assertTrue(fake.channel_closed)
        self.assertTrue(fake.client_closed)

    def test_preauthorization_keeps_output_budget_and_exit_status(self) -> None:
        self.enable_test_policy()
        fake = _fixtures.FakeSSH(stdout=b"x" * (bridge.MAX_SSH_OUTPUT_BYTES + 200), stderr=b"y" * 100)
        with self.mock_ssh(fake), patch.object(bridge.time, "sleep"):
            result = self.run_command("systemctl restart nginx", intent_zh=INTENT)["structuredContent"]
        self.assertEqual(len(result["stdout"].encode()) + len(result["stderr"].encode()), bridge.MAX_SSH_OUTPUT_BYTES)
        self.assertTrue(result["output_truncated"])
        self.assertEqual(result["approval_basis"], "host_preauthorized")
        self.assertFalse(result["read_only"])
        self.assertTrue(fake.channel_closed)
        with self.mock_ssh(_fixtures.FakeSSH(stdout=b"", stderr=b"fixture failure\n", exit_code=3)):
            response = self.run_command("systemctl restart nginx", intent_zh=INTENT)
        self.assertTrue(response["isError"])
        self.assertEqual(response["structuredContent"]["exit_code"], 3)
        self.assertEqual(response["structuredContent"]["stderr"], "fixture failure\n")
        self.assertFalse(response["structuredContent"]["approval_required"])

    def test_preauthorization_keeps_command_and_alias_validation(self) -> None:
        self.enable_test_policy()
        for changes in ({"alias": "unknown-alias"}, {"alias": None}, {"alias": "test-host; other"},
                        {"command": ""}, {"command": "  "}, {"command": "x" * 12001},
                        {"command": "whoami\x00id"}, {"command": []}):
            with self.subTest(changes=changes), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation"
            ) as approval, self.assertRaises(bridge.BridgeError):
                bridge.ssh_run_command({"alias": "test-host", "command": "whoami", "intent_zh": INTENT, **changes}, self.cfg)
            approval.assert_not_called()
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_status_exposes_only_per_alias_policy_fields_in_text_and_structured_data(self) -> None:
        self.enable_test_policy()
        self.cfg["ssh_hosts"]["legacy"] = {key: value for key, value in self.host.items() if key not in TEST_POLICY}
        self.cfg["ssh_hosts"]["production"] = {**self.cfg["ssh_hosts"]["legacy"], "environment": "production"}
        self.host["private_key_file"] = "C:/test-only-private-key-path/key.pem"
        expected = {
            "test-host": TEST_POLICY,
            "legacy": DEFAULT_POLICY,
            "production": {"environment": "production", "approval_policy": "confirm_writes"},
        }
        with self.mock_ssh() as (fake, credential), patch.object(bridge, "request_confirmation") as approval:
            result = bridge.tool_call("bridge_status", {}, self.cfg)
        for public in (result["structuredContent"], json.loads(result["content"][0]["text"])):
            self.assertEqual(public["ssh_host_policies"], expected)
            self.assertEqual(public["ssh_hosts"], sorted(expected))
            for policy in public["ssh_host_policies"].values():
                self.assertEqual(set(policy), {"environment", "approval_policy"})
        encoded = json.dumps(result)
        for sensitive in (self.host["host"], self.host["username"], self.host["credential_target"],
                          self.host["host_key_sha256"], self.host["private_key_file"], "fixture-only-secret"):
            self.assertNotIn(sensitive, encoded)
        credential.assert_not_called()
        approval.assert_not_called()
        fake.module.SSHClient.assert_not_called()
        empty = bridge.tool_call("bridge_status", {}, {})["structuredContent"]
        self.assertEqual(empty["ssh_host_policies"], {})

    def test_config_reread_revokes_preauthorization_on_the_next_mcp_call(self) -> None:
        self.enable_test_policy()
        artifact_root = PLUGIN_ROOT / "test"
        artifact_root.mkdir(exist_ok=True)
        # 只写本测试合成配置；不触及插件真实 config/bridge.json。
        with tempfile.TemporaryDirectory(prefix="host-policy-", dir=artifact_root) as directory:
            config_path = Path(directory) / "fixture.json"
            params = {"name": "ssh_run_command", "arguments": {
                "alias": "test-host", "command": "systemctl restart nginx", "intent_zh": INTENT,
            }}
            with patch.object(bridge, "CONFIG_PATH", config_path):
                config_path.write_text(json.dumps(self.cfg), encoding="utf-8")
                with self.mock_ssh(), patch.object(bridge, "send_result") as sent, patch.object(
                    bridge, "request_confirmation", side_effect=AssertionError("preauthorized")
                ):
                    bridge.handle_tool("before", params)
                first = sent.call_args.args[1]
                self.assertFalse(first["isError"])
                self.assertEqual(first["structuredContent"]["approval_basis"], "host_preauthorized")

                for fields in ({"environment": "test", "approval_policy": "confirm_writes"}, {}, {"environment": "production"}):
                    host = {key: value for key, value in self.host.items() if key not in TEST_POLICY}
                    config_path.write_text(json.dumps({"ssh_hosts": {"test-host": {**host, **fields}}}), encoding="utf-8")
                    with self.subTest(revocation=fields), self.mock_ssh() as (fake, credential), patch.object(
                        bridge, "send_result"
                    ) as sent, patch.object(bridge, "request_confirmation", side_effect=bridge.BridgeError("fixture revoked")) as approval:
                        bridge.handle_tool("revoked", params)
                    approval.assert_called_once()
                    credential.assert_not_called()
                    fake.module.SSHClient.assert_not_called()
                    self.assertTrue(sent.call_args.args[1]["isError"])
                    self.assertIn("fixture revoked", sent.call_args.args[1]["content"][0]["text"])

                config_path.write_text(json.dumps({"ssh_hosts": {}}), encoding="utf-8")
                with self.mock_ssh() as (fake, credential), patch.object(bridge, "send_result") as sent, patch.object(
                    bridge, "request_confirmation"
                ) as approval:
                    bridge.handle_tool("removed", params)
                self.assertTrue(sent.call_args.args[1]["isError"])
                approval.assert_not_called()
                credential.assert_not_called()
                fake.module.SSHClient.assert_not_called()

    def test_ssh_preauthorization_never_bypasses_email_confirmation(self) -> None:
        self.enable_test_policy()
        self.cfg["email"] = {
            "host": "smtp.example.invalid", "port": 465, "security": "ssl", "username": "mailer",
            "from": "sender@example.invalid", "credential_target": "SecureCredentialBridge/email/fixture",
            "allowed_recipients": ["operator@example.invalid"],
        }
        with patch.dict(bridge.DRAFTS, {}, clear=True), patch.object(bridge, "read_credential") as credential, patch.object(
            bridge.smtplib, "SMTP_SSL"
        ) as smtp_ssl, patch.object(bridge.smtplib, "SMTP") as smtp, patch.object(
            bridge, "request_confirmation", side_effect=bridge.BridgeError("fixture mail declined")
        ) as approval:
            draft = bridge.email_create_draft({"to": "operator@example.invalid", "subject": "Fixture", "body": "Synthetic body"}, self.cfg)["structuredContent"]
            approval.assert_not_called()
            with self.assertRaisesRegex(bridge.BridgeError, "fixture mail declined"):
                bridge.tool_call("email_send_draft", {"draft_id": draft["draft_id"], "sha256": draft["sha256"]}, self.cfg)
            approval.assert_called_once()
            self.assertIn(draft["sha256"], approval.call_args.args[0])
            credential.assert_not_called()
            smtp_ssl.assert_not_called()
            smtp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
