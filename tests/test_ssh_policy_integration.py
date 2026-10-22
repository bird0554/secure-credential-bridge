"""验证策略、确认和 SSH 执行边界；所有认证、网络及窗口均为替身。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_policy_integration", PLUGIN_ROOT / "mcp" / "server.py")
assert SPEC and SPEC.loader
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


def fingerprint(key: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode("ascii").rstrip("=")


class FakeSSH:
    """保留真实服务端的 pin 校验入口和执行顺序，不运行远端命令。"""

    def __init__(self, *, key: bytes = b"test-only-host-key", check_callback: bool = True,
                 transport_key: bytes | None = b"test-only-host-key", stdout: bytes = b"query-result\n",
                 stderr: bytes = b"", exit_code: int = 0) -> None:
        self.events: list[object] = []
        self.options: dict[str, object] = {}
        self.execute_options: dict[str, object] = {}
        self.key = key
        self.transport_key = transport_key
        self.check_callback = check_callback
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.policy = None
        self.channel_closed = False
        self.client_closed = False
        self.module = types.ModuleType("paramiko")
        self.module.MissingHostKeyPolicy = type("MissingHostKeyPolicy", (), {})
        self.module.SSHException = type("SSHException", (Exception,), {})
        self.module.AuthenticationException = type("AuthenticationException", (Exception,), {})
        self.module.SSHClient = Mock(side_effect=self.new_client)

    @staticmethod
    def host_key(value: bytes) -> object:
        return types.SimpleNamespace(asbytes=lambda: value)

    def new_client(self) -> "FakeSSH":
        self.events.append("new_client")
        return self

    def set_missing_host_key_policy(self, policy: object) -> None:
        self.policy = policy

    def connect(self, **kwargs: object) -> None:
        self.events.append("connect")
        self.options = kwargs
        if self.check_callback:
            self.policy.missing_host_key(self, "192.0.2.10", self.host_key(self.key))

    def get_transport(self) -> object:
        return types.SimpleNamespace(get_remote_server_key=lambda: (
            self.host_key(self.transport_key) if self.transport_key is not None else None
        ))

    def exec_command(self, command: str, **kwargs: object) -> tuple[None, object, object]:
        self.events.append(("execute", command))
        self.execute_options = kwargs
        stream = types.SimpleNamespace(channel=self)
        return None, stream, stream

    def recv_ready(self) -> bool:
        return bool(self.stdout)

    def recv_stderr_ready(self) -> bool:
        return bool(self.stderr)

    def recv(self, size: int) -> bytes:
        result, self.stdout = self.stdout[:size], self.stdout[size:]
        return result

    def recv_stderr(self, size: int) -> bytes:
        result, self.stderr = self.stderr[:size], self.stderr[size:]
        return result

    def exit_status_ready(self) -> bool:
        return not self.stdout and not self.stderr

    def recv_exit_status(self) -> int:
        return self.exit_code

    def close(self) -> None:
        self.client_closed = True
        self.channel_closed = True


class SSHPolicyIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.host = {
            "host": "192.0.2.10", "port": 2222, "username": "test-user",
            "host_key_sha256": fingerprint(b"test-only-host-key"),
            "credential_target": "SecureCredentialBridge/ssh/test-host",
        }
        self.cfg = {"ssh_hosts": {"test-host": self.host}}

    @contextmanager
    def mock_ssh(self, fake: FakeSSH | None = None):
        fake = fake or FakeSSH()

        def credential(_target: str) -> str:
            fake.events.append("credential")
            return "fixture-only-secret"

        with patch.dict(sys.modules, {"paramiko": fake.module}), patch.object(
            bridge, "read_credential", side_effect=credential
        ) as read:
            yield fake, read

    def run_command(self, command: str, **kwargs: object) -> dict:
        return bridge.ssh_run_command({"alias": "test-host", "command": command, **kwargs}, self.cfg)

    def test_supported_read_only_queries_execute_without_confirmation(self) -> None:
        for command in ("whoami", "df -h", "docker ps"):
            with self.subTest(command=command), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation", side_effect=AssertionError("read-only must not prompt")
            ) as approval:
                result = self.run_command(command, timeout_seconds=17)["structuredContent"]
            approval.assert_not_called()
            credential.assert_called_once_with(self.host["credential_target"])
            self.assertEqual(fake.events, ["new_client", "credential", "connect", ("execute", command)])
            self.assertEqual(fake.execute_options, {"timeout": 17, "get_pty": False})
            self.assertFalse(fake.options["allow_agent"])
            self.assertFalse(fake.options["look_for_keys"])
            self.assertEqual(fake.options["port"], 2222)
            self.assertTrue(fake.client_closed)
            self.assertTrue(result["read_only"])
            self.assertFalse(result["approval_required"])
            self.assertEqual(result["stdout"], "query-result\n")

    def test_read_only_does_not_require_available_confirmation_ui(self) -> None:
        with self.mock_ssh(), patch.object(bridge, "APPROVAL_MODE", "native"), patch.object(
            bridge, "CLIENT_ELICITATION", False
        ), patch.object(bridge, "send") as send:
            self.assertTrue(self.run_command("whoami")["structuredContent"]["read_only"])
        send.assert_not_called()

    def test_read_only_still_rejects_callback_host_fingerprint_mismatch(self) -> None:
        with self.mock_ssh(FakeSSH(key=b"untrusted-test-key")) as (fake, _), patch.object(
            bridge, "request_confirmation"
        ) as approval, self.assertRaisesRegex(bridge.BridgeError, "fingerprint"):
            self.run_command("whoami")
        approval.assert_not_called()
        self.assertFalse(any(isinstance(event, tuple) for event in fake.events))
        self.assertTrue(fake.client_closed)

    def test_read_only_checks_transport_pin_even_without_missing_key_callback(self) -> None:
        with self.mock_ssh(FakeSSH(check_callback=False, transport_key=b"untrusted-test-key")) as (fake, _), self.assertRaisesRegex(
            bridge.BridgeError, "fingerprint"
        ):
            self.run_command("whoami")
        self.assertNotIn(("execute", "whoami"), fake.events)
        self.assertTrue(fake.client_closed)

    def test_read_only_rejects_missing_transport_key(self) -> None:
        with self.mock_ssh(FakeSSH(transport_key=None)) as (fake, _), self.assertRaisesRegex(
            bridge.BridgeError, "did not provide a host key"
        ):
            self.run_command("whoami")
        self.assertNotIn(("execute", "whoami"), fake.events)
        self.assertTrue(fake.client_closed)

    def test_connection_preflight_skips_confirmation_and_never_executes_command(self) -> None:
        with self.mock_ssh() as (fake, _), patch.object(bridge, "request_confirmation") as approval:
            result = bridge.ssh_connect({"alias": "test-host"}, self.cfg)["structuredContent"]
        approval.assert_not_called()
        self.assertTrue(result["connected"])
        self.assertFalse(result["remote_command_executed"])
        self.assertFalse(any(isinstance(event, tuple) for event in fake.events))
        self.assertTrue(fake.client_closed)

    def test_connection_preflight_still_requires_matching_pin(self) -> None:
        with self.mock_ssh(FakeSSH(key=b"untrusted-test-key")) as (fake, _), patch.object(
            bridge, "launch_ssh_manager", return_value=False
        ), self.assertRaisesRegex(bridge.BridgeError, "fingerprint"):
            bridge.ssh_connect({"alias": "test-host"}, self.cfg)
        self.assertFalse(any(isinstance(event, tuple) for event in fake.events))
        self.assertTrue(fake.client_closed)

    def test_mutation_and_unknown_command_require_approval_before_credentials_and_network(self) -> None:
        intent = "执行指定维护任务并更新服务状态"
        for command in ("systemctl restart nginx", "custom-maintenance --mode audit"):
            with self.subTest(command=command), self.mock_ssh() as (fake, _):
                def approve(message: str, *, intent_zh: str) -> None:
                    self.assertEqual(fake.events, [])
                    self.assertIn(command, message)
                    self.assertIn("test-user@192.0.2.10:2222", message)
                    self.assertEqual(intent_zh, intent)
                    fake.events.append("approved")

                with patch.object(bridge, "request_confirmation", side_effect=approve) as approval:
                    result = self.run_command(command, intent_zh=intent)["structuredContent"]
            approval.assert_called_once()
            self.assertEqual(fake.events, ["approved", "new_client", "credential", "connect", ("execute", command)])
            self.assertTrue(result["approval_required"])
            self.assertFalse(result["read_only"])

    def test_declined_mutation_never_opens_client_reads_credentials_or_connects(self) -> None:
        with self.mock_ssh() as (fake, credential), patch.object(
            bridge, "request_confirmation", side_effect=bridge.BridgeError("declined")
        ) as approval, self.assertRaisesRegex(bridge.BridgeError, "declined"):
            self.run_command("systemctl restart nginx", intent_zh="重启 nginx 服务")
        approval.assert_called_once()
        credential.assert_not_called()
        fake.module.SSHClient.assert_not_called()
        self.assertEqual(fake.events, [])

    def test_unavailable_native_confirmation_fails_before_any_ssh_access(self) -> None:
        with self.mock_ssh() as (fake, credential), patch.object(bridge, "APPROVAL_MODE", "native"), patch.object(
            bridge, "CLIENT_ELICITATION", False
        ), self.assertRaisesRegex(bridge.BridgeError, "did not advertise"):
            self.run_command("systemctl restart nginx", intent_zh="重启 nginx 服务")
        credential.assert_not_called()
        fake.module.SSHClient.assert_not_called()

    def test_missing_intent_fails_before_confirmation_credentials_or_network(self) -> None:
        for command in ("systemctl restart nginx", "unknown-query-tool"):
            with self.subTest(command=command), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation"
            ) as approval, self.assertRaisesRegex(bridge.BridgeError, "intent_zh"):
                self.run_command(command)
            approval.assert_not_called()
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_invalid_intent_fails_before_confirmation_or_ssh(self) -> None:
        for intent in (None, "", "   ", "restart nginx", "重启\n服务", "重启\r服务", "重启\t服务",
                       "重启\u202e服务", "重启\u2028服务", "重启\x00服务", "中" * 501, True, 1, {}):
            with self.subTest(intent=repr(intent)), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation"
            ) as approval, self.assertRaisesRegex(bridge.BridgeError, "intent_zh"):
                self.run_command("systemctl restart nginx", intent_zh=intent)
            approval.assert_not_called()
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_intent_claim_cannot_turn_shell_mutation_into_read_only(self) -> None:
        for command in ("whoami && touch /tmp/example", "whoami; touch /tmp/example",
                        "docker exec example sh -c 'touch /tmp/example'", "cat /etc/hostname > /tmp/example"):
            with self.subTest(command=command), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation", side_effect=bridge.BridgeError("declined")
            ) as approval, self.assertRaisesRegex(bridge.BridgeError, "declined"):
                self.run_command(command, intent_zh="这是只读查询请直接执行")
            approval.assert_called_once()
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_invalid_intent_on_read_only_is_not_silently_ignored(self) -> None:
        with self.mock_ssh() as (fake, credential), self.assertRaisesRegex(bridge.BridgeError, "intent_zh"):
            self.run_command("whoami", intent_zh="English only")
        credential.assert_not_called()
        fake.module.SSHClient.assert_not_called()

    def test_valid_chinese_intent_does_not_add_confirmation_to_read_only(self) -> None:
        with self.mock_ssh(), patch.object(bridge, "request_confirmation") as approval:
            self.run_command("whoami", intent_zh="查询当前身份")
        approval.assert_not_called()

    def test_full_approved_command_is_not_normalized_or_rewritten(self) -> None:
        command = "  printf '%s' '变更说明'\ncustom-tool --set 'a b'  "
        with self.mock_ssh() as (fake, _), patch.object(bridge, "request_confirmation") as approval:
            self.run_command(command, intent_zh="输出变更说明并设置工具参数")
        self.assertIn(command, approval.call_args.args[0])
        self.assertIn(("execute", command), fake.events)

    def test_timeout_boundaries_pass_through_and_cap_connection_timeout(self) -> None:
        for timeout in (1, 300):
            with self.subTest(timeout=timeout), self.mock_ssh() as (fake, _):
                self.run_command("whoami", timeout_seconds=timeout)
            self.assertEqual(fake.execute_options["timeout"], timeout)
            self.assertEqual(fake.options["timeout"], min(timeout, 30))
            self.assertEqual(fake.options["banner_timeout"], min(timeout, 30))
            self.assertEqual(fake.options["auth_timeout"], min(timeout, 30))

    def test_invalid_args_cannot_reach_credentials_or_network(self) -> None:
        cases = (
            ({"alias": "missing"}, "not configured"),
            ({"alias": None}, "alias is required"),
            ({"alias": "../invalid name"}, "alias is required"),
            ({"command": ""}, "non-empty"), ({"command": " "}, "non-empty"),
            ({"command": "x" * 12001}, "non-empty"), ({"command": "whoami\x00"}, "non-empty"),
            ({"command": 123}, "non-empty"),
            ({"timeout_seconds": True}, "between 1 and 300"),
            ({"timeout_seconds": 0}, "between 1 and 300"),
            ({"timeout_seconds": 301}, "between 1 and 300"),
            ({"timeout_seconds": 1.0}, "between 1 and 300"),
            ({"timeout_seconds": "60"}, "between 1 and 300"),
            ({"read_only": True}, "Unsupported SSH command argument"),
            ({"approved": True}, "Unsupported SSH command argument"),
            ({"skip_approval": True}, "Unsupported SSH command argument"),
            ({"target": "different-host"}, "Unsupported SSH command argument"),
        )
        for changes, message in cases:
            args = {"alias": "test-host", "command": "whoami", **changes}
            with self.subTest(changes=changes), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation"
            ) as approval, self.assertRaisesRegex(bridge.BridgeError, message):
                bridge.ssh_run_command(args, self.cfg)
            approval.assert_not_called()
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_output_limit_still_applies_to_exempt_queries(self) -> None:
        fake = FakeSSH(stdout=b"x" * (bridge.MAX_SSH_OUTPUT_BYTES + 200))
        with self.mock_ssh(fake), patch.object(bridge.time, "sleep"):
            result = self.run_command("whoami")["structuredContent"]
        self.assertEqual(len(result["stdout"].encode("utf-8")), bridge.MAX_SSH_OUTPUT_BYTES)
        self.assertTrue(result["output_truncated"])
        self.assertTrue(fake.channel_closed)
        self.assertTrue(result["read_only"])

    def test_nonzero_exit_status_remains_an_error_for_exempt_query(self) -> None:
        with self.mock_ssh(FakeSSH(stdout=b"", stderr=b"query failed\n", exit_code=3)):
            result = self.run_command("whoami")
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["exit_code"], 3)
        self.assertEqual(result["structuredContent"]["stderr"], "query failed\n")


class ConfirmationTransportTests(unittest.TestCase):
    def test_local_approval_transports_chinese_intent_and_command_as_utf8(self) -> None:
        message = "目标主机：test-host\n完整命令：\nprintf '中文'"
        intent = "输出中文维护说明"
        completed = subprocess.CompletedProcess([], 0, '{"approved": true}\n', "")
        with patch.object(bridge.subprocess, "run", return_value=completed) as run:
            bridge.request_local_approval(message, intent_zh=intent)
        options = run.call_args.kwargs
        self.assertEqual(options["encoding"], "utf-8")
        self.assertTrue(options["text"])
        self.assertEqual(json.loads(options["input"]), {"message": message, "intent_zh": intent})
        self.assertIn(intent, options["input"])
        self.assertNotIn(intent, " ".join(run.call_args.args[0]))

    def test_local_confirmation_propagates_intent_and_full_message(self) -> None:
        with patch.object(bridge, "APPROVAL_MODE", "local"), patch.object(bridge, "request_local_approval") as local:
            bridge.request_confirmation("完整命令：systemctl restart nginx", intent_zh="重启 nginx 服务")
        local.assert_called_once()
        self.assertIn("重启 nginx 服务", local.call_args.args[0])
        self.assertIn("systemctl restart nginx", local.call_args.args[0])
        self.assertEqual(local.call_args.kwargs, {"intent_zh": "重启 nginx 服务"})

    def test_auto_fallback_preserves_chinese_intent(self) -> None:
        with patch.object(bridge, "APPROVAL_MODE", "auto"), patch.object(bridge, "CLIENT_ELICITATION", False), patch.object(
            bridge, "request_local_approval"
        ) as local:
            bridge.request_confirmation("完整命令：systemctl restart nginx", intent_zh="重启 nginx 服务")
        self.assertEqual(local.call_args.kwargs, {"intent_zh": "重启 nginx 服务"})
        self.assertIn("重启 nginx 服务", local.call_args.args[0])

    def test_native_confirmation_includes_chinese_intent_and_requires_exact_acceptance(self) -> None:
        sent = []

        def respond(message: dict) -> None:
            sent.append(message)
            bridge.PENDING_REQUESTS[message["id"]].put({"result": {"action": "accept", "content": {"confirm": True}}})

        before = set(bridge.PENDING_REQUESTS)
        with patch.object(bridge, "APPROVAL_MODE", "native"), patch.object(bridge, "CLIENT_ELICITATION", True), patch.object(
            bridge, "send", side_effect=respond
        ), patch.object(bridge, "request_local_approval") as local:
            bridge.request_confirmation("完整命令：systemctl restart nginx", intent_zh="重启 nginx 服务")
        local.assert_not_called()
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["method"], "elicitation/create")
        self.assertIn("【请确认操作意图】重启 nginx 服务", sent[0]["params"]["message"])
        self.assertIn("systemctl restart nginx", sent[0]["params"]["message"])
        self.assertFalse(sent[0]["params"]["requestedSchema"]["properties"]["confirm"]["default"])
        self.assertEqual(set(bridge.PENDING_REQUESTS), before)

    def test_native_denial_and_nonboolean_acceptance_fail_closed_and_cleanup(self) -> None:
        responses = (
            {"result": {"action": "decline"}}, {"result": {"action": "cancel"}},
            {"result": {"action": "accept", "content": {"confirm": "true"}}},
            {"result": {"action": "accept", "content": {"confirm": False}}},
            {"result": {"action": "accept", "content": {}}},
            {"error": {"code": -32603, "message": "unavailable"}},
        )
        before = set(bridge.PENDING_REQUESTS)
        for response in responses:
            def respond(message: dict) -> None:
                bridge.PENDING_REQUESTS[message["id"]].put(response)

            with self.subTest(response=response), patch.object(bridge, "APPROVAL_MODE", "native"), patch.object(
                bridge, "CLIENT_ELICITATION", True
            ), patch.object(bridge, "send", side_effect=respond), self.assertRaises(bridge.BridgeError):
                bridge.request_confirmation("完整命令：systemctl restart nginx", intent_zh="重启 nginx 服务")
            self.assertEqual(set(bridge.PENDING_REQUESTS), before)

    def test_invalid_intent_never_reaches_confirmation_transport(self) -> None:
        with patch.object(bridge, "send") as send, patch.object(bridge, "request_local_approval") as local, self.assertRaisesRegex(
            bridge.BridgeError, "intent_zh"
        ):
            bridge.request_confirmation("command", intent_zh="English only")
        send.assert_not_called()
        local.assert_not_called()

    def test_local_transport_rejects_invalid_intent_before_spawning_ui(self) -> None:
        with patch.object(bridge.subprocess, "run") as run, self.assertRaisesRegex(bridge.BridgeError, "intent_zh"):
            bridge.request_local_approval("command", intent_zh="中文\n隐藏行")
        run.assert_not_called()

    def test_legacy_confirmation_without_intent_remains_compatible(self) -> None:
        completed = subprocess.CompletedProcess([], 0, '{"approved": true}\n', "")
        with patch.object(bridge.subprocess, "run", return_value=completed) as run:
            bridge.request_local_approval("Email recipient and digest")
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), {"message": "Email recipient and digest"})


if __name__ == "__main__":
    unittest.main()
