"""Regression checks for the prompt-free SSH read path; all SSH access is mocked."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


_FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "scb_readonly_upgrade_fixtures", Path(__file__).with_name("test_ssh_policy_integration.py")
)
assert _FIXTURE_SPEC and _FIXTURE_SPEC.loader
_fixtures = importlib.util.module_from_spec(_FIXTURE_SPEC)
_FIXTURE_SPEC.loader.exec_module(_fixtures)
bridge = _fixtures.bridge


SAFE_QUERIES = (
    "find /var/log -maxdepth 2 -type f -name '*.log'",
    "ss -lntp",
    "ip addr show",
    "ip route show",
    "lsblk -f",
    "file --brief /etc/os-release",
    r"printf '%s\n' status",
    "test -f /etc/os-release",
    "docker network ls",
    "docker volume ls",
    "cat /etc/hosts | sort | uniq",
    "rg -n ERROR /var/log/app.log",
    "systemctl status nginx",
    "journalctl -n 20",
    "cd /var/log && head -n 20 syslog",
    "whoami; id",
    "whoami\nid",
    "whoami || id",
    r"grep -E '\bERROR\b' /var/log/app.log",
)

REQUIRES_APPROVAL = (
    "find /var/log -delete",
    "find /var/log -exec touch /tmp/example +",
    "find /var/log -fprint /tmp/example",
    "ss -K dst 192.0.2.10",
    "ip route add 192.0.2.0/24 dev eth0",
    "ip route del 192.0.2.0/24",
    "ip route flush table main",
    "file -C",
    "printf -v PATH evil",
    "printf '%n' PATH",
    "printf '%s%n' x PATH",
    "printf '%1$n' PATH",
    "printf '%n' 'a[$(touch /tmp/example)]'",
    "ss -D /tmp/dump",
    "ss -F script",
    "ip -batch script",
    "ip netns exec namespace sh",
    "find /var/log -fprintf /tmp/result '%p'",
    "find /var/log -fls /tmp/result",
    "find /var/log -okdir touch /tmp/example +",
    "file --compile",
    "git status",
    "git log --format='%G?'",
    "cd /var/log && rm syslog",
    "whoami; touch /tmp/example",
    "whoami\ntouch /tmp/example",
    "whoami || touch /tmp/example",
    "cat /etc/hosts | sort -o /tmp/example",
    "whoami | tee /tmp/example",
    "cat /etc/hosts > /tmp/example",
    "cat /etc/hosts >> /tmp/example",
    "cat /etc/hosts 2>/tmp/example",
    "cat $(touch /tmp/example)",
    "cat `touch /tmp/example`",
    "sh -c 'touch /tmp/example'",
    "python -c 'print(1)'",
    "custom-diagnostic-script",
    "docker network create example",
    "docker volume rm example",
)


class ReadOnlyUpgradePolicyTests(unittest.TestCase):
    def test_normalization_preserves_operators_and_literal_argument_boundaries(self) -> None:
        command = "rg 'a;b||c' /var/log/app.log || systemctl status nginx; journalctl -n 20"
        self.assertEqual(
            bridge.classify_command(command).execution_command,
            "rg --no-config 'a;b||c' /var/log/app.log || systemctl --no-pager status nginx ; journalctl --no-pager -n 20",
        )
        self.assertTrue(bridge.classify_command("printf '%%n' literal").read_only)
        self.assertEqual(
            bridge.classify_command("docker exec app sudo -n rg 'a b' log").execution_command,
            "docker exec app sudo -n rg --no-config 'a b' log",
        )

    def test_common_queries_and_complete_read_only_lists_are_recognized(self) -> None:
        for command in SAFE_QUERIES:
            with self.subTest(command=command):
                policy = bridge.classify_command(command)
                self.assertTrue(policy.read_only, policy.reason_zh)

    def test_new_command_families_do_not_exempt_mutating_arguments(self) -> None:
        for command in REQUIRES_APPROVAL:
            with self.subTest(command=command):
                self.assertFalse(bridge.classify_command(command).read_only)

    def test_query_guards_are_attached_to_the_relevant_stage(self) -> None:
        for command, guard in (
            ("rg -n ERROR /var/log/app.log", "--no-config"),
            ("systemctl status nginx", "--no-pager"),
            ("journalctl -n 20", "--no-pager"),
            ("sudo -n systemctl status nginx", "--no-pager"),
            ("docker exec app rg -n ERROR /var/log/app.log", "--no-config"),
        ):
            with self.subTest(command=command):
                policy = bridge.classify_command(command)
                self.assertTrue(policy.read_only, policy.reason_zh)
                self.assertIsInstance(policy.execution_command, str)
                self.assertIn(guard, policy.execution_command)
                self.assertTrue(bridge.classify_command(policy.execution_command).read_only)

    def test_quote_boundaries_do_not_turn_literal_operators_into_stages(self) -> None:
        for command in (
            "grep -F 'a;b||c' /var/log/app.log",
            r"grep -F '$(touch /tmp/example)\n' /var/log/app.log",
            "printf '%s' '&& touch /tmp/example'",
        ):
            with self.subTest(command=command):
                self.assertTrue(bridge.classify_command(command).read_only)
        for command in (
            "grep -F 'a;b||c' /var/log/app.log; touch /tmp/example",
            'printf "%s" "$(touch /tmp/example)"',
            "printf '%s' 'literal'; touch /tmp/example",
        ):
            with self.subTest(command=command):
                self.assertFalse(bridge.classify_command(command).read_only)


class ReadOnlyUpgradeIntegrationTests(unittest.TestCase):
    # Reuse fixture methods without inheriting or rediscovering the older test cases.
    setUp = _fixtures.SSHPolicyIntegrationTests.setUp
    mock_ssh = _fixtures.SSHPolicyIntegrationTests.mock_ssh
    run_command = _fixtures.SSHPolicyIntegrationTests.run_command

    def run_read(self, command: str, **kwargs: object) -> dict:
        return bridge.ssh_read_command(
            {"alias": "test-host", "command": command, **kwargs}, self.cfg
        )

    def test_read_tool_exposes_accurate_read_only_annotations(self) -> None:
        tools = {tool["name"]: tool for tool in bridge.tools_for({})}
        tool = tools["ssh_read_command"]
        self.assertTrue(tool["annotations"]["readOnlyHint"])
        self.assertFalse(tool["annotations"]["destructiveHint"])
        self.assertEqual(tool["inputSchema"]["required"], ["alias", "command"])
        self.assertFalse(tool["inputSchema"]["additionalProperties"])
        self.assertFalse(tools["ssh_run_command"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["ssh_run_command"]["annotations"]["destructiveHint"])

    def test_read_tool_dispatches_through_the_public_mcp_entrypoint(self) -> None:
        args = {"alias": "test-host", "command": "whoami"}
        with self.mock_ssh() as (fake, _), patch.object(
            bridge, "request_confirmation", side_effect=AssertionError("must not prompt")
        ) as approval:
            result = bridge.tool_call("ssh_read_command", args, self.cfg)["structuredContent"]
        approval.assert_not_called()
        self.assertTrue(result["read_only"])
        self.assertIn(("execute", "whoami"), fake.events)

    def test_all_supported_reads_use_no_confirmation_through_either_tool(self) -> None:
        for command in SAFE_QUERIES:
            for operation in (self.run_read, self.run_command):
                with self.subTest(command=command, tool=operation.__name__), self.mock_ssh() as (
                    fake, credential
                ), patch.object(
                    bridge, "request_confirmation", side_effect=AssertionError("must not prompt")
                ) as approval:
                    result = operation(command, timeout_seconds=17)["structuredContent"]
                approval.assert_not_called()
                credential.assert_called_once()
                self.assertTrue(result["read_only"])
                self.assertFalse(result["approval_required"])
                self.assertIn(("execute", result.get("executed_command", command)), fake.events)
                self.assertEqual(fake.execute_options, {"timeout": 17, "get_pty": False})

    def test_normalized_reads_report_original_and_executed_command(self) -> None:
        for command, guard in (
            ("rg -n ERROR /var/log/app.log", "--no-config"),
            ("systemctl status nginx", "--no-pager"),
            ("journalctl -n 20", "--no-pager"),
        ):
            with self.subTest(command=command), self.mock_ssh() as (fake, _), patch.object(
                bridge, "request_confirmation"
            ) as approval:
                result = self.run_read(command)["structuredContent"]
            approval.assert_not_called()
            self.assertEqual(result["command"], command)
            self.assertNotEqual(result["executed_command"], command)
            self.assertIn(guard, result["executed_command"])
            self.assertIn(("execute", result["executed_command"]), fake.events)
            self.assertNotIn(("execute", command), fake.events)

    def test_read_tool_rejects_changes_without_prompt_credentials_or_network(self) -> None:
        for command in REQUIRES_APPROVAL:
            with self.subTest(command=command), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation"
            ) as approval, self.assertRaisesRegex(bridge.BridgeError, "read-only"):
                self.run_read(command)
            approval.assert_not_called()
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()
            self.assertEqual(fake.events, [])

    def test_general_tool_still_requests_approval_for_new_mutation_families(self) -> None:
        for command in (
            "find /var/log -delete",
            "ss -K dst 192.0.2.10",
            "ip route flush table main",
            "file -C",
            "whoami; touch /tmp/example",
        ):
            with self.subTest(command=command), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation", side_effect=bridge.BridgeError("declined")
            ) as approval, self.assertRaisesRegex(bridge.BridgeError, "declined"):
                self.run_command(command, intent_zh="执行指定维护命令并修改远端状态")
            approval.assert_called_once()
            self.assertIn(command, approval.call_args.args[0])
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()

    def test_read_tool_still_checks_fingerprint_before_executing(self) -> None:
        fake = _fixtures.FakeSSH(key=b"untrusted-test-key")
        with self.mock_ssh(fake), patch.object(bridge, "request_confirmation") as approval, self.assertRaisesRegex(
            bridge.BridgeError, "fingerprint"
        ):
            self.run_read("whoami")
        approval.assert_not_called()
        self.assertNotIn(("execute", "whoami"), fake.events)
        self.assertTrue(fake.client_closed)

    def test_read_tool_does_not_accept_a_caller_supplied_policy_override(self) -> None:
        for extra in ({"read_only": True}, {"approved": True}, {"skip_approval": True}):
            with self.subTest(extra=extra), self.mock_ssh() as (fake, credential), patch.object(
                bridge, "request_confirmation"
            ) as approval, self.assertRaises(bridge.BridgeError):
                self.run_read("whoami", **extra)
            approval.assert_not_called()
            credential.assert_not_called()
            fake.module.SSHClient.assert_not_called()


if __name__ == "__main__":
    unittest.main()
