from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PLUGIN_ROOT / "mcp" / "command_policy.py"
SPEC = importlib.util.spec_from_file_location("scb_command_policy_tests", POLICY_PATH)
policy_module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = policy_module
SPEC.loader.exec_module(policy_module)
classify_command = policy_module.classify_command


class CommandPolicyTests(unittest.TestCase):
    def assert_read_only(self, command: str) -> None:
        with self.subTest(command=command):
            self.assertTrue(classify_command(command).read_only, classify_command(command).reason_zh)

    def assert_requires_approval(self, command: str) -> None:
        with self.subTest(command=command):
            self.assertFalse(classify_command(command).read_only, classify_command(command).reason_zh)

    def test_supported_bounded_or_common_queries(self) -> None:
        for command in (
            "whoami",
            "id -un",
            "uname -a",
            "date +%F",
            "ls -lah /etc",
            "cat /etc/os-release",
            "head -n 20 /var/log/syslog",
            "tail --lines=20 /var/log/syslog",
            "wc -l /etc/passwd",
            "stat -c '%a %n' /etc/passwd",
            "readlink -f /bin/sh",
            "df -h",
            "du -sh /var/log",
            "free -h",
            "ps aux",
            "grep -F -n 'failed' /var/log/service.log",
            "rg --no-config -n 'error|failed' /var/log",
            "sort -c /etc/hosts",
            "uniq /etc/hosts",
            "sed -n '1,20p' /etc/hosts",
            "systemctl --no-pager status nginx",
            "systemctl show --no-pager --property=ActiveState nginx",
            "journalctl --no-pager --unit nginx --lines 100 --since '1 hour ago'",
            "docker ps -a",
            "docker images nginx",
            "docker logs --tail 100 nginx",
            "docker exec nginx cat /etc/os-release",
            "sudo -n -- /usr/bin/systemctl --no-pager is-active nginx",
        ):
            self.assert_read_only(command)

    def test_all_pipeline_and_and_stages_must_be_supported(self) -> None:
        self.assert_read_only("ps aux | grep -F nginx | head -n 5")
        self.assert_read_only("systemctl --no-pager status nginx && journalctl --no-pager -n 20")
        for command in (
            "whoami | touch /tmp/pwned",
            "whoami && rm /tmp/file",
            "whoami || id",
            "whoami ||| id",
            "whoami &&& id",
            "| whoami",
            "whoami |",
        ):
            self.assert_requires_approval(command)

    def test_only_operators_outside_quotes_are_shell_syntax(self) -> None:
        self.assert_read_only("grep -F 'a|b&&c' /var/log/app.log")
        self.assert_read_only('grep -F "a|b&&c" /var/log/app.log')
        # 单引号保留 $ 和反引号为普通参数；双引号内的 shell 展开必须确认。
        self.assert_read_only("grep -F '$HOME `id`' /var/log/app.log")
        self.assert_requires_approval('grep -F "$HOME" /var/log/app.log')
        self.assert_requires_approval("grep -F `id` /var/log/app.log")
        self.assert_requires_approval("grep -F $(id) /var/log/app.log")
        self.assert_requires_approval("grep -F ${HOME} /var/log/app.log")
        self.assert_requires_approval("grep -F 'unterminated /var/log/app.log")

    def test_quoted_operators_do_not_hide_a_second_output_argument(self) -> None:
        for command in ("uniq '|' output", "uniq '&&' output", "uniq '*' output"):
            self.assert_requires_approval(command)
        self.assert_read_only("uniq '|' ")
        self.assert_read_only("grep -F 'foo;bar' /var/log/app.log")

    def test_globs_and_braces_cannot_expand_uniq_input_into_output(self) -> None:
        for command in ("uniq *", "uniq /tmp/{input,output}", "uniq /tmp/[io]*", "uniq ~/input"):
            self.assert_requires_approval(command)
        self.assert_read_only("uniq '/tmp/*'")
        self.assert_read_only('uniq "/tmp/*"')

    def test_shell_expansion_and_redirection_are_not_exempt(self) -> None:
        for command in (
            "cat *.log",
            "cat /var/log/{syslog,auth.log}",
            "cat ~/private.txt",
            "grep x /tmp/[ab]",
            "grep x /tmp/?.log",
            "cat file > copy",
            "cat file >> copy",
            "cat < file",
            "whoami; id",
            "whoami & id",
            "whoami |& id",
            "ls # comment",
            "ls ^file",
            "cat file\\ name",
            "cat file\nrm file",
        ):
            self.assert_requires_approval(command)

    def test_command_specific_mutation_and_dangerous_options_are_rejected(self) -> None:
        for command in (
            "rm -f /tmp/file",
            "touch /tmp/file",
            "cp source target",
            "curl https://example.invalid",
            "sh -c 'id'",
            "grep -f /tmp/patterns /var/log/app.log --color=always --devices=readwrite",
            "rg --no-config --pre 'sh -c id' ERROR /var/log",
            "rg -r 'new' old /var/log/app.log",
            "rg --no-config --search-zip ERROR /var/log",
            "sort /etc/passwd",
            "sort -o /tmp/sorted /etc/passwd",
            "sort --compress-program=sh /etc/passwd",
            "uniq input output",
            "sed -i 's/a/b/' /tmp/file",
            "sed -n '1,20p;w /tmp/out' /tmp/input",
            "systemctl restart nginx",
            "systemctl --no-pager start nginx",
            "systemctl status nginx",
            "systemctl --property --no-pager show nginx",
            "journalctl -f",
            "journalctl -D /tmp/other-journal",
            "journalctl -n 10",
            "docker rm nginx",
            "docker exec --privileged nginx cat /etc/passwd",
            "docker exec nginx sh -c 'touch /tmp/pwned'",
            "docker exec nginx cat /etc/passwd > /tmp/copy",
            "sudo rm /tmp/file",
            "sudo -u root id",
        ):
            self.assert_requires_approval(command)

    def test_pager_and_ripgrep_config_cannot_be_injected_as_option_values(self) -> None:
        self.assert_requires_approval("systemctl --lines --no-pager status nginx")
        self.assert_requires_approval("journalctl --unit --no-pager")
        self.assert_requires_approval("rg -g --no-config ERROR /var/log")
        self.assert_requires_approval("rg -n ERROR /var/log")
        self.assert_read_only("rg --no-config --glob '*.log' -n ERROR /var/log")

    def test_ripgrep_replace_and_text_options_only_transform_stdout(self) -> None:
        self.assert_read_only("rg --no-config -a -r REDACTED secret /var/log/app.log")
        self.assert_read_only("rg --no-config --replace=REDACTED secret /var/log/app.log")
        self.assert_requires_approval("rg --no-config --pre=script ERROR /var/log/app.log")

    def test_non_streaming_and_check_flags_must_be_real_flags(self) -> None:
        self.assert_read_only("docker stats --no-stream nginx")
        self.assert_requires_approval("docker stats nginx")
        self.assert_requires_approval("docker stats --format --no-stream nginx")
        self.assert_requires_approval("sort --key --check /etc/passwd")
        self.assert_requires_approval("sort --check -o /tmp/result /etc/passwd")
        self.assert_requires_approval("tail -f /var/log/app.log")

    def test_docker_exec_requires_a_bare_container_and_supported_query(self) -> None:
        self.assert_read_only("docker exec app-1 /bin/cat /etc/os-release")
        for command in (
            "docker exec --user root app-1 cat /etc/os-release",
            "docker exec app-1 -- cat /etc/os-release",
            "docker exec '-app' cat /etc/os-release",
            "docker exec app-1 env cat /etc/os-release",
            "docker exec app-1 cat /etc/os-release | rm -f /tmp/file",
        ):
            self.assert_requires_approval(command)

    def test_limits_and_control_characters_fail_closed(self) -> None:
        self.assert_read_only(" | ".join(["cat"] * 16))
        self.assert_requires_approval(" | ".join(["cat"] * 17))
        for control in ("\x00", "\x1b", "\x7f", "\u202e", "\u2028", "\u2029", "\ud800"):
            self.assert_requires_approval("cat 'file" + control + "name'")
        self.assert_requires_approval("docker exec a docker exec b docker exec c docker exec d whoami")

    def test_paths_and_unknown_options_fail_closed(self) -> None:
        for command in (
            "/tmp/cat /etc/passwd",
            "./systemctl --no-pager status nginx",
            "env FOO=bar id",
            "ls --unknown-option",
            "head -n",
            "date --set='tomorrow'",
            "journalctl --pager-end",
            "docker exec nginx python -c 'print(1)'",
        ):
            self.assert_requires_approval(command)

    def test_non_string_empty_and_oversized_inputs_fail_closed(self) -> None:
        for value in (None, 1, "", " \t", "x" * 12_001):
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(classify_command(value).read_only)


if __name__ == "__main__":
    unittest.main()
