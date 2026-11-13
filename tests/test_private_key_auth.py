"""加密私钥回归：真实解析临时测试密钥；SSH、凭据与窗口均为替身。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import tempfile
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import paramiko
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "scb_private_key_auth_gui", PLUGIN_ROOT / "scripts" / "ssh_manager_gui.py"
)
assert SPEC and SPEC.loader
gui = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gui)
bridge = gui.bridge
HOST_KEY = b"offline-private-key-auth-host-key"
HOST_PIN = "SHA256:" + base64.b64encode(hashlib.sha256(HOST_KEY).digest()).decode("ascii").rstrip("=")
ROUTES = ("manager", "connect", "command")


class OfflineSSHClient:
    """只保留 pin 校验和调用记录，不能建立网络连接。"""

    def __init__(self) -> None:
        self.options: dict[str, object] | None = None
        self.policy = None
        self.commands: list[str] = []
        self.closed = False

    def set_missing_host_key_policy(self, policy: object) -> None:
        self.policy = policy

    def connect(self, **kwargs: object) -> None:
        self.policy.missing_host_key(self, "192.0.2.10", self.host_key())
        self.options = kwargs

    @staticmethod
    def host_key() -> object:
        return types.SimpleNamespace(asbytes=lambda: HOST_KEY)

    def get_transport(self) -> object:
        return types.SimpleNamespace(get_remote_server_key=self.host_key)

    def exec_command(self, command: str, **_kwargs: object) -> tuple[None, object, object]:
        self.commands.append(command)
        channel = types.SimpleNamespace(
            recv_ready=lambda: False,
            recv_stderr_ready=lambda: False,
            exit_status_ready=lambda: True,
            recv_exit_status=lambda: 0,
        )
        stream = types.SimpleNamespace(channel=channel)
        return None, stream, stream

    def close(self) -> None:
        self.closed = True


class PrivateKeyAuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        root = PLUGIN_ROOT / "test"
        root.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="private-key-auth-", dir=root)
        self.addCleanup(self.directory.cleanup)
        self.key_path = Path(self.directory.name) / "id_ed25519"
        self.private_key = Ed25519PrivateKey.generate()

    def write_key(self, secret: str | None) -> dict[str, object]:
        encryption = (
            serialization.BestAvailableEncryption(secret.encode("utf-8"))
            if secret else serialization.NoEncryption()
        )
        self.key_path.write_bytes(self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, encryption
        ))
        host = {
            "host": "192.0.2.10", "port": 2222, "username": "fixture-user",
            "host_key_sha256": HOST_PIN, "private_key_file": str(self.key_path),
        }
        if secret is not None:
            host["credential_target"] = "SecureCredentialBridge/ssh/private-key-fixture"
        return host

    def invoke(self, route: str, host: dict, secret: str | None):
        if route == "manager":
            return gui.test_ssh_authentication(host, credential_override=secret)
        cfg = {"ssh_hosts": {"private-key-fixture": host}}
        if route == "connect":
            return bridge.ssh_connect({"alias": "private-key-fixture"}, cfg)
        return bridge.ssh_run_command(
            {"alias": "private-key-fixture", "command": "whoami"}, cfg
        )

    def offline_stack(self, fake: OfflineSSHClient, secret: str | None) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(patch.object(paramiko, "SSHClient", return_value=fake))
        stack.enter_context(patch.object(
            gui.socket, "create_connection", side_effect=AssertionError("offline test must not connect")
        ))
        stack.enter_context(patch.object(bridge, "read_credential", return_value=secret))
        stack.enter_context(patch.object(bridge, "launch_ssh_manager", return_value=False))
        stack.enter_context(patch.object(
            bridge, "request_confirmation", side_effect=AssertionError("read-only must not prompt")
        ))
        return stack

    def assert_successful_key_auth(self, secret: str | None) -> None:
        host = self.write_key(secret)
        expected = self.private_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ).split()[1]
        for route in ROUTES:
            with self.subTest(route=route):
                fake = OfflineSSHClient()
                with self.offline_stack(fake, secret), patch.object(
                    paramiko.PKey, "from_path", wraps=paramiko.PKey.from_path
                ) as load_key:
                    result = self.invoke(route, host, secret)
                load_key.assert_called_once_with(
                    str(self.key_path), passphrase=secret.encode("utf-8") if secret else None
                )
                self.assertIsInstance(fake.options["pkey"], paramiko.Ed25519Key)
                self.assertEqual(fake.options["pkey"].get_base64(), expected.decode("ascii"))
                self.assertNotIn("password", fake.options)
                self.assertFalse(fake.options["allow_agent"])
                self.assertFalse(fake.options["look_for_keys"])
                self.assertEqual(fake.commands, ["whoami"] if route == "command" else [])
                self.assertTrue(fake.closed)
                if route == "connect":
                    self.assertTrue(result["structuredContent"]["connected"])
                    self.assertFalse(result["structuredContent"]["remote_command_executed"])
                elif route == "command":
                    self.assertTrue(result["structuredContent"]["read_only"])

    def test_ascii_passphrase_loads_real_encrypted_ed25519_for_every_entrypoint(self) -> None:
        self.assert_successful_key_auth("offline-only-ascii-passphrase")

    def test_unicode_passphrase_loads_real_encrypted_ed25519_for_every_entrypoint(self) -> None:
        self.assert_successful_key_auth("离线测试口令-UTF8")

    def test_unencrypted_ed25519_needs_no_credential_or_password_fallback(self) -> None:
        self.assert_successful_key_auth(None)

    def test_empty_passphrase_is_none_for_an_unencrypted_private_key(self) -> None:
        self.assert_successful_key_auth("")

    def assert_rejected_without_sensitive_detail(self, host: dict, secret: str) -> None:
        for route in ROUTES:
            with self.subTest(route=route):
                fake = OfflineSSHClient()
                with self.offline_stack(fake, secret), self.assertRaises(bridge.BridgeError) as raised:
                    self.invoke(route, host, secret)
                message = str(raised.exception)
                for sensitive in (secret, str(self.key_path), host["host"], host["username"]):
                    self.assertNotIn(sensitive, message)
                self.assertIsNone(fake.options)
                self.assertEqual(fake.commands, [])
                self.assertTrue(fake.closed)

    def test_wrong_passphrase_fails_before_connect_without_leaking_or_password_fallback(self) -> None:
        host = self.write_key("offline-only-correct-passphrase")
        self.assert_rejected_without_sensitive_detail(host, "offline-only-wrong-passphrase")

    def test_unsupported_private_key_format_fails_without_sensitive_details(self) -> None:
        host = self.write_key("offline-only-fixture-passphrase")
        self.key_path.write_bytes(b"offline-only unsupported private key fixture")
        self.assert_rejected_without_sensitive_detail(host, "offline-only-fixture-passphrase")

    def test_loader_type_error_and_unsupported_algorithm_are_redacted(self) -> None:
        secret = "offline-only-fixture-passphrase"
        host = self.write_key(secret)
        for error_type in (TypeError, UnsupportedAlgorithm):
            with self.subTest(error=error_type.__name__), patch.object(
                paramiko.PKey, "from_path", side_effect=error_type(f"{self.key_path}: {secret}")
            ):
                self.assert_rejected_without_sensitive_detail(host, secret)


if __name__ == "__main__":
    unittest.main()
