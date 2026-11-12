"""Small local Tkinter UI for the Secure Credential Bridge SSH allowlist."""

from __future__ import annotations

import base64
import argparse
import hashlib
import json
import os
import queue
import re
import socket
import sys
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "mcp"))
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
import server as bridge  # noqa: E402
from manage_credential import delete as delete_credential  # noqa: E402
from manage_credential import store_secret  # noqa: E402


ENVIRONMENT_LABELS = {"unspecified": "未指定", "test": "测试环境", "production": "生产环境"}
APPROVAL_POLICY_LABELS = {"confirm_writes": "写操作确认", "test_all_commands": "全部操作预授权"}
APPROVAL_POLICY_COLORS = {"confirm_writes": "#2457a7", "test_all_commands": "#b85c00"}


def default_config_path() -> Path:
    """Prefer the newest installed plugin copy so Codex reads edits on restart."""
    override = os.environ.get("SCB_CONFIG")
    if override:
        return Path(override).expanduser()

    profile = os.environ.get("USERPROFILE")
    cache_root = Path(profile) / ".codex" / "plugins" / "cache" / "personal" / "secure-credential-bridge" if profile else None
    if cache_root and cache_root.is_dir():
        installed = [p for p in cache_root.iterdir() if (p / "mcp" / "server.py").is_file()]
        if installed:
            latest = max(installed, key=lambda p: p.stat().st_mtime)
            return latest / "config" / "bridge.json"
    return PLUGIN_ROOT / "config" / "bridge.json"


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"配置文件无法读取或不是有效 JSON：{exc}") from None
    if not isinstance(value, dict):
        raise ValueError("配置文件顶层必须是 JSON 对象。")
    return value


def write_config(path: Path, value: dict[str, Any]) -> None:
    """Validate and atomically persist config without disturbing other adapters."""
    bridge.validate_config(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, suffix=".tmp", delete=False) as stream:
            temp_name = stream.name
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def credential_ref(alias: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@/-]{0,127}", alias):
        raise ValueError("主机别名只能包含字母、数字、点、下划线、短横线、斜杠或 @。")
    return f"SecureCredentialBridge/ssh/{alias}"


def read_ssh_fingerprint(host: str, port: int, timeout: float = 20.0) -> tuple[str, str]:
    """Read a server's public host key without attempting user authentication."""
    try:
        import paramiko
    except ImportError:
        raise RuntimeError("缺少 Paramiko。请先运行：py -3 -m pip install -r \"%s\"" % (PLUGIN_ROOT / "scripts" / "requirements.txt")) from None

    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.banner_timeout = timeout
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
        return f"SHA256:{digest}", key.get_name()
    finally:
        transport.close()


def test_ssh_authentication(
    host: dict[str, Any], timeout: float = 15.0, credential_override: str | None = None
) -> None:
    """Verify the configured host pin and authentication without running a command."""
    bridge.validate_config({"ssh_hosts": {"test": host}})
    try:
        import paramiko
    except ImportError:
        raise bridge.BridgeError("缺少 Paramiko，请先安装插件 SSH 依赖。") from None

    client = paramiko.SSHClient()
    secret: str | None = None

    class PinnedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client: Any, _hostname: str, key: Any) -> None:
            digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
            if f"SHA256:{digest}" != host["host_key_sha256"]:
                raise bridge.BridgeError("服务器指纹与配置不符，未发送凭据。")

    try:
        if credential_override is not None:
            secret = credential_override
        elif host.get("credential_target"):
            secret = bridge.read_credential(host["credential_target"])
        elif not host.get("private_key_file"):
            raise bridge.BridgeError("没有可用的 SSH 凭据，请先保存密码或私钥口令。")

        client.set_missing_host_key_policy(PinnedHostKey())
        options: dict[str, Any] = {
            "hostname": host["host"],
            "port": host.get("port", 22),
            "username": host["username"],
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if host.get("private_key_file"):
            try:
                options["pkey"] = paramiko.PKey.from_path(host["private_key_file"], passphrase=secret)
            except (OSError, paramiko.SSHException):
                raise bridge.BridgeError("私钥无法读取或口令不正确。") from None
        else:
            options["password"] = secret

        # Do not load ambient known_hosts: the configured pin must be checked
        # by PinnedHostKey before Paramiko sends any authentication material.
        client.connect(**options)
        transport = client.get_transport()
        server_key = transport.get_remote_server_key() if transport else None
        if server_key is None:
            raise bridge.BridgeError("SSH 服务器未提供主机指纹，测试失败。")
        digest = base64.b64encode(hashlib.sha256(server_key.asbytes()).digest()).decode("ascii").rstrip("=")
        if f"SHA256:{digest}" != host["host_key_sha256"]:
            raise bridge.BridgeError("服务器指纹与配置不符，未执行远端命令。")
    except bridge.BridgeError:
        raise
    except paramiko.AuthenticationException:
        raise bridge.BridgeError("SSH 认证失败；请核对用户名和已保存的密码。多次失败可能触发服务器锁定。") from None
    except (TimeoutError, socket.timeout):
        raise bridge.BridgeError("SSH 测试超时；请检查 VPN、主机地址和端口。") from None
    except Exception:
        raise bridge.BridgeError("SSH 测试失败；主机、凭据及底层错误详情已隐藏。") from None
    finally:
        secret = None
        try:
            client.close()
        except Exception:
            pass


class HostDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, initial: dict[str, Any] | None = None):
        super().__init__(parent)
        self.title("SSH 主机")
        self.resizable(False, False)
        self.result: dict[str, Any] | None = None
        item = initial or {}
        self.alias = tk.StringVar(value=item.get("_alias", ""))
        self.host = tk.StringVar(value=item.get("host", ""))
        self.port = tk.StringVar(value=str(item.get("port", 22)))
        self.username = tk.StringVar(value=item.get("username", ""))
        self.fingerprint = tk.StringVar(value=item.get("host_key_sha256", ""))
        self.private_key = tk.StringVar(value=item.get("private_key_file", ""))
        self.fingerprint_status = tk.StringVar(value="")
        self._fingerprint_results: queue.Queue[tuple[bool, str, str]] = queue.Queue(maxsize=1)
        self.auth = tk.StringVar(value="私钥" if item.get("private_key_file") else "密码")
        self.encrypted_key = tk.BooleanVar(value=bool(item.get("private_key_file") and item.get("credential_target")))
        self.old_target = item.get("credential_target")
        try:
            policy = bridge.ssh_host_policy(item)
            policy_status = "全部操作预授权仅限测试环境；包含写入、删除等命令，不逐条弹出确认。"
        except bridge.BridgeError:
            # 错误配置不继承预授权，用户可以在本表单修正后重新保存。
            policy = bridge.ssh_host_policy({})
            policy_status = "原环境或审批策略无效，已恢复写操作确认；请核对后保存。"
        self.environment = tk.StringVar(value=ENVIRONMENT_LABELS[policy["environment"]])
        self.approval_policy = tk.StringVar(value=APPROVAL_POLICY_LABELS[policy["approval_policy"]])
        self.policy_status = tk.StringVar(value=policy_status)
        self._policy_identity = self._identity_values()

        frame = ttk.Frame(self, padding=14)
        frame.grid(sticky="nsew")
        row = 0
        self._field(frame, row, "主机别名", self.alias); row += 1
        self._field(frame, row, "主机名 / IP", self.host); row += 1
        self._field(frame, row, "SSH 端口", self.port); row += 1
        self._field(frame, row, "登录用户名", self.username); row += 1
        ttk.Label(frame, text="SHA256 主机指纹").grid(row=row, column=0, sticky="w", pady=4)
        fingerprint_row = ttk.Frame(frame)
        fingerprint_row.grid(row=row, column=1, sticky="ew", pady=4)
        ttk.Entry(fingerprint_row, textvariable=self.fingerprint, width=37).pack(side="left", fill="x", expand=True)
        self.fingerprint_button = ttk.Button(fingerprint_row, text="读取", command=self._fetch_fingerprint)
        self.fingerprint_button.pack(side="left", padx=(6, 0))
        row += 1
        ttk.Label(frame, textvariable=self.fingerprint_status, foreground="#315d88").grid(row=row, column=1, sticky="w")
        row += 1
        ttk.Label(frame, text="认证方式").grid(row=row, column=0, sticky="w", pady=4)
        auth_box = ttk.Combobox(frame, textvariable=self.auth, values=("密码", "私钥"), state="readonly", width=45)
        auth_box.grid(row=row, column=1, sticky="ew", pady=4)
        auth_box.bind("<<ComboboxSelected>>", lambda _e: self._toggle_auth())
        row += 1
        ttk.Label(frame, text="私钥文件").grid(row=row, column=0, sticky="w", pady=4)
        key_row = ttk.Frame(frame)
        key_row.grid(row=row, column=1, sticky="ew", pady=4)
        self.key_entry = ttk.Entry(key_row, textvariable=self.private_key, width=39)
        self.key_entry.pack(side="left", fill="x", expand=True)
        self.browse_button = ttk.Button(key_row, text="浏览…", command=self._browse_key)
        self.browse_button.pack(side="left", padx=(6, 0))
        row += 1
        self.encrypted_check = ttk.Checkbutton(frame, text="私钥有口令（需要保存口令）", variable=self.encrypted_key)
        self.encrypted_check.grid(row=row, column=1, sticky="w", pady=4)
        row += 1
        ttk.Label(frame, text="主机环境").grid(row=row, column=0, sticky="w", pady=4)
        self.environment_box = ttk.Combobox(frame, textvariable=self.environment,
            values=tuple(ENVIRONMENT_LABELS.values()), state="readonly", width=45)
        self.environment_box.grid(row=row, column=1, sticky="ew", pady=4)
        row += 1
        ttk.Label(frame, text="命令审批策略").grid(row=row, column=0, sticky="w", pady=4)
        self.policy_box = ttk.Combobox(frame, textvariable=self.approval_policy,
            values=tuple(APPROVAL_POLICY_LABELS.values()), state="readonly", width=45)
        self.policy_box.grid(row=row, column=1, sticky="ew", pady=4)
        row += 1
        ttk.Label(frame, textvariable=self.policy_status, foreground="#8a4f00", wraplength=430).grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(4, 8))
        row += 1
        # 写入变量的所有途径（包含读取指纹）均撤销旧身份的预授权。
        for identity_var in (self.alias, self.host, self.port, self.username, self.fingerprint):
            identity_var.trace_add("write", self._identity_changed)
        self.environment.trace_add("write", self._environment_changed)
        self._environment_changed()
        ttk.Label(frame, text="确认安全指纹后再保存；密码/口令单独存入 Windows 凭据管理器。", wraplength=430).grid(row=row, column=0, columnspan=2, sticky="w", pady=(8, 12))
        buttons = ttk.Frame(frame)
        buttons.grid(row=row + 1, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="取消", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="确定", command=self._accept).pack(side="right")
        self._toggle_auth()
        self.transient(parent)
        self.grab_set()
        self.wait_visibility()
        self.focus_set()
        self.wait_window(self)

    @staticmethod
    def _field(parent: ttk.Frame, row: int, label: str, value: tk.StringVar, width: int = 46) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=value, width=width).grid(row=row, column=1, sticky="ew", pady=4)

    def _toggle_auth(self) -> None:
        key_mode = self.auth.get() == "私钥"
        state = "normal" if key_mode else "disabled"
        self.key_entry.configure(state=state)
        self.browse_button.configure(state=state)
        self.encrypted_check.configure(state=state)

    def _identity_values(self) -> tuple[str, ...]:
        return tuple(value.get().strip() for value in (self.alias, self.host, self.port, self.username, self.fingerprint))

    def _identity_changed(self, *_args: Any) -> None:
        identity = self._identity_values()
        if identity != self._policy_identity:
            self._policy_identity = identity
            self.approval_policy.set(APPROVAL_POLICY_LABELS["confirm_writes"])
            self.policy_status.set("连接身份已变更，审批策略已重置为写操作确认；核对当前测试主机后可重新选择全部操作预授权。")

    def _environment_changed(self, *_args: Any) -> None:
        is_test = self.environment.get() == ENVIRONMENT_LABELS["test"]
        if not is_test:
            self.approval_policy.set(APPROVAL_POLICY_LABELS["confirm_writes"])
        self.policy_box.configure(values=tuple(APPROVAL_POLICY_LABELS.values()) if is_test
            else (APPROVAL_POLICY_LABELS["confirm_writes"],))

    def _browse_key(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="选择 SSH 私钥文件")
        if path:
            self.private_key.set(path)

    def _fetch_fingerprint(self) -> None:
        host = self.host.get().strip()
        try:
            port = int(self.port.get())
            if not bridge.valid_host(host) or not 1 <= port <= 65535:
                raise ValueError("请先填写有效的主机名或 IP 地址及端口。")
        except (ValueError, TypeError) as exc:
            messagebox.showerror("读取指纹失败", str(exc), parent=self)
            return

        self.fingerprint_button.configure(state="disabled")
        self.fingerprint_status.set("正在读取服务器公钥…窗口仍可操作。")
        self.configure(cursor="watch")
        threading.Thread(target=self._read_fingerprint_worker, args=(host, port), daemon=True).start()
        self.after(100, self._poll_fingerprint_result)

    def _read_fingerprint_worker(self, host: str, port: int) -> None:
        try:
            fingerprint, key_type = read_ssh_fingerprint(host, port)
            self._fingerprint_results.put((True, fingerprint, key_type))
        except Exception as exc:
            detail = "连接超时，请确认 VPN、主机地址和 SSH 端口后重试。" if isinstance(exc, TimeoutError) else str(exc)
            self._fingerprint_results.put((False, detail, ""))

    def _poll_fingerprint_result(self) -> None:
        try:
            success, value, key_type = self._fingerprint_results.get_nowait()
        except queue.Empty:
            if self.winfo_exists():
                self.after(100, self._poll_fingerprint_result)
            return

        if not self.winfo_exists():
            return
        self.fingerprint_button.configure(state="normal")
        self.configure(cursor="")
        if not success:
            self.fingerprint_status.set("读取失败，可检查网络后重试。")
            messagebox.showerror("读取指纹失败", value, parent=self)
            return

        self.fingerprint.set(value)
        self.fingerprint_status.set(f"已读取 {key_type} 指纹；请与可信来源核对。")
        messagebox.showinfo(
            "已读取服务器指纹",
            f"{key_type} {value}\n\n指纹已填入表单。首次读取的值仍应与管理员或可信管理平台提供的值核对。",
            parent=self,
        )

    def _accept(self) -> None:
        try:
            alias = self.alias.get().strip()
            ref = credential_ref(alias)
            port = int(self.port.get())
            if not 1 <= port <= 65535:
                raise ValueError("端口必须在 1 到 65535 之间。")
            host = self.host.get().strip()
            username = self.username.get().strip()
            fingerprint = self.fingerprint.get().strip()
            if not host or not username:
                raise ValueError("主机名和用户名不能为空。")
            if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{20,44}", fingerprint):
                raise ValueError("请填写从可信渠道核实的 SHA256 主机指纹。")
            entry: dict[str, Any] = {"host": host, "port": port, "username": username, "host_key_sha256": fingerprint}
            environments = {label: value for value, label in ENVIRONMENT_LABELS.items()}
            policies = {label: value for value, label in APPROVAL_POLICY_LABELS.items()}
            if self.environment.get() not in environments or self.approval_policy.get() not in policies:
                raise ValueError("请选择有效的主机环境和命令审批策略。")
            entry.update(bridge.ssh_host_policy({
                "environment": environments[self.environment.get()],
                "approval_policy": policies[self.approval_policy.get()],
            }))
            wants_credential = self.auth.get() == "密码" or self.encrypted_key.get()
            if self.auth.get() == "私钥":
                private_key = self.private_key.get().strip()
                if not private_key or not Path(private_key).is_file():
                    raise ValueError("请选择存在的私钥文件。")
                entry["private_key_file"] = private_key
            if wants_credential:
                entry["credential_target"] = self.old_target or ref
            bridge.validate_config({"ssh_hosts": {alias: entry}})
            self.result = {"alias": alias, "entry": entry, "credential_ref": entry.get("credential_target") or ref, "wants_credential": wants_credential}
            self.destroy()
        except (ValueError, OSError, bridge.BridgeError) as exc:
            messagebox.showerror("主机信息有误", str(exc), parent=self)


class CredentialDialog(simpledialog.Dialog):
    def __init__(self, parent: tk.Misc, title: str, *, require_secret: bool = True):
        self.secret = ""
        self.require_secret = require_secret
        super().__init__(parent, title)

    def body(self, master: tk.Misc) -> tk.Widget:
        ttk.Label(master, text="输入密码或私钥口令（内容不会写入配置文件）：").grid(row=0, column=0, sticky="w", pady=(2, 8))
        self.first = ttk.Entry(master, show="•", width=42)
        self.first.grid(row=1, column=0, sticky="ew", pady=4)
        ttk.Label(master, text="再次确认：").grid(row=2, column=0, sticky="w", pady=(8, 2))
        self.second = ttk.Entry(master, show="•", width=42)
        self.second.grid(row=3, column=0, sticky="ew", pady=4)
        self.show_secret = tk.BooleanVar(value=False)
        ttk.Checkbutton(master, text="显示口令", variable=self.show_secret, command=self._toggle_visibility).grid(
            row=4, column=0, sticky="w", pady=(4, 8)
        )
        return self.first

    def buttonbox(self) -> None:
        box = ttk.Frame(self)
        ttk.Button(box, text="取消", command=self.cancel).pack(side="right", padx=(8, 0))
        ttk.Button(box, text="测试连接并保存", command=self.ok, default="active").pack(side="right")
        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack()

    def _toggle_visibility(self) -> None:
        mask = "" if self.show_secret.get() else "•"
        self.first.configure(show=mask)
        self.second.configure(show=mask)

    def validate(self) -> bool:
        if self.require_secret and not self.first.get():
            messagebox.showerror("未保存", "凭据不能为空。", parent=self)
            return False
        if self.first.get() != self.second.get():
            messagebox.showerror("未保存", "两次输入不一致。", parent=self)
            return False
        self.secret = self.first.get()
        self.first.delete(0, "end")
        self.second.delete(0, "end")
        return True

    def apply(self) -> None:
        pass


class SSHDiscoveryDialog(tk.Toplevel):
    """Choose a literal host alias read from the local OpenSSH config."""

    def __init__(self, parent: tk.Misc, candidates: dict[str, dict[str, Any]]):
        super().__init__(parent)
        self.title("发现本机 SSH 配置")
        self.geometry("660x330")
        self.resizable(True, True)
        self.result: tuple[str, dict[str, Any]] | None = None
        ttk.Label(
            self,
            text="只读取本机 ~/.ssh/config 中的显式 Host 条目；不会扫描网络或读取密码。导入后仍需核验主机指纹并保存凭据。",
            wraplength=620,
        ).pack(anchor="w", padx=12, pady=(12, 8))
        frame = ttk.Frame(self, padding=(12, 0, 12, 8))
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=("host", "port", "user", "key"), show="headings", selectmode="browse")
        for column, heading, width in (("host", "SSH 别名", 150), ("port", "主机", 220), ("user", "用户名", 110), ("key", "认证提示", 120)):
            self.tree.heading(column, text=heading)
            self.tree.column(column, width=width, anchor="w")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.candidates = candidates
        for alias, entry in sorted(candidates.items(), key=lambda item: item[0].casefold()):
            auth_hint = "私钥路径" if entry.get("private_key_file") else "需手动选择"
            self.tree.insert("", "end", iid=alias, values=(alias, f"{entry['host']}:{entry['port']}", entry.get("username") or "（未配置）", auth_hint))
        buttons = ttk.Frame(self, padding=(12, 0, 12, 12))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="取消", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="导入所选", command=self._select).pack(side="right")
        self.tree.bind("<Double-1>", lambda _event: self._select())
        if candidates:
            first = next(iter(sorted(candidates, key=str.casefold)))
            self.tree.selection_set(first)
            self.tree.focus(first)
        self.transient(parent)
        self.grab_set()
        self.wait_visibility()
        self.focus_set()
        self.wait_window(self)

    def _select(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("请选择主机", "请先选择一条 SSH 配置。", parent=self)
            return
        alias = selected[0]
        self.result = (alias, dict(self.candidates[alias]))
        self.destroy()


class SSHManager(tk.Tk):
    def __init__(self, prefill_alias: str | None = None) -> None:
        super().__init__()
        self.title("Secure Credential Bridge · SSH 管理")
        self.geometry("900x590")
        self.minsize(760, 480)
        self.config_path = default_config_path()
        try:
            self.config_data = load_config(self.config_path)
        except ValueError as exc:
            messagebox.showerror("配置加载失败", str(exc), parent=self)
            self.config_data = {}
        self.config_data.setdefault("ssh_hosts", {})
        self.prefill_alias = prefill_alias
        self._test_results: queue.Queue[tuple[str, bool, str]] = queue.Queue(maxsize=1)
        self._testing_alias: str | None = None
        self._pending_secret: str | None = None
        self._pending_credential_target: str | None = None
        self._build()
        self._refresh()
        if prefill_alias and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@/-]{0,127}", prefill_alias):
            self.after(150, lambda: self._prefill_alias(prefill_alias))

    def _build(self) -> None:
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="按主机配置 SSH 凭据及审批策略：蓝色为写操作确认，橙色为测试环境全部操作预授权。", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        path_row = ttk.Frame(outer)
        path_row.pack(fill="x", pady=(5, 10))
        ttk.Label(path_row, text="配置文件：").pack(side="left")
        self.path_label = ttk.Label(path_row, text=str(self.config_path), foreground="#315d88")
        self.path_label.pack(side="left", fill="x", expand=True)
        self._choose_config_button = ttk.Button(path_row, text="选择…", command=self._choose_config)
        self._choose_config_button.pack(side="right")

        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        self.host_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.host_tab, text="SSH 主机")
        self.host_tree = self._tree(self.host_tab, ("alias", "host", "user", "auth", "environment", "policy"),
            ("别名", "主机", "用户名", "认证", "环境", "审批策略"), (120, 220, 110, 80, 100, 170))
        for policy, color in APPROVAL_POLICY_COLORS.items():
            self.host_tree.tag_configure(policy, foreground=color)
        self.host_tree.tag_configure("invalid_policy", foreground="#a32424")
        self._host_action_buttons = self._buttons(
            self.host_tab,
            [("发现本机 SSH 配置", self._discover_hosts), ("添加", self._add_host), ("编辑", self._edit_host),
             ("删除", self._remove_host), ("测试连接并保存密码/口令…", self._save_secret), ("移除凭据…", self._remove_secret)],
        )
        self._test_status = tk.StringVar(value="测试只验证主机指纹和登录认证，不运行远端命令；验证通过后自动保存凭据。")
        ttk.Label(self.host_tab, textvariable=self._test_status, foreground="#315d88").pack(anchor="w", pady=(6, 0))
        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(10, 0))
        ttk.Label(bottom, text="新增及导入默认写操作确认；全部预授权仅限明确标记的测试主机。", foreground="#8a4f00").pack(side="left")
        self._save_config_button = ttk.Button(bottom, text="保存配置", command=self._save)
        self._save_config_button.pack(side="right")

    def _prefill_alias(self, alias: str) -> None:
        self.tabs.select(self.host_tab)
        if alias in self.config_data["ssh_hosts"]:
            self.host_tree.selection_set(alias)
            self.host_tree.focus(alias)
            self.host_tree.see(alias)
            self._edit_host()
            return
        candidate = bridge.discover_ssh_hosts().get(alias)
        if candidate:
            self._apply_discovered_candidate(alias, candidate)
        else:
            self._add_host()

    def _discover_hosts(self) -> None:
        candidates = bridge.discover_ssh_hosts()
        if not candidates:
            messagebox.showinfo("没有发现主机", "本机 ~/.ssh/config 中没有可导入的显式 Host 别名。没有执行网络扫描。", parent=self)
            return
        dialog = SSHDiscoveryDialog(self, candidates)
        if dialog.result:
            alias, candidate = dialog.result
            self._apply_discovered_candidate(alias, candidate)

    def _apply_discovered_candidate(self, alias: str, candidate: dict[str, Any]) -> None:
        initial = {**candidate, "_alias": alias}
        existing = alias in self.config_data["ssh_hosts"]
        if existing:
            initial.update(self.config_data["ssh_hosts"][alias])
            initial["_alias"] = alias
        # 导入不继承候选数据或同名旧记录的预授权；编辑原主机才保留有效策略。
        initial.update(environment="unspecified", approval_policy="confirm_writes")
        dialog = HostDialog(self, initial)
        if not dialog.result:
            return
        new_alias, entry = dialog.result["alias"], dialog.result["entry"]
        if new_alias != alias and new_alias in self.config_data["ssh_hosts"]:
            messagebox.showerror("别名重复", "该主机别名已存在。", parent=self)
            return
        if existing:
            self.config_data["ssh_hosts"].pop(alias, None)
        self.config_data["ssh_hosts"][new_alias] = entry
        self._refresh()
        self.host_tree.selection_set(new_alias)
        self.host_tree.focus(new_alias)
        self._test_status.set(f"{new_alias} 已载入；核验指纹后请保存配置，并单独保存密码/口令。")

    @staticmethod
    def _tree(parent: ttk.Frame, columns: tuple[str, ...], headings: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=80, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return tree

    @staticmethod
    def _buttons(parent: ttk.Frame, buttons: list[tuple[str, Any]]) -> dict[str, ttk.Button]:
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=(8, 0))
        created: dict[str, ttk.Button] = {}
        for label, callback in buttons:
            button = ttk.Button(frame, text=label, command=callback)
            button.pack(side="left", padx=(0, 6))
            created[label] = button
        return created

    def _refresh(self) -> None:
        for item in self.host_tree.get_children():
            self.host_tree.delete(item)
        for alias, host in sorted(self.config_data.get("ssh_hosts", {}).items()):
            auth = "私钥" if host.get("private_key_file") else "密码"
            try:
                policy = bridge.ssh_host_policy(host)
                environment_label = ENVIRONMENT_LABELS[policy["environment"]]
                policy_label = APPROVAL_POLICY_LABELS[policy["approval_policy"]]
                tag = policy["approval_policy"]
            except bridge.BridgeError:
                environment_label, policy_label, tag = "配置无效", "配置无效（不可执行）", "invalid_policy"
            self.host_tree.insert("", "end", iid=alias, values=(alias, f"{host.get('host')}:{host.get('port', 22)}",
                host.get("username", ""), auth, environment_label, policy_label), tags=(tag,))

    def _choose_config(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, title="选择或创建 bridge.json", initialdir=str(self.config_path.parent), initialfile="bridge.json", defaultextension=".json", filetypes=(("JSON 配置", "*.json"),))
        if not path:
            return
        try:
            data = load_config(Path(path))
            data.setdefault("ssh_hosts", {})
            self.config_path, self.config_data = Path(path), data
            self.path_label.configure(text=str(self.config_path))
            self._refresh()
        except ValueError as exc:
            messagebox.showerror("配置加载失败", str(exc), parent=self)

    def _selected(self, tree: ttk.Treeview) -> str | None:
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("请选择", "请先在列表中选择一项。", parent=self)
            return None
        return selection[0]

    def _add_host(self) -> None:
        dialog = HostDialog(self)
        if not dialog.result:
            return
        alias, entry = dialog.result["alias"], dialog.result["entry"]
        if alias in self.config_data["ssh_hosts"]:
            messagebox.showerror("别名重复", "该主机别名已存在。", parent=self)
            return
        self.config_data["ssh_hosts"][alias] = entry
        self._refresh()

    def _edit_host(self) -> None:
        alias = self._selected(self.host_tree)
        if alias is None:
            return
        dialog = HostDialog(self, {**self.config_data["ssh_hosts"][alias], "_alias": alias})
        if not dialog.result:
            return
        new_alias, entry = dialog.result["alias"], dialog.result["entry"]
        if new_alias != alias and new_alias in self.config_data["ssh_hosts"]:
            messagebox.showerror("别名重复", "该主机别名已存在。", parent=self)
            return
        self.config_data["ssh_hosts"].pop(alias)
        self.config_data["ssh_hosts"][new_alias] = entry
        self._refresh()

    def _remove_host(self) -> None:
        alias = self._selected(self.host_tree)
        if alias is None:
            return
        if not messagebox.askyesno("删除主机", f"删除 {alias}？凭据不会自动删除。", parent=self):
            return
        self.config_data["ssh_hosts"].pop(alias, None)
        self._refresh()

    def _save_secret(self) -> None:
        if self._testing_alias is not None:
            return
        alias = self._selected(self.host_tree)
        if alias is None:
            return
        configured_host = self.config_data["ssh_hosts"][alias]
        host = dict(configured_host)
        target = host.get("credential_target")
        require_secret = not bool(host.get("private_key_file") and not target)
        dialog = CredentialDialog(self, "测试 SSH 并保存密码/私钥口令", require_secret=require_secret)
        secret = dialog.secret
        dialog.secret = ""
        if secret:
            target = target or credential_ref(alias)
            host["credential_target"] = target

        self._testing_alias = alias
        self._pending_secret = secret
        self._pending_credential_target = target
        self._set_testing_controls(False)
        self._test_status.set(f"正在测试 {alias}：只验证登录，成功后保存口令，不执行远端命令…")
        threading.Thread(target=self._test_connection_worker, args=(alias, host, secret), daemon=True).start()
        secret = None
        self.after(100, self._poll_test_result)

    def _test_connection_worker(self, alias: str, host: dict[str, Any], secret: str) -> None:
        try:
            test_ssh_authentication(host, credential_override=secret)
            result = (alias, True, "SSH 连接和认证成功；没有执行任何远端命令。")
        except bridge.BridgeError as exc:
            result = (alias, False, str(exc))
        except Exception:
            result = (alias, False, "SSH 测试失败；主机、凭据及底层错误详情已隐藏。")
        finally:
            secret = ""
        self._test_results.put(result)

    def _poll_test_result(self) -> None:
        try:
            alias, success, message = self._test_results.get_nowait()
        except queue.Empty:
            if self.winfo_exists():
                self.after(100, self._poll_test_result)
            return

        self._testing_alias = None
        if not self.winfo_exists():
            self._pending_secret = None
            self._pending_credential_target = None
            return
        self._set_testing_controls(True)
        secret = self._pending_secret
        target = self._pending_credential_target
        self._pending_secret = None
        self._pending_credential_target = None
        if success:
            host = self.config_data["ssh_hosts"].get(alias)
            if host is not None:
                original_host = dict(host)
                config_saved = False
                try:
                    if secret and target:
                        host["credential_target"] = target
                    write_config(self.config_path, self.config_data)
                    config_saved = True
                    if secret and target:
                        store_secret(target, secret)
                except Exception:
                    host.clear()
                    host.update(original_host)
                    if config_saved:
                        try:
                            write_config(self.config_path, self.config_data)
                        except Exception:
                            pass
                    message = "连接验证通过，但口令或主机配置未能自动保存；请检查本机凭据管理器和配置文件。"
                    success = False
            else:
                message = "连接验证通过，但主机已从列表移除，配置没有保存。"
                success = False
        if success:
            message = "SSH 连接和认证成功；主机配置及需要的口令已自动保存，没有执行任何远端命令。"
        self._test_status.set(f"{alias}：{message}")
        secret = None
        if success:
            messagebox.showinfo("SSH 测试成功", message, parent=self)
        else:
            title = "连接验证通过，但保存失败" if "验证通过" in message else "SSH 测试失败"
            messagebox.showerror(title, message, parent=self)

    def _set_testing_controls(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for button in self.__dict__.get("_host_action_buttons", {}).values():
            button.configure(state=state)
        for name in ("_choose_config_button", "_save_config_button"):
            button = self.__dict__.get(name)
            if button is not None:
                button.configure(state=state)

    def _remove_secret(self) -> None:
        alias = self._selected(self.host_tree)
        if alias is None:
            return
        target = self.config_data["ssh_hosts"][alias].get("credential_target")
        if not target:
            messagebox.showinfo("没有凭据引用", "此主机配置没有引用凭据条目。", parent=self)
            return
        if messagebox.askyesno("移除凭据", f"从当前 Windows 用户的凭据管理器移除 {target}？此操作不可由本工具撤销。", parent=self):
            try:
                delete_credential(target)
                messagebox.showinfo("已移除", "凭据条目已移除。", parent=self)
            except Exception as exc:
                messagebox.showerror("移除失败", str(exc), parent=self)

    def _save(self) -> None:
        try:
            write_config(self.config_path, self.config_data)
            messagebox.showinfo("已保存", f"配置已写入：\n{self.config_path}\n\n当前线程下一次工具调用会读取这份配置。若更改了插件代码或工具定义，请重新加载 MCP 插件。", parent=self)
        except (ValueError, OSError, bridge.BridgeError) as exc:
            messagebox.showerror("保存失败", str(exc), parent=self)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Credential Bridge SSH manager")
    parser.add_argument("--prefill-alias", help="Prefill or select one discovered/configured alias")
    options = parser.parse_args()
    SSHManager(prefill_alias=options.prefill_alias).mainloop()
