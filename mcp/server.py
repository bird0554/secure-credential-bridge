"""Local stdio MCP bridge for tightly scoped infrastructure actions."""

from __future__ import annotations

import base64
import ctypes
import fnmatch
import hashlib
import json
import os
import queue
import re
import smtplib
import ssl
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from pathlib import Path
from typing import Any


# 支持脚本启动，以及管理器/测试通过文件路径加载本模块。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from approval_intent import validate_intent
from command_policy import classify_command


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(os.environ.get("SCB_CONFIG", ROOT / "config" / "bridge.json"))
MAX_WORKERS = 8
MAX_DRAFTS = 100
DRAFT_TTL_SECONDS = 600
MAX_TOOL_TEXT_BYTES = 32_000
MAX_SECRET_BYTES = 2560
MAX_SSH_OUTPUT_BYTES = 8192
PROTOCOL_VERSION = "2025-03-26"
CREDENTIAL_PREFIX = "SecureCredentialBridge/"

OUTPUT_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()
PENDING_REQUESTS: dict[str, queue.Queue[dict[str, Any]]] = {}
DRAFTS: dict[str, dict[str, Any]] = {}
CLIENT_ELICITATION = False
# Keep direct/manual server launches on the original MCP-confirmation path.
# The bundled .mcp.json explicitly opts into the separate local approval proxy.
APPROVAL_MODE = os.environ.get("SCB_APPROVAL_MODE", "native").strip().lower()
APPROVAL_PROXY_PATH = ROOT / "scripts" / "approval_proxy.py"
APPROVAL_TIMEOUT_SECONDS = 120


class BridgeError(Exception):
    """An intentionally nonsensitive user-facing error."""


def send(message: dict[str, Any]) -> None:
    encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    with OUTPUT_LOCK:
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()


def send_result(request_id: Any, result: dict[str, Any]) -> None:
    send({"jsonrpc": "2.0", "id": request_id, "result": result})


def send_error(request_id: Any, code: int, message: str) -> None:
    send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def config() -> dict[str, Any]:
    if not CONFIG_PATH.is_file():
        return {}
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise BridgeError("Bridge configuration is unreadable or invalid JSON.") from None
    if not isinstance(raw, dict):
        raise BridgeError("Bridge configuration must be a JSON object.")
    validate_config(raw)
    return raw


def validate_config(raw: dict[str, Any]) -> None:
    # Keep accepting the retired ssh_actions root so older local config files
    # remain loadable; those entries are intentionally ignored and never run.
    allowed_roots = {"ssh_hosts", "ssh_actions", "email", "postgres"}
    if set(raw) - allowed_roots:
        raise BridgeError("Bridge configuration contains unsupported top-level fields.")
    hosts = raw.get("ssh_hosts", {})
    if not isinstance(hosts, dict):
        raise BridgeError("SSH hosts must be a named object.")
    for alias, host in hosts.items():
        if not safe_name(alias) or not isinstance(host, dict):
            raise BridgeError("Invalid SSH host entry.")
        if set(host) - {"host", "port", "username", "host_key_sha256", "credential_target", "private_key_file"}:
            raise BridgeError("SSH host entry contains an unsupported field.")
        if not valid_host(host.get("host")) or not safe_name(host.get("username")):
            raise BridgeError("SSH host and username must be valid fixed values.")
        if not isinstance(host.get("port", 22), int) or not 1 <= host.get("port", 22) <= 65535:
            raise BridgeError("SSH port is invalid.")
        fingerprint = host.get("host_key_sha256")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{20,44}", fingerprint):
            raise BridgeError("Every SSH host requires a pinned SHA256 host-key fingerprint.")
        if not host.get("credential_target") and not host.get("private_key_file"):
            raise BridgeError("SSH host requires a Credential Manager target or private key file.")
        if host.get("credential_target") and not valid_credential_target(host["credential_target"]):
            raise BridgeError("SSH credential target is invalid.")
        if host.get("private_key_file") and not Path(host["private_key_file"]).is_file():
            raise BridgeError("Configured SSH private key file does not exist.")
    if "email" in raw:
        mail = raw["email"]
        if not isinstance(mail, dict) or set(mail) - {"host", "port", "security", "username", "from", "credential_target", "allowed_recipients", "timeout_seconds"}:
            raise BridgeError("Invalid email configuration.")
        if not valid_host(mail.get("host")) or not safe_name(mail.get("username")) or not valid_credential_target(mail.get("credential_target")):
            raise BridgeError("Email host, username, or credential target is invalid.")
        if mail.get("security") not in {"starttls", "ssl"}:
            raise BridgeError("Email transport must use STARTTLS or implicit TLS.")
        if not isinstance(mail.get("port"), int) or not 1 <= mail["port"] <= 65535:
            raise BridgeError("Email port is invalid.")
        if not valid_email(mail.get("from")):
            raise BridgeError("Email sender address is invalid.")
        recipients = mail.get("allowed_recipients")
        if not isinstance(recipients, list) or not recipients or not all(valid_email(x) for x in recipients):
            raise BridgeError("Email requires an explicit list of allowed recipients.")
    if "postgres" in raw:
        db = raw["postgres"]
        if not isinstance(db, dict) or set(db) - {"host", "port", "database", "username", "credential_target", "sslmode", "sslrootcert", "queries"}:
            raise BridgeError("Invalid PostgreSQL configuration.")
        if not valid_host(db.get("host")) or not safe_name(db.get("database")) or not safe_name(db.get("username")) or not valid_credential_target(db.get("credential_target")):
            raise BridgeError("PostgreSQL host, database, username, or credential target is invalid.")
        if not isinstance(db.get("port", 5432), int) or not 1 <= db.get("port", 5432) <= 65535:
            raise BridgeError("PostgreSQL port is invalid.")
        if db.get("sslmode") not in {"verify-full", "require"}:
            raise BridgeError("PostgreSQL TLS must use verify-full or require.")
        if db.get("sslmode") == "verify-full" and not isinstance(db.get("sslrootcert"), str):
            raise BridgeError("PostgreSQL verify-full requires a configured CA certificate path.")
        queries = db.get("queries", {})
        if not isinstance(queries, dict):
            raise BridgeError("PostgreSQL named queries must be an object.")
        for name, query in queries.items():
            if not safe_name(name) or not isinstance(query, dict) or set(query) - {"sql", "parameters", "max_rows", "timeout_ms"}:
                raise BridgeError("Invalid PostgreSQL named query.")
            sql = query.get("sql")
            if not isinstance(sql, str) or not is_single_read_query(sql):
                raise BridgeError("Only one configured SELECT or WITH query is permitted.")
            if not isinstance(query.get("parameters", {}), dict) or not all(safe_name(x) and y in {"string", "integer", "number", "boolean"} for x, y in query.get("parameters", {}).items()):
                raise BridgeError("PostgreSQL query parameter types are invalid.")
            if not isinstance(query.get("max_rows", 100), int) or not 1 <= query.get("max_rows", 100) <= 500:
                raise BridgeError("PostgreSQL row limit must be between 1 and 500.")
            if not isinstance(query.get("timeout_ms", 5000), int) or not 100 <= query.get("timeout_ms", 5000) <= 30000:
                raise BridgeError("PostgreSQL statement timeout must be between 100 and 30000 ms.")


def safe_name(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@/-]{0,127}", value) is not None


def valid_credential_target(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(CREDENTIAL_PREFIX) and safe_name(value)


def valid_host(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 253 and re.fullmatch(r"[A-Za-z0-9.-]+", value) is not None


def valid_email(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 254 and re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", value) is not None


def discover_ssh_hosts(config_path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Read literal OpenSSH Host aliases without invoking ssh or scanning networks.

    This intentionally does not evaluate Include, Match exec, ProxyCommand, or other
    directives with possible side effects. It extracts only connection coordinates
    and an explicitly configured IdentityFile for use as a GUI prefill.
    """
    if config_path is None:
        profile = os.environ.get("USERPROFILE")
        config_path = (Path(profile) if profile else Path.home()) / ".ssh" / "config"
    try:
        lines = config_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return {}

    blocks: list[tuple[list[str], dict[str, str]]] = []
    current_patterns: list[str] | None = None
    current_values: dict[str, str] = {}
    allowed = {"hostname", "user", "port", "identityfile"}

    def save_block() -> None:
        if current_patterns is not None:
            blocks.append((current_patterns, current_values.copy()))

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        directive = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if directive == "host":
            save_block()
            current_patterns = [item.strip('"\'') for item in value.split() if item]
            current_values = {}
            continue
        if directive == "match":
            save_block()
            current_patterns = None
            current_values = {}
            continue
        if current_patterns is None or directive not in allowed or not value:
            continue
        value = value.strip('"\'')
        current_values.setdefault(directive, value)
    save_block()

    aliases: set[str] = set()
    for patterns, _values in blocks:
        for pattern in patterns:
            if any(char in pattern for char in "*!?") or not safe_name(pattern):
                continue
            aliases.add(pattern)

    discovered: dict[str, dict[str, Any]] = {}
    for alias in sorted(aliases, key=str.casefold):
        effective: dict[str, str] = {}
        for patterns, values in blocks:
            positive = any(fnmatch.fnmatchcase(alias.casefold(), pattern.casefold()) for pattern in patterns if not pattern.startswith("!"))
            excluded = any(fnmatch.fnmatchcase(alias.casefold(), pattern[1:].casefold()) for pattern in patterns if pattern.startswith("!"))
            if positive and not excluded:
                for name, value in values.items():
                    effective.setdefault(name, value)
        hostname = effective.get("hostname", alias)
        username = effective.get("user", "")
        try:
            port = int(effective.get("port", "22"))
        except ValueError:
            continue
        if not valid_host(hostname) or not 1 <= port <= 65535 or (username and not safe_name(username)):
            continue
        candidate: dict[str, Any] = {"host": hostname, "port": port, "username": username}
        identity = effective.get("identityfile", "")
        if identity and "%" not in identity:
            expanded_identity = os.path.expandvars(os.path.expanduser(identity))
            if Path(expanded_identity).is_file():
                candidate["private_key_file"] = str(Path(expanded_identity).resolve())
        discovered[alias] = candidate
    return discovered


def launch_ssh_manager(alias: str | None = None) -> bool:
    """Open the local SSH UI against this server's exact configuration file."""
    manager_path = ROOT / "scripts" / "ssh_manager_gui.py"
    if not manager_path.is_file():
        return False
    executable = sys.executable
    if os.name == "nt":
        windowless = Path(sys.executable).with_name("pythonw.exe")
        if windowless.is_file():
            executable = str(windowless)
    command = [executable, str(manager_path)]
    if alias and safe_name(alias):
        command.extend(["--prefill-alias", alias])
    environment = os.environ.copy()
    environment["SCB_CONFIG"] = str(CONFIG_PATH)
    options: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": environment,
        "close_fds": True,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    try:
        subprocess.Popen(command, **options)
        return True
    except OSError:
        return False


def verify_ssh_authentication(host: dict[str, Any], timeout: int = 15) -> None:
    """Authenticate to one pinned host and run no remote command."""
    try:
        import paramiko
    except ImportError:
        raise BridgeError("SSH adapter dependency is missing; install the plugin requirements first.") from None

    client = paramiko.SSHClient()
    secret: str | None = None

    class PinnedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client: Any, _hostname: str, key: Any) -> None:
            digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
            if f"SHA256:{digest}" != host["host_key_sha256"]:
                raise BridgeError("SSH server host-key fingerprint did not match the configured pin.")

    try:
        if host.get("credential_target"):
            secret = read_credential(host["credential_target"])
        elif not host.get("private_key_file"):
            raise BridgeError("No SSH credential is configured for this host.")
        client.set_missing_host_key_policy(PinnedHostKey())
        options: dict[str, Any] = {
            "hostname": host["host"], "port": host.get("port", 22), "username": host["username"],
            "timeout": timeout, "banner_timeout": timeout, "auth_timeout": timeout,
            "allow_agent": False, "look_for_keys": False,
        }
        if host.get("private_key_file"):
            try:
                options["pkey"] = paramiko.PKey.from_path(host["private_key_file"], passphrase=secret)
            except (OSError, paramiko.SSHException):
                raise BridgeError("Configured SSH key could not be loaded.") from None
        else:
            options["password"] = secret
        client.connect(**options)
        transport = client.get_transport()
        server_key = transport.get_remote_server_key() if transport else None
        if server_key is None:
            raise BridgeError("SSH server did not provide a host key.")
        digest = base64.b64encode(hashlib.sha256(server_key.asbytes()).digest()).decode("ascii").rstrip("=")
        if f"SHA256:{digest}" != host["host_key_sha256"]:
            raise BridgeError("SSH server host-key fingerprint did not match the configured pin.")
    except BridgeError:
        raise
    except paramiko.AuthenticationException:
        raise BridgeError("SSH authentication failed; check the username and saved credential.") from None
    except (TimeoutError, OSError):
        raise BridgeError("SSH connection timed out or could not reach the host; check VPN, address, and port.") from None
    except Exception:
        raise BridgeError("SSH connection failed; host and credential details were suppressed.") from None
    finally:
        secret = None
        try:
            client.close()
        except Exception:
            pass


def is_single_read_query(sql: str) -> bool:
    cleaned = re.sub(r"--[^\n]*|/\*[\s\S]*?\*/", " ", sql).strip()
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].rstrip()
    if not cleaned or ";" in cleaned:
        return False
    return re.match(r"(?is)^(SELECT|WITH)\b", cleaned) is not None


def read_credential(target: str) -> str:
    if not valid_credential_target(target):
        raise BridgeError("Credential target must use the plugin's dedicated Credential Manager namespace.")
    if os.name != "nt":
        raise BridgeError("Windows Credential Manager is available only on Windows.")
    advapi = ctypes.WinDLL("Advapi32", use_last_error=True)

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [("Flags", ctypes.c_uint32), ("Type", ctypes.c_uint32), ("TargetName", ctypes.c_wchar_p),
                    ("Comment", ctypes.c_wchar_p), ("LastWritten", ctypes.c_uint64), ("CredentialBlobSize", ctypes.c_uint32),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", ctypes.c_uint32),
                    ("AttributeCount", ctypes.c_uint32), ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", ctypes.c_wchar_p), ("UserName", ctypes.c_wchar_p)]

    pointer = ctypes.POINTER(CREDENTIALW)()
    advapi.CredReadW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.POINTER(CREDENTIALW))]
    advapi.CredReadW.restype = ctypes.c_int
    if not advapi.CredReadW(target, 1, 0, ctypes.byref(pointer)):
        raise BridgeError("Credential reference was not found in Windows Credential Manager.")
    try:
        credential = pointer.contents
        if credential.CredentialBlobSize == 0 or credential.CredentialBlobSize > MAX_SECRET_BYTES:
            raise BridgeError("Stored credential has an unsupported size.")
        secret_bytes = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        try:
            return secret_bytes.decode("utf-16-le")
        except UnicodeDecodeError:
            raise BridgeError("Stored credential encoding is invalid.") from None
    finally:
        advapi.CredFree.argtypes = [ctypes.c_void_p]
        advapi.CredFree(pointer)


def request_local_approval(message: str, *, intent_zh: str | None = None) -> None:
    """Ask the separate desktop approval proxy; never execute without its reply."""
    if not APPROVAL_PROXY_PATH.is_file():
        raise BridgeError("Local approval proxy is unavailable; action was not run.")
    request = {"message": message}
    if intent_zh is not None:
        try:
            request["intent_zh"] = validate_intent(intent_zh)
        except ValueError as error:
            raise BridgeError(str(error)) from None
    payload = json.dumps(request, ensure_ascii=False) + "\n"
    options: dict[str, Any] = {
        "input": payload,
        "text": True,
        "encoding": "utf-8",
        "capture_output": True,
        "timeout": APPROVAL_TIMEOUT_SECONDS,
        "check": False,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run([sys.executable, str(APPROVAL_PROXY_PATH)], **options)
    except subprocess.TimeoutExpired:
        raise BridgeError("Local approval timed out after 120 seconds; action was not run.") from None
    except OSError:
        raise BridgeError("Local approval proxy could not be started; action was not run.") from None
    if completed.returncode != 0:
        raise BridgeError("Local approval proxy failed or was closed; action was not run.")
    try:
        response = json.loads(completed.stdout.strip())
    except (TypeError, json.JSONDecodeError):
        raise BridgeError("Local approval proxy returned an invalid response; action was not run.") from None
    if not isinstance(response, dict) or response.get("approved") is not True:
        raise BridgeError("Action was declined in the local approval window; nothing was sent or executed.")


def request_confirmation(message: str, *, intent_zh: str | None = None) -> None:
    if intent_zh is not None:
        try:
            intent_zh = validate_intent(intent_zh)
        except ValueError as error:
            raise BridgeError(str(error)) from None
        # 原生 MCP 确认框颜色由客户端控制；仍保留明确的中文意图和完整命令。
        message = f"【请确认操作意图】{intent_zh}\n\n{message}"
    if APPROVAL_MODE == "local":
        request_local_approval(message, intent_zh=intent_zh)
        return
    if APPROVAL_MODE not in {"auto", "native"}:
        raise BridgeError("Approval mode is invalid; action was not run.")
    if APPROVAL_MODE == "auto" and not CLIENT_ELICITATION:
        request_local_approval(message, intent_zh=intent_zh)
        return
    if not CLIENT_ELICITATION:
        raise BridgeError("Confirmation unavailable: this MCP client did not advertise elicitation support; action was not run.")
    request_id = f"server-{uuid.uuid4()}"
    response_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
    with STATE_LOCK:
        PENDING_REQUESTS[request_id] = response_queue
    send({"jsonrpc": "2.0", "id": request_id, "method": "elicitation/create", "params": {
        "mode": "form", "message": message,
        "requestedSchema": {"type": "object", "properties": {"confirm": {"type": "boolean", "title": "Confirm this exact action", "default": False}}, "required": ["confirm"]}
    }})
    try:
        response = response_queue.get(timeout=120)
    except queue.Empty:
        raise BridgeError("Confirmation timed out after 120 seconds; action was not run.") from None
    finally:
        with STATE_LOCK:
            PENDING_REQUESTS.pop(request_id, None)
    if "error" in response:
        raise BridgeError("Confirmation unavailable: the MCP client rejected or could not process the request; action was not run.")
    result = response.get("result", {})
    action = result.get("action")
    if action in {"decline", "cancel"}:
        raise BridgeError(f"Action was {action} in the confirmation UI; nothing was sent or executed.")
    if action != "accept":
        raise BridgeError("Confirmation unavailable: the MCP client returned an unrecognized response; action was not run.")
    content = result.get("content")
    if not isinstance(content, dict) or content.get("confirm") is not True:
        raise BridgeError("Action was not approved; nothing was sent or executed.")


def result_text(text: str, *, is_error: bool = False, structured: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error, "structuredContent": structured or {}}


def tools_for(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = [
        {"name": "bridge_status", "description": "Show configured SSH host and query names only. Never displays credentials or checks live connections.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}},
        {"name": "ssh_discover_hosts", "description": "List literal alias names from the local OpenSSH config for selection. Returns no endpoint, username, credential, or private-key path; makes no network connection and never scans networks.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}},
        {"name": "ssh_connect", "description": "Test authentication to one configured, fingerprint-pinned SSH host selected by its local alias. Alias may be omitted only when exactly one host is configured. If setup is missing, opens the local SSH configuration window. Runs no remote command and needs no per-call approval; verifies the configured pin and never scans networks or tries multiple hosts automatically.", "inputSchema": {"type": "object", "properties": {"alias": {"type": "string", "minLength": 1, "maxLength": 128}}, "additionalProperties": False}, "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}},
    ]
    tools.append({"name": "ssh_run_command", "description": "Run a user-requested command on one configured, fingerprint-pinned SSH host. Recognized read-only queries run without approval. Other commands require intent_zh, a Chinese purpose description, and explicit confirmation showing the full target/command; local mode displays the intent in red. Unknown syntax requires approval. The intent never overrides classification. Never place secrets in command arguments.", "inputSchema": {"type": "object", "properties": {"alias": {"type": "string", "minLength": 1, "maxLength": 128}, "command": {"type": "string", "minLength": 1, "maxLength": 12000}, "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300}, "intent_zh": {"type": "string", "minLength": 1, "maxLength": 500, "description": "Chinese description of the command purpose and impact; required for commands not recognized as read-only. Does not grant an exemption."}}, "required": ["alias", "command"], "additionalProperties": False}, "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}})
    if "email" in cfg:
        tools.extend([
            {"name": "email_create_draft", "description": "Create a short-lived in-memory email draft for an allowlisted recipient. Does not send mail.", "inputSchema": {"type": "object", "properties": {"to": {"type": "string", "format": "email"}, "subject": {"type": "string", "maxLength": 200}, "body": {"type": "string", "maxLength": 12000}}, "required": ["to", "subject", "body"], "additionalProperties": False}, "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}},
            {"name": "email_send_draft", "description": "Send a draft only after a separate interactive user confirmation. Confirmation displays recipient, subject, and content digest; uncertain delivery is never retried automatically.", "inputSchema": {"type": "object", "properties": {"draft_id": {"type": "string"}, "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}}, "required": ["draft_id", "sha256"], "additionalProperties": False}, "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}},
        ])
    if "postgres" in cfg and cfg["postgres"].get("queries"):
        db = cfg["postgres"]
        param_schemas = {q: {"type": "object", "properties": {name: {"type": sql_type} for name, sql_type in cfg_query.get("parameters", {}).items()}, "required": list(cfg_query.get("parameters", {})), "additionalProperties": False} for q, cfg_query in db["queries"].items()}
        tools.append({"name": "postgres_query", "description": "Execute one named, preconfigured parameterized read-only PostgreSQL query with server-side read-only transaction, timeout, and row limits. No arbitrary SQL is accepted.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "enum": sorted(db["queries"])}, "parameters": {"type": "object"}}, "required": ["query", "parameters"], "additionalProperties": False}, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}})
    return tools


def tool_call(name: str, args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    if name == "bridge_status":
        hosts = sorted(cfg.get("ssh_hosts", {}))
        queries = sorted(cfg.get("postgres", {}).get("queries", {}))
        return result_text(json.dumps({"ssh_hosts": hosts, "email": "configured" if "email" in cfg else "not_configured", "postgres_queries": queries, "credential_store": "Windows Credential Manager"}, ensure_ascii=False), structured={"ssh_hosts": hosts, "email_configured": "email" in cfg, "postgres_queries": queries})
    if name == "ssh_discover_hosts":
        candidates = discover_ssh_hosts()
        public_candidates = [
            {
                "alias": alias,
                "private_key_available": bool(candidate.get("private_key_file")),
                "configured_in_bridge": alias in cfg.get("ssh_hosts", {}),
            }
            for alias, candidate in candidates.items()
        ]
        return result_text(
            json.dumps({"candidates": public_candidates, "network_scan_performed": False}, ensure_ascii=False),
            structured={"candidates": public_candidates, "network_scan_performed": False},
        )
    if name == "ssh_connect":
        return ssh_connect(args, cfg)
    if name == "ssh_run_command":
        return ssh_run_command(args, cfg)
    if name == "email_create_draft":
        return email_create_draft(args, cfg)
    if name == "email_send_draft":
        return email_send_draft(args, cfg)
    if name == "postgres_query":
        return postgres_query(args, cfg)
    raise BridgeError("Unknown tool.")


def ssh_connect(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Authenticate to one saved host; auto-select only when exactly one is configured."""
    alias = args.get("alias")
    configured_hosts = cfg.get("ssh_hosts", {})
    if set(args) - {"alias"}:
        raise BridgeError("SSH connection accepts only a locally configured alias; host and account details are not tool arguments.")
    if alias is None:
        if len(configured_hosts) == 1:
            alias = next(iter(configured_hosts))
        elif len(configured_hosts) > 1:
            choices = ", ".join(sorted(configured_hosts))
            raise BridgeError(f"Multiple SSH hosts are configured; select one local alias: {choices}")
        else:
            candidates = discover_ssh_hosts()
            prefill_alias = next(iter(candidates)) if len(candidates) == 1 else None
            opened = launch_ssh_manager(prefill_alias)
            if prefill_alias:
                message = f"Found the only literal alias '{prefill_alias}' in the local OpenSSH config. The configuration window is prefilled; verify its SHA256 host-key fingerprint through a trusted source, save the host and credential, then retry. No SSH authentication or remote command was attempted."
            elif candidates:
                message = "Multiple literal aliases were found in the local OpenSSH config. The configuration window was opened; select the intended host, verify its SHA256 host-key fingerprint through a trusted source, save, then retry. No SSH authentication or remote command was attempted."
            else:
                message = "No configured host or literal local OpenSSH alias was found. The configuration window was opened for manual setup; no network scan, authentication, or remote command was attempted."
            if not opened:
                message += " The configuration window could not be started automatically."
            raise BridgeError(message)
    if not safe_name(alias):
        raise BridgeError("SSH host alias is invalid.")
    host = configured_hosts.get(alias)
    if host is None:
        candidate = discover_ssh_hosts().get(alias)
        opened = launch_ssh_manager(alias)
        if candidate:
            message = "Found this alias in the local OpenSSH config. The configuration window is prefilled; verify its SHA256 host-key fingerprint through a trusted source, save credentials locally, and retry. No SSH authentication or remote command was attempted."
        else:
            message = "No saved host or literal local OpenSSH alias was found. The configuration window was opened for manual setup; no network scan, authentication, or remote command was attempted."
        if not opened:
            message += " The configuration window could not be started automatically."
        raise BridgeError(message)

    # 仅验证选定主机的密钥与认证，不执行远端命令，无需逐次弹框。
    try:
        verify_ssh_authentication(host)
    except BridgeError as error:
        opened = launch_ssh_manager(alias)
        suffix = " The SSH configuration window was opened; verify the host-key pin and saved credential, save, then retry." if opened else " The SSH configuration window could not be started."
        raise BridgeError(f"{error}{suffix}") from None
    return result_text(
        json.dumps({"alias": alias, "connected": True, "remote_command_executed": False}, ensure_ascii=False),
        structured={"alias": alias, "connected": True, "remote_command_executed": False},
    )


def ssh_run_command(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """已支持的只读查询免确认；其余命令必须展示中文意图并获得批准。"""
    if set(args) - {"alias", "command", "timeout_seconds", "intent_zh"}:
        raise BridgeError("Unsupported SSH command argument; no approval bypass flags are accepted.")
    alias = args.get("alias")
    command = args.get("command")
    timeout = args.get("timeout_seconds", 60)
    if not isinstance(alias, str) or not safe_name(alias):
        raise BridgeError("A configured SSH host alias is required.")
    if not isinstance(command, str) or not command.strip() or len(command) > 12000 or "\x00" in command:
        raise BridgeError("SSH command must be non-empty and no longer than 12000 characters.")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise BridgeError("SSH command timeout must be between 1 and 300 seconds.")
    host = cfg.get("ssh_hosts", {}).get(alias)
    if host is None:
        raise BridgeError("SSH host alias is not configured.")

    policy = classify_command(command)
    intent_zh = None
    if "intent_zh" in args or not policy.read_only:
        try:
            intent_zh = validate_intent(args.get("intent_zh"))
        except ValueError as error:
            raise BridgeError(f"{error}. 非只读或未识别命令必须提供中文操作目的；尚未连接或执行。") from None
    if not policy.read_only:
        request_confirmation(
            f"目标主机：{alias} ({host['username']}@{host['host']}:{host.get('port', 22)})\n\n"
            f"确认原因：{policy.reason_zh}\n超时：{timeout} 秒\n\n完整命令：\n{command}",
            intent_zh=intent_zh,
        )
    try:
        import paramiko
    except ImportError:
        raise BridgeError("SSH adapter dependency is missing; install the plugin requirements first.") from None

    client = paramiko.SSHClient()

    class PinnedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client: Any, _hostname: str, key: Any) -> None:
            digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
            if f"SHA256:{digest}" != host["host_key_sha256"]:
                raise BridgeError("SSH server host-key fingerprint did not match the configured pin.")

    try:
        client.set_missing_host_key_policy(PinnedHostKey())
        secret = read_credential(host["credential_target"]) if host.get("credential_target") else None
        options: dict[str, Any] = {
            "hostname": host["host"], "port": host.get("port", 22), "username": host["username"],
            "timeout": min(timeout, 30), "banner_timeout": min(timeout, 30), "auth_timeout": min(timeout, 30),
            "allow_agent": False, "look_for_keys": False,
        }
        if host.get("private_key_file"):
            try:
                options["pkey"] = paramiko.PKey.from_path(host["private_key_file"], passphrase=secret)
            except (OSError, paramiko.SSHException):
                raise BridgeError("Configured SSH key could not be loaded.") from None
        else:
            options["password"] = secret
        client.connect(**options)
        transport = client.get_transport()
        server_key = transport.get_remote_server_key() if transport else None
        if server_key is None:
            raise BridgeError("SSH server did not provide a host key.")
        digest = base64.b64encode(hashlib.sha256(server_key.asbytes()).digest()).decode("ascii").rstrip("=")
        if f"SHA256:{digest}" != host["host_key_sha256"]:
            raise BridgeError("SSH server host-key fingerprint did not match the configured pin.")

        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=False)
        channel = stdout.channel
        deadline = time.monotonic() + timeout
        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        out_size = err_size = 0
        while time.monotonic() < deadline:
            remaining = MAX_SSH_OUTPUT_BYTES + 1 - out_size - err_size
            if remaining > 0 and channel.recv_ready():
                chunk = channel.recv(min(2048, remaining))
                if chunk:
                    out_chunks.append(chunk)
                    out_size += len(chunk)
            remaining = MAX_SSH_OUTPUT_BYTES + 1 - out_size - err_size
            if remaining > 0 and channel.recv_stderr_ready():
                chunk = channel.recv_stderr(min(2048, remaining))
                if chunk:
                    err_chunks.append(chunk)
                    err_size += len(chunk)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if out_size + err_size > MAX_SSH_OUTPUT_BYTES:
                channel.close()
                break
            time.sleep(0.02)
        if time.monotonic() >= deadline and not channel.exit_status_ready():
            channel.close()
            raise BridgeError("SSH command timed out.")
        out = b"".join(out_chunks)[:MAX_SSH_OUTPUT_BYTES]
        err = b"".join(err_chunks)[:max(0, MAX_SSH_OUTPUT_BYTES - len(out))]
        exit_code = channel.recv_exit_status() if channel.exit_status_ready() else -1
        result = {
            "alias": alias,
            "approval_required": not policy.read_only,
            "read_only": policy.read_only,
            "exit_code": exit_code,
            "stdout": out.decode("utf-8", errors="replace"),
            "stderr": err.decode("utf-8", errors="replace"),
            "output_truncated": out_size + err_size > MAX_SSH_OUTPUT_BYTES,
        }
        return result_text(json.dumps(result, ensure_ascii=False), is_error=exit_code != 0, structured=result)
    except BridgeError:
        raise
    except Exception:
        raise BridgeError("SSH command failed or timed out; connection details and credentials were suppressed.") from None
    finally:
        try:
            client.close()
        except Exception:
            pass


def email_create_draft(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    mail = cfg.get("email")
    to = args.get("to")
    subject = args.get("subject")
    body = args.get("body")
    if mail is None or to not in mail["allowed_recipients"]:
        raise BridgeError("Email adapter is unavailable or recipient is not allowlisted.")
    if not valid_email(to) or not isinstance(subject, str) or not subject.strip() or len(subject) > 200 or any(c in subject for c in "\r\n"):
        raise BridgeError("Email address or subject is invalid.")
    if not isinstance(body, str) or len(body) > 12000:
        raise BridgeError("Email body exceeds the configured draft limit.")
    digest = hashlib.sha256((to + "\n" + subject + "\n" + body).encode("utf-8")).hexdigest()
    draft_id = str(uuid.uuid4())
    now = time.time()
    with STATE_LOCK:
        for key, draft in list(DRAFTS.items()):
            if draft["expires"] <= now:
                DRAFTS.pop(key, None)
        if len(DRAFTS) >= MAX_DRAFTS:
            raise BridgeError("Too many pending drafts; wait for existing drafts to expire.")
        DRAFTS[draft_id] = {"to": to, "subject": subject, "body": body, "sha256": digest, "expires": now + DRAFT_TTL_SECONDS}
    return result_text(json.dumps({"status": "draft_created_not_sent", "draft_id": draft_id, "to": to, "subject": subject, "sha256": digest, "expires_in_seconds": DRAFT_TTL_SECONDS}, ensure_ascii=False), structured={"status": "draft_created_not_sent", "draft_id": draft_id, "to": to, "subject": subject, "sha256": digest})


def email_send_draft(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    draft_id = args.get("draft_id")
    digest = args.get("sha256")
    with STATE_LOCK:
        draft = DRAFTS.get(draft_id)
    if draft is None or draft["expires"] <= time.time() or draft["sha256"] != digest:
        raise BridgeError("Draft is missing, expired, or its content digest does not match.")
    request_confirmation(f"Review and send this exact email?\nTo: {draft['to']}\nSubject: {draft['subject']}\n\n--- Message body ---\n{draft['body']}\n--- End body ---\nSHA-256: {draft['sha256']}")
    with STATE_LOCK:
        current = DRAFTS.pop(draft_id, None)
    if current is None or current["sha256"] != digest:
        raise BridgeError("Draft was already used or changed; no second send was attempted.")
    mail = cfg["email"]
    message = EmailMessage()
    message["From"] = mail["from"]
    message["To"] = current["to"]
    message["Subject"] = current["subject"]
    message.set_content(current["body"])
    password = read_credential(mail["credential_target"])
    context = ssl.create_default_context()
    try:
        if mail["security"] == "ssl":
            with smtplib.SMTP_SSL(mail["host"], mail["port"], timeout=mail.get("timeout_seconds", 15), context=context) as server:
                server.login(mail["username"], password)
                server.send_message(message)
        else:
            with smtplib.SMTP(mail["host"], mail["port"], timeout=mail.get("timeout_seconds", 15)) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(mail["username"], password)
                server.send_message(message)
    except Exception:
        raise BridgeError("Email delivery outcome may be uncertain. The draft was consumed to prevent accidental duplicate sends; verify the mailbox before retrying.") from None
    return result_text(json.dumps({"status": "sent", "to": current["to"], "subject": current["subject"], "sha256": digest}, ensure_ascii=False), structured={"status": "sent", "to": current["to"], "subject": current["subject"], "sha256": digest})


def postgres_query(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    db = cfg.get("postgres")
    query_name = args.get("query")
    query = db.get("queries", {}).get(query_name) if db else None
    if query is None:
        raise BridgeError("PostgreSQL query name is not configured.")
    parameters = args.get("parameters", {})
    expected = query.get("parameters", {})
    if not isinstance(parameters, dict) or set(parameters) != set(expected):
        raise BridgeError("Query parameters do not match the configured parameter names.")
    for name, value in parameters.items():
        kind = expected[name]
        valid = (kind == "string" and isinstance(value, str) and len(value) <= 1000) or (kind == "integer" and isinstance(value, int) and not isinstance(value, bool)) or (kind == "number" and isinstance(value, (int, float)) and not isinstance(value, bool)) or (kind == "boolean" and isinstance(value, bool))
        if not valid:
            raise BridgeError(f"Query parameter '{name}' has the wrong type or size.")
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:
        raise BridgeError("PostgreSQL adapter dependency is missing; install the plugin requirements first.") from None
    password = read_credential(db["credential_target"])
    conn_kwargs = {"host": db["host"], "port": db.get("port", 5432), "dbname": db["database"], "user": db["username"], "password": password, "sslmode": db["sslmode"], "connect_timeout": 10, "autocommit": False, "row_factory": dict_row}
    if db.get("sslrootcert"):
        conn_kwargs["sslrootcert"] = db["sslrootcert"]
    try:
        with psycopg.connect(**conn_kwargs) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION READ ONLY")
                cursor.execute("SELECT set_config('statement_timeout', %s, true)", (f"{query.get('timeout_ms', 5000)}ms",))
                cursor.execute(query["sql"], parameters)
                rows = cursor.fetchmany(query.get("max_rows", 100) + 1)
                truncated = len(rows) > query.get("max_rows", 100)
                rows = rows[:query.get("max_rows", 100)]
                safe_rows = json.loads(json.dumps(rows, default=str, ensure_ascii=False))
                payload = {"query": query_name, "rows": safe_rows, "truncated": truncated}
                text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                while len(text.encode("utf-8")) > MAX_TOOL_TEXT_BYTES and safe_rows:
                    safe_rows.pop()
                    payload["rows"] = safe_rows
                    payload["truncated"] = True
                    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                return result_text(text, structured=payload)
    except BridgeError:
        raise
    except Exception:
        raise BridgeError("PostgreSQL query failed; connection details and credentials were suppressed.") from None


def handle_tool(request_id: Any, params: dict[str, Any]) -> None:
    try:
        cfg = config()
        name = params.get("name")
        if name not in {tool["name"] for tool in tools_for(cfg)}:
            send_result(request_id, result_text("Tool is not available in the current configuration.", is_error=True))
            return
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            send_result(request_id, result_text("Tool arguments must be an object.", is_error=True))
            return
        result = tool_call(name, args, cfg)
        send_result(request_id, result)
    except BridgeError as error:
        send_result(request_id, result_text(str(error), is_error=True))
    except Exception:
        send_result(request_id, result_text("Operation failed safely; sensitive details were suppressed.", is_error=True))


def process_message(message: dict[str, Any], pool: ThreadPoolExecutor) -> None:
    global CLIENT_ELICITATION
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params", {})
    if method is None and request_id is not None:
        with STATE_LOCK:
            waiter = PENDING_REQUESTS.get(str(request_id))
        if waiter:
            try:
                waiter.put_nowait(message)
            except queue.Full:
                pass
        return
    if method == "initialize":
        CLIENT_ELICITATION = isinstance(params.get("capabilities", {}).get("elicitation"), dict)
        send_result(request_id, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}}, "serverInfo": {"name": "secure-credential-bridge", "version": "0.1.3"}, "instructions": "Credentials are fetched locally from Windows Credential Manager and never returned by tools. Recognized read-only SSH queries and connection checks need no per-call approval. Other SSH commands require a Chinese intent_zh and confirmation of the exact target and command; local mode displays the intent in red. Unknown commands remain subject to approval. Never include secrets in commands or intent. This same-user process is not a security boundary against other local processes."})
    elif method == "notifications/initialized":
        return
    elif method == "ping":
        send_result(request_id, {})
    elif method == "tools/list":
        try:
            send_result(request_id, {"tools": tools_for(config())})
        except BridgeError as error:
            send_error(request_id, -32000, str(error))
    elif method == "tools/call":
        pool.submit(handle_tool, request_id, params)
    elif request_id is not None:
        send_error(request_id, -32601, "Method not found.")


def main() -> None:
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                if isinstance(message, dict):
                    process_message(message, pool)
            except (json.JSONDecodeError, TypeError):
                continue


if __name__ == "__main__":
    # MCP 的 Windows stdio 必须使用 UTF-8，避免中文意图在审批前变成码页乱码。
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    main()
