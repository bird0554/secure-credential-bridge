# Secure Credential Bridge

A local Codex MCP plugin for individually approved SSH commands, reviewed SMTP delivery, and named read-only PostgreSQL queries. Credentials are stored in Windows Credential Manager and are never a tool result. This local stdio process does **not** isolate itself from other software running as the same Windows user.

## Contents

- `.codex-plugin/plugin.json` — Codex plugin metadata.
- `.mcp.json` — starts the local stdio MCP server.
- `mcp/server.py` — tool protocol, adapter allowlists, TLS, confirmation gates, limits, and redacted errors.
- `config/bridge.example.json` — non-secret configuration example; copy to `config/bridge.json` and replace every example endpoint/fingerprint.
- `scripts/manage_credential.py` — hidden-prompt storage/removal in Windows Credential Manager.
- `scripts/ssh_manager_gui.py` — local Tkinter window for editing SSH hosts and managing SSH credentials.
- `scripts/approval_proxy.py` — one-shot local desktop approval window used before an SSH or email side effect.
- `scripts/requirements.txt` — Paramiko SSH and Psycopg PostgreSQL adapters.
- `skills/secure-credential-bridge/SKILL.md` — tool-use and security instructions for Codex.
- `tests/test_bridge.py` — configuration, guardrail, draft, and stdio protocol tests; does not connect to external systems.
- `.gitignore` — excludes local connection configuration, credentials, private keys, caches, and logs from Git.

## Setup

Requires Windows, Python 3.10+ with Tkinter, Git, and Codex with local MCP support. Use a Python installation available to the same Windows account that runs Codex.

Clone the repository and run these commands in PowerShell. If you already have a checkout, start from its root directory and skip `git clone` / `Set-Location`:

```powershell
git clone https://github.com/bird0554/secure-credential-bridge.git
Set-Location secure-credential-bridge
$plugin = (Get-Location).Path
if (-not (Test-Path "$plugin\config\bridge.json")) {
    Copy-Item "$plugin\config\bridge.example.json" "$plugin\config\bridge.json"
}
python -m pip install -r "$plugin\scripts\requirements.txt"
```

The example endpoints and fingerprint are placeholders. Replace them before connecting; `postgres.sslrootcert` must point to your own trusted CA certificate if PostgreSQL is used. The local `config/bridge.json` is ignored by Git and must never be uploaded.

For a standalone checkout, register the MCP server directly (do not also enable a marketplace copy of the same server):

```powershell
codex mcp add secure-credential-bridge --env SCB_APPROVAL_MODE=local --env "SCB_CONFIG=$plugin\config\bridge.json" -- python "$plugin\mcp\server.py"
```

This registers the MCP tools; it does not install the bundled skill. To make that skill available to Codex, copy `skills/secure-credential-bridge` into your Codex skills directory, preserving any existing customized version. Reload Codex's MCP connection after registration. `codex mcp add --help` describes the supported CLI arguments for your installed version.

For SSH, you can use the local management window instead of editing JSON by hand. Set `SCB_CONFIG` explicitly so the window edits the same file as the standalone server:

```powershell
$env:SCB_CONFIG = "$plugin\config\bridge.json"
pyw -3 "$plugin\scripts\ssh_manager_gui.py"
```

Without `SCB_CONFIG`, the window prefers the newest installed copy under the `personal` marketplace cache, then falls back to the checkout's `config\bridge.json`. For another marketplace, set `SCB_CONFIG` or choose its actual configuration file in the UI. Add or import a host, verify its SHA-256 fingerprint using a trusted source, then save the configuration. Use **Save password/passphrase** to store authentication in the current Windows user's Credential Manager. The GUI does not store secrets in JSON. Host configuration is reread for each tool call, so saving a host or credential can be followed immediately by a call in the current Codex thread. The separate **Test connection** button checks authentication but runs no remote command. Remote commands are supplied through Codex and each full target/command is shown in the local approval window before execution.

The same GUI can also be launched from PowerShell with `py -3` if `pyw` is unavailable. The UI does not start a web server or background service.

### Discover, test, and operate over SSH from Codex

Call `ssh_connect` with a local SSH alias, or omit it only when exactly one host is configured. Tool arguments accept aliases only; endpoint, username, passwords, and private keys stay in local configuration or Windows Credential Manager. If the alias is not configured, the tool reads literal `Host` aliases from the current Windows user's `~/.ssh/config` and opens the local manager with a matching alias prefilled. `ssh_discover_hosts` returns alias names only. Neither tool scans a subnet. Discovery does not resolve `Include`/`Match exec`/proxy directives, read credentials, or return endpoint, username, or private-key paths.

`ssh_connect` only tests authentication to one selected host; it never runs a remote command. Before sending authentication material, it requires the configured local approval window and verifies the pinned SHA-256 host-key fingerprint. If authentication/network verification fails, it opens the SSH manager with that alias prefilled. Confirm the fingerprint from a trusted independent source, save the host configuration and password/passphrase in Windows Credential Manager, then call `ssh_connect` again. The current call does not resume automatically after the GUI closes, and it never falls back to trying other hosts.

`ssh_run_command` accepts a configured host alias, command, and optional timeout (1-300 seconds). The local approval window displays the target and complete command on every call, before authentication or execution. Only clicking **确认并执行** allows the bridge to connect and run it. Output is capped, and secrets must never be placed in command text. Since the bridge reads `bridge.json` for each call and the tool schema does not depend on configured aliases, adding a host and saving credentials in the local manager takes effect in the existing Codex thread. Updating the plugin code or adding a new tool still requires the MCP plugin to reload.

For email/PostgreSQL, edit `config\bridge.json` with the actual non-secret endpoint, account, recipient, and fixed query definitions. Do not put passwords or tokens there. Obtain each SSH host-key fingerprint through a trusted independent channel before adding it; do not trust a first-seen key scan by itself. Use a dedicated PostgreSQL account granted only the required `SELECT` privileges and configure a trusted CA with `sslmode: verify-full`.

Save each password or SSH private-key passphrase using a hidden interactive prompt (the target names shown here are references, not secrets):

```powershell
python "$plugin\scripts\manage_credential.py" set ssh/staging
python "$plugin\scripts\manage_credential.py" set email/primary
python "$plugin\scripts\manage_credential.py" set postgres/readonly
```

The corresponding configuration values must use the full references `SecureCredentialBridge/ssh/staging`, `SecureCredentialBridge/email/primary`, and `SecureCredentialBridge/postgres/readonly`. Omit a Credential Manager target only when using an unencrypted SSH key file; storing private key files is outside this MVP.

### Existing marketplace installation

If your Codex installation already has a marketplace named `personal` with an entry for this plugin, install or update it with `codex plugin add secure-credential-bridge@personal`. This GitHub repository does not register that marketplace for you. Otherwise use the standalone MCP registration above, or have your marketplace maintainer add an entry for this plugin. Reload the MCP plugin after installing changed code or new tools. Later host, fingerprint, or credential changes saved by the local manager are read on the next call in the same thread; they do not require reopening Codex.

The plugin's `.mcp.json` selects the local approval mode (`SCB_APPROVAL_MODE=local`); each SSH command and email send starts a separate visible `approval_proxy.py` process. The command proceeds only after you click **确认并执行** in that window. Closing it, denying it, timing out, running without a desktop session, or failing to start all stop the action. This is the plugin's local approval boundary, not a Codex-native approval dialog and not an OS isolation boundary. No service or background daemon is required.

## Tools and limits

- `bridge_status`: configured host and query names only; no credential metadata/value.
- `ssh_discover_hosts`: read-only enumeration of explicit local OpenSSH aliases; no network access or credential access.
- `ssh_connect`: approved, fingerprint-pinned authentication test selected by local alias; the alias can be omitted only when a single configured host is available; no endpoint or username input; no remote command.
- `ssh_run_command`: runs a caller-supplied command on one configured host pinned by SHA-256 host-key fingerprint; every call requires a local approval showing the exact target and command.
- `email_create_draft`: exact recipient allowlist; draft is memory-only for 10 minutes and is never sent by this tool.
- `email_send_draft`: displays recipient, subject, full body, and content SHA-256 in the selected approval UI; in bundled local mode this is the one-shot local approval window. The draft is consumed once. SMTP must use STARTTLS or implicit TLS. Ambiguous delivery is not retried automatically.
- `postgres_query`: only named parameterized `SELECT`/`WITH` queries; read-only transaction, statement timeout, 500-row and 32 KB output caps. Use server-side least-privilege grants as well.

Local approval is fail-closed: if the approval process cannot display a decision, SSH and email actions do not proceed. The approval process receives only the human-readable operation description; it does not read Credential Manager, authenticate, or execute SSH/email operations. Credential resolution requires the current process to run on Windows under the same account that stored the Credential Manager entry. Set `SCB_APPROVAL_MODE=native` only if the MCP client is known to support elicitation; `auto` uses native elicitation when advertised and otherwise falls back to the local proxy.

Older `bridge.json` files may still contain an `ssh_actions` section. The updated plugin accepts that field for compatibility but ignores it; the former fixed-action tool is no longer registered or callable.

If no approval window appears, check that Python has a usable Windows desktop session and that the plugin was reloaded from the updated marketplace entry. The MCP call will fail closed rather than run silently. Every command still requires a separate approval and remains subject to the configured host fingerprint, timeout, and output limit.

### Timeout limitation

The bundled `.mcp.json` sets the client's tool timeout to 60 seconds, while local approval can wait up to 120 seconds and an SSH command can run for up to 300 seconds, plus connection time. The server does not currently handle MCP cancellation notifications. A client timeout therefore does not prove that execution stopped: a pending local approval or an already approved command may still continue. Close any pending approval window and verify the operation's outcome before retrying. When configuring a client for long operations, budget for approval, connection, and execution time together; changing a timeout does not add cancellation support.

## Checks

From the repository root, run:

```powershell
python -u -m unittest discover -s tests -v
```

Expected result: all 32 tests pass. The tests use temporary local MCP stdio processes, example configuration, and mocked adapters. They do not connect to SSH, SMTP, or PostgreSQL. If imports fail, confirm the active Python version and dependencies; if the stdio test fails, inspect the assertion and subprocess exit status. A successful local validation does not prove that a remote host is reachable or that its credentials are configured. The current suite does not verify all output truncation, command timeout, and fingerprint mismatch paths.

For a manual connection check, first configure a trusted test host and its pinned fingerprint in the local manager. In Codex, call `bridge_status`, then `ssh_connect` using that alias and approve the local authentication prompt. Expect `connected: true` and `remote_command_executed: false`. To check command execution, request a read-only command supported by that test host and approve the exact command in the window; expect its bounded output and exit code. On failure, check the selected configuration path, independently verified fingerprint, Credential Manager reference, and network access before another attempt. These manual checks contact the configured host and are separate from the automated tests.

## Important security boundary

This bridge keeps credentials out of its MCP schemas and results, but Windows Credential Manager entries remain accessible to software running as the same Windows user. A local MCP plugin alone cannot guarantee that a model or another shell-capable tool can never access them directly. For that stronger threat model, host the adapters and secrets under a separate restricted Windows service identity and expose an ACL-protected local IPC endpoint with the same allowlists, limits, and approvals.
