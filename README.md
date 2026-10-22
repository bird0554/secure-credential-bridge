# Secure Credential Bridge

A local Codex MCP plugin for recognized read-only SSH queries without per-call prompts, other SSH commands with explicit Chinese-purpose confirmation, reviewed SMTP delivery, and named read-only PostgreSQL queries. Credentials are stored in Windows Credential Manager and are never a tool result. This local stdio process does **not** isolate itself from other software running as the same Windows user.

## Contents

- `.codex-plugin/plugin.json` — Codex plugin metadata.
- `.mcp.json` — starts the local stdio MCP server.
- `mcp/server.py` — tool protocol, adapter allowlists, TLS, confirmation gates, limits, and redacted errors.
- `mcp/command_policy.py` — conservative POSIX/Linux command and argument allowlist for prompt-free queries.
- `mcp/approval_intent.py` — shared Chinese intent validation; intent never determines command classification.
- `config/bridge.example.json` — non-secret configuration example; copy to `config/bridge.json` and replace every example endpoint/fingerprint.
- `scripts/manage_credential.py` — hidden-prompt storage/removal in Windows Credential Manager.
- `scripts/ssh_manager_gui.py` — local Tkinter window for editing SSH hosts and managing SSH credentials.
- `scripts/approval_proxy.py` — one-shot local confirmation window with red bold Chinese intent and the full target/command; UTF-8 JSON over stdin/stdout, with no credential access.
- `scripts/requirements.txt` — Paramiko SSH and Psycopg PostgreSQL adapters.
- `skills/secure-credential-bridge/SKILL.md` — tool-use and security instructions for Codex.
- `tests/` — command-policy regressions, mocked SSH/approval/UI integration, configuration, draft, and stdio protocol checks; no external services or real approval windows.
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

Without `SCB_CONFIG`, the window prefers the newest installed copy under the `personal` marketplace cache, then falls back to the checkout's `config\bridge.json`. For another marketplace, set `SCB_CONFIG` or choose its actual configuration file in the UI. Add or import a host, verify its SHA-256 fingerprint using a trusted source, then save the configuration. Use **Save password/passphrase** to store authentication in the current Windows user's Credential Manager. The GUI does not store secrets in JSON. Host configuration is reread for each tool call, so saving a host or credential can be followed immediately by a call in the current Codex thread. The separate **Test connection** button checks authentication but runs no remote command. Remote commands are supplied through Codex. Recognized read-only commands run directly; other commands display the Chinese purpose and full target/command for confirmation.

The same GUI can also be launched from PowerShell with `py -3` if `pyw` is unavailable. The UI does not start a web server or background service.

### Discover, test, and operate over SSH from Codex

Call `ssh_connect` with a local SSH alias, or omit it only when exactly one host is configured. Tool arguments accept aliases only; endpoint, username, passwords, and private keys stay in local configuration or Windows Credential Manager. If the alias is not configured, the tool reads literal `Host` aliases from the current Windows user's `~/.ssh/config` and opens the local manager with a matching alias prefilled. `ssh_discover_hosts` returns alias names only. Neither tool scans a subnet. Discovery does not resolve `Include`/`Match exec`/proxy directives, read credentials, or return endpoint, username, or private-key paths.

`ssh_connect` only tests authentication to one selected host; it never runs a remote command. Version 0.1.3 requires no per-call approval for this connection-only check and still verifies the pinned SHA-256 host-key fingerprint before authentication. If authentication/network verification fails, it opens the SSH manager with that alias prefilled. Confirm the fingerprint from a trusted independent source, save the host configuration and password/passphrase in Windows Credential Manager, then call `ssh_connect` again. The current call does not resume automatically after the GUI closes, and it never falls back to trying other hosts.

`ssh_run_command` accepts `alias`, `command`, optional `timeout_seconds` (1–300), and `intent_zh`. The server independently classifies the entire command before accessing credentials or opening a connection. Supported read-only queries execute directly. Everything else requires a valid Chinese intent and confirmation. In local mode the intent appears in **red bold Chinese text**, followed by the full target, reason for confirmation, timeout, and original command. Only **确认并执行** permits such a command to proceed. The intent is caller-provided context, not a guarantee: review the command itself. Secrets must never appear in either field. Unsupported arguments such as `skip_approval` are rejected.

Host/credential configuration is reread on each tool call. Changed code and tool schemas require an installed update and MCP reload; editing the skill alone cannot alter a running 0.1.2 server.

### Read-only exemption in 0.1.3

The exemption targets known Linux/POSIX utility semantics on trusted configured hosts. It is deliberately narrower than every possible read-only operation. Examples:

```json
{"alias":"staging","command":"df -h"}
{"alias":"staging","command":"docker ps"}
{"alias":"staging","command":"docker logs --tail 100 app | grep -F ERROR"}
{"alias":"staging","command":"systemctl status app --no-pager"}
```

The parser checks every stage of supported `|` / `&&` chains, preserving quoted arguments. Unsupported shell syntax, substitutions, unquoted expansion, redirections, unknown commands/options, interpreters (`python`, `sh -c`), API calls (`curl`), and arbitrary SQL over SSH fall back to confirmation. A harmless-looking first command cannot exempt a later modifying stage. The exact allowlist lives in `mcp/command_policy.py`; no caller-supplied boolean can bypass it.

Use a Chinese single-line `intent_zh` (1–500 characters, no invisible control characters) for other commands, including observational scripts the policy cannot establish as read-only:

```json
{"alias":"staging","command":"systemctl restart app","intent_zh":"重启应用服务，使配置生效；服务会短暂中断。"}
```

This is an example for a trusted test environment, not a recommendation to restart production. Missing/invalid intent returns an error before authentication or execution. A correct intent does not automatically approve the command. Rejecting or closing confirmation prevents it from running. The result adds `read_only` and `approval_required`, which report policy classification rather than proof of all remote effects.

Require explicit `--no-pager` for supported `systemctl` / `journalctl` queries and `--no-config` for supported `rg` searches. Unknown flags stay behind approval. Common bounded `head`, `tail`, disk/process queries, selected Docker queries and recursively supported `docker exec` queries are covered. Follow-mode logs, arbitrary shell wrappers, and normal `sort` (which may spill to temporary files) are not exempt. Keep diagnostics relevant and bounded; an exemption does not authorize reading secrets or unrelated sensitive data.

This policy assumes trusted remote utilities, PATH, shell startup files, and container binaries. It is not a sandbox and cannot prove that a replaced executable, device/proc file, alias, or remote environment has no side effects. Normal login/access audit logs and metadata updates can still occur.

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

The plugin's `.mcp.json` selects the local approval mode (`SCB_APPROVAL_MODE=local`); commands outside the read-only allowlist and email sends start a separate visible `approval_proxy.py` process. The command proceeds only after you click **确认并执行** in that window. Closing it, denying it, timing out, running without a desktop session, or failing to start all stop the action. This is the plugin's local approval boundary, not a Codex-native approval dialog and not an OS isolation boundary. No service or background daemon is required.

## Tools and limits

- `bridge_status`: configured host and query names only; no credential metadata/value.
- `ssh_discover_hosts`: read-only enumeration of explicit local OpenSSH aliases; no network access or credential access.
- `ssh_connect`: prompt-free, fingerprint-pinned authentication test selected by local alias; the alias can be omitted only when a single configured host is available; no endpoint or username input; no remote command.
- `ssh_run_command`: runs a caller-supplied command on one configured host pinned by SHA-256 host-key fingerprint; supported read-only queries skip approval; all others require `intent_zh` and confirmation of the exact target and command.
- `email_create_draft`: exact recipient allowlist; draft is memory-only for 10 minutes and is never sent by this tool.
- `email_send_draft`: displays recipient, subject, full body, and content SHA-256 in the selected approval UI; in bundled local mode this is the one-shot local approval window. The draft is consumed once. SMTP must use STARTTLS or implicit TLS. Ambiguous delivery is not retried automatically.
- `postgres_query`: only named parameterized `SELECT`/`WITH` queries; read-only transaction, statement timeout, 500-row and 32 KB output caps. Use server-side least-privilege grants as well.

Required approval is fail-closed: if its process cannot display a decision, that command/email action does not proceed. Allowlisted queries and connection-only checks do not invoke the approval UI. The approval process receives only the human-readable operation description and optional Chinese intent; it does not read Credential Manager, authenticate, or execute SSH/email operations. Credential resolution requires the current process to run on Windows under the same account that stored the Credential Manager entry. Set `SCB_APPROVAL_MODE=native` only if the MCP client is known to support elicitation; `auto` uses native elicitation when advertised and otherwise falls back to the local proxy. Native mode includes the Chinese intent in text, but font color is controlled by the client; use the bundled `local` mode for the red warning.

Older `bridge.json` files may still contain an `ssh_actions` section. The updated plugin accepts that field for compatibility but ignores it; the former fixed-action tool is no longer registered or callable.

No window is expected for supported read-only queries. If a command outside the allowlist fails to show a window, check its `intent_zh`, the loaded version/schema, `SCB_APPROVAL_MODE`, and Python desktop/Tk availability; required confirmation fails closed. All commands remain subject to host pinning, timeout and output limits.

### Timeout limitation

The bundled `.mcp.json` sets the client's tool timeout to 60 seconds, while local approval can wait up to 120 seconds and an SSH command can run for up to 300 seconds, plus connection time. The server does not currently handle MCP cancellation notifications. A client timeout therefore does not prove that execution stopped: a pending local approval or an already approved command may still continue. Close any pending approval window and verify the operation's outcome before retrying. When configuring a client for long operations, budget for approval, connection, and execution time together; changing a timeout does not add cancellation support.

## Checks

From the repository root, run:

```powershell
python -u -m unittest discover -s tests -v
```

Expected result: the full suite passes. Tests use example configuration, temporary stdio processes and mocked adapters/Tk; they never contact SSH, SMTP or PostgreSQL, and never click a real approval window. They cover read-only routing, intent validation, approval refusal, pinned-host mismatch, command/output preservation, UTF-8 approval transport, and red/bold UI properties. These are not a real GUI display or production connectivity test. If imports fail, check Python and dependencies; if the stdio test fails, inspect its subprocess/assertion output.

For manual acceptance after installing and reloading **0.1.3**, use an independently verified, trusted test host:

1. Call `bridge_status`, then `ssh_connect` with its configured alias. Expect no approval popup, `connected: true`, and `remote_command_executed: false`.
2. Call `ssh_run_command` with `df -h`. Expect no popup and a bounded result containing `read_only: true` / `approval_required: false`.
3. Submit `printf test` with `intent_zh: "输出测试文本，验证非允许列表命令的审批提示。"`. This harmless command is intentionally outside the allowlist. Expect the red bold Chinese purpose and complete original command. Click **拒绝**; expect a declined error and no remote execution. Repeat only when you intentionally want to test acceptance, then confirm and expect `test` in stdout.
4. Omit the intent for that same command: expect a validation error with no connection or popup. A malformed intent is not silently accepted.

On failure, distinguish missing intent / unknown syntax / stale schema / unavailable desktop from network or credential problems. Check the active configuration path, independently verified fingerprint, Credential Manager reference and network access. Do not paste secrets into logs/chat. These manual checks contact only the host you select and are separate from the automated tests.

Rollback: keep the previous installed build and local configuration intact; switch back to the previous build and reload its MCP connection if necessary. Do not delete configuration or Credential Manager entries to roll back code. Current sessions may retain the old schema until reload; do not treat a successful install as a verified live connection.

## Important security boundary

This bridge keeps credentials out of its MCP schemas and results, but Windows Credential Manager entries remain accessible to software running as the same Windows user. A local MCP plugin alone cannot guarantee that a model or another shell-capable tool can never access them directly. For that stronger threat model, host the adapters and secrets under a separate restricted Windows service identity and expose an ACL-protected local IPC endpoint with the same allowlists, limits, and approvals.
