# Secure Credential Bridge

A local Codex MCP plugin for recognized read-only SSH queries without per-call prompts, Chinese-purpose confirmation for other SSH commands, optional all-command preauthorization for explicitly configured test host aliases, reviewed SMTP delivery, and named read-only PostgreSQL queries. Credentials are stored in Windows Credential Manager and are never a tool result. This local stdio process does **not** isolate itself from other software running as the same Windows user.

## Contents

- `.codex-plugin/plugin.json` — Codex plugin metadata.
- `.mcp.json` — starts the local stdio MCP server.
- `mcp/server.py` — tool protocol, per-alias SSH approval policies, adapter allowlists, TLS, confirmation gates, limits, and redacted errors.
- `mcp/command_policy.py` — conservative POSIX/Linux command and argument allowlist for prompt-free queries.
- `mcp/approval_intent.py` — shared Chinese intent validation; intent never determines command classification.
- `config/bridge.example.json` — non-secret configuration example; copy to `config/bridge.json` and replace every example endpoint/fingerprint.
- `scripts/manage_credential.py` — hidden-prompt storage/removal in Windows Credential Manager.
- `scripts/ssh_manager_gui.py` — local Tkinter window for editing SSH hosts, environment and approval policy, a color-coded policy list, SSH credential management, and the running plugin version.
- `scripts/approval_proxy.py` — one-shot local confirmation window with red bold Chinese intent and the full target/command; UTF-8 JSON over stdin/stdout, with no credential access.
- `scripts/requirements.txt` — Paramiko SSH and Psycopg PostgreSQL adapters.
- `skills/secure-credential-bridge/SKILL.md` — tool-use and security instructions for Codex.
- `skills/scb-setup/` — the Codex plugin setup entry, named **打开 SCB 配置**, which opens the bundled local manager without connecting to SSH.
- `tests/` — command-policy regressions, mocked SSH/approval/UI integration, configuration, draft, and stdio protocol checks; no external services or real approval windows.
- `.gitignore` — excludes local connection configuration, credentials, private keys, caches, and logs from Git.

## Setup

### Open configuration from Codex

Version **0.1.8** adds the **打开 SCB 配置** skill to the plugin details and declares `onboardingSkill: "scb-setup"` for Codex clients that support that setup action. Selecting the skill or the plugin's first example action lets Codex open the native local configuration window without a manually written prompt. Submit the prepared prompt if the client requires it. This is a Codex-assisted flow, not a custom native toolbar button or an SSH connection check.

Local verification with the app's `0.166.0-alpha.5.1` backend confirms that the enabled setup skill and first example action are returned by `plugin/read`. That backend reports `onboardingSkill: null`, so a separate native setup button is not established for this client; use the visible skill/example entry instead. Other clients may expose the declared setup action. After updating, refresh the plugin details; reload the plugin or reopen Codex if its cached metadata still shows the previous version. The window continues to read the installed configuration, with `SCB_CONFIG` taking precedence. No host, key, passphrase, or approval policy is changed merely by opening setup.

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

Without `SCB_CONFIG`, the window prefers the newest installed copy under the `personal` marketplace cache, then falls back to the checkout's `config\bridge.json`. For another marketplace, set `SCB_CONFIG` or choose its actual configuration file in the UI. Add or import a host and verify its SHA-256 fingerprint using a trusted source. Click **测试连接并保存密码/口令** to enter the password or key passphrase, including when setting up password authentication for the first time; both fields are masked until **显示口令** is enabled. The GUI verifies the pinned host fingerprint and SSH authentication without running a remote command. On success it saves the secret to the current Windows user's Credential Manager and saves the host configuration and credential reference; failed tests do not save the entered secret. Secrets are never written to JSON. Host configuration is reread on each tool call, so saved settings can be used immediately in the current Codex thread. Remote commands are supplied through Codex. Recognized read-only commands run directly; other commands display the Chinese purpose and full target/command for confirmation unless the selected test alias has explicit all-command preauthorization.

The same GUI can also be launched from PowerShell with `py -3` if `pyw` is unavailable. The UI does not start a web server or background service.

Since **0.1.9**, the configuration window shows its version in both the title bar and the upper-right corner. It reads the version from the running manager's own `.codex-plugin/plugin.json`, independently of the selected host configuration file; missing or invalid version metadata displays **未知**. Close and reopen an older configuration window after updating to see the new version display.

### Xshell public-key authentication and private-key passphrases

Xshell's **Public Key** method uses a private key plus its optional passphrase. That passphrase unlocks the local private key; it is not the server account's login password. In SCB, edit the host, select **私钥**, choose the same private key used by Xshell, and enable **私钥有口令** if it is encrypted. Then use **测试连接并保存密码/口令** to enter the key passphrase locally. Selecting **密码** instead sends a server login password and does not use the Xshell key.

SCB accepts private keys that Paramiko can load in OpenSSH or PEM format. A key name in Xshell is not a file path, and a `.pub` file is a public key, not a private key. If an Xshell-managed key is in an incompatible format, export that selected key to OpenSSH format from Xshell and keep the exported private key local. Do not paste a private key or passphrase into chat, and do not change the verified host fingerprint just to make authentication pass.

Version **0.1.7** fixes encrypted-key loading for GUI tests, `ssh_connect`, and SSH command execution by passing UTF-8 passphrase bytes to Paramiko's key loader. Invalid formats and incorrect passphrases produce a redacted key-specific error instead of an opaque generic failure. This change does not enable agent/key discovery or fall back from key authentication to password authentication. `tests/test_private_key_auth.py` exercises locally generated encrypted/unencrypted keys with mocked SSH clients; it does not access real credentials or remote hosts.

### Discover, test, and operate over SSH from Codex

Call `ssh_connect` with a local SSH alias, or omit it only when exactly one host is configured. Tool arguments accept aliases only; endpoint, username, passwords, and private keys stay in local configuration or Windows Credential Manager. If the alias is not configured, the tool reads literal `Host` aliases from the current Windows user's `~/.ssh/config` and opens the local manager with a matching alias prefilled. `ssh_discover_hosts` returns alias names only. Neither tool scans a subnet. Discovery does not resolve `Include`/`Match exec`/proxy directives, read credentials, or return endpoint, username, or private-key paths.

`ssh_connect` only tests authentication to one selected host; it never runs a remote command. Since version 0.1.4, it requires no per-call approval for this connection-only check and still verifies the pinned SHA-256 host-key fingerprint before authentication. If authentication/network verification fails, it opens the SSH manager with that alias prefilled. Confirm the fingerprint from a trusted independent source, save the host configuration and password/passphrase in Windows Credential Manager, then call `ssh_connect` again. The current call does not resume automatically after the GUI closes, and it never falls back to trying other hosts.

`ssh_read_command` is the preferred inspection tool. It accepts `alias`, `command`, and optional `timeout_seconds`, advertises `readOnlyHint: true`, and never requests confirmation. It rejects unsupported or modifying commands before credential access or SSH connection. The host client still controls its own tool permission policy.

`ssh_run_command` accepts `alias`, `command`, optional `timeout_seconds` (1–300), and `intent_zh`. The server independently classifies the entire command before accessing credentials or opening a connection. Supported read-only queries execute directly. Everything else requires a valid Chinese intent and, by default, confirmation. An alias explicitly configured for test-host preauthorization skips the per-call confirmation only; see the policy section below. In local mode the intent appears in **red bold Chinese text**, followed by the full target, reason for confirmation, timeout, and original command. When confirmation is required, only **确认并执行** permits the command to proceed. The intent is caller-provided context, not a guarantee: review the command itself. Secrets must never appear in either field. Unsupported arguments such as `skip_approval` are rejected.

Host/credential configuration is reread on each tool call. Changed code and tool schemas require an installed update and MCP reload; editing the skill alone cannot alter a running older server.

### Per-host SSH approval policy in 0.1.5

Each configured alias has two policy choices in the local SSH manager. The list displays the policy name as well as its color:

| GUI policy | Configuration value | List color | Behavior |
| --- | --- | --- | --- |
| 写操作确认 | `confirm_writes` (default) | Blue | Recognized read-only commands run directly; writes and unknown commands require confirmation. |
| 全部操作预授权 | `test_all_commands` | Orange | All commands through `ssh_run_command` run without per-call confirmation for this test alias. |

`environment` accepts exactly `unspecified` (default), `test`, or `production`. The all-command policy requires `environment: "test"`; production, unspecified, misspelled, and non-string values fail configuration validation. Alias names and addresses never imply a test environment. These fields belong inside one entry in `ssh_hosts`, alongside its existing pinned connection details; they are not global settings or tool arguments.

The checked-in example remains **写操作确认**. No existing host is automatically enabled or migrated. To opt in later, select the intended alias in the local manager, choose the test environment and **全部操作预授权**, then save configuration. Equivalently, merge these fields into that existing host entry:

```json
{
  "environment": "test",
  "approval_policy": "test_all_commands"
}
```

The manager defaults newly added/imported hosts to **写操作确认**, preserves an unchanged host's selected policy, and resets preauthorization when its alias, address, port, username or fingerprint changes. After such an edit, explicitly reselect preauthorization if appropriate. Switching away from the test environment also resets the policy. Saving the form alone still requires the manager's **保存配置** to persist it.

This policy includes writes, deployments, restarts, deletions, scripts and commands of unknown effect, within the configured SSH account's permissions. It is selected locally for a specific host; `intent_zh` and caller-supplied flags never enable it. It does not expand the user's requested task scope. Non-read-only commands still require an accurate Chinese `intent_zh`. The returned `approval_basis` is `host_preauthorized` for those commands, `read_only` for recognized queries, or `user_confirmation` after per-call approval. A preauthorized write still reports `read_only: false` and `approval_required: false`.

`ssh_read_command` continues to reject writes/unknown commands on every host. SSH fingerprint checks, timeout/output bounds, email-send confirmation, and PostgreSQL restrictions remain enforced. The host application may apply its own tool permission rules; this setting controls SCB's confirmation gate only.

After installing/reloading 0.1.5, policy saves and revocations take effect for the next tool call. Check `bridge_status.ssh_host_policies` to see the effective per-alias policy without exposing connection details. A policy change does not cancel calls already in progress. Do not install or enable a test policy as part of an unrelated task.

### Read-only command classification

The exemption targets known Linux/POSIX utility semantics on trusted configured hosts. It is deliberately narrower than every possible read-only operation. Examples:

```json
{"alias":"staging","command":"df -h"}
{"alias":"staging","command":"docker ps"}
{"alias":"staging","command":"docker logs --tail 100 app | grep -F ERROR"}
{"alias":"staging","command":"systemctl status app --no-pager"}
```

The parser checks every stage of supported `|`, `&&`, `||`, semicolon, and newline command lists, preserving quoted arguments and operator semantics. Single-quoted regular expressions and literal backslashes are supported. Unsupported shell syntax, substitutions, unquoted expansion, redirections, unknown commands/options, interpreters (`python`, `sh -c`), API calls (`curl`), and arbitrary SQL over SSH fall back to the selected host approval policy (confirmation by default). A harmless-looking first command cannot exempt a later modifying stage. The exact allowlist lives in `mcp/command_policy.py`; no caller-supplied boolean can bypass it.

Use a Chinese single-line `intent_zh` (1–500 characters, no invisible control characters) for other commands, including observational scripts the policy cannot establish as read-only:

```json
{"alias":"staging","command":"systemctl restart app","intent_zh":"重启应用服务，使配置生效；服务会短暂中断。"}
```

This is an example for a trusted test environment, not a recommendation to restart production. Missing/invalid intent returns an error before authentication or execution. A correct intent does not automatically approve the command. Rejecting or closing confirmation prevents it from running. The result reports `read_only`, `approval_required`, `approval_basis`, `environment`, and `approval_policy`, plus the validated `intent_zh` when provided. These describe classification and authorization, not proof of all remote effects.

The server automatically prepends `--no-pager` to supported `systemctl` / `journalctl` queries and `--no-config` to supported `rg` searches, including inside supported `sudo -n` and `docker exec` wrappers. Results include both `command` and `executed_command` so the exact query is visible. Commands requiring approval run exactly as shown in their confirmation window.

The expanded list covers bounded file/log searches, read-only `find` predicates, `ss`, `ip show/list/get`, disk/process/hardware status, checksums, `file`, stdout-only `sort`/`cut`/`tr`, string `printf`, file tests, temporary shell `cd`, and selected Docker network/volume/container/image queries. Sorting may use temporary scratch space without changing source files. `find -delete/-exec/-fprint`, `ss -K`, `ip` changes, output-file flags/redirection, `printf -v/%n`, service changes, arbitrary scripts, and unknown flags require confirmation under the default host policy. Git remains outside the read-only exemption because hooks, filters, signature helpers, and lazy fetches can cause changes even in nominal queries. Keep diagnostics relevant and bounded; an exemption does not authorize reading secrets or unrelated sensitive data.

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

The plugin's `.mcp.json` selects the local approval mode (`SCB_APPROVAL_MODE=local`); SSH commands requiring confirmation under their host policy and all email sends start a separate visible `approval_proxy.py` process. The command proceeds only after you click **确认并执行** in that window. Closing it, denying it, timing out, running without a desktop session, or failing to start all stop the action. This is the plugin's local approval boundary, not a Codex-native approval dialog and not an OS isolation boundary. No service or background daemon is required.

## Tools and limits

- `bridge_status`: configured alias and query names, plus `ssh_host_policies` (environment and approval policy by alias); no endpoints, account names, private-key paths, credential references or values.
- `ssh_discover_hosts`: read-only enumeration of explicit local OpenSSH aliases; no network access or credential access.
- `ssh_connect`: prompt-free, fingerprint-pinned authentication test selected by local alias; the alias can be omitted only when a single configured host is available; no endpoint or username input; no remote command.
- `ssh_read_command`: preferred prompt-free query entry point with accurate read-only MCP annotations; rejects changes and unsupported commands before credentials/network access.
- `ssh_run_command`: runs a caller-supplied command on one configured host pinned by SHA-256 host-key fingerprint; supported read-only queries skip approval; all others require `intent_zh` and follow the configured per-alias policy: confirmation of the exact target/command by default, or explicit test-host preauthorization.
- `email_create_draft`: exact recipient allowlist; draft is memory-only for 10 minutes and is never sent by this tool.
- `email_send_draft`: displays recipient, subject, full body, and content SHA-256 in the selected approval UI; in bundled local mode this is the one-shot local approval window. The draft is consumed once. SMTP must use STARTTLS or implicit TLS. Ambiguous delivery is not retried automatically.
- `postgres_query`: only named parameterized `SELECT`/`WITH` queries; read-only transaction, statement timeout, 500-row and 32 KB output caps. Use server-side least-privilege grants as well.

Required approval is fail-closed: if its process cannot display a decision, that command/email action does not proceed. Allowlisted queries, connection-only checks, and general SSH commands for preauthorized test aliases do not invoke the approval UI. The approval process receives only the human-readable operation description and optional Chinese intent; it does not read Credential Manager, authenticate, or execute SSH/email operations. Credential resolution requires the current process to run on Windows under the same account that stored the Credential Manager entry. Set `SCB_APPROVAL_MODE=native` only if the MCP client is known to support elicitation; `auto` uses native elicitation when advertised and otherwise falls back to the local proxy. Native mode includes the Chinese intent in text, but font color is controlled by the client; use the bundled `local` mode for the red warning.

Older `bridge.json` files may still contain an `ssh_actions` section. The updated plugin accepts that field for compatibility but ignores it; the former fixed-action tool is no longer registered or callable.

No window is expected for supported read-only queries or explicitly preauthorized test aliases. If a command requiring confirmation fails to show a window, check its alias policy in `bridge_status`, `intent_zh`, the loaded version/schema, `SCB_APPROVAL_MODE`, and Python desktop/Tk availability; required confirmation fails closed. All commands remain subject to host pinning, timeout and output limits.

### Timeout limitation

The bundled `.mcp.json` sets the client's tool timeout to 60 seconds, while local approval can wait up to 120 seconds and an SSH command can run for up to 300 seconds, plus connection time. The server does not currently handle MCP cancellation notifications. A client timeout therefore does not prove that execution stopped: a pending local approval or an already approved command may still continue. Close any pending approval window and verify the operation's outcome before retrying. When configuring a client for long operations, budget for approval, connection, and execution time together; changing a timeout does not add cancellation support.

## Checks

From the repository root, run:

```powershell
python -u -m unittest discover -s tests -v
```

Expected result: the full suite passes. Tests also cover strict per-alias policy validation, preauthorized writes, alias isolation, revocation on the next call, default confirmation, GUI policy persistence/reset and list colors. Tests use example configuration, temporary stdio processes and mocked adapters/Tk; they never contact SSH, SMTP or PostgreSQL, and never click a real approval window. They cover read-only routing, intent validation, approval refusal, pinned-host mismatch, command/output preservation, UTF-8 approval transport, and red/bold UI properties. These are not a real GUI display or production connectivity test. If imports fail, check Python and dependencies; if the stdio test fails, inspect its subprocess/assertion output.

For manual acceptance after installing and reloading **0.1.5**, use an independently verified, trusted test host initially set to **写操作确认** (`confirm_writes`):

1. Call `bridge_status`, then `ssh_connect` with its configured alias. Expect no approval popup, `connected: true`, and `remote_command_executed: false`.
2. Call `ssh_read_command` with `df -h`, `systemctl status app`, or `rg ERROR /var/log/app.log`. Expect no popup and a bounded result containing `read_only: true` / `approval_required: false`.
3. Submit `sh -c 'printf test'` through `ssh_run_command` with `intent_zh: "输出测试文本，验证未识别脚本的审批提示。"`. This harmless example uses a shell wrapper that is intentionally outside the allowlist. Expect the red bold Chinese purpose and complete original command. Click **拒绝**; expect a declined error and no remote execution. Repeat only when you intentionally want to test acceptance, then confirm and expect `test` in stdout.
4. Submit that shell wrapper through `ssh_read_command`: expect rejection without a popup or connection. Omit the intent through `ssh_run_command`: expect a validation error with no connection or popup. A malformed intent is not silently accepted.
5. In the local manager, explicitly enable **全部操作预授权** on that test alias and save. Expect an orange list row and the matching `bridge_status.ssh_host_policies` entry. Run the same harmless shell wrapper with Chinese intent through `ssh_run_command`; expect `test`, no SCB popup, `read_only: false`, `approval_required: false`, and `approval_basis: "host_preauthorized"`. The read-only tool must still reject it.
6. Restore **写操作确认** and save. Expect a blue row and the next wrapper call to request confirmation again; decline it to avoid execution. Other aliases must retain their own policies. Editing the endpoint or switching to production must reset the GUI policy. These optional manual steps are not part of the offline suite.

On failure, distinguish missing intent / unknown syntax / stale schema / unavailable desktop from network or credential problems. Check the active configuration path, independently verified fingerprint, Credential Manager reference and network access. Do not paste secrets into logs/chat. These manual checks contact only the host you select and are separate from the automated tests.

Rollback: to revoke preauthorization, save `approval_policy: "confirm_writes"`; new calls then require confirmation for writes/unknown commands. Already running calls are not cancelled. Before reverting to 0.1.4, remove the new `environment` and `approval_policy` host fields, because that version rejects them. Keep the previous installed build and local configuration intact; switch back to the previous build and reload its MCP connection if necessary. Do not delete configuration or Credential Manager entries to roll back code. Before a marketplace update, preserve the active installed `config/bridge.json` and copy it unchanged into the new version if the installer does not migrate it; leave Windows Credential Manager entries untouched. Current sessions may retain the old schema until reload; do not treat a successful install as a verified live connection.

## Important security boundary

This bridge keeps credentials out of its MCP schemas and results, but Windows Credential Manager entries remain accessible to software running as the same Windows user. A local MCP plugin alone cannot guarantee that a model or another shell-capable tool can never access them directly. For that stronger threat model, host the adapters and secrets under a separate restricted Windows service identity and expose an ACL-protected local IPC endpoint with the same allowlists, limits, and approvals.
