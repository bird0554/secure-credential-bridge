---
name: secure-credential-bridge
description: Use the local Secure Credential Bridge MCP tools for preconfigured SSH connections, recognized read-only SSH queries without per-call prompts, and approved remote changes or explicitly preauthorized test-host commands without exposing credentials. Also covers its optional allowlisted email and read-only PostgreSQL adapters.
---

# Secure Credential Bridge

Use this skill when the user wants Codex to connect to a remote machine or run a remote maintenance operation through the local bridge.

## SSH workflow

1. Call `bridge_status` to see configured host names. It reports names, readiness, and `ssh_host_policies` (per-alias environment and approval policy), without endpoints or credentials.
2. If the local alias is unknown, call `ssh_discover_hosts`. This returns alias names only, reads the local OpenSSH config, and makes no network connection.
3. When a connection check is needed, call `ssh_connect` with one local alias. Reuse a successful check within the current task instead of repeating it before every query. Host addresses and usernames are never accepted as tool arguments. Version 0.1.5 authenticates to one fingerprint-pinned host without a per-call approval prompt and runs no remote command. If setup is missing, the local SSH manager opens so the human can configure it outside Codex.
4. Classify the complete operation using the rules below. Prefer `ssh_read_command` with the configured alias and requested command for supported inspection: it is marked read-only and never opens a confirmation dialog. Unsupported or modifying commands are rejected before credentials/network access. Use `ssh_run_command` with `intent_zh` for changes or unsupported commands; the default policy requires explicit confirmation. Only a locally configured test alias with `environment: "test"` and `approval_policy: "test_all_commands"` skips per-call SSH confirmation. For clearly read-only queries within the user's requested scope, proceed directly without asking for another conversational confirmation. The plugin independently checks the entire command; an assistant statement that it is read-only does not grant an exemption. For a changing or unsupported command, include `intent_zh`: a concise Chinese sentence describing its actual purpose and impact. When required by the host policy, the local confirmation window shows that sentence in red bold type, plus the full target and original command. Do not add an extra conversational confirmation when the user has already authorized the operation; the plugin applies that alias's configured confirmation policy.

Treat a failed or denied call as final for that attempt. Do not guess another host, retry repeatedly, bypass the approval window, or fall back to direct shell/SSH commands. Never put passwords, tokens, or other secrets in remote command arguments because command text is displayed and may be returned in logs/results.

Use only the bridge's configured MCP tools. Host addresses and usernames are stored in the local bridge configuration, and passwords/key passphrases are stored in Windows Credential Manager. Never ask the user to paste an address, username, password, token, private key, or database connection string into chat or tool arguments.

## Capabilities and approval

- `bridge_status` reports configured SSH aliases, their environment/approval policy, and database query names; no endpoint, username, private-key path, or credential reference/value.
- `ssh_read_command` accepts only `alias`, `command`, and optional `timeout_seconds`. Its read-only classification is enforced by the server; never silently retry a rejection through the general tool to avoid user review.
- `ssh_run_command` accepts a command for one configured host, with a 300-second timeout ceiling and bounded output. Apply the read-only policy below instead of requesting confirmation solely because a command runs remotely.
- `email_create_draft` accepts only an exact allowlisted recipient and does not send. `email_send_draft` displays the complete recipient, subject, body, and digest in the configured local approval window before sending. Confirm the digest corresponds to that draft. Delivery failures are not retried automatically; verify the mailbox first because SMTP may have accepted a message before the connection failed.
- `postgres_query` accepts only a configured query name and its declared parameters. Execute permitted read-only queries within the requested scope without additional conversational confirmation. Do not propose arbitrary SQL to bypass the allowlist.

### Read-only queries

The user's request to inspect or diagnose the selected environment authorizes the necessary read-only queries. Do not ask "may I run this query?" before each command, including in production, when the target and scope are already clear. Brief progress updates are sufficient.

Read-only means observing existing state without intentionally changing remote files, configuration, business data, running services, or task execution. Examples include bounded log searches, process and disk status, `docker ps`, `systemctl status nginx --no-pager`, reading relevant non-secret configuration, and configured read-only database queries. Normal access logs generated by a query do not make it a write operation.

Evaluate the whole command and its arguments, every pipeline stage, shell substitution, script, and API call. A command name such as `cat`, `SELECT`, or an HTTP `GET` method alone is insufficient evidence. Writes, output redirection to remote files, restarts, deployment, deletion, task retries/requeues, email delivery, and calls with unknown side effects do not qualify. For mixed operations, run the independent read-only part first when useful, and route the changing part through the general tool under the configured host policy. Inspect unknown scripts or command semantics before classifying them; if the side effects remain unclear, do not classify the operation as read-only. Unknown commands still follow the selected host policy.

Keep queries bounded and relevant to the user's task. The read-only exception does not authorize retrieving passwords, tokens, private keys, or unrelated sensitive data. Mutating operations follow the explicit per-alias approval policy below.

### Host-alias preauthorization

The local host manager has two explicit policies: **写操作确认** (`confirm_writes`, blue list entry) and **全部操作预授权** (`test_all_commands`, orange list entry). Unspecified/legacy configurations default to confirmation for writes and unknown commands. All-command preauthorization is valid only when the same alias has `environment: "test"`; no alias spelling, endpoint, command intent or caller argument establishes that policy. Other environments (`production` and `unspecified`) cannot use it.

When the user has enabled preauthorization for the selected test alias, execute requested SSH operations through `ssh_run_command` without asking for another per-call confirmation, including writes, scripts and unknown commands. Continue supplying an accurate Chinese `intent_zh` for every non-read-only command. The result records `approval_basis: "host_preauthorized"`, `approval_required: false`, and truthful command classification. This is configured prior authorization, not a read-only classification or a grant for unrelated tasks.

Do not enable or change a host's policy unless the user requests that configuration change. No current alias is automatically opted in. The GUI resets preauthorization on changes to alias/endpoint/account/fingerprint or on leaving the test environment; the user can explicitly select it again after the edit. Read `bridge_status` to check the active policy; saved changes apply to the next tool call and do not cancel in-flight operations.

`ssh_read_command` always rejects writes and unknown commands, even on preauthorized test hosts. Host pinning, execution limits, email-send confirmation and named read-only PostgreSQL restrictions are unaffected. Never bypass a refused call by changing configuration, using direct SSH or inventing tool flags. If the host application imposes its own approval, respect it; SCB preauthorization controls only SCB's gate.

### Runtime policy and compatibility

Version 0.1.5 supports common file/log/process/disk/hardware queries, read-only `find`, `ss`, `ip show/list/get`, checksums, selected Docker queries, string `printf`, and stdout-only text processing. Every stage of `|`, `&&`, `||`, semicolon, or newline lists must qualify. The server adds `--no-pager` to supported `systemctl`/`journalctl` queries and `--no-config` to `rg`, including under supported `sudo -n` and `docker exec`. The response reports the original `command` and actual `executed_command`. Unknown commands, Git, arbitrary interpreters/scripts/SQL through SSH, API calls, shell expansion, file redirection, and unsupported flags use the general tool and require confirmation under the default host policy. See the plugin README and `mcp/command_policy.py` for the exact subset. This is a policy for trusted POSIX/Linux utilities, not a sandbox or proof about arbitrary executables or shell startup files.

`intent_zh` must be a nonempty single-line Chinese description of at most 500 characters. It is required for commands outside the allowlist and never changes classification. Never label a restart, requeue, deletion, or write as a read-only check. For an unsupported diagnostic script, state its diagnostic purpose accurately and let the plugin apply the configured host policy.

On success the tool returns `read_only`, `approval_required`, `approval_basis`, `environment`, and `approval_policy` together with the bounded execution result and validated intent when provided. These describe classification and authorization, not independent verification of every side effect. A required approval that is denied, closed, unavailable, invalid, or timed out stops execution before credential resolution/network access. The bundled local mode provides red text; native MCP clients control their own visual styling and receive the Chinese intent in plain text.

Check the actually loaded tool schema. A running version older than 0.1.4 lacks `ssh_read_command` and the expanded query policy, and versions older than 0.1.5 lack per-alias test preauthorization; editing this skill alone does not update that process. Reload after installing the changed plugin. Do not invent skip-approval parameters, auto-click approval windows, or use direct shell/SSH to evade an enforced confirmation. A client timeout does not prove a pending or running command stopped; reconcile its outcome before retrying.

## Credential handling

Credentials are resolved by the local process from Windows Credential Manager. The tools must never return, log, or persist a credential. Configure only non-secret host/account metadata in `config/bridge.json`; place passwords or SSH key passphrases in Credential Manager with `scripts/manage_credential.py` (it prompts without echo and never accepts secrets as command-line arguments). Never ask the user to paste an IP, username, password, token, private key, or passphrase into Codex when a local alias/configuration can be used.

The skill does not create or discover credentials. The human configures the host address, username, pinned host-key fingerprint, and credential reference in the local manager. The MCP server reads its configuration for each tool call, so saving host/credential configuration can be followed by an immediate tool call in the current thread; a new thread is not needed for host configuration. Loading a changed plugin build or new tool definition may still require the MCP plugin to reload.

## Security boundary

This plugin prevents its own MCP tools from returning credentials, but it is not an OS isolation boundary: a local process running as the same Windows user, including another tool with shell access, may be able to read that user's Credential Manager entries. For protection against a compromised model/tool process, move the credential store and adapters into a separate restricted Windows service identity and expose only authenticated, ACL-protected local IPC with the same operation allowlists.
