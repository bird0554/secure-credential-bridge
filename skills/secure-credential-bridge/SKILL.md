---
name: secure-credential-bridge
description: Use the local Secure Credential Bridge MCP tools for approved, preconfigured SSH connections and remote actions without placing IPs, usernames, passwords, or private keys in Codex. Also covers its optional allowlisted email and read-only PostgreSQL adapters.
---

# Secure Credential Bridge

Use this skill when the user wants Codex to connect to a remote machine or run a remote maintenance operation through the local bridge.

## SSH workflow

1. Call `bridge_status` to see configured host names. It reports names and readiness only.
2. If the local alias is unknown, call `ssh_discover_hosts`. This returns alias names only, reads the local OpenSSH config, and makes no network connection.
3. Call `ssh_connect` with one local alias. Host addresses and usernames are never accepted as tool arguments. It authenticates to one fingerprint-pinned host and runs no remote command. If setup is missing, the local SSH manager opens so the human can configure it outside Codex.
4. After a successful connection check, call `ssh_run_command` with the configured alias and the user-requested command. The local approval window displays the exact target and command for every run; execution happens only after approval.

Treat a failed or denied call as final for that attempt. Do not guess another host, retry repeatedly, bypass the approval window, or fall back to direct shell/SSH commands. Never put passwords, tokens, or other secrets in remote command arguments because command text is displayed and may be returned in logs/results.

Use only the bridge's configured MCP tools. Host addresses and usernames are stored in the local bridge configuration, and passwords/key passphrases are stored in Windows Credential Manager. Never ask the user to paste an address, username, password, token, private key, or database connection string into chat or tool arguments.

## Capabilities and approval

- `bridge_status` reports configured SSH host and database query names only.
- `ssh_run_command` accepts a command for one configured host and requires a local interactive approval showing the exact target and command on every run. It has a 300-second timeout ceiling and bounded output. Treat all remote commands as potentially destructive; use read-only commands when that is what the user requested.
- `email_create_draft` accepts only an exact allowlisted recipient and does not send. `email_send_draft` displays the complete recipient, subject, body, and digest in the configured local approval window before sending. Confirm the digest corresponds to that draft. Delivery failures are not retried automatically; verify the mailbox first because SMTP may have accepted a message before the connection failed.
- `postgres_query` accepts only a configured query name and its declared parameters. Do not propose arbitrary SQL to bypass the allowlist.

If the MCP confirmation UI is unavailable, the bridge fails closed. Do not replace it with a verbal confirmation or direct shell commands.

## Credential handling

Credentials are resolved by the local process from Windows Credential Manager. The tools must never return, log, or persist a credential. Configure only non-secret host/account metadata in `config/bridge.json`; place passwords or SSH key passphrases in Credential Manager with `scripts/manage_credential.py` (it prompts without echo and never accepts secrets as command-line arguments). Never ask the user to paste an IP, username, password, token, private key, or passphrase into Codex when a local alias/configuration can be used.

The skill does not create or discover credentials. The human configures the host address, username, pinned host-key fingerprint, and credential reference in the local manager. The MCP server reads its configuration for each tool call, so saving host/credential configuration can be followed by an immediate tool call in the current thread; a new thread is not needed for host configuration. Loading a changed plugin build or new tool definition may still require the MCP plugin to reload.

## Security boundary

This plugin prevents its own MCP tools from returning credentials, but it is not an OS isolation boundary: a local process running as the same Windows user, including another tool with shell access, may be able to read that user's Credential Manager entries. For protection against a compromised model/tool process, move the credential store and adapters into a separate restricted Windows service identity and expose only authenticated, ACL-protected local IPC with the same operation allowlists.
