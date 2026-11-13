---
name: scb-setup
description: Open the local Secure Credential Bridge configuration window from Codex plugin setup, or when the user asks to open SCB settings and manage SSH hosts, private keys, or stored passphrases. This opens the manager only; it does not test connections or run remote commands.
---

# Open SCB configuration

Open the bundled SSH management window immediately when this skill is invoked. The user should not need to supply another prompt or connection details.

1. Resolve the plugin root as two directories above this skill folder, then locate `scripts/ssh_manager_gui.py` under that root. Use the absolute path from the loaded skill location, not a hardcoded plugin cache version or the current working directory.
2. On Windows, locate the available Python 3 interpreter and prefer its sibling `pythonw.exe`. Launch the manager with PowerShell `Start-Process`, a quoted absolute script argument, the plugin root as `WorkingDirectory`, and `-WindowStyle Normal`. If only `python.exe` is available, use `-WindowStyle Hidden` to hide its console. Keep the child detached so the launch command returns while the GUI stays open.
3. Preserve any existing `SCB_CONFIG` environment override. Otherwise let the manager select the currently installed plugin configuration itself; do not substitute a source-checkout configuration.
4. Verify the launched process has not exited and, when available, has a nonzero main window handle. Report briefly in Chinese that the configuration window is open, or report the launch failure without claiming success.

Opening this window needs no SSH authentication. Do not call `ssh_connect`, run a remote command, test a host, read credentials or private-key contents, or change configuration and approval policies as part of setup. The human enters connection details, selects local keys, and saves or tests them in the opened window. Do not install software or restart Codex merely to open it.
