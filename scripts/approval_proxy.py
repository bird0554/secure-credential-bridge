"""Visible, one-shot desktop approval dialog for Secure Credential Bridge.

The MCP process sends only a description of the preconfigured operation over
stdin.  This process returns one JSON decision over stdout and never handles
credentials.  It is a local user-consent boundary, not a Codex approval UI or
an OS isolation boundary.
"""

from __future__ import annotations

import json
import sys
import tkinter as tk
from tkinter import ttk
from typing import Any


def read_request(stream: Any) -> str:
    raw = stream.read()
    request = json.loads(raw)
    if not isinstance(request, dict) or not isinstance(request.get("message"), str):
        raise ValueError("approval request must contain a message")
    message = request["message"].strip()
    if not message or len(message) > 24_000:
        raise ValueError("approval message is empty or too large")
    return message


def ask_user(message: str) -> bool:
    root = tk.Tk()
    root.title("Secure Credential Bridge · 确认执行")
    root.geometry("820x620")
    root.minsize(620, 420)
    try:
        root.attributes("-topmost", True)
    except tk.TclError:
        pass
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    frame = ttk.Frame(root, padding=14)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="请逐字检查目标主机与命令。拒绝或关闭窗口都会取消操作。", wraplength=780).pack(anchor="w", pady=(0, 10))
    text_frame = ttk.Frame(frame)
    text_frame.pack(fill="both", expand=True)
    text = tk.Text(text_frame, wrap="word", height=20)
    scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=scrollbar.set)
    text.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    text.insert("1.0", message)
    text.configure(state="disabled")
    approved = tk.BooleanVar(value=False)
    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=(12, 0))
    ttk.Button(buttons, text="拒绝", command=root.destroy).pack(side="right", padx=(8, 0))
    ttk.Button(buttons, text="确认并执行", command=lambda: (approved.set(True), root.destroy())).pack(side="right")
    root.grab_set()
    root.focus_force()
    root.wait_window()
    return approved.get()


def main() -> int:
    try:
        message = read_request(sys.stdin)
        approved = ask_user(message)
        sys.stdout.write(json.dumps({"approved": approved}, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return 0
    except Exception:
        # Do not expose Tk, path, or request details to the MCP process.
        sys.stdout.write(json.dumps({"approved": False}, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
