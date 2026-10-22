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
from pathlib import Path
from tkinter import ttk
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp"))
from approval_intent import validate_intent


DEFAULT_INTENT_ZH = "将执行下方所示操作。请核对操作目的、目标及影响后再确认。"


def parse_request(stream: Any) -> tuple[str, str | None]:
    raw = stream.read()
    request = json.loads(raw)
    if not isinstance(request, dict) or not isinstance(request.get("message"), str):
        raise ValueError("approval request must contain a message")
    message = request["message"].strip()
    if not message or len(message) > 24_000:
        raise ValueError("approval message is empty or too large")
    intent = validate_intent(request["intent_zh"]) if "intent_zh" in request else None
    return message, intent


def read_request(stream: Any) -> str:
    # 保留旧调用者只读取 message 的接口，同时校验新增的意图字段。
    return parse_request(stream)[0]


def ask_user(message: str, intent_zh: str | None = None) -> bool:
    intent = validate_intent(intent_zh) if intent_zh is not None else DEFAULT_INTENT_ZH
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
    # 使用显式红色粗体，避免主题样式使高风险操作说明不醒目。
    tk.Label(
        frame,
        text="请确认操作意图",
        foreground="#b91c1c",
        font=("Microsoft YaHei", 16, "bold"),
        anchor="w",
    ).pack(anchor="w", pady=(0, 6))
    tk.Label(
        frame,
        text=intent,
        foreground="#b91c1c",
        font=("Microsoft YaHei", 13, "bold"),
        wraplength=760,
        justify="left",
        anchor="w",
    ).pack(anchor="w", fill="x", pady=(0, 12))
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
        message, intent = parse_request(sys.stdin)
        approved = ask_user(message, intent_zh=intent)
        sys.stdout.write(json.dumps({"approved": approved}, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return 0
    except Exception:
        # Do not expose Tk, path, or request details to the MCP process.
        sys.stdout.write(json.dumps({"approved": False}, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return 2


if __name__ == "__main__":
    # Windows 管道默认代码页可能不是 UTF-8；与服务器的 JSON 通道保持一致。
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
