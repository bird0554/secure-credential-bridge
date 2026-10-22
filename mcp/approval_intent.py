"""共享的中文操作意图校验；意图文本不参与只读权限判定。"""

from __future__ import annotations

import re
import unicodedata
from typing import Any


def validate_intent(intent: Any) -> str:
    # 拒绝不可见控制字符，避免确认窗口中的操作说明被遮蔽。
    if not isinstance(intent, str) or not intent.strip() or len(intent) > 500:
        raise ValueError("intent_zh must be a nonempty string of at most 500 characters")
    if any(unicodedata.category(char).startswith("C") or char in "\u2028\u2029" for char in intent):
        raise ValueError("intent_zh must not contain control characters")
    if not re.search(r"[\u3400-\u9fff]", intent):
        raise ValueError("intent_zh must contain a Chinese description of the operation")
    return intent.strip()
