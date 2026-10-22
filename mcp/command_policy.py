"""对受限 POSIX 命令语法使用只读允许列表；不能判定时保留人工确认。

这不是远端沙箱：假定 PATH 中的标准工具、容器和远端 shell 本身可信。
读取文件仍可能产生访问时间、审计日志等系统副作用。
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandPolicy:
    read_only: bool
    reason_zh: str


@dataclass
class _ParsedOptions:
    positionals: list[str]
    seen: set[str]


def _options(args: list[str], flags: set[str], values: set[str] | None = None,
             short_flags: str = "", short_values: str = "") -> _ParsedOptions | None:
    """只接受完整的已知选项，并保留真实选项，避免将选项值误判为开关。"""
    values = values or set()
    result = _ParsedOptions([], set())
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            result.positionals.extend(args[index + 1:])
            return result
        if token.startswith("--"):
            name, equal, value = token.partition("=")
            if name in flags and not equal:
                result.seen.add(name)
            elif name in values:
                if equal:
                    if not value:
                        return None
                else:
                    index += 1
                    if index >= len(args) or not args[index]:
                        return None
                result.seen.add(name)
            else:
                return None
        elif token.startswith("-") and token != "-":
            letters = token[1:]
            for offset, letter in enumerate(letters):
                if letter in short_values:
                    if offset == len(letters) - 1:
                        index += 1
                        if index >= len(args) or not args[index]:
                            return None
                    result.seen.add("-" + letter)
                    break
                if letter not in short_flags:
                    return None
                result.seen.add("-" + letter)
        else:
            result.positionals.append(token)
        index += 1
    return result


def _at_most(parsed: _ParsedOptions | None, count: int) -> bool:
    return parsed is not None and len(parsed.positionals) <= count


def _container_name(value: str) -> bool:
    # 不允许容器位置被选项或空参数占据；Docker 名称和 ID 均满足此格式。
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value))


def _query(tokens: list[str], depth: int = 0) -> bool:
    if not tokens or depth > 3:
        return False
    executable, *args = tokens
    # 不接受任意路径下的同名程序、环境赋值或解释器包装。
    if "/" in executable:
        directory, _, executable = executable.rpartition("/")
        if directory not in {"/bin", "/usr/bin", "/sbin", "/usr/sbin"}:
            return False
    if executable == "sudo":
        if args[:1] != ["-n"]:
            return False
        args = args[1:]
        if args[:1] == ["--"]:
            args = args[1:]
        return bool(args) and args[0].rsplit("/", 1)[-1] != "sudo" and _query(args, depth + 1)
    if executable in {"whoami", "pwd", "uptime", "w", "who", "id", "groups", "uname"}:
        allowed = {
            "whoami": "", "pwd": "LP", "uptime": "ps", "w": "hfsu",
            "who": "abHlmpqrstTu", "id": "ugGnrz", "groups": "", "uname": "asnrvmpio",
        }
        parsed = _options(args, {"--help", "--version"}, short_flags=allowed[executable])
        return _at_most(parsed, 1 if executable in {"id", "who"} else (100 if executable == "groups" else 0))
    if executable == "hostname":
        return _at_most(_options(args, set(), short_flags="fdisIA"), 0)
    if executable == "date":
        parsed = _options(args, {"--utc", "--universal", "--rfc-email"},
                          {"--date", "--rfc-3339"}, "uR", "d")
        return parsed is not None and (not parsed.positionals or (
            len(parsed.positionals) == 1 and parsed.positionals[0].startswith("+")))
    if executable == "ls":
        return _options(args, {"--all", "--almost-all", "--human-readable", "--numeric-uid-gid", "--directory"},
                        {"--color", "--sort", "--time-style"}, "aAlhdnrtRS1Fip") is not None
    if executable == "cat":
        return _options(args, {"--show-all", "--number", "--number-nonblank", "--squeeze-blank"},
                        short_flags="AbEnsTuv") is not None
    if executable in {"head", "tail"}:
        # -f/-F 不在范围内，查询应能结束，仍由执行器限制时长和输出。
        return _options(args, {"--quiet", "--silent", "--verbose"}, {"--lines", "--bytes"}, "qv", "nc") is not None
    if executable == "wc":
        return _options(args, {"--lines", "--words", "--bytes", "--chars", "--max-line-length"},
                        short_flags="lwmcL") is not None
    if executable == "stat":
        return _options(args, {"--dereference", "--file-system", "--terse"}, {"--format", "--printf"}, "Lft", "c") is not None
    if executable == "readlink":
        return _options(args, {"--canonicalize", "--canonicalize-existing", "--canonicalize-missing"},
                        short_flags="efmnqsvz") is not None
    if executable in {"df", "du", "free"}:
        flags = {"--human-readable", "--si", "--total"}
        if executable == "df":
            return _options(args, flags | {"--all", "--local", "--print-type", "--inodes"},
                            {"--type", "--exclude-type"}, "ahHiklPT", "tx") is not None
        if executable == "du":
            return _options(args, flags | {"--summarize", "--all", "--one-file-system"},
                            {"--max-depth"}, "ahHskmcx", "d") is not None
        return _at_most(_options(args, flags, short_flags="bkmghtwl"), 0)
    if executable == "ps":
        # 只接受开头的常见 BSD 格式，不能从选项值中删除同名字符串。
        if args[:1] and args[0] in {"aux", "ax", "axu", "ef"}:
            args = args[1:]
        return _at_most(_options(args, {"--forest", "--no-headers"}, {"--sort", "--pid", "--format"}, "aefluxw", "op"), 0)
    if executable == "grep":
        return _options(args, {
            "--fixed-strings", "--extended-regexp", "--ignore-case", "--line-number",
            "--invert-match", "--count", "--files-with-matches", "--files-without-match",
            "--only-matching", "--no-messages", "--text", "--recursive", "--dereference-recursive",
        }, {"--regexp", "--file", "--after-context", "--before-context", "--context", "--max-count",
            "--include", "--exclude", "--exclude-dir"}, "FEinvwxclLhHoqsrRabI", "efABCm") is not None
    if executable == "rg":
        parsed = _options(args, {
            "--no-config", "--fixed-strings", "--ignore-case", "--line-number", "--invert-match",
            "--count", "--files-with-matches", "--files-without-match", "--only-matching",
            "--no-messages", "--text", "--hidden", "--no-ignore", "--files",
        }, {"--regexp", "--file", "--after-context", "--before-context", "--context", "--max-count",
            "--glob", "--replace"}, "FinvwxcllhHoqsaI", "efABCmgr")
        # ripgrep 配置可以注入 --pre，必须显式禁用。-r/--replace 只替换输出文本。
        return parsed is not None and "--no-config" in parsed.seen
    if executable == "sort":
        parsed = _options(args, {"--check", "--numeric-sort", "--human-numeric-sort", "--reverse", "--unique", "--ignore-case"},
                          {"--key", "--field-separator"}, "cCnhruf", "kt")
        # 普通排序可能落盘临时文件，仅免确认“不生成排序结果”的校验模式。
        return parsed is not None and bool(parsed.seen & {"--check", "-c", "-C"})
    if executable == "uniq":
        # 第二个位置参数是输出文件；词法分析还必须排除能扩成多个参数的 glob。
        return _at_most(_options(args, {"--count", "--repeated", "--unique", "--ignore-case"}, short_flags="cdui"), 1)
    if executable == "sed":
        # 仅输出行区间；排除 e、w、r、-i 以及额外脚本参数。
        return len(args) >= 2 and args[0] == "-n" and bool(re.fullmatch(
            r"(?:[0-9]+|\$)(?:,(?:[0-9]+|\$))?p", args[1])) and all(not arg.startswith("-") for arg in args[2:])
    if executable == "systemctl":
        parsed = _options(args, {"--no-pager", "--no-legend", "--plain", "--all", "--failed", "--full"},
                          {"--type", "--state", "--property", "--lines"}, "al", "np")
        return parsed is not None and "--no-pager" in parsed.seen and bool(parsed.positionals) and parsed.positionals[0] in {
            "status", "show", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-jobs",
        }
    if executable == "journalctl":
        parsed = _options(args, {"--no-pager", "--utc", "--reverse", "--quiet", "--list-boots", "--disk-usage", "--all"},
                          {"--unit", "--lines", "--since", "--until", "--output", "--priority", "--boot"}, "raq", "unSUpob")
        return parsed is not None and "--no-pager" in parsed.seen and not parsed.positionals
    if executable == "docker":
        if not args:
            return False
        subcommand, *rest = args
        if subcommand in {"ps", "images"}:
            parsed = _options(rest, {"--all", "--quiet", "--no-trunc", "--size", "--digests"},
                              {"--filter", "--format"}, "aqs", "f")
            return _at_most(parsed, 1 if subcommand == "images" else 0)
        if subcommand == "logs":
            parsed = _options(rest, {"--timestamps", "--details"}, {"--tail", "--since", "--until"}, "t")
            return parsed is not None and len(parsed.positionals) == 1 and _container_name(parsed.positionals[0])
        if subcommand == "inspect":
            parsed = _options(rest, {"--size"}, {"--format", "--type"}, "s", "f")
            return parsed is not None and bool(parsed.positionals)
        if subcommand in {"version", "info"}:
            return _at_most(_options(rest, set(), {"--format"}, short_values="f"), 0)
        if subcommand == "stats":
            parsed = _options(rest, {"--no-stream", "--all", "--no-trunc"}, {"--format"}, "a")
            return parsed is not None and "--no-stream" in parsed.seen
        if subcommand == "top":
            return len(rest) == 1 and _container_name(rest[0])
        if subcommand in {"container", "image"}:
            # 子命令别名只映射实际存在的查询，不能宽泛递归到任意 Docker 命令。
            aliases = {"container": {"ls": "ps", "inspect": "inspect", "logs": "logs", "stats": "stats", "top": "top"},
                       "image": {"ls": "images", "inspect": "inspect"}}
            return bool(rest) and rest[0] in aliases[subcommand] and _query(
                ["docker", aliases[subcommand][rest[0]], *rest[1:]], depth + 1)
        if subcommand == "exec":
            # 不允许任何 exec 选项（环境、用户、交互、特权、工作目录等）。
            return len(rest) >= 2 and _container_name(rest[0]) and _query(rest[1:], depth + 1)
    return False


def _split_stages(command: str) -> list[list[str]] | None:
    """解析不发生 shell 展开的 POSIX 子集，保留引号内的操作符字面量。

    只允许空格/制表符、单/双引号、管道和 &&。反斜线及复杂语法宁可交由
    人工确认；单引号内的 $ 等字符是字面量，不能误当成 shell 展开。
    """
    stages: list[list[str]] = [[]]
    token: list[str] = []
    started = False
    quote: str | None = None
    index = 0

    def finish_token() -> None:
        nonlocal started
        if started:
            stages[-1].append("".join(token))
            token.clear()
            started = False

    while index < len(command):
        char = command[index]
        if char == "\\" or (unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} and char != "\t"):
            return None
        if quote:
            if char == quote:
                quote = None
            elif quote == '"' and char in "$`":
                return None
            else:
                token.append(char)
        elif char in "'\"":
            quote = char
            started = True
        elif char in " \t":
            finish_token()
        elif char == "|" or (char == "&" and command[index:index + 2] == "&&"):
            finish_token()
            if not stages[-1] or len(stages) >= 16:
                return None
            stages.append([])
            if char == "&":
                index += 1
        elif char in "$`;&<>(){}*?[]~#!^":
            # 拒绝 glob/brace/tilde/substitution，确保参数数量与所审查内容相同。
            return None
        else:
            token.append(char)
            started = True
        index += 1
    if quote:
        return None
    finish_token()
    return stages if stages[-1] else None


def classify_command(command: str) -> CommandPolicy:
    """只豁免明确支持的查询；无法完整解析时仍走原确认流程。"""
    if not isinstance(command, str) or not command.strip() or len(command) > 12_000:
        return CommandPolicy(False, "命令为空或超出可判定范围。")
    stages = _split_stages(command)
    if stages is None:
        return CommandPolicy(False, "命令包含展开、重定向、复杂或不完整的 shell 语法，不能确认只读。")
    if not all(_query(stage) for stage in stages):
        return CommandPolicy(False, "命令、参数或管道阶段未通过只读允许列表；需要确认后执行。")
    return CommandPolicy(True, "完整命令及所有管道阶段均为已支持的只读查询。")
