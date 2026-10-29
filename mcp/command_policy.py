"""对受限 POSIX 命令语法使用只读允许列表；不能判定时保留人工确认。

这不是远端沙箱：假定 PATH 中的标准工具、容器和远端 shell 本身可信。
读取文件仍可能产生访问时间、审计日志等系统副作用。
"""

from __future__ import annotations

import re
import shlex
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandPolicy:
    read_only: bool
    reason_zh: str
    execution_command: str | None = None


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
                    if index >= len(args) or not args[index] or args[index].startswith("--"):
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
                        if index >= len(args) or not args[index] or args[index].startswith("--"):
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


def _find_query(args: list[str]) -> bool:
    """只接受路径、筛选表达式和标准输出动作，排除执行/写文件动作。"""
    index = 0
    if args[:1] and args[0] in {"-H", "-L", "-P"}:
        index += 1
    while index < len(args) and not args[index].startswith("-") and args[index] not in {"!", "(", ")"}:
        index += 1
    flags = {"-print", "-print0", "-ls", "-quit", "-empty", "-readable", "-writable",
             "-executable", "-mount", "-xdev", "-depth", "-ignore_readdir_race",
             "-true", "-false", "-a", "-and", "-o", "-or", "-not", "!", "(", ")"}
    values = {"-name", "-iname", "-path", "-ipath", "-type", "-size", "-mtime", "-mmin",
              "-atime", "-amin", "-ctime", "-cmin", "-newer", "-user", "-group", "-uid",
              "-gid", "-perm", "-links", "-inum", "-printf", "-maxdepth", "-mindepth"}
    while index < len(args):
        token = args[index]
        if token in values:
            index += 1
            if index >= len(args) or not args[index]:
                return False
            if token in {"-maxdepth", "-mindepth"} and not args[index].isdigit():
                return False
        elif token not in flags:
            return False
        index += 1
    return True


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
    if executable == "cd":
        # 仅改变本次 SSH shell 的工作目录，链中后续操作仍逐一审查。
        return len(args) == 1 and bool(args[0]) and not args[0].startswith("-")
    if executable in {"true", "false"}:
        return not args
    if executable == "echo":
        return True  # 仅输出参数；所有 shell 展开/重定向已在词法层排除。
    if executable == "printf":
        # -v 和 %n 会改变量；仅支持字符串/字符输出，避免算术求值扩展。
        if args[:1] == ["--"]:
            args = args[1:]
        if not args or args[0].startswith("-"):
            return False
        return "%" not in re.sub(r"%(?:%|[- #0]*[0-9]*(?:\.[0-9]+)?[bcs])", "", args[0])
    if executable in {"test", "["}:
        if executable == "[":
            if args[-1:] != ["]"]:
                return False
            args = args[:-1]
        return (len(args) == 2 and args[0] in {"-e", "-f", "-d", "-L", "-h", "-r", "-w", "-x", "-s", "-n", "-z"}) or (
            len(args) == 3 and args[1] in {"=", "!=", "-eq", "-ne", "-lt", "-le", "-gt", "-ge"}
            # 数值比较仅接受字面数字，避免某些 shell 的算术表达式解释。
            and (args[1] in {"=", "!="} or all(re.fullmatch(r"-?[0-9]+", x) for x in (args[0], args[2]))))
    if executable == "find":
        return _find_query(args)
    if executable == "ss":
        return _options(args, {"--all", "--listening", "--numeric", "--processes", "--summary",
                               "--tcp", "--udp", "--unix", "--ipv4", "--ipv6", "--no-header",
                               "--extended", "--memory", "--info"}, short_flags="alnptux46sHemioO") is not None
    if executable == "ip":
        while args and args[0] in {"-4", "-6", "-o", "-oneline", "-br", "-brief", "-s", "-stats", "-d", "-details", "-j", "-json", "-p", "-pretty"}:
            args = args[1:]
        if not args:
            return False
        obj, *rest = args
        if obj == "netns":
            return not rest or rest == ["list"]
        return obj in {"addr", "address", "link", "route", "rule", "neigh", "neighbour"} and (
            not rest or rest[0] in {"show", "list"} or (obj == "route" and rest[0] == "get"))
    if executable in {"lsblk", "lscpu"}:
        return _options(args, {"--json", "--list", "--raw", "--bytes", "--fs", "--all",
                               "--noheadings", "--paths", "--nodeps", "--output-all"},
                        {"--output", "--exclude", "--include", "--sort"}, "Jlbfa nprd".replace(" ", ""), "oex") is not None
    if executable == "file":
        return _options(args, {"--brief", "--dereference", "--mime", "--mime-type", "--mime-encoding",
                               "--keep-going", "--no-pad", "--raw"}, {"--separator"}, "bLikNr", "F") is not None
    if executable in {"sha256sum", "sha512sum", "sha1sum", "md5sum", "cksum"}:
        return _options(args, {"--binary", "--text", "--tag", "--check", "--status", "--quiet", "--strict"},
                        short_flags="btc") is not None
    if executable == "cut":
        return _options(args, {"--only-delimited", "--complement", "--zero-terminated"},
                        {"--bytes", "--characters", "--fields", "--delimiter", "--output-delimiter"}, "nsz", "bcfd") is not None
    if executable == "tr":
        return _at_most(_options(args, {"--complement", "--delete", "--squeeze-repeats", "--truncate-set1"},
                                 short_flags="cdsCt"), 2)
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
        # 执行计划会加 --no-config，阻止配置注入 --pre。-r 只替换标准输出。
        return parsed is not None
    if executable == "sort":
        parsed = _options(args, {"--check", "--numeric-sort", "--human-numeric-sort", "--reverse", "--unique", "--ignore-case"},
                          {"--key", "--field-separator"}, "cCnhruf", "kt")
        # 正常排序只输出到 stdout；运行时可能使用临时空间，不改源文件。
        # -o/--output 和 --compress-program 均不允许。
        return parsed is not None
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
        return parsed is not None and bool(parsed.positionals) and parsed.positionals[0] in {
            "status", "show", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-jobs",
        }
    if executable == "journalctl":
        parsed = _options(args, {"--no-pager", "--utc", "--reverse", "--quiet", "--list-boots", "--disk-usage", "--all"},
                          {"--unit", "--lines", "--since", "--until", "--output", "--priority", "--boot"}, "raq", "unSUpob")
        return parsed is not None and not parsed.positionals
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
        if subcommand in {"network", "volume"}:
            if rest[:1] == ["ls"]:
                return _at_most(_options(rest[1:], {"--quiet", "--no-trunc"}, {"--filter", "--format"}, "q", "f"), 0)
            if rest[:1] == ["inspect"]:
                parsed = _options(rest[1:], set(), {"--format"}, short_values="f")
                return parsed is not None and bool(parsed.positionals)
            return False
        if subcommand == "system":
            return rest in (["df"], ["df", "-v"], ["df", "--verbose"])
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


def _guard_query(tokens: list[str]) -> list[str]:
    """仅为已经通过审查的查询补安全参数，包括 sudo / docker exec 内层。"""
    executable = tokens[0].rsplit("/", 1)[-1]
    if executable == "sudo":
        offset = 3 if tokens[2:3] == ["--"] else 2
        return tokens[:offset] + _guard_query(tokens[offset:])
    if executable == "docker" and tokens[1:2] == ["exec"]:
        return tokens[:3] + _guard_query(tokens[3:])
    guard = {"rg": "--no-config", "systemctl": "--no-pager", "journalctl": "--no-pager"}.get(executable)
    # 放在任何选项/-- 之前；不把恰好同名的参数值当作已有保护。
    if guard and tokens[1:2] != [guard]:
        return [tokens[0], guard, *tokens[1:]]
    return tokens


def _split_stages(command: str) -> tuple[list[list[str]], list[str]] | None:
    """解析不发生 shell 展开的 POSIX 子集，保留引号内的操作符字面量。

    保留每个连接符和参数边界；单引号中的反斜线是字面量。展开、重定向、
    后台任务及其他复杂语法保留人工确认。
    """
    stages: list[list[str]] = [[]]
    operators: list[str] = []
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
        if (unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
                and char not in {"\t", "\n"}):
            return None
        if quote:
            if char == quote:
                quote = None
            elif char == "\n" or (quote == '"' and char in "$`\\"):
                return None
            else:
                token.append(char)
        elif char in "'\"":
            quote = char
            started = True
        elif char in " \t":
            finish_token()
        elif char in "|;\n" or (char == "&" and command[index:index + 2] == "&&"):
            finish_token()
            if not stages[-1] or len(stages) >= 16:
                return None
            stages.append([])
            operator = command[index:index + 2] if command[index:index + 2] in {"&&", "||"} else char
            operators.append(operator)
            if len(operator) == 2:
                index += 1
        elif char in "$`&<>(){}*?[]~#!^\\":
            # 拒绝 glob/brace/tilde/substitution，确保参数数量与所审查内容相同。
            return None
        else:
            token.append(char)
            started = True
        index += 1
    if quote:
        return None
    finish_token()
    return (stages, operators) if stages[-1] else None


def classify_command(command: str) -> CommandPolicy:
    """只豁免明确支持的查询；无法完整解析时仍走原确认流程。"""
    if not isinstance(command, str) or not command.strip() or len(command) > 12_000:
        return CommandPolicy(False, "命令为空或超出可判定范围。")
    parsed = _split_stages(command)
    if parsed is None:
        return CommandPolicy(False, "命令包含展开、重定向、复杂或不完整的 shell 语法，不能确认只读。")
    stages, operators = parsed
    if not all(_query(stage) for stage in stages):
        return CommandPolicy(False, "命令、参数或管道阶段未通过只读允许列表；需要确认后执行。")
    guarded = [_guard_query(stage) for stage in stages]
    execution_command = command
    if guarded != stages:
        execution_command = shlex.join(guarded[0])
        for operator, stage in zip(operators, guarded[1:]):
            execution_command += " " + operator + " " + shlex.join(stage)
    return CommandPolicy(True, "完整命令及所有阶段均为已支持的只读查询。", execution_command)
