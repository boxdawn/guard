"""Rule values for the command guard. Server side only — never shipped.

Lists are the place a guard goes stale (Continue CVE-2026-76072 was a list
missing `/home`), so the evaluator does not rely on them alone: a value it
cannot read asks or denies on its own, whatever is listed here.
"""
from __future__ import annotations

from boxdawn_guard.command_guard import CommandRules

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox"})

# Inline code is read as text, so these are keyword scans with the weakness
# GuardFall describes. Per language: a backtick means "run" in ruby, not in
# python (found on real transcripts, 2026-10-29). What a scan reads as clean
# gets no decision (design §5).
_PYTHON = (
    r"\bshutil\.(rmtree|move)\b", r"\bos\.(remove|unlink|rmdir|removedirs|truncate|kill)\b",
    r"\bos\.(system|popen|exec\w*|spawn\w*|startfile)\b", r"\bsubprocess\b",
    r"\.(unlink|rmdir)\s*\(", r"\bsend2trash\b", r"\b__import__\b",
    r"\b(exec|eval|compile)\s*\(", r"\bimportlib\.import_module\b", r"\bctypes\b",
    r"\bimport\s+pty\b",
)
_NODE = (
    r"\bchild_process\b", r"\b(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\(",
    r"\b(execSync|execFileSync|spawnSync|spawn|execFile)\s*\(", r"\bFunction\s*\(",
    r"\beval\s*\(", r"\bDeno\.(remove|run|Command)\b", r"\bBun\.(spawn|\$)",
)
_POWERSHELL = (
    r"(?i)\b(Remove-Item|Clear-Content|Clear-Disk|Format-Volume|Invoke-Expression|"
    r"Start-Process|Stop-Computer|Restart-Computer)\b",
    r"(?i)(^|[;|\s])(iex|rm|del|rd|rmdir|erase|ri)\s",
)
_RUBY = (r"\b(FileUtils\.rm\w*|File\.delete|system|exec|spawn|eval)\b", r"`", r"%x[\(\{\[]")
_PERL = (r"\b(unlink|rmtree|system|exec|eval)\b", r"`", r"\bqx[\(\{/]")
_PHP = (r"\b(unlink|rmdir|system|exec|shell_exec|passthru|popen|proc_open|eval)\s*\(", r"`")
_SQL = (
    r"(?i)\bdrop\s+(table|database|schema|collection)\b", r"(?i)\btruncate\s+table\b",
    r"(?i)\bdelete\s+from\b",
)


def default_command_rules() -> CommandRules:
    return CommandRules(
        interpreters=_SHELLS | {
            "python", "python3", "perl", "ruby", "node", "php", "pwsh", "powershell",
            "deno", "bun", "lua", "osascript",
        },
        shells=_SHELLS,
        code_flags={
            **{s: frozenset({"-c"}) for s in _SHELLS},
            "python": frozenset({"-c"}), "python3": frozenset({"-c"}),
            "perl": frozenset({"-e", "-E"}), "ruby": frozenset({"-e"}),
            "node": frozenset({"-e", "--eval", "-p", "--print"}),
            "php": frozenset({"-r"}), "pwsh": frozenset({"-c", "-Command"}),
            "powershell": frozenset({"-c", "-Command"}),
            "deno": frozenset({"eval"}), "bun": frozenset({"-e", "--eval"}),
            "lua": frozenset({"-e"}), "osascript": frozenset({"-e"}),
        },
        wrappers=frozenset({
            "env", "nice", "nohup", "time", "timeout", "command", "builtin", "exec",
            "stdbuf", "xargs", "ionice", "caffeinate",
        }),
        privilege=frozenset({"sudo", "doas", "pkexec", "su", "runas", "gsudo"}),
        source=frozenset({"source", "."}),
        always_deny=frozenset({"shred", "wipefs", "srm", "blkdiscard", "sgdisk", "fdisk", "parted"}),
        always_deny_prefixes=("mkfs", "mke2fs", "mkswap"),
        devices=("/dev/sd", "/dev/nvme", "/dev/disk", "/dev/hd", "/dev/vd",
                 "/dev/xvd", "/dev/mmcblk", "/dev/rdisk", "/dev/mapper/"),
        harmless_devices=frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}),
        db_clients=frozenset({
            "psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli",
            "cqlsh", "clickhouse-client", "sqlcmd", "duckdb",
        }),
        db_code_flags=frozenset({"-c", "--command", "-e", "--execute", "--eval", "-Q", "-q"}),
        db_file_flags=frozenset({"-f", "--file", "-i", "--init"}),
        db_destructive=(
            r"\bdrop\s+(table|database|schema|index|view|collection|user|role)\b",
            r"\btruncate\b",
            r"\bdelete\s+from\b(?![\s\S]*\bwhere\b)",
            r"\bflushall\b", r"\bflushdb\b",
            r"\bdropDatabase\s*\(", r"\.drop\s*\(",
            r"\bdelete(Many)?\s*\(\s*\{\s*\}\s*\)",
            r"\balter\s+table\b[\s\S]*\bdrop\b",
        ),
        # Inline code is read as text, so this is a keyword scan with the
        # weakness GuardFall describes; anything it cannot rule out it asks
        # about, and what it reads as clean gets no decision (design §5).
        inline_code_risky={
            **{n: _PYTHON + _SQL for n in ("python", "python3")},
            **{n: _NODE + _SQL for n in ("node", "deno", "bun")},
            **{n: _POWERSHELL for n in ("pwsh", "powershell")},
            "ruby": _RUBY + _SQL, "perl": _PERL + _SQL, "php": _PHP + _SQL,
            # lua and osascript have no rules: their inline code asks.
        },
        scratch_dirs=("/tmp", "/var/tmp", "/private/tmp", "~/AppData/Local/Temp"),
        unattended_modes=frozenset({"bypassPermissions", "dontAsk"}),
    )
