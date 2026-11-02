"""Send the block record to Boxdawn, for team plans (session start only).

Runs in the same background `fetch-rules` process, after the signed rules
were stored: the key was just accepted on a paid plan, and no new connection
moment is added. The plugin setting `keep_blocks_local` turns it off.

Each day file is first renamed to an outbox file that carries a random batch
id. Hooks open the day file by name for every line, so lines written after the
rename start a new day file and are never lost under the send. The batch id
stays with the outbox until the server answers 2xx, so a send whose answer was
lost goes again with the same id and the server stores nothing twice.

Only lines that are exactly what `block_log.entry` writes leave the machine;
anything else in a file is dropped, never sent. A refused key (401/403)
removes the record, as `rules_bundle.fetch` does. A network failure or a
server error keeps the outbox for the next session; `block_log.prune` deletes
it after KEEP_DAYS like any day file.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path

from boxdawn_guard import block_log
from boxdawn_guard.command_guard import RULE_IDS, TARGETS

BLOCKS_URL = "https://jeonsewon--boxdawn-analyzer-web.modal.run/guard/blocks"
SEND_TIMEOUT_SECONDS = 60
MAX_LINES = 5000
# A hook opens the day file, writes one line and closes it, in well under a
# millisecond. One that opened the file just before the rename still writes
# into the renamed file; reading only after this pause means it has finished,
# so the outbox read and later removed holds its line. Without the pause, 10
# writers lost 4-9 of 2,000 lines on Linux (CI, 2026-11-02). The send runs in
# the background, so no one waits for it.
RENAME_GRACE_SECONDS = 2.0
_OUTBOX = re.compile(r"outbox-(\d{8})-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.jsonl")
_KEYS = frozenset({"v", "t", "tool", "decision", "escalated", "findings", "rules", "exp", "build"})
_FINDING_KEYS = frozenset({"rule", "level", "target"})
_BUILD_ID = re.compile(r"[0-9a-f]{7,64}")


def _line_ok(line) -> bool:
    if not isinstance(line, dict) or set(line) != _KEYS:
        return False
    findings = line["findings"]
    if not (type(line["v"]) is int and line["v"] == block_log.LOG_VERSION
            and line["rules"] == "bundle" and type(line["t"]) is int and type(line["exp"]) is int
            and line["tool"] in block_log.TOOLS and line["decision"] in block_log.LEVELS
            and type(line["escalated"]) is bool
            and (line["build"] is None or (isinstance(line["build"], str)
                                           and _BUILD_ID.fullmatch(line["build"])))
            and isinstance(findings, list) and findings):
        return False
    return all(isinstance(f, dict) and set(f) == _FINDING_KEYS and f["rule"] in RULE_IDS
               and f["level"] in block_log.LEVELS and (f["target"] is None or f["target"] in TARGETS)
               for f in findings)


def _to_outbox(folder: Path) -> bool:
    """Rename day files to outboxes; True when any was renamed."""
    renamed = False
    for p in sorted(folder.glob("blocks-*.jsonl")):
        m = block_log.DAY_FILE.fullmatch(p.name)
        if m:
            try:
                os.replace(p, folder / f"outbox-{m.group(1)}-{uuid.uuid4()}.jsonl")
                renamed = True
            except OSError:
                pass
    return renamed


def _write_new_outbox(folder: Path, day: str, raw: bytes) -> None:
    tmp = folder / f".outbox.{uuid.uuid4().hex}.tmp"
    tmp.write_bytes(raw)
    os.replace(tmp, folder / f"outbox-{day}-{uuid.uuid4()}.jsonl")


def send(api_key: str | None, data_dir: str | None, *, url: str = BLOCKS_URL,
         timeout: float = SEND_TIMEOUT_SECONDS) -> str:
    """Send waiting lines; returns what happened, for the log line."""
    if not api_key or not data_dir:
        return "no key"
    folder = Path(data_dir) / block_log.LOG_DIR
    if not folder.is_dir():
        return "nothing to send"
    import urllib.error
    import urllib.request

    if _to_outbox(folder):
        time.sleep(RENAME_GRACE_SECONDS)
    sent = dropped = 0
    for p in sorted(folder.glob("outbox-*.jsonl")):
        m = _OUTBOX.fullmatch(p.name)
        if not m:
            continue
        raw = p.read_bytes()
        # Complete lines only; a line still being written stays in the tail.
        whole = raw[:raw.rfind(b"\n") + 1]
        chunks = whole.splitlines(keepends=True)[:MAX_LINES]
        used = sum(len(c) for c in chunks)
        lines = []
        for c in chunks:
            try:
                line = json.loads(c)
            except ValueError:
                line = None
            if _line_ok(line):
                lines.append(line)
            else:
                dropped += 1
        if lines:
            req = urllib.request.Request(
                url, method="POST",
                data=json.dumps({"batch": m.group(2), "lines": lines}, separators=(",", ":")).encode(),
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
                    resp.read()
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    block_log.remove(data_dir)
                    return f"refused ({exc.code}); block record removed"
                return f"server error ({exc.code}); kept {p.name}"
            except (urllib.error.URLError, OSError) as exc:
                return f"unreachable ({type(exc).__name__}); kept outbox"
            sent += len(lines)
        # Whatever came after what was read (a writer that opened the day
        # file just before the rename) goes to a new outbox, not away.
        rest = p.read_bytes()[used:]
        if rest:
            _write_new_outbox(folder, m.group(1), rest)
        p.unlink(missing_ok=True)
    return f"sent {sent}" + (f", dropped {dropped}" if dropped else "")
