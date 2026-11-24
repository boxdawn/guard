"""Install the assembled plugin from a marketplace and check that a real
Claude Code session is blocked by it — on whatever OS this runs on.

Usage: python packaging/runtime_test.py <assembled-plugin-dir>
Needs `claude` on PATH. Exits non-zero on any unexpected result, so CI
goes red.

A stand-in for the model API (in this process, on a local port) answers
each session: it calls the tool named in the prompt with the command
written there, then says DONE. So no key is used and nothing is paid for.
Claude Code, the plugin install, the hook and the checks on disk are real.
BDX_RT_REAL_MODEL=1 uses the real model instead (needs ANTHROPIC_API_KEY).

What counts is what happened on disk, not what the model says:
  ok    echo marker > ok.txt                  ran if ok.txt exists
  ask   git reset --hard HEAD                 ran if victim.txt is back to its commit
  deny  dd ... of=$HOME/boxdawn_guard_probe.bin  ran if the probe file exists
Plan: a first session with an empty plugin data dir (ok must run: the
binary was placed before the first Bash call), then default and
bypassPermissions x ok/ask/deny with the plugin, the same six in a
project without it (control: each must run), and one session after the
marketplace's BUILD_ID changes (the placed build must be replaced).

On Windows the twelve plugin/control sessions run again through the
PowerShell tool (on by default there, and the primary shell):
  ok    Set-Content -Path ok.txt -Value marker      ran if ok.txt exists
  ask   git reset --hard HEAD                       as above
  deny  Remove-Item -Recurse -Force "$HOME\boxdawn_guard_probe_dir"
                                                    ran if that directory is gone
"""
from __future__ import annotations

import json
import os
import pathlib
import platform
import shutil
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "claude-haiku-5-5"
CASES = {
    "ok": "echo marker > ok.txt",
    "ask": "git reset --hard HEAD",
    "deny": "dd if=/dev/zero of=$HOME/boxdawn_guard_probe.bin bs=1 count=1",
}
PS_CASES = {
    "ok": "Set-Content -Path ok.txt -Value marker",
    "ask": "git reset --hard HEAD",
    "deny": 'Remove-Item -Recurse -Force "$HOME\\boxdawn_guard_probe_dir"',
}
MODES = ["default", "bypassPermissions"]
PROBE = pathlib.Path.home() / "boxdawn_guard_probe.bin"
PROBE_DIR = pathlib.Path.home() / "boxdawn_guard_probe_dir"
DATA = pathlib.Path.home() / ".claude" / "plugins" / "data" / "boxdawn-guard-boxdawn"
# CLAUDE_BIN overrides PATH: on Windows `claude` on PATH can be npm's claude.CMD,
# and a batch file mangles arguments.
CLAUDE = os.environ.get("CLAUDE_BIN") or shutil.which("claude")
PROJECTS = pathlib.Path.home() / ".claude" / "projects"
TRANSCRIPT_DIRS: set[pathlib.Path] = set()
SESSION_ENV: dict[str, str] = {}  # the stand-in's address, when it is used


# The model stand-in. Each answer is read from the request alone: the prompt names the tool
# and the command; once a tool result is in the conversation, the answer is DONE.
def _prompt(body: dict) -> str:
    for m in body.get("messages") or []:
        if m.get("role") != "user":
            continue
        content = m.get("content")
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content or []
        text = " ".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
        if "BDXRT" in text or "run exactly this command" in text:
            return text
    return ""


def _answered(body: dict) -> bool:
    return any(isinstance(b, dict) and b.get("type") == "tool_result"
               for m in body.get("messages") or [] if isinstance(m.get("content"), list) for b in m["content"])


def _reply(body: dict) -> list[dict]:
    names = {t.get("name") for t in body.get("tools") or []}
    prompt = _prompt(body)
    call = None
    m = re.search(r"Use the (\w+) tool to run exactly this command once, unchanged, and nothing else: "
                  r"(.*?)  Then reply with the single word DONE\.", prompt, re.S)
    if m:
        call = (m.group(1), {"command": m.group(2), "description": "t"})
    elif "grep -rn BDXRTKEY ." in prompt:
        call = ("Bash", {"command": "grep -rn BDXRTKEY .", "description": "t"})
    elif "Grep tool once with pattern BDXRTKEY" in prompt:
        call = ("Grep", {"pattern": "BDXRTKEY", "output_mode": "content"})
    if call and call[0] in names and not _answered(body):
        return [{"type": "tool_use", "id": "toolu_bdxrt", "name": call[0], "input": call[1]}]
    return [{"type": "text", "text": "DONE"}]


def _sse(content: list[dict], model: str):
    stop = "tool_use" if content[0]["type"] == "tool_use" else "end_turn"
    yield "message_start", {"type": "message_start", "message": {
        "id": "msg_stand_in", "type": "message", "role": "assistant", "model": model, "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}}
    for i, block in enumerate(content):
        if block["type"] == "text":
            start, delta = {"type": "text", "text": ""}, {"type": "text_delta", "text": block["text"]}
        else:
            start = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
            delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
        yield "content_block_start", {"type": "content_block_start", "index": i, "content_block": start}
        yield "content_block_delta", {"type": "content_block_delta", "index": i, "delta": delta}
        yield "content_block_stop", {"type": "content_block_stop", "index": i}
    yield "message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                            "usage": {"output_tokens": 1}}
    yield "message_stop", {"type": "message_stop"}


class _StandIn(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, payload: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._send(b"{}", "application/json")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if "count_tokens" in self.path:
            return self._send(b'{"input_tokens":1}', "application/json")
        if "/messages" not in self.path:
            return self._send(b"{}", "application/json")
        content, model = _reply(body), body.get("model", "stand-in")
        if body.get("stream"):
            text = "".join(f"event: {n}\ndata: {json.dumps(d)}\n\n" for n, d in _sse(content, model))
            return self._send(text.encode(), "text/event-stream")
        stop = "tool_use" if content[0]["type"] == "tool_use" else "end_turn"
        self._send(json.dumps({"id": "msg_stand_in", "type": "message", "role": "assistant", "model": model,
                               "content": content, "stop_reason": stop, "stop_sequence": None,
                               "usage": {"input_tokens": 1, "output_tokens": 1}}).encode(), "application/json")


def start_stand_in() -> ThreadingHTTPServer:
    class Quiet(ThreadingHTTPServer):
        def handle_error(self, request, client_address):  # a connection Claude Code drops is not news
            pass

    server = Quiet(("127.0.0.1", 0), _StandIn)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    SESSION_ENV.update(ANTHROPIC_BASE_URL=f"http://127.0.0.1:{server.server_address[1]}",
                       ANTHROPIC_API_KEY="stand-in-not-a-key", DISABLE_AUTOUPDATER="1", DISABLE_TELEMETRY="1",
                       CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
    return server


def sh(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


def project(root: pathlib.Path, name: str) -> pathlib.Path:
    d = root / name
    d.mkdir()
    sh(["git", "init", "-q"], d)
    sh(["git", "config", "user.email", "t@example.com"], d)
    sh(["git", "config", "user.name", "t"], d)
    (d / "victim.txt").write_text("keep me\n")
    sh(["git", "add", "victim.txt"], d)
    sh(["git", "commit", "-qm", "init"], d)
    return d


def ran(case: str, d: pathlib.Path, tool: str) -> bool:
    if case == "ok":
        return (d / "ok.txt").exists()
    if case == "ask":
        return (d / "victim.txt").read_text() == "keep me\n"
    if tool == "PowerShell":
        return not PROBE_DIR.exists()
    return PROBE.exists()


def session(d: pathlib.Path, mode: str, case: str, tool: str = "Bash") -> dict:
    (d / "ok.txt").unlink(missing_ok=True)
    (d / "victim.txt").write_text("changed\n")
    PROBE.unlink(missing_ok=True)
    PROBE_DIR.mkdir(exist_ok=True)
    command = (PS_CASES if tool == "PowerShell" else CASES)[case]
    prompt = (f"Use the {tool} tool to run exactly this command once, unchanged, and nothing else: "
              f"{command}  Then reply with the single word DONE.")
    env = {**os.environ, **SESSION_ENV, **({"CLAUDE_CODE_USE_POWERSHELL_TOOL": "1"} if tool == "PowerShell" else {})}
    p = subprocess.run(
        [CLAUDE, "-p", prompt, "--model", MODEL, "--permission-mode", mode,
         "--allowedTools", tool, "--setting-sources", "project",
         "--output-format", "json", "--max-turns", "4"],
        cwd=d, capture_output=True, text=True, timeout=300, env=env)
    executed = ran(case, d, tool)
    PROBE.unlink(missing_ok=True)
    shutil.rmtree(PROBE_DIR, ignore_errors=True)
    try:
        j = json.loads(p.stdout)
    except ValueError:
        j = {}
    placed = DATA / "current" / "BUILD_ID"
    # The guard's reason is in Claude Code's own transcript of the session,
    # not reliably in the model's final answer.
    transcripts = list(PROJECTS.glob(f"*/{j.get('session_id')}.jsonl")) if j.get("session_id") else []
    TRANSCRIPT_DIRS.update(t.parent for t in transcripts)
    return {"tool": tool, "mode": mode, "case": case, "executed": executed,
            "denials": len(j.get("permission_denials") or []),
            "by_guard": any("Boxdawn guard" in t.read_text(encoding="utf-8") for t in transcripts),
            "placed": placed.read_text().strip() if placed.exists() else None,
            "exit": p.returncode, "stderr": p.stderr[-300:], "result": (j.get("result") or "")[:300],
            "stdout_head": "" if j else p.stdout[:300]}


def search_sees(d: pathlib.Path, tool: str) -> tuple[bool, bool]:
    """(the ordinary file, the secret file) as a real session found them. The prompt
    never holds the secret's value, so it can only come from the search."""
    (d / ".env").write_text("BDXRTKEY=BDXRTSECRET\n")
    (d / "plain.txt").write_text("BDXRTKEY=BDXRTPLAIN\n")
    prompt = ("Run this with the Bash tool, once, unchanged: grep -rn BDXRTKEY ." if tool == "Bash" else
              "Use the Grep tool once with pattern BDXRTKEY and output_mode content, with no path or glob.")
    try:
        p = subprocess.run(
            [CLAUDE, "-p", prompt + " Then print what it found.", "--model", MODEL, "--permission-mode", "default",
             "--allowedTools", tool, "--setting-sources", "project", "--output-format", "json", "--max-turns", "4"],
            cwd=d, capture_output=True, text=True, timeout=300, env={**os.environ, **SESSION_ENV})
    finally:
        (d / ".env").unlink()
        (d / "plain.txt").unlink()
    try:
        sid = json.loads(p.stdout).get("session_id")
    except ValueError:
        sid = None
    transcripts = list(PROJECTS.glob(f"*/{sid}.jsonl")) if sid else []
    TRANSCRIPT_DIRS.update(t.parent for t in transcripts)
    text = p.stdout + "".join(t.read_text(encoding="utf-8") for t in transcripts)
    return "BDXRTPLAIN" in text, "BDXRTSECRET" in text


def main() -> int:
    if not CLAUDE:
        sys.exit("claude not on PATH")
    src = pathlib.Path(sys.argv[1]).resolve()
    # resolve(): the Windows runner's TEMP is an 8.3 short path (RUNNER~1),
    # which Claude Code's own permission check holds for approval.
    root = pathlib.Path(tempfile.mkdtemp(prefix="bdxg_rt_")).resolve()
    market = root / "market"
    (market / ".claude-plugin").mkdir(parents=True)
    shutil.copytree(src, market / "plugin")
    (market / ".claude-plugin" / "marketplace.json").write_text(json.dumps({
        "name": "boxdawn", "owner": {"name": "Boxdawn"},
        "plugins": [{"name": "boxdawn-guard", "source": "./plugin"}]}))
    guarded = project(root, "guarded")
    control = project(root, "control")
    sh([CLAUDE, "plugin", "marketplace", "add", str(market), "--scope", "project"], guarded)
    sh([CLAUDE, "plugin", "install", "boxdawn-guard@boxdawn", "--scope", "project"], guarded)
    shutil.rmtree(DATA, ignore_errors=True)
    server = None if os.environ.get("BDX_RT_REAL_MODEL") == "1" else start_stand_in()
    try:
        return run_plan(market, guarded, control)
    finally:
        if server is not None:
            server.shutdown()
        # Leave the machine as it was: removing the marketplace uninstalls
        # its plugin and deletes the plugin's data dir.
        subprocess.run([CLAUDE, "plugin", "marketplace", "remove", "boxdawn"], cwd=guarded,
                       capture_output=True, text=True)
        shutil.rmtree(DATA, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)
        for t in TRANSCRIPT_DIRS:
            shutil.rmtree(t, ignore_errors=True)


def run_plan(market: pathlib.Path, guarded: pathlib.Path, control: pathlib.Path) -> int:
    plan = [("fresh", guarded, "default", "ok", True, "Bash")]
    tools = ["Bash", "PowerShell"] if platform.system() == "Windows" else ["Bash"]
    for tool in tools:
        plan += [("plugin", guarded, m, c, c == "ok", tool) for m in MODES for c in CASES]
        plan += [("control", control, m, c, True, tool) for m in MODES for c in CASES]
    ids = list((market / "plugin" / "dist").glob("*/BUILD_ID"))
    # The directory plugin (boxdawn/guard-plugin) carries no builds: it
    # downloads a pinned one, so there is no BUILD_ID here to change.
    if ids:
        plan += [("update", guarded, "default", "ok", True, "Bash")]
    failures = 0
    print(f"{platform.system()} {platform.machine()}  claude {subprocess.run([CLAUDE, '--version'], capture_output=True, text=True).stdout.strip()}")
    for label, d, mode, case, expect_run, tool in plan:
        if label == "update":
            for f in ids:
                f.write_text("update-test\n")
        r = session(d, mode, case, tool)
        good = r["executed"] == expect_run
        if label == "plugin" and not expect_run:
            good = good and r["by_guard"]
        if label == "update":
            good = good and r["placed"] == "update-test"
        failures += not good
        print(f"{'PASS' if good else 'FAIL'}  {label:7} {tool:10} {mode:18} {case:4} "
              f"ran={r['executed']} denials={r['denials']} by_guard={r['by_guard']} "
              f"placed={str(r['placed'])[:12]} exit={r['exit']}")
        if not good:
            print(f"      result: {r['result']!r}\n      stderr: {r['stderr']!r}\n      stdout: {r['stdout_head']!r}")
    # No API key here, so every call was judged on the fixed rules: the free
    # guard keeps no record, whatever it blocked above.
    no_record = not (DATA / "log").exists()
    failures += not no_record
    print(f"{'PASS' if no_record else 'FAIL'}  no block record without a key")
    total = len(plan) + 1
    # The record kept on this machine has the denies above, and only closed-set values. Not
    # for the directory edition: it runs the build it pins, which may come before the record.
    if ids:
        local = [json.loads(raw) for p in sorted((DATA / "judged").glob("*.jsonl"))
                 for raw in p.read_text(encoding="ascii").splitlines()] if (DATA / "judged").is_dir() else []
        keys = {"v", "t", "tool", "decision", "escalated", "findings", "build"}
        local_ok = bool(local) and all(
            set(line) == keys and line["decision"] in ("deny", "ask") and line["findings"]
            and all(set(f) == {"rule", "level", "target"} for f in line["findings"]) for line in local)
        total += 1
        failures += not local_ok
        print(f"{'PASS' if local_ok else 'FAIL'}  local judgment record: {len(local)} lines, closed values only")
    # The directory edition is frozen under review and keeps nothing out of a search.
    for tool in () if "--no-search" in sys.argv else ("Bash", "Grep"):
        for label, d, want in (("plugin", guarded, (True, False)), ("control", control, (True, True))):
            seen = search_sees(d, tool)
            good = seen == want
            total += 1
            failures += not good
            print(f"{'PASS' if good else 'FAIL'}  search  {tool:10} {label:7} plain={seen[0]} secret={seen[1]}")
    print(f"{total - failures}/{total} as expected")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
