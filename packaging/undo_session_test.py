"""`undo` in a real Claude Code session, with the built guard, on the system this runs on.

A stand-in for the model API (in this process, on a local port) tells Claude Code which tools
to call, so no account and no key are used and nothing is paid for. Claude Code itself is the
real program, and the hook is the built `bdxguard`.

What must hold:
1. the session runs the commands (the guard blocks when it fails, so a broken hook shows here);
2. a script run by the agent damages the project, and the list has a snapshot from before it;
3. `undo restore` typed by the agent, with nobody present, is refused;
4. `undo restore` typed by a person puts every original file back, byte for byte.

Usage: python packaging/undo_session_test.py <folder with the built bdxguard and _internal>
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BUILT = os.path.abspath(sys.argv[1])
ROOT = os.path.realpath(tempfile.mkdtemp(prefix="bdxundo"))
CFG, W, DATA = (os.path.join(ROOT, n) for n in ("cfg", "w", "data"))
CURRENT = os.path.join(DATA, "current")
EXE = os.path.join(CURRENT, "bdxguard.exe").replace("\\", "/")  # the one name the hooks use on every system
PY = sys.executable.replace("\\", "/")
CLAUDE = shutil.which("claude.cmd") or shutil.which("claude")

STEPS = [
    ("Bash", {"command": "echo made-in-step-1 > step1.txt", "description": "t"}),
    ("Bash", {"command": f'"{PY}" wipe.py', "description": "t"}),
    ("Bash", {"command": f'"{EXE}" undo restore 1 "{W.replace(chr(92), "/")}"', "description": "t"}),
]
calls = {"n": 0}
results: list[dict] = []


def reply(body: dict) -> list[dict]:
    messages = body.get("messages") or []
    last = messages[-1].get("content") if messages else []
    for block in last if isinstance(last, list) else []:
        # Claude Code sends the same turn more than once (its own side requests): one answer per call.
        if isinstance(block, dict) and block.get("type") == "tool_result" \
                and block.get("tool_use_id") not in {r.get("tool_use_id") for r in results}:
            results.append(block)
    names = {t.get("name") for t in body.get("tools") or []}
    if calls["n"] < len(STEPS) and STEPS[calls["n"]][0] in names:
        name, tool_input = STEPS[calls["n"]]
        calls["n"] += 1
        return [{"type": "tool_use", "id": f"toolu_{calls['n']}", "name": name, "input": tool_input}]
    return [{"type": "text", "text": "done"}]


def sse(content: list[dict], model: str):
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, payload: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.send(b"{}", "application/json")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if "count_tokens" in self.path:
            return self.send(b'{"input_tokens":1}', "application/json")
        if "/messages" not in self.path:
            return self.send(b"{}", "application/json")
        content, model = reply(body), body.get("model", "stand-in")
        if body.get("stream"):
            text = "".join(f"event: {n}\ndata: {json.dumps(d)}\n\n" for n, d in sse(content, model))
            return self.send(text.encode(), "text/event-stream")
        stop = "tool_use" if content[0]["type"] == "tool_use" else "end_turn"
        self.send(json.dumps({"id": "msg_stand_in", "type": "message", "role": "assistant", "model": model,
                              "content": content, "stop_reason": stop, "stop_sequence": None,
                              "usage": {"input_tokens": 1, "output_tokens": 1}}).encode(), "application/json")


def write(rel: str, data: bytes) -> None:
    path = os.path.join(W, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def state() -> dict[str, str]:
    found = {}
    for folder, _, files in os.walk(W):
        for name in files:
            path = os.path.join(folder, name)
            with open(path, "rb") as f:
                found[os.path.relpath(path, W).replace("\\", "/")] = hashlib.sha256(f.read()).hexdigest()
    return found


def main() -> int:
    if not CLAUDE:
        print("claude is not installed")
        return 1
    for folder in (CFG, W):
        os.makedirs(folder)
    shutil.copytree(BUILT, CURRENT)
    plain = os.path.join(CURRENT, "bdxguard")
    if os.path.isfile(plain):  # macOS and Linux build it without the extension
        os.replace(plain, os.path.join(CURRENT, "bdxguard.exe"))
        os.chmod(os.path.join(CURRENT, "bdxguard.exe"), 0o755)
    write("README.md", b"# demo\n")
    write("src/app.py", b"print('v1')\n")
    write(".env", b"API_KEY=not-a-real-key\n")
    write("wipe.py", b"import os\nos.remove('.env')\nopen('src/app.py', 'w').write('broken\\n')\n")
    original = state()
    with open(os.path.join(CFG, "settings.json"), "w", encoding="utf-8") as f:
        json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell", "hooks": [
            {"type": "command", "command": EXE, "args": [], "onFailure": "block"}]}]}}, f)

    class Quiet(ThreadingHTTPServer):
        def handle_error(self, request, client_address):  # a connection Claude Code drops is not news
            pass

    server = Quiet(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CLAUDE_PLUGIN_", "CLAUDECODE", "CLAUDE_CODE_", "BDX_", "ANTHROPIC_"))}
    env.update(CLAUDE_CONFIG_DIR=CFG, ANTHROPIC_BASE_URL=f"http://127.0.0.1:{server.server_address[1]}",
               ANTHROPIC_API_KEY="stand-in-not-a-key", DISABLE_AUTOUPDATER="1", DISABLE_TELEMETRY="1",
               CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", CLAUDE_PLUGIN_OPTION_UNDO="true",
               CLAUDE_PLUGIN_DATA=DATA, CLAUDE_PLUGIN_OPTION_LANGUAGE="English")
    session = subprocess.run([CLAUDE, "-p", "do the steps", "--output-format", "stream-json", "--verbose",
                              "--permission-mode", "bypassPermissions"], cwd=W, env=env, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=600, encoding="utf-8", errors="replace")
    server.shutdown()

    def undo(*args: str) -> tuple[int, str]:
        out = subprocess.run([EXE, "undo", *args], env=env, cwd=ROOT, capture_output=True, timeout=300)
        return out.returncode, (out.stdout + out.stderr).decode("utf-8", "replace")

    def text_of(block: dict) -> str:
        content = block.get("content")
        return content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)

    failed: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(("PASS  " if ok else "FAIL  ") + name + (f"\n      {detail[:600]}" if detail and not ok else ""))
        if not ok:
            failed.append(name)

    print(f"system {sys.platform} | session exit {session.returncode} | tool results {len(results)}")
    for i, block in enumerate(results):
        print(f"  step {i + 1}: {'error ' if block.get('is_error') else 'ok    '}{' '.join(text_of(block).split())[:170]}")
    check("the session ended normally and every step got an answer",
          session.returncode == 0 and len(results) == len(STEPS), session.stdout[-600:] + session.stderr[-600:])
    after = state()
    check("the first command ran", "step1.txt" in after)
    check("the agent's script damaged the project", ".env" not in after and after.get("src/app.py") != original["src/app.py"],
          str(sorted(after)))
    refused = len(results) == len(STEPS) and bool(results[2].get("is_error")) and "snapshot" in text_of(results[2])
    check("`undo restore` typed by the agent with nobody present is refused", refused,
          text_of(results[2]) if len(results) == len(STEPS) else "")
    code, listed = undo("list", W)
    print("\n".join("   | " + line for line in listed.rstrip().splitlines()[:12]))
    number = next((line.split()[0] for line in listed.splitlines() if "wipe.py" in line and line.split()[0].isdigit()), None)
    check("the list has a numbered snapshot from before the script", code == 0 and number is not None, listed)
    if number is not None:
        code, said = undo("restore", number, W)
        print("   | " + " ".join(said.split())[:300])
        now = state()
        back = {name: now.get(name) for name in original}
        check("a person's `undo restore` puts every original file back, byte for byte",
              code == 0 and back == original,
              f"missing {sorted(n for n in original if n not in now)}, "
              f"different {sorted(n for n in original if n in now and now[n] != original[n])}")
    shutil.rmtree(ROOT, ignore_errors=True)
    print(f"{'FAILED: ' + '; '.join(failed) if failed else 'all held'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
