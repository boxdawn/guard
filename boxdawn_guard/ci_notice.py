"""Tell the agent when the commit it just pushed newly broke the project's CI.

A PostToolUse hook on Bash and PowerShell, run by Claude Code in the background
(`asyncRewake`). After a `git push` that went through, it waits for the GitHub
Actions runs of the pushed commit, using the `gh` CLI the person already has
signed in. When a run fails whose workflow passed on the run before it (on the
same branch, or for a branch's first run on the default branch), it writes a
short note to stderr and exits 2, which wakes the agent with that note. Any
other outcome, an error included, exits 0 and says nothing.

It never blocks, changes or retries anything, never runs CI, and sends nothing
to Boxdawn. It reads GitHub only, through `gh`. Off unless the `ci_notice`
plugin setting is on.

Quiet on purpose: a run that was already failing before this push; a check of
the commit message or pull request title; a job not started for billing; a
commit that changes only documentation; a lint or format job whose annotations
all point at files the commit did not change. At most one note per push and
`MAX_PER_SESSION` per session, and the same failure (workflow and failed jobs)
is told once per session.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from typing import Callable

POLL_SECONDS = 25
FIRST_RUN_WAIT = 180  # no run at all after this: the repository has no Actions for this push
DEADLINE = 1500  # the hook's own timeout in hooks.json is longer
MAX_PER_SESSION = 3
BAD = ("failure", "timed_out")

MSG_CHECK = re.compile(r"commit ?lint|commit messages?|conventional commits?|pr title|semantic pr|lint commit", re.I)
LINTY = re.compile(r"lint|format|fmt|clippy|vet|style|prettier|eslint|ruff", re.I)
BILLING = re.compile(r"payments have failed|spending limit|billing", re.I)
DOC = re.compile(r"(\.(md|rst|txt|adoc|png|jpg|jpeg|gif|svg)$|(^|/)(CHANGELOG|LICENSE|NOTICE|AUTHORS)[^/]*$)", re.I)
SECRETISH = re.compile(r"token|secret|password|passwd|api[_-]?key|authorization", re.I)
_ENDS = re.compile(r"&&|\|\||[;|\n]")
_ANN = re.compile(r"^(\S+?):\d+ ")

Run = Callable[[list[str], str], tuple[int, str]]


def _on() -> bool:
    return (os.environ.get("CLAUDE_PLUGIN_OPTION_CI_NOTICE") or "").lower() in ("true", "1", "yes")


def _inside(path: str, folder: str) -> bool:
    path, folder = os.path.normcase(path), os.path.normcase(folder)
    return path == folder or path.startswith(folder.rstrip("\\/") + os.sep)


def _exe(name: str, project: str | None) -> str | None:
    """`name` from the PATH folders written in full and not in the project: a `gh.bat` or
    `git.exe` in the repository must not run (the same rule as the snapshot's git)."""
    names = (name + ".exe",) if os.name == "nt" else (name,)
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        folder = folder.strip('"')
        if not os.path.isabs(folder) or folder.replace("\\", "/").startswith("//") \
                or (project and _inside(os.path.realpath(folder), project)):
            continue
        for n in names:
            full = os.path.join(folder, n)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                return full
    return None


def _runner(project: str | None) -> Run | None:
    git, gh = _exe("git", project), _exe("gh", project)
    if not git or not gh:
        return None
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def run(cmd: list[str], cwd: str) -> tuple[int, str]:
        exe = {"git": git, "gh": gh}[cmd[0]]
        try:
            p = subprocess.run([exe, *cmd[1:]], cwd=cwd, capture_output=True, timeout=60, creationflags=flags,
                               stdin=subprocess.DEVNULL, env={**os.environ, "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"})
        except (OSError, subprocess.TimeoutExpired):
            return 1, ""
        return p.returncode, p.stdout.decode("utf-8", "replace")
    return run


def find_push(command: str) -> dict | None:
    """The first `git … push` in the line, read loosely: its remote, its refspec and its folder.
    None when there is none, or it pushes nothing to look at (dry run, delete, tags only, --all)."""
    for piece in _ENDS.split(command or ""):
        try:
            words = shlex.split(piece, posix=True)
        except ValueError:
            words = piece.split()
        while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
            words = words[1:]
        if not words or os.path.basename(words[0]).lower() not in ("git", "git.exe"):
            continue
        i, folder = 1, None
        while i < len(words) and words[i].startswith("-"):
            if words[i] == "-C" and i + 1 < len(words):
                folder = words[i + 1]
                i += 2
            elif words[i] in ("-c", "--git-dir", "--work-tree", "--namespace") and i + 1 < len(words):
                i += 2
            else:
                i += 1
        if i >= len(words) or words[i] != "push":
            continue
        rest = words[i + 1:]
        if any(w in ("-n", "--dry-run", "-d", "--delete", "--tags", "--all", "--mirror", "--prune") for w in rest):
            return None
        pos = [w for w in rest if not w.startswith("-")]
        refspec = pos[1] if len(pos) > 1 else None
        if refspec and refspec.startswith(":"):
            return None
        return {"remote": pos[0] if pos else None, "refspec": refspec, "folder": folder}
    return None


def pushed_ok(tool_response) -> bool:
    if not isinstance(tool_response, dict):
        return isinstance(tool_response, str) and not re.search(r"\b(rejected|fatal:|error:)", tool_response)
    if tool_response.get("interrupted"):
        return False
    text = " ".join(str(tool_response.get(k) or "") for k in ("stdout", "stderr", "output"))
    return not re.search(r"\[rejected\]|\[remote rejected\]|fatal:|error: failed to push", text)


def _repo(url: str) -> str | None:
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", url.strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


def target(push: dict, cwd: str, run: Run) -> dict | None:
    """Repository (owner/name), branch and commit the push sent."""
    _, branch_now = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd)
    branch_now = branch_now.strip()
    src = dst = None
    if push["refspec"]:
        spec = push["refspec"].lstrip("+")
        src, _, dst = spec.partition(":")
        dst = dst or src
    src = src if src and src != "HEAD" else (branch_now if branch_now != "HEAD" else "HEAD")
    dst = (dst if dst and dst != "HEAD" else branch_now)
    dst = dst.replace("refs/heads/", "")
    if not dst or dst == "HEAD":
        return None
    remote = push["remote"]
    if not remote:
        code, up = run(["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], cwd)
        remote = up.strip().split("/", 1)[0] if code == 0 and "/" in up else "origin"
    code, url = run(["git", "remote", "get-url", remote], cwd)
    repo = _repo(url) if code == 0 else _repo(remote)
    code, sha = run(["git", "rev-parse", src + "^{commit}"], cwd)
    if not repo or code != 0 or not re.fullmatch(r"[0-9a-f]{40}", sha.strip()):
        return None
    return {"repo": repo, "branch": dst, "sha": sha.strip()}


def _json(run: Run, cmd: list[str], cwd: str):
    code, out = run(cmd, cwd)
    if code != 0:
        return None
    try:
        return json.loads(out or "null")
    except ValueError:
        return None


def changed_files(t: dict, cwd: str, run: Run) -> list[str] | None:
    code, out = run(["git", "diff", "--name-only", t["sha"] + "^", t["sha"]], cwd)
    return [l.strip() for l in out.splitlines() if l.strip()] if code == 0 else None


def runs_of(t: dict, cwd: str, run: Run) -> list[dict]:
    return _json(run, ["gh", "run", "list", "--repo", t["repo"], "--commit", t["sha"], "--limit", "50", "--json",
                       "databaseId,workflowName,workflowDatabaseId,status,conclusion,headBranch,createdAt"], cwd) or []


def previous(t: dict, r: dict, cwd: str, run: Run, default_branch: Callable[[], str | None]) -> str | None:
    """Conclusion of the same workflow's last finished run before this one on a different commit:
    on the branch, or, for a branch's first run, on the default branch."""
    for branch in (r.get("headBranch") or t["branch"], None):
        if branch is None:
            branch = default_branch()
            if not branch or branch == (r.get("headBranch") or t["branch"]):
                return None
        rows = _json(run, ["gh", "run", "list", "--repo", t["repo"], "--workflow", str(r["workflowDatabaseId"]),
                           "--branch", branch, "--status", "completed", "--limit", "20", "--json",
                           "databaseId,headSha,conclusion,createdAt"], cwd) or []
        before = [x for x in rows if x.get("headSha") != t["sha"] and (x.get("createdAt") or "") < (r.get("createdAt") or "")]
        if before:
            return max(before, key=lambda x: x.get("createdAt") or "").get("conclusion")
    return None


def failure_detail(t: dict, r: dict, cwd: str, run: Run) -> dict:
    view = _json(run, ["gh", "run", "view", str(r["databaseId"]), "--repo", t["repo"], "--json", "jobs"], cwd) or {}
    jobs = []
    for j in view.get("jobs") or []:
        if j.get("conclusion") not in BAD:
            continue
        steps = [s.get("name") for s in j.get("steps") or [] if s.get("conclusion") in BAD]
        ann = _json(run, ["gh", "api", f"repos/{t['repo']}/check-runs/{j.get('databaseId')}/annotations",
                          "--jq", '[.[] | {level: .annotation_level, path: .path, line: .start_line, message: .message}]'], cwd) or []
        jobs.append({"name": j.get("name") or "", "steps": [s for s in steps if s], "ann": [a for a in ann if isinstance(a, dict)]})
    return {"jobs": jobs}


def quiet_reason(t: dict, r: dict, detail: dict, changed: list[str] | None) -> str | None:
    names = " ".join([r.get("workflowName") or ""] + [j["name"] + " " + " ".join(j["steps"]) for j in detail["jobs"]])
    if MSG_CHECK.search(names):
        return "message check"
    if any(BILLING.search(a.get("message") or "") for j in detail["jobs"] for a in j["ann"]):
        return "billing"
    if detail["jobs"] and changed is not None and all(LINTY.search(j["name"] + " " + " ".join(j["steps"])) for j in detail["jobs"]):
        paths = {a.get("path") for j in detail["jobs"] for a in j["ann"]
                 if a.get("level") == "failure" and a.get("path") and not str(a.get("path")).startswith(".github")}
        if paths and not any(p in changed or any(c.endswith(p) or p.endswith(c) for c in changed) for p in paths):
            return "lint outside the change"
    return None


def note(t: dict, r: dict, detail: dict, prev: str, korean: bool) -> str:
    lines = []
    for j in detail["jobs"][:3]:
        steps = ", ".join(j["steps"][:3])
        lines.append(f"- {j['name']}" + (f" → {steps}" if steps else ""))
        for a in [a for a in j["ann"] if a.get("level") == "failure"][:3]:
            msg = " ".join(str(a.get("message") or "").split())[:200]
            if msg and not SECRETISH.search(msg) and not re.fullmatch(r"Process completed with exit code \d+\.?", msg):
                lines.append(f"    {a.get('path')}:{a.get('line')} {msg}")
    where = f"{t['repo']} {t['branch']} @ {t['sha'][:7]}"
    if korean:
        head = (f"Boxdawn guard: 방금 push 한 커밋에서 CI 가 새로 실패했습니다 ({where}). "
                f"워크플로 '{r.get('workflowName')}' — 직전 실행은 통과였습니다.")
        tail = (f"이 변경 때문인지 확인하세요: gh run view {r['databaseId']} --repo {t['repo']} --log-failed  "
                "(변경과 상관없는 실패일 수도 있습니다.)")
    else:
        head = (f"Boxdawn guard: CI newly failed on the commit you just pushed ({where}). "
                f"Workflow '{r.get('workflowName')}': its previous run passed.")
        tail = (f"Check whether your change caused it: gh run view {r['databaseId']} --repo {t['repo']} --log-failed  "
                "(it may also be unrelated to the change).")
    return "\n".join([head, *lines, tail])


def _state_path(data_dir: str | None, session: str | None) -> str | None:
    if not data_dir or not session or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", session):
        return None
    return os.path.join(data_dir, "ci_notice", session + ".json")


def _load(path: str | None) -> dict:
    try:
        return json.load(open(path, encoding="utf-8")) if path else {}
    except (OSError, ValueError):
        return {}


def _save(path: str | None, state: dict) -> None:
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        json.dump(state, open(tmp, "w", encoding="utf-8"))
        os.replace(tmp, path)
    except OSError:
        pass


def watch(payload: dict, run: Run, *, korean: bool = False, data_dir: str | None = None,
          sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> tuple[int, str]:
    """(exit code, stderr text). 2 = wake the agent with the text; 0 = say nothing."""
    tool_input = payload.get("tool_input") or {}
    push = find_push(tool_input.get("command") or "")
    if not push or not pushed_ok(payload.get("tool_response")):
        return 0, ""
    cwd = payload.get("cwd") or os.getcwd()
    if push["folder"]:
        cwd = os.path.join(cwd, push["folder"])
    t = target(push, cwd, run)
    if not t:
        return 0, ""
    state_path = _state_path(data_dir, payload.get("session_id"))
    state = _load(state_path)
    if state.get("told", 0) >= MAX_PER_SESSION:
        return 0, ""
    changed = changed_files(t, cwd, run)
    if changed and all(DOC.search(c) for c in changed):
        return 0, ""
    default: dict = {}

    def default_branch() -> str | None:
        if "v" not in default:
            d = _json(run, ["gh", "repo", "view", t["repo"], "--json", "defaultBranchRef"], cwd) or {}
            default["v"] = (d.get("defaultBranchRef") or {}).get("name")
        return default["v"]

    start, seen = clock(), set()
    while clock() - start < DEADLINE:
        runs = runs_of(t, cwd, run)
        if not runs and clock() - start >= FIRST_RUN_WAIT:
            return 0, ""
        for r in runs:
            if r.get("status") != "completed" or r.get("databaseId") in seen:
                continue
            seen.add(r.get("databaseId"))
            if r.get("conclusion") not in BAD:
                continue
            prev = previous(t, r, cwd, run, default_branch)
            if prev != "success":
                continue
            detail = failure_detail(t, r, cwd, run)
            if quiet_reason(t, r, detail, changed):
                continue
            sig = f"{r.get('workflowName')}|{'|'.join(sorted(j['name'] for j in detail['jobs']))}"
            if sig in state.get("sigs", []):
                continue
            state["told"] = state.get("told", 0) + 1
            state["sigs"] = [*state.get("sigs", []), sig][-20:]
            _save(state_path, state)
            return 2, note(t, r, detail, prev, korean)
        if runs and all(r.get("status") == "completed" for r in runs):
            return 0, ""
        sleep(POLL_SECONDS)
    return 0, ""


def main() -> int:
    if not _on():
        return 0
    try:
        stdin = sys.stdin
        raw = stdin.buffer.read().decode("utf-8") if hasattr(stdin, "buffer") else stdin.read()
        payload = json.loads(raw or "{}")
        if payload.get("tool_name") not in ("Bash", "PowerShell"):
            return 0
        project = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd")
        run = _runner(os.path.realpath(project) if project else None)
        if run is None:
            return 0
        from boxdawn_guard.command_hook import _korean
        code, text = watch(payload, run, korean=_korean(), data_dir=os.environ.get("CLAUDE_PLUGIN_DATA"))
    except Exception:  # noqa: BLE001 - a notice that breaks must stay silent: it never decides anything
        return 0
    if code == 2:
        sys.stderr.write(text + "\n")
    return code
