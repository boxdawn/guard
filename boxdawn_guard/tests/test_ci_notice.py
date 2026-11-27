"""The CI notice: when it wakes the agent and when it stays quiet. A fake `git` and `gh`, no network."""
from __future__ import annotations

import json

import pytest

from boxdawn_guard import ci_notice

SHA = "a" * 40
PARENT_SHA = "b" * 40


class Fake:
    """Answers the git and gh calls ci_notice makes, from a small description of the repository."""

    def __init__(self, *, runs, prev=None, default_prev=None, changed=("src/app.py",), jobs=None, ann=None,
                 branch="feat/x", url="git@github.com:acme/app.git", default_branch="main"):
        self.runs, self.prev, self.default_prev = runs, prev or {}, default_prev or {}
        self.changed, self.jobs, self.ann = list(changed), jobs, ann or []
        self.branch, self.url, self.default_branch = branch, url, default_branch
        self.calls = []

    def __call__(self, cmd, cwd):
        self.calls.append(cmd)
        c = cmd[1:]
        if cmd[0] == "git":
            if c[:2] == ["rev-parse", "--abbrev-ref"] and c[2] == "HEAD":
                return 0, self.branch + "\n"
            if c[:2] == ["rev-parse", "--abbrev-ref"]:
                return 0, "origin/" + self.branch + "\n"
            if c[:2] == ["remote", "get-url"]:
                return 0, self.url + "\n"
            if c[0] == "rev-parse":
                return 0, SHA + "\n"
            if c[0] == "diff":
                return 0, "\n".join(self.changed) + "\n"
        if cmd[0] == "gh":
            if c[:2] == ["run", "list"] and "--commit" in c:
                return 0, json.dumps(self.runs)
            if c[:2] == ["run", "list"] and "--workflow" in c:
                wf, br = c[c.index("--workflow") + 1], c[c.index("--branch") + 1]
                table = self.prev if br != self.default_branch or br == self.branch else self.default_prev
                rows = table.get(wf, [])
                return 0, json.dumps(rows)
            if c[:2] == ["run", "view"]:
                return 0, json.dumps({"jobs": self.jobs if self.jobs is not None else [
                    {"name": "test", "conclusion": "failure", "databaseId": 7, "steps": [{"name": "Run tests", "conclusion": "failure"}]}]})
            if c[0] == "api":
                return 0, json.dumps(self.ann)
            if c[:2] == ["repo", "view"]:
                return 0, json.dumps({"defaultBranchRef": {"name": self.default_branch}})
        return 1, ""


def run_row(conclusion="failure", status="completed", wf=11, name="CI", rid=100, branch="feat/x"):
    return {"databaseId": rid, "workflowName": name, "workflowDatabaseId": wf, "status": status,
            "conclusion": conclusion, "headBranch": branch, "createdAt": "2026-11-27T10:00:00Z"}


def prev_rows(conclusion):
    return {"11": [{"databaseId": 90, "headSha": PARENT_SHA, "conclusion": conclusion, "createdAt": "2026-11-27T09:00:00Z"}]}


def payload(command="git push", response=None, session="s1"):
    return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/w/app", "session_id": session,
            "tool_response": response if response is not None else {"stdout": "", "stderr": "To github.com:acme/app.git\n   1..2  feat/x -> feat/x"}}


def go(fake, p=None, tmp_path=None, korean=False):
    return ci_notice.watch(p or payload(), fake, korean=korean, data_dir=str(tmp_path) if tmp_path else None,
                           sleep=lambda s: None, clock=_Clock())


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        self.t += 30
        return self.t


def test_new_failure_wakes_with_job_step_and_annotation(tmp_path):
    fake = Fake(runs=[run_row()], prev=prev_rows("success"),
                ann=[{"level": "failure", "path": "src/app.py", "line": 3, "message": "AssertionError: expected 2"}])
    code, text = go(fake, tmp_path=tmp_path)
    assert code == 2
    assert "acme/app feat/x @ aaaaaaa" in text and "test → Run tests" in text and "src/app.py:3 AssertionError" in text
    assert "gh run view 100 --repo acme/app --log-failed" in text


def test_already_failing_before_stays_quiet(tmp_path):
    assert go(Fake(runs=[run_row()], prev=prev_rows("failure")), tmp_path=tmp_path) == (0, "")


def test_all_passing_stays_quiet(tmp_path):
    assert go(Fake(runs=[run_row("success")], prev=prev_rows("success")), tmp_path=tmp_path) == (0, "")


def test_first_run_on_a_branch_compares_with_the_default_branch(tmp_path):
    fake = Fake(runs=[run_row()], prev={}, default_prev=prev_rows("success"))
    assert go(fake, tmp_path=tmp_path)[0] == 2
    fake = Fake(runs=[run_row()], prev={}, default_prev=prev_rows("failure"))
    assert go(fake, tmp_path=tmp_path)[0] == 0


def test_first_run_with_no_history_anywhere_stays_quiet(tmp_path):
    assert go(Fake(runs=[run_row()], prev={}, default_prev={}), tmp_path=tmp_path) == (0, "")


def test_commit_message_check_stays_quiet(tmp_path):
    fake = Fake(runs=[run_row(name="Lint Commit Messages")], prev=prev_rows("success"))
    assert go(fake, tmp_path=tmp_path) == (0, "")


def test_billing_stays_quiet(tmp_path):
    fake = Fake(runs=[run_row()], prev=prev_rows("success"),
                ann=[{"level": "failure", "path": ".github", "line": 1,
                      "message": "The job was not started because recent account payments have failed"}])
    assert go(fake, tmp_path=tmp_path) == (0, "")


def test_docs_only_commit_stays_quiet_without_asking_github(tmp_path):
    fake = Fake(runs=[run_row()], prev=prev_rows("success"), changed=["README.md", "docs/a.rst"])
    assert go(fake, tmp_path=tmp_path) == (0, "")
    assert not any(c[0] == "gh" for c in fake.calls)


def test_lint_pointing_outside_the_change_stays_quiet_inside_wakes(tmp_path):
    jobs = [{"name": "lint", "conclusion": "failure", "databaseId": 7, "steps": [{"name": "golangci-lint", "conclusion": "failure"}]}]
    out = Fake(runs=[run_row()], prev=prev_rows("success"), jobs=jobs,
               ann=[{"level": "failure", "path": "pkg/other.go", "line": 9, "message": "ireturn"}])
    assert go(out, tmp_path=tmp_path) == (0, "")
    inside = Fake(runs=[run_row()], prev=prev_rows("success"), jobs=jobs, changed=["pkg/other.go"],
                  ann=[{"level": "failure", "path": "pkg/other.go", "line": 9, "message": "ireturn"}])
    assert go(inside, tmp_path=tmp_path)[0] == 2


def test_not_a_push_or_a_failed_push_does_nothing(tmp_path):
    fake = Fake(runs=[run_row()], prev=prev_rows("success"))
    for cmd in ("git status", "echo git push", "git push --dry-run", "git push origin --delete old", "git push --tags",
                "git push origin :old"):
        assert go(fake, payload(cmd), tmp_path=tmp_path) == (0, ""), cmd
    rejected = payload(response={"stdout": "", "stderr": " ! [rejected]        feat/x -> feat/x (fetch first)"})
    assert go(fake, rejected, tmp_path=tmp_path) == (0, "")
    assert not fake.calls


def test_push_forms_read(tmp_path):
    assert ci_notice.find_push("cd app && git -C sub push -u origin HEAD:feat/y") == {"remote": "origin", "refspec": "HEAD:feat/y", "folder": "sub"}
    assert ci_notice.find_push("GIT_TRACE=1 git push") == {"remote": None, "refspec": None, "folder": None}
    assert ci_notice.find_push("npm test; git push origin main") == {"remote": "origin", "refspec": "main", "folder": None}


def test_not_github_stays_quiet(tmp_path):
    fake = Fake(runs=[run_row()], prev=prev_rows("success"), url="https://gitlab.com/acme/app.git")
    assert go(fake, tmp_path=tmp_path) == (0, "")


def test_no_runs_at_all_gives_up_quietly(tmp_path):
    assert go(Fake(runs=[]), tmp_path=tmp_path) == (0, "")


def test_once_per_failure_and_at_most_three_per_session(tmp_path):
    fake = Fake(runs=[run_row()], prev=prev_rows("success"))
    assert go(fake, tmp_path=tmp_path)[0] == 2
    assert go(fake, tmp_path=tmp_path)[0] == 0  # same workflow and jobs: told already
    for i, name in enumerate(("CI-b", "CI-c", "CI-d")):
        f = Fake(runs=[run_row(name=name, rid=200 + i)], prev=prev_rows("success"))
        assert go(f, tmp_path=tmp_path)[0] == (2 if i < 2 else 0)  # third different one is over the cap of 3
    other_session = Fake(runs=[run_row(name="CI-d", rid=300)], prev=prev_rows("success"))
    assert go(other_session, payload(session="s2"), tmp_path=tmp_path)[0] == 2


def test_secret_looking_annotation_is_left_out(tmp_path):
    fake = Fake(runs=[run_row()], prev=prev_rows("success"),
                ann=[{"level": "failure", "path": "a.py", "line": 1, "message": "API_KEY=sk-123 missing"}])
    code, text = go(fake, tmp_path=tmp_path)
    assert code == 2 and "sk-123" not in text


def test_korean_note(tmp_path):
    code, text = go(Fake(runs=[run_row()], prev=prev_rows("success")), tmp_path=tmp_path, korean=True)
    assert code == 2 and "CI 가 새로 실패했습니다" in text and "직전 실행은 통과였습니다" in text and "success" not in text
    code, text = go(Fake(runs=[run_row()], prev=prev_rows("success")), tmp_path=tmp_path / "en")
    assert code == 2 and "its previous run passed" in text


def test_main_is_off_unless_the_setting_is_on(monkeypatch):
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_CI_NOTICE", raising=False)
    assert ci_notice.main() == 0


def test_main_stays_silent_when_it_breaks(monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_CI_NOTICE", "true")
    monkeypatch.setattr("sys.stdin", _Broken())
    assert ci_notice.main() == 0
    assert capsys.readouterr().err == ""


class _Broken:
    def read(self):
        raise RuntimeError("boom")


@pytest.mark.parametrize("cmd", ["git push", "git.exe push origin main"])
def test_powershell_push_is_read_too(cmd, tmp_path):
    p = payload(cmd)
    p["tool_name"] = "PowerShell"
    fake = Fake(runs=[run_row()], prev=prev_rows("success"))
    assert go(fake, p, tmp_path=tmp_path)[0] == 2
