"""An org's own rules (server 0032): they add an ask or a deny and nothing else."""
from __future__ import annotations

import dataclasses
import json
import os

import pytest

pytest.importorskip("tree_sitter_bash")
pytest.importorskip("cryptography")

from boxdawn_guard import block_log, block_send, powershell_guard  # noqa: E402
from boxdawn_guard.command_guard import CustomRule, Finding, Verdict, evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402
from boxdawn_guard.rules_bundle import BundleError, custom_from_list, rules_to_dict, verify  # noqa: E402
from boxdawn_guard.tests.test_rules_bundle import KEY, KEYS, NOW, _b64  # noqa: E402

CWD, HOME = "/work/proj", "/home/me"
TEAM = (
    CustomRule("r1", "deny", "terraform", ("apply",), ("-auto-approve",), "review prod applies first"),
    CustomRule("r2", "ask", "kubectl", ("scale",)),
    CustomRule("r3", "deny", "gh", ("repo", "delete")),
)
RULES = dataclasses.replace(default_command_rules(), custom=TEAM)


def judge(command, rules=RULES, unattended=False):
    return evaluate(command, cwd=CWD, home=HOME, rules=rules, unattended=unattended)


@pytest.mark.parametrize("command, decision, rules", [
    ("terraform apply -auto-approve", "deny", ["custom.r1", "iac.auto_approve"]),
    ("terraform apply -auto-approve=true", "deny", ["custom.r1"]),
    ("TERRAFORM.EXE apply -auto-approve", "deny", ["custom.r1"]),
    ("terraform -chdir=infra apply -auto-approve", "deny", ["custom.r1", "iac.auto_approve"]),
    ("terraform apply", None, []),
    ("terraform plan -auto-approve", None, []),
    ("echo terraform apply -auto-approve", None, []),
    # the command inside sudo, env, bash -c and eval meets the rule too
    ("sudo env terraform apply -auto-approve", "deny", ["privilege.elevated", "custom.r1", "iac.auto_approve"]),
    ("bash -c 'terraform apply -auto-approve'", "deny", ["custom.r1", "iac.auto_approve"]),
    ("eval 'terraform apply -auto-approve'", "deny", ["custom.r1", "iac.auto_approve"]),
    # C: a value known only at run time that could complete the match asks
    ('terraform apply "$FLAGS"', "ask", ["custom.r1"]),
    ('terraform "$CMD" -auto-approve', "ask", ["custom.r1"]),
    ("echo x | xargs terraform apply", "ask", ["custom.r1"]),
    ('terraform plan "$X"', "ask", ["custom.r1"]),  # $X may be "apply", and a flag may be anything
    ("terraform plan -out=plan.bin", None, []),
    # other args may sit between the rule's words
    ("kubectl -n prod scale deploy web --replicas=0", "ask", ["custom.r2"]),
    ("kubectl get pods", None, []),
    # ours still applies, and the stronger decision wins
    ("kubectl scale deploy web --replicas=0 && kubectl delete ns staging", "deny",
     ["custom.r2", "k8s.delete"]),
    ("gh repo delete boxdawn/x --yes", "deny", ["custom.r3", "gh.delete"]),
    ("gh repo view boxdawn/x", None, []),
])
def test_team_rules(command, decision, rules):
    v = judge(command)
    assert (v.decision, [f.rule for f in v.findings]) == (decision, rules), command


def test_without_team_rules_nothing_changes():
    assert judge("kubectl -n prod scale deploy web --replicas=0", rules=default_command_rules()).decision is None


def test_the_reason_carries_the_orgs_note():
    v = judge("terraform apply -auto-approve")
    assert v.reasons == ("team rule r1: review prod applies first",
                         "`terraform apply -auto-approve` changes infrastructure without a review")


def test_with_nobody_to_ask_a_team_ask_is_a_deny():
    v = judge("kubectl -n prod scale deploy web --replicas=0", unattended=True)
    assert (v.decision, v.escalated) == ("deny", True)


@pytest.mark.skipif(not (os.environ.get("BDX_PSPARSE") and os.path.isfile(os.environ["BDX_PSPARSE"])),
                    reason="BDX_PSPARSE (bdxpsparse.exe) not built")
def test_a_native_command_from_powershell_meets_the_rule():
    v = powershell_guard.evaluate_powershell(
        "cd C:\\work\\proj; terraform apply -auto-approve", cwd="C:\\work\\proj",
        home="C:\\Users\\me", rules=RULES)
    assert (v.decision, [f.rule for f in v.findings]) == ("deny", ["custom.r1", "iac.auto_approve"])


# ── from the bundle ────────────────────────────────────────────────────────

ONE = {"id": "r12", "level": "deny", "command": "Terraform.exe", "args": ["apply"],
       "flags": ["-auto-approve"], "note": "review"}


def _signed(custom):
    body = {"v": 1, "kind": "command_rules", "kid": "t1", "iat": NOW, "exp": NOW + 3600,
            "fp": "x", "rules": rules_to_dict(default_command_rules())}
    if custom is not ...:
        body["custom"] = custom
    raw = json.dumps(body, sort_keys=True).encode()
    return {"kid": "t1", "payload": _b64(raw), "sig": _b64(KEY.sign(raw))}


def test_a_bundle_carries_the_orgs_rules():
    rules = verify(_signed([ONE]), KEYS, now=NOW + 1)
    assert rules.custom == (CustomRule("r12", "deny", "terraform", ("apply",), ("-auto-approve",), "review"),)
    assert evaluate("terraform apply -auto-approve", cwd=CWD, home=HOME, rules=rules).decision == "deny"


@pytest.mark.parametrize("custom", [..., [], None])
def test_a_bundle_without_them_has_none(custom):
    assert verify(_signed(custom), KEYS, now=NOW + 1).custom == ()


@pytest.mark.parametrize("change", [
    {"level": "allow"}, {"id": "12"}, {"id": "r1x"}, {"command": "rm -rf"}, {"command": ""},
    {"args": ["--force"]}, {"args": ["a b"]}, {"args": [1]}, {"args": ["a"] * 9},
    {"flags": ["force"]}, {"flags": "-x"}, {"note": "x" * 121}, {"note": "two\nlines"},
    {"extra": 1},
])
def test_a_malformed_rule_refuses_the_whole_bundle(change):
    with pytest.raises(BundleError):
        custom_from_list([{**ONE, **change}])
    with pytest.raises(BundleError):
        verify(_signed([{**ONE, **change}]), KEYS, now=NOW + 1)


def test_more_than_the_servers_limit_is_refused():
    with pytest.raises(BundleError):
        custom_from_list([{**ONE, "id": f"r{i}"} for i in range(101)])
    assert len(custom_from_list([{**ONE, "id": f"r{i}"} for i in range(100)])) == 100


# ── the block record ───────────────────────────────────────────────────────

def test_a_team_rule_is_recorded_by_its_id_only():
    v = judge("terraform apply -auto-approve")
    line = block_log.entry(v, tool="Bash", exp=NOW + 60, build=None, now=NOW)
    assert line["findings"] == [{"rule": "custom.r1", "level": "deny", "target": None},
                                {"rule": "iac.auto_approve", "level": "ask", "target": None}]
    assert "terraform" not in json.dumps(line) and "review" not in json.dumps(line)
    assert block_send._line_ok(line)


@pytest.mark.parametrize("rule", ["custom.x", "custom.r", "custom.r1.x", "custom"])
def test_anything_else_under_custom_is_dropped(rule):
    v = Verdict("deny", ("x",), (Finding(rule, "deny", None),))
    assert block_log.entry(v, tool="Bash", exp=NOW + 60, build=None, now=NOW) is None
