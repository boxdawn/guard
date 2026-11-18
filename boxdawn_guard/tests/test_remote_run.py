"""A command run inside a container or on another machine (`docker exec`,
`docker compose exec|run`, `kubectl exec`, `ssh host …`) is read too (#37574).

Its paths are not this computer's, so what it would hold or block asks: never
a deny of ours. A path relative to where it runs is read as inside that place.
"""
from __future__ import annotations

import dataclasses
import os

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import messages_ko, powershell_guard  # noqa: E402
from boxdawn_guard.command_guard import CustomRule, evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()
RULE = "remote.run"


def bash(command, rules=RULES, unattended=False):
    return evaluate(command, cwd="/work/proj", home="/home/me", rules=rules, unattended=unattended,
                    known_env={"TEMP": "/tmp", "TMPDIR": "/tmp"})


def rules_of(verdict):
    return sorted({f.rule for f in verdict.findings})


ASKS = [
    # #37574: the dev database was purged through `docker compose exec`
    ("docker compose exec php bin/console doctrine:fixtures:load --no-interaction", "db.reset"),
    ("docker compose exec -T php bin/console doctrine:fixtures:load", "db.reset"),
    ("docker compose -f dev.yml exec -T php bin/console doctrine:fixtures:load", "db.reset"),
    ("docker-compose exec php bin/console doctrine:fixtures:load", "db.reset"),
    ("docker compose run --rm php bin/console doctrine:fixtures:load", "db.reset"),
    ("docker exec -it app php bin/console doctrine:fixtures:load", "db.reset"),
    ("docker exec app sh -c 'php bin/console doctrine:fixtures:load'", "db.reset"),
    ("docker compose exec app npx prisma migrate reset --force", "db.reset"),
    ("docker compose exec db psql -U u -c 'DROP DATABASE app'", "db.destructive"),
    ("docker exec app rm -rf /", "rm.outside"),
    ("docker exec app sh -c 'rm -rf /var/lib/postgresql/data'", "rm.outside"),
    ("docker exec app rm -rf .", "rm.project_root"),
    ('docker exec "$C" rm -rf /data', "rm.outside"),
    ("docker container exec app rm -rf /data", "rm.outside"),
    ("docker -H tcp://h exec app rm -rf /data", "rm.outside"),
    ("docker compose run --rm --entrypoint rm php -rf /data", "rm.outside"),
    ("docker exec app cat .env", "secret.read"),
    ('docker exec app "$CMD"', "name.runtime"),
    ("kubectl exec -it pod -- rm -rf /data", "rm.outside"),
    ("kubectl exec pod rm -rf /data", "rm.outside"),
    ("kubectl -n prod exec pod -c app -- psql -c 'DROP TABLE t'", "db.destructive"),
    ("kubectl exec pod -- php artisan migrate:fresh", "db.reset"),
    ("ssh host rm -rf /srv/app", "rm.outside"),
    ("ssh -p 22 -i key host rm -rf /srv", "rm.outside"),
    ("ssh -tt host 'cd /srv && rm -rf app'", "rm.outside"),
    ("ssh host 'php artisan migrate:fresh'", "db.reset"),
    ('ssh host "$CMD"', "code.runtime"),
    # the review (2026-11-18): a cluster ending in a letter that takes a value
    ("docker exec -itu root c rm -rf /data", "rm.outside"),
    ("docker exec -ie A=1 c rm -rf /data", "rm.outside"),
    ("docker compose exec -Tu root web rm -rf /data", "rm.outside"),
    ("docker compose run -Tv /:/h web rm -rf /h", "rm.outside"),
    ("docker exec -iu0 c rm -rf /data", "rm.outside"),
    # ssh reads options after the host too
    ("ssh host -t 'rm -rf /data'", "rm.outside"),
    ("ssh host -l root 'rm -rf /data'", "rm.outside"),
    ("ssh host -p 22 rm -rf /data", "rm.outside"),
    ("ssh host -- rm -rf /data", "rm.outside"),
    ("ssh -- host rm -rf /data", "rm.outside"),
    # compose splits --entrypoint into words; kubectl's old form has options after the pod
    ("docker compose run --entrypoint 'rm -rf /data' web", "rm.outside"),
    ("docker compose run --entrypoint 'sh -c' web 'rm -rf /data'", "rm.outside"),
    ("kubectl exec -it pod -c app bash -c 'rm -rf /data'", "rm.outside"),
]


@pytest.mark.parametrize("command,inner", ASKS)
def test_a_risky_command_in_there_asks(command, inner):
    v = bash(command)
    assert v.decision == "ask", (command, v.reasons)
    assert RULE in rules_of(v) and inner in rules_of(v)
    assert all(f.level == "ask" for f in v.findings)


NONE = [
    "docker compose exec php ls", "docker exec app cat /etc/hosts", "kubectl exec pod -- ls /",
    "docker compose exec -e X=1 -u root -w /app php bin/console cache:clear",
    "docker exec app rm -rf var/cache", "docker exec app rm -rf /tmp/build",
    "docker compose run --rm -v ./x:/x php ls",
    "ssh host uptime", "ssh host", "ssh -p2222 host ls", "ssh -o StrictHostKeyChecking=no host git status",
    "docker ps", "docker compose up -d", "kubectl get pods", "docker compose logs -f app",
]


@pytest.mark.parametrize("command", NONE)
def test_a_plain_command_in_there_is_not_held(command):
    v = bash(command)
    assert v.decision is None, (command, v.reasons)


def test_what_the_wrapper_itself_does_still_counts():
    assert bash("kubectl delete pod x").decision == "deny"
    assert bash("docker compose exec app ls; docker compose down -v").decision == "ask"


@pytest.mark.parametrize("command", [
    "ssh -o ProxyCommand='rm -rf /data' host",
    "ssh -o LocalCommand='rm -rf ~' -o PermitLocalCommand=yes host",
])
def test_what_ssh_runs_on_this_computer_is_judged_here(command):
    assert bash(command).decision == "deny"


@pytest.mark.parametrize("command", [
    "ssh -o ProxyCommand=none host uptime", "ssh -J bastion -o ProxyCommand='ssh -W %h:%p bastion' host uptime",
    "ssh -t host htop", "docker exec -it c bash", "kubectl exec -it pod -c app -- ls",
])
def test_these_stay_quiet(command):
    assert bash(command).decision is None


@pytest.mark.parametrize("wrap", ["docker exec c env ", "docker exec c ", "kubectl exec p -- docker exec c ",
                                  "docker compose exec w ", "docker exec c sudo env "])
def test_deep_nesting_does_not_hide_a_later_deny(wrap):
    v = bash(wrap * 300 + "ls; rm -rf /")
    assert v.decision == "deny" and "guard.crashed" not in rules_of(v)


def test_nobody_present_turns_the_ask_into_a_deny():
    v = bash("docker exec app rm -rf /", unattended=True)
    assert v.decision == "deny" and v.escalated


def test_an_org_rule_in_there_keeps_its_level():
    rules = dataclasses.replace(RULES, custom=(CustomRule("r7", "deny", "psql", (), (), "no psql in prod"),))
    v = bash("kubectl exec pod -- psql -c 'select 1'", rules=rules)
    assert v.decision == "deny" and "custom.r7" in rules_of(v)


def test_the_reason_says_where_it_runs_in_korean():
    v = bash("docker exec app rm -rf /")
    said = [messages_ko.translate(r) for r in v.reasons]
    assert "`docker`: 컨테이너나 다른 기계 안에서 위험한 명령을 실행합니다" in said


# ── PowerShell ──────────────────────────────────────────────────────────────
_helper = os.environ.get("BDX_PSPARSE")
needs_helper = pytest.mark.skipif(not (_helper and os.path.isfile(_helper)),
                                  reason="BDX_PSPARSE (bdxpsparse.exe) not built")


def ps(command):
    return powershell_guard.evaluate_powershell(
        command, cwd=r"C:\work\proj", home=r"C:\Users\me", rules=RULES,
        known_env={"TEMP": r"C:\Users\me\AppData\Local\Temp"})


@needs_helper
@pytest.mark.parametrize("command,inner", [
    ("docker compose exec php bin/console doctrine:fixtures:load", "db.reset"),
    ("docker exec app rm -rf /", "rm.outside"),
    ("kubectl exec pod -- rm -rf /data", "rm.outside"),
    ("ssh host 'rm -rf /srv'", "rm.outside"),
])
def test_powershell_reads_it_too(command, inner):
    v = ps(command)
    assert v.decision == "ask" and RULE in rules_of(v) and inner in rules_of(v), v.reasons


@needs_helper
@pytest.mark.parametrize("command", ["docker exec app ls", "ssh host uptime", "docker ps"])
def test_powershell_plain_is_not_held(command):
    assert ps(command).decision is None
