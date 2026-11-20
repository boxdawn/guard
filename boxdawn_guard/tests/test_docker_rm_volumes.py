"""`docker rm -v` (and `container rm -v`, `compose rm -v`, podman's) takes the
anonymous volumes the containers made with them, as `compose down -v` takes the
project's: it asks. Without `-v` the volumes stay, and nothing is said.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import messages_ko, powershell_guard  # noqa: E402
from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def bash(command):
    return evaluate(command, cwd="/work/proj", home="/home/me", rules=RULES)


ASKS = [
    ("docker rm -v n8n", "`docker rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker rm -fv n8n", "`docker rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker rm -f -v n8n", "`docker rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker rm n8n --volumes", "`docker rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker -H tcp://h rm -v n8n", "`docker rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker container rm -v n8n", "`docker container rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker compose rm -v", "`docker compose rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker compose rm -sfv", "`docker compose rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker compose -f a.yml -p app rm -fv db", "`docker compose rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker-compose rm -v", "`docker-compose rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("podman rm -v n8n", "`podman rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("podman compose rm -v", "`podman compose rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("sudo docker rm -v n8n", "`docker rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
    ("docker stop n8n && docker rm -v n8n", "`docker rm -v`: 컨테이너의 이름 없는 볼륨을 지웁니다"),
]


@pytest.mark.parametrize("command,said", ASKS)
def test_removing_containers_with_their_volumes_asks(command, said):
    v = bash(command)
    assert v.decision == "ask", v.reasons
    assert "docker.prune" in {f.rule for f in v.findings}
    assert said in [messages_ko.translate(r) for r in v.reasons], v.reasons


QUIET = [
    "docker rm n8n",
    "docker rm -f n8n",
    "docker container rm n8n",
    "docker compose rm",
    "docker compose rm -sf",
    "docker rm --volumes=false n8n",
    "docker compose -f v.yml rm -f",
    "docker run --rm -v /data alpine true",  # `--rm` with a volume: not `docker rm`
    "docker volume ls -v",
    "docker image rm -f app",
]


@pytest.mark.parametrize("command", QUIET)
def test_removing_containers_alone_gets_no_decision(command):
    assert bash(command).decision is None


_helper = os.environ.get("BDX_PSPARSE")


@pytest.mark.skipif(not (_helper and os.path.isfile(_helper)), reason="BDX_PSPARSE (bdxpsparse.exe) not built")
@pytest.mark.parametrize("command,expected", [("docker rm -fv n8n", "ask"), ("docker compose rm -sfv", "ask"),
                                              ("docker rm -f n8n", None)])
def test_powershell_judges_the_same(command, expected):
    v = powershell_guard.evaluate_powershell(command, cwd=r"C:\work\proj", home=r"C:\Users\me", rules=RULES)
    assert v.decision == expected, v.reasons
