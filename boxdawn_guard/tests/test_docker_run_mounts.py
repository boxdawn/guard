"""`docker run` (and podman's) starts a new container, thrown away with what
it holds. What runs in it is read only when a folder of this computer is
mounted in it writable (`-v`, `--mount`); there a path under the mount is that
folder, and is judged as it would be here. What lands outside the project keeps
its level; anything else that would hold asks, as `docker exec` does.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import messages_ko  # noqa: E402
from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def bash(command):
    return evaluate(command, cwd="/work/proj", home="/home/me", rules=RULES,
                    known_env={"TEMP": "/tmp", "TMPDIR": "/tmp"})


def rules_of(verdict):
    return {f.rule for f in verdict.findings}


DENIES = [
    "docker run --rm -v /:/host alpine rm -rf /host",
    "docker run --rm -v /:/host alpine rm -rf /host/etc",
    "docker run --rm -v /:/host alpine rm -rf /",  # takes the mounted folder with it
    "docker run --rm -v ~/:/h alpine rm -rf /h",
    "docker run --rm -v ~:/h alpine rm -rf /h/Documents",
    "docker run --rm -v /home/me:/h alpine rm -rf /h",
    "docker run --rm -v ../other:/o alpine rm -rf /o",
    "docker run --rm --mount type=bind,source=/,target=/host alpine rm -rf /host",
    "docker run --rm --mount type=bind,src=/home/me,dst=/h alpine rm -rf /h",
    "docker run --rm --volume=/:/host alpine rm -rf /host",
    "docker run --rm -v/:/host alpine rm -rf /host",
    "docker container run -it --rm -v /:/host alpine rm -rf /host",
    "docker run -d --name x -e A=1 -p 80:80 -v /:/host alpine rm -rf /host",
    "docker run --rm --entrypoint rm -v /:/host alpine -rf /host",
    "docker run --rm --entrypoint bash -v /:/host alpine -c 'rm -rf /host'",
    "docker run --rm -v /:/host alpine sh -c 'rm -rf /host/home'",
    "podman run --rm -v /:/host alpine rm -rf /host",
    "sudo docker run --rm -v /:/host alpine rm -rf /host",
    "docker -H tcp://h run --rm -v /:/host alpine rm -rf /host",
    "docker run --rm -v /:/host -w //host alpine rm -rf etc",
    # options that take a value, also written with an unknown one
    "podman run --rm -v /:/host --retry 3 alpine rm -rf /host",
    "docker run --rm --cpu-count 2 -v /:/host alpine rm -rf /host",
    "docker run --rm --user=$(id -u):$(id -g) -v /:/host alpine rm -rf /host",
    # `$PWD` after `cd` is that folder too
    'cd /elsewhere && docker run --rm -v "$PWD":/app alpine rm -rf /app/dist',
]


@pytest.mark.parametrize("command", DENIES)
def test_a_delete_through_a_mount_of_a_folder_outside_the_project_is_denied(command):
    v = bash(command)
    assert v.decision == "deny", v.reasons
    assert "rm.outside" in rules_of(v)


def test_the_reason_says_which_folder_of_this_computer_it_is():
    v = bash("docker run --rm -v ~/:/h alpine rm -rf /h")
    assert "`/h` inside the container is `~/` on this computer" in v.reasons


ASKS = [
    ("docker run --rm -v .:/app alpine rm -rf /app", "rm.project_root"),
    ('docker run --rm -v "$(pwd)":/app alpine rm -rf /app', "rm.project_root"),
    ('docker run --rm -v "$SRC":/app alpine rm -rf /app/dist', "rm.runtime"),
    ('cd "$X" && docker run --rm -v "$PWD":/app alpine rm -rf /app/dist', "rm.runtime"),
    ('docker run --rm -v "$PWD":/app -v nm:/app/node_modules -w /app node:20 rm -rf node_modules', "rm.runtime"),
    ("docker run --rm -v pgdata:/var/lib/postgresql/data alpine rm -rf /var/lib/postgresql/data", "rm.runtime"),
    ("docker run --rm --volumes-from db alpine rm -rf /var/lib/mysql", "rm.runtime"),
    ("docker run --rm -v data:/d alpine rm -rf d", "rm.runtime"),  # it starts at `/` unless `-w` says
    ("echo 'rm -rf /host' | docker run -i --rm -v /:/host alpine sh", "pipe.into_interpreter"),
    ("docker run --rm -v /:/host alpine psql -h db -c 'DROP TABLE t'", "db.destructive"),
    ("docker run --rm -v /:/host alpine cat /host/home/me/.env", "secret.read"),
]


@pytest.mark.parametrize("command,rule", ASKS)
def test_what_may_reach_a_mounted_folder_asks(command, rule):
    v = bash(command)
    assert v.decision == "ask", v.reasons
    assert {rule, "remote.run"} <= rules_of(v)


QUIET = [
    # nothing of this computer in the container
    "docker run --rm alpine rm -rf /",
    "docker run --rm alpine sh -c 'rm -rf /'",
    "docker run --rm -v /data alpine rm -rf /data",  # a new volume, thrown away with it
    "docker run --rm --mount type=tmpfs,target=/t alpine rm -rf /t",
    "docker run --rm --mount type=volume,target=/v alpine rm -rf /v",
    # mounted read-only
    "docker run --rm -v /:/host:ro alpine rm -rf /host",
    "docker run --rm --mount type=bind,src=/,dst=/host,readonly alpine rm -rf /host",
    # a path the mount does not reach
    "docker run --rm -v /:/host alpine rm -rf /tmp/x",
    "docker run --rm -v /:/host alpine rm -rf /hostname",
    # inside the project, as here
    "docker run --rm -v .:/app -w /app node:20 rm -rf dist",
    "docker run --rm -v .:/app node:20 rm -rf /app/dist",
    "docker run --rm -v /work/proj:/app node:20 rm -rf /app/node_modules",
    # `$PWD` is where the line starts: the project
    'docker run --rm -v "$PWD":/app alpine rm -rf /app/dist',
    "docker run --rm -v $(pwd):/app -w /app alpine rm -rf dist",
    'docker run --rm --mount type=bind,source="$(pwd)"/,target=/app node sh -c "cd app && rm -r dist"',
    'cd frontend && docker run --rm -v "$PWD":/app -w /app node:20 sh -c "rm -rf dist && npm run build"',
    'docker run --rm -v "$PWD":"$PWD" -w "$PWD" node:20 sh -c "rm -rf dist && npm run build"',
    "docker run --rm -v $(pwd):$(pwd) -w $(pwd) node:20 rm -rf dist",
    "docker run --rm -v /$PWD:/app -w /app node:20 rm -rf dist",
    "docker run --rm -v //work/proj:/app -w /app node:20 rm -rf dist",  # `//`: Git Bash keeps the path as is
    'docker run --rm --name=$N -v "$PWD":/app -w /app node:20 rm -rf dist',
    "docker run --rm --volumes-from db:ro alpine rm -rf /var/lib/mysql",
    # everyday runs
    'docker run --rm -v "$PWD":/app -w /app node:20 npm test',
    "docker run --rm -v .:/app -w /app node:20 npm ci",
    "docker run --rm -it -v .:/src -w /src golang:1.23 go build ./...",
    "docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=x -v pgdata:/var/lib/postgresql/data postgres:16",
    # stdin goes in only with -i
    "echo 'rm -rf /host' | docker run --rm -v /:/host alpine sh",
    # options or the image known only at run time: as before
    "docker run $OPTS -v /:/host alpine rm -rf /host",
    'docker run --rm -v /:/host "$IMAGE" rm -rf /host',
]


@pytest.mark.parametrize("command", QUIET)
def test_what_cannot_reach_this_computer_gets_no_decision(command):
    v = bash(command)
    assert v.decision is None, v.reasons


def test_a_named_volume_is_not_called_a_folder_of_this_computer():
    v = bash('docker run --rm -v "$PWD":/app -v nm:/app/node_modules -w /app node:20 rm -rf node_modules')
    assert not any("on this computer" in r for r in v.reasons), v.reasons


@pytest.mark.parametrize("command,decision", [
    ("docker run --rm -v //c/Users/dev/proj:/app -w /app node:20 rm -rf dist", None),
    ('docker run --rm -v "/$(pwd)":/app -w //app node:20 rm -rf dist', None),
    ("docker run --rm -v //c/Users/dev:/h alpine rm -rf /h", "deny"),
])
def test_git_bash_paths_from_a_windows_project(command, decision):
    v = evaluate(command, cwd="C:\\Users\\dev\\proj", home="C:\\Users\\dev", rules=RULES)
    assert v.decision == decision, v.reasons


def test_the_new_reason_has_a_korean_message():
    assert "이 컴퓨터의" in messages_ko.translate("`/h` inside the container is `~/` on this computer")
