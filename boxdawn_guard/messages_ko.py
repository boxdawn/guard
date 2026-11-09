"""The guard's reasons in Korean, for the `language` plugin setting.

The verdict never depends on this: it is decided in English and translated on
the way out. A reason not in the table goes out in English.
"""
from __future__ import annotations

import re

KOREAN = "한국어"

# `{}` is a value: a command, a path. Korean order may differ, so `{0}` `{1}` name them.
_TABLE = (
    ("the guard could not read this command ({})", "차단기가 이 명령을 읽지 못했습니다 ({0})"),
    ("commands nested too deep to read", "명령이 너무 깊게 겹쳐 있어 읽지 못했습니다"),
    ("the shell syntax could not be read", "셸 문법을 읽지 못했습니다"),
    ("the PowerShell syntax could not be read", "PowerShell 문법을 읽지 못했습니다"),
    ("the PowerShell reader of this guard is missing", "차단기의 PowerShell 판독기가 없습니다"),
    ("the command name is only known at run time", "실행해야만 명령 이름을 알 수 있습니다"),
    ("the git subcommand is known only at run time", "실행해야만 git 하위 명령을 알 수 있습니다"),
    ("nobody is present to approve it", "승인할 사람이 없습니다"),
    # secret files
    ("`{}` reads the secret file `{}`", "`{0}`: 비밀 파일을 읽습니다: `{1}`"),
    ("`{}` sends the secret file `{}` out", "`{0}`: 비밀 파일을 밖으로 보냅니다: `{1}`"),
    ("`{}` code names the secret file `{}`", "`{0}`: 코드에 비밀 파일 이름이 있습니다: `{1}`"),
    ("a secret file `{}` is fed to a command that sends it out", "비밀 파일이 밖으로 보내는 명령에 들어갑니다: `{0}`"),
    ("the secret file `{}` is read through a redirect", "리다이렉트로 비밀 파일을 읽습니다: `{0}`"),
    ("a secret file is sent out through a pipe", "파이프로 비밀 파일을 밖으로 보냅니다"),
    ("`{}` sends what a secret file holds out", "`{0}`: 비밀 파일 내용을 밖으로 보냅니다"),
    ("`xargs` is handed a secret file `find` listed", "`xargs`: `find` 가 찾은 비밀 파일을 받습니다"),
    ("`{}` sends a secret file out through a pipe", "`{0}`: 파이프로 비밀 파일을 밖으로 보냅니다"),
    ("`{}` is handed a secret file down the pipe", "`{0}`: 파이프로 비밀 파일을 받습니다"),
    # code and run-time text
    ("`{}` runs inline code this guard has no rules for", "`{0}`: 차단기에 규칙이 없는 코드를 바로 실행합니다"),
    ("`{}` code deletes files, runs other programs or rewrites data",
     "`{0}`: 코드가 파일을 지우거나 다른 프로그램을 실행하거나 데이터를 고칩니다"),
    ("`eval` runs text known only at run time", "`eval`: 실행해야만 알 수 있는 내용을 실행합니다"),
    ("`su -c` runs text known only at run time", "`su -c`: 실행해야만 알 수 있는 내용을 실행합니다"),
    ("`{}` runs text known only at run time", "`{0}`: 실행해야만 알 수 있는 내용을 실행합니다"),
    ("`{}` runs code known only at run time", "`{0}`: 실행해야만 알 수 있는 코드를 실행합니다"),
    ("output of another command is run as `{}` code", "다른 명령의 출력을 `{0}` 코드로 실행합니다"),
    ("text known only at run time is fed into `{}` as code", "실행해야만 알 수 있는 내용이 `{0}` 에 코드로 들어갑니다"),
    # rights and scripts
    ("`{}` runs a command with more rights", "`{0}`: 더 높은 권한으로 명령을 실행합니다"),
    ("`{}` may run a program with more rights", "`{0}`: 더 높은 권한으로 프로그램을 실행할 수 있습니다"),
    ("`{}` runs a script file in this shell", "`{0}`: 이 셸에서 스크립트 파일을 실행합니다"),
    ("`{}` destroys data by design", "`{0}`: 데이터를 지우는 명령입니다"),
    # writing
    ("output is written to a path known only at run time", "실행해야만 알 수 있는 경로에 출력을 씁니다"),
    ("output overwrites the disk device `{}`", "디스크 장치를 덮어씁니다: `{0}`"),
    ("output is written to `{}` outside the project", "프로젝트 밖에 출력을 씁니다: `{0}`"),
    ("{} is written to a path known only at run time", "{0}: 실행해야만 알 수 있는 경로에 씁니다"),
    ("{} is written to `{}` outside the project", "{0}: 프로젝트 밖에 씁니다: `{1}`"),
    ("`{} -Force` replaces a path known only at run time", "`{0} -Force`: 실행해야만 알 수 있는 경로를 바꿔 씁니다"),
    ("`{} -Force` replaces `{}` outside the project", "`{0} -Force`: 프로젝트 밖 파일을 바꿔 씁니다: `{1}`"),
    ("`{}` writes over a path known only at run time", "`{0}`: 실행해야만 알 수 있는 경로를 덮어씁니다"),
    ("`{}` writes over `{}` outside the project", "`{0}`: 프로젝트 밖 파일을 덮어씁니다: `{1}`"),
    ("`{}` takes away a path known only at run time", "`{0}`: 실행해야만 알 수 있는 경로를 옮겨 버립니다"),
    ("`{}` takes away `{}` outside the project", "`{0}`: 프로젝트 밖 파일을 옮겨 버립니다: `{1}`"),
    ("`sed -i` edits `{}` outside the project", "`sed -i`: 프로젝트 밖 파일을 고칩니다: `{0}`"),
    ("`truncate` empties a file outside the project: `{}`", "`truncate`: 프로젝트 밖 파일을 비웁니다: `{0}`"),
    ("`truncate` empties a file", "`truncate`: 파일을 비웁니다"),
    ("`{}` empties a file outside the project: `{}`", "`{0}`: 프로젝트 밖 파일을 비웁니다: `{1}`"),
    ("`{}` empties a file", "`{0}`: 파일을 비웁니다"),
    ("`{} -R` changes everything under `{}`", "`{0} -R`: 아래 전체를 바꿉니다: `{1}`"),
    ("`dd` operand known only at run time", "`dd`: 실행해야만 대상을 알 수 있습니다"),
    ("`dd` writes over the disk device `{}`", "`dd`: 디스크 장치를 덮어씁니다: `{0}`"),
    ("`dd` writes outside the project: `{}`", "`dd`: 프로젝트 밖에 씁니다: `{0}`"),
    ("`dd` overwrites a file", "`dd`: 파일을 덮어씁니다"),
    # deleting
    ("`{}` target is known only at run time", "`{0}`: 실행해야만 대상을 알 수 있습니다"),
    ("`{}` reaches outside the project: `{}`", "`{0}`: 프로젝트 밖까지 닿습니다: `{1}`"),
    ("`{}` removes the whole project directory", "`{0}`: 프로젝트 폴더 전체를 지웁니다"),
    ("`{} -Recurse` with `-Include` or `-Exclude` follows links below the path",
     "`{0} -Recurse`: `-Include`·`-Exclude` 를 쓰면 아래 링크를 따라갑니다"),
    ("`rsync --delete` removes files under a path known only at run time", "`rsync --delete`: 실행해야만 알 수 있는 경로 아래를 지웁니다"),
    ("`rsync --delete` removes files under `{}` outside the project", "`rsync --delete`: 프로젝트 밖 파일을 지웁니다: `{0}`"),
    ("`rsync --delete` removes files on another machine: `{}`", "`rsync --delete`: 다른 컴퓨터의 파일을 지웁니다: `{0}`"),
    ("the .NET call `{}` changes a path known only at run time", ".NET 호출 `{0}`: 실행해야만 알 수 있는 경로를 바꿉니다"),
    ("the .NET call `{}` changes `{}` outside the project", ".NET 호출 `{0}`: 프로젝트 밖 파일을 바꿉니다: `{1}`"),
    ("`find -delete` under `{}`", "`find -delete`: 이 아래를 지웁니다: `{0}`"),
    ("`find -delete` removes files in bulk", "`find -delete`: 파일을 한꺼번에 지웁니다"),
    # links
    ("`{}` goes through a link this command makes", "`{0}`: 이 명령이 만드는 링크를 거쳐 갑니다"),
    ("`ln -s` makes a link whose name is known only at run time", "`ln -s`: 실행해야만 이름을 알 수 있는 링크를 만듭니다"),
    # git
    ("`git push --force` rewrites history others share", "`git push --force`: 다른 사람과 공유하는 이력을 고칩니다"),
    ("`git push --force-with-lease` rewrites remote history", "`git push --force-with-lease`: 원격 이력을 고칩니다"),
    ("`git push` deletes or mirrors remote refs", "`git push`: 원격 참조를 지우거나 통째로 맞춥니다"),
    ("`git reset --hard` discards uncommitted work", "`git reset --hard`: 커밋 안 한 작업을 버립니다"),
    ("`git clean -f` deletes untracked files", "`git clean -f`: 추적 안 하는 파일을 지웁니다"),
    ("`git branch -D` deletes an unmerged branch", "`git branch -D`: 머지 안 된 브랜치를 지웁니다"),
    ("`git {}` rewrites history", "`git {0}`: 이력을 고칩니다"),
    # databases and infrastructure
    ("`{}` runs a destructive statement", "`{0}`: 데이터를 지우는 문장을 실행합니다"),
    ("`{}` runs a statement known only at run time", "`{0}`: 실행해야만 알 수 있는 문장을 실행합니다"),
    ("`{}` runs statements from a file", "`{0}`: 파일에 있는 문장을 실행합니다"),
    ("`{}` destroys infrastructure", "`{0}`: 인프라를 지웁니다"),
    ("`pulumi destroy` destroys infrastructure", "`pulumi destroy`: 인프라를 지웁니다"),
    ("`kubectl delete` removes cluster resources", "`kubectl delete`: 클러스터 자원을 지웁니다"),
    ("`helm uninstall` removes a release", "`helm uninstall`: 릴리스를 지웁니다"),
    ("`aws s3 rm` deletes objects", "`aws s3 rm`: 객체를 지웁니다"),
    ("`aws s3 rb` deletes a bucket", "`aws s3 rb`: 버킷을 지웁니다"),
    ("`aws {} {}` deletes cloud resources", "`aws {0} {1}`: 클라우드 자원을 지웁니다"),
    ("`{} … delete` deletes cloud resources", "`{0} … delete`: 클라우드 자원을 지웁니다"),
    ("`docker` prune removes data", "`docker` prune: 데이터를 지웁니다"),
    ("`{}` runs a program known only at run time", "`{0}`: 실행해야만 알 수 있는 프로그램을 실행합니다"),
    ("`{}` program runs other commands", "`{0}`: 프로그램이 다른 명령을 실행합니다"),
    ("`wsl --unregister` deletes the distro and every file in it", "`wsl --unregister`: 배포판과 그 안의 파일 전부를 지웁니다"),
    ("`{}` resets or drops a database", "`{0}`: 데이터베이스를 초기화하거나 지웁니다"),
    ("`git {}` overwrites uncommitted changes", "`git {0}`: 커밋 안 한 변경을 덮어씁니다"),
    ("`git rm -r .` deletes every tracked file", "`git rm -r .`: 추적 중인 파일을 전부 지웁니다"),
    ("`git stash {}` deletes stashed work", "`git stash {0}`: 보관해 둔 작업을 지웁니다"),
    ("`rm` removes `{}`, which no build makes again", "`rm`: 다시 만들 수 없는 것을 지웁니다: `{0}`"),
    ("`{} apply -auto-approve` changes infrastructure without a review", "`{0} apply -auto-approve`: 검토 없이 인프라를 바꿉니다"),
    ("`docker compose down -v` deletes the project's volumes", "`docker compose down -v`: 프로젝트 볼륨을 지웁니다"),
    ("`robocopy /MIR` deletes files the source does not have", "`robocopy /MIR`: 원본에 없는 파일을 지웁니다"),
    ("`lftp mirror --delete` deletes files the source does not have", "`lftp mirror --delete`: 원본에 없는 파일을 지웁니다"),
    ("`gh repo delete` deletes a repository", "`gh repo delete`: 저장소를 지웁니다"),
    ("`gh api` sends a DELETE", "`gh api`: DELETE 요청을 보냅니다"),
    ("`firebase {}` deletes or takes down cloud resources", "`firebase {0}`: 클라우드 자원을 지우거나 내립니다"),
    # phones and other devices
    ("`fastboot {}` wipes data on the device", "`fastboot {0}`: 기기의 데이터를 지웁니다"),
    ("`fastboot {}` overwrites a partition on the device", "`fastboot {0}`: 기기의 파티션을 덮어씁니다"),
    ("`adb uninstall` removes an app and its data from the device", "`adb uninstall`: 기기에서 앱과 그 데이터를 지웁니다"),
    ("`adb shell` clears or removes an app's data on the device", "`adb shell`: 기기에서 앱 데이터를 지우거나 앱을 지웁니다"),
    ("`adb shell` deletes or wipes data on the device", "`adb shell`: 기기의 데이터를 지웁니다"),
    # an org's own rules: the note stays as the org wrote it
    ("team rule {}: {} (a value is known only at run time)", "조직 규칙 {0}: {1} (실행해야만 값을 알 수 있습니다)"),
    ("team rule {} on `{}` (a value is known only at run time)", "조직 규칙 {0}: `{1}` (실행해야만 값을 알 수 있습니다)"),
    ("team rule {} on `{}`", "조직 규칙 {0}: `{1}`"),
    ("team rule {}: {}", "조직 규칙 {0}: {1}"),
)
_PATTERNS = tuple((re.compile("(.+?)".join(map(re.escape, en.split("{}"))) + "$", re.S), ko) for en, ko in _TABLE)

SEARCH_NOTE = "Boxdawn 차단기는 .env 같은 비밀 파일을 폴더 검색에서 뺍니다. 빠진 파일이 있을 수 있습니다. 파일 하나를 검색하려면 그 경로를 주세요."
GREP_NOTE = "Boxdawn 차단기가 비밀 파일을 빼려고 이 grep 에 --exclude 를 붙였습니다. 빠진 파일이 있을 수 있습니다."
FAILED = "Boxdawn 차단기가 고장 나서 ({}) 막습니다"


def translate(reason: str) -> str:
    for pattern, korean in _PATTERNS:
        m = pattern.match(reason)
        if m:
            return korean.format(*m.groups())
    return reason
