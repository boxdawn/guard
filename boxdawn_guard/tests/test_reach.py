"""Ways a command reaches outside the project without naming the path plainly."""
import pytest

from boxdawn_guard.command_guard import evaluate
from boxdawn_guard.command_rules_source import default_command_rules
from boxdawn_guard.powershell_guard import evaluate_powershell
from boxdawn_guard.tests.test_links import RULES, bash, repo  # noqa: F401 - repo is a fixture

KW = dict(cwd="/home/u/proj", home="/home/u", rules=default_command_rules())


def decision(command):
    return evaluate(command, **KW).decision


def ps(command):
    verdict = evaluate_powershell(command, **KW)
    if verdict is None:
        pytest.skip("no PowerShell parser on this machine")
    return verdict.decision


@pytest.mark.parametrize("command", [
    "rm -rf {/etc,own}", "rm -rf own/{a,/../../../x}", "rm -rf {own,{a,/etc}}", "rm -rf {'/etc',own}",
])
def test_braces_are_read_as_the_shell_reads_them(command):
    assert decision(command) == "deny"


@pytest.mark.parametrize("command", [
    "rm -rf own/{a,b}", "rm '{/etc,own}'", "rm \\{/etc,own\\}", "git log --format='{a,b}'", "echo {a,b}{c,d}",
    "rm {}", "rm own/{a}",
])
def test_braces_that_stay_inside_or_are_quoted(command):
    assert decision(command) is None


def test_quoted_code_is_not_cut_at_a_brace():
    assert decision("bash -c 'rm -rf {/etc,own}'") == "deny"
    assert decision("python -c 'x={1,2}'") is None


def test_more_brace_words_than_are_read_is_a_path_not_known():
    assert decision("rm -rf " + "{a,b}" * 30) == "deny"


@pytest.mark.parametrize("command", [
    "cd /etc && bash -c 'rm -rf sub'", "cd /etc && eval 'rm -rf sub'", "cd /etc; sh -c \"rm -rf sub\"",
    "cd /etc && bash -c 'bash -c \"rm -rf sub\"'", "env -C /etc rm -rf sub", "env --chdir=/etc rm -rf sub",
    "env --chdir /etc rm -rf sub", "bash -c 'cd /etc && rm -rf sub'",
])
def test_nested_code_starts_where_the_line_is(command):
    assert decision(command) == "deny"


@pytest.mark.parametrize("command", ["cd own && bash -c 'rm -rf sub'", "env -C own rm -rf sub", "env FOO=1 rm -rf sub"])
def test_nested_code_inside_the_project(command):
    assert decision(command) is None


def test_powershell_nested_code_starts_where_the_line_is():
    assert ps("cd /etc; powershell -Command 'Remove-Item sub -Recurse -Force'") == "deny"


@pytest.mark.parametrize("command", ["find /etc -name x -exec rm -f {}/sub \\;", "find -H /etc -exec rm -rf {} +",
                                     "find -L /etc -exec rm -rf {} +"])
def test_find_exec_is_judged_on_what_it_is_given(command):
    assert decision(command) == "deny"


@pytest.mark.parametrize("command", ["find . -name '*.pyc' -exec rm {} +", "find . -exec rm -rf {}/sub \\;",
                                     "find own -exec cat {} +"])
def test_find_exec_inside_the_project(command):
    assert decision(command) is None


def test_find_exec_on_the_project_itself_still_asks():
    assert decision("find . -exec rm -rf {} \\;") == "ask"


def test_find_following_a_link_goes_behind_it(repo):  # noqa: F811
    assert bash("find -L link -type f -exec rm -f {} +", repo) == "deny"
    assert bash("find link -type f -exec rm -f {} +", repo) is None  # without -L find stays on the link


@pytest.mark.parametrize("command, want", [
    ("tar -C /etc -xf a.tar", "ask"), ("tar xf a.tar -C /etc", "ask"), ("tar -xf a.tar --directory=/etc", "ask"),
    ("tar -xf a.tar -C/etc", "ask"), ("tar --extract -f a.tar --directory /etc", "ask"),
    ("unzip a.zip -d /etc", "ask"), ("unzip a.zip -d/etc", "ask"), ("install a /etc/x", "ask"),
    ("install -m 755 a /etc/x", "ask"), ("tee /etc/x", "ask"), ("echo a | tee ~/.bashrc", "ask"),
    ("tee \"$OUT\"", "ask"), ("rsync -a a/ /etc/", "ask"), ("rsync -a --delete a/ /etc/", "deny"),
    ("rsync -a --delete-after a/ /etc/", "deny"), ("rsync -a --delete a/ host:/srv/", "ask"),
    ("rsync -a --delete -e ssh a/ user@host:/srv/", "ask"), ("rsync --delete a/ rsync://host/m", "ask"),
])
def test_writing_outside_with_these_commands(command, want):
    assert decision(command) == want


@pytest.mark.parametrize("command", [
    "tar -C /etc -cf own.tar .", "tar -tf a.tar -C /etc", "tar xf a.tar", "tar xf a.tar -C own", "unzip a.zip",
    "unzip a.zip -d own", "install a own/x", "install -d /etc/x", "tee own.txt", "tee -a /etc/x", "tee /dev/null",
    "rsync -a --delete own/ other/", "rsync -a a/ host:/srv/", "rsync -a /etc/ own/",
    "rsync --exclude /etc/ a/ own/",
])
def test_these_commands_with_no_decision(command):
    assert decision(command) is None


@pytest.mark.parametrize("command", [
    "Rename-Item /etc/x y", "ren /etc/x y", "rni -Path /etc/x -NewName y",
    "[IO.File]::Delete('/etc/x')", "[System.IO.Directory]::Delete(\"/etc/x\", $true)",
    "[io.file]::Move('/etc/x', 'b')", "[IO.File]::WriteAllText('/etc/x', 'y')", "[IO.File]::Delete($p)",
])
def test_powershell_asks(command):
    assert ps(command) == "ask"


@pytest.mark.parametrize("command", [
    "Rename-Item a b", "[IO.File]::Delete('a.txt')", "[IO.File]::WriteAllText('own/a.txt', 'y')",
    "[IO.File]::WriteAllText($p, 'y')", "[IO.File]::ReadAllText('/etc/x')", "Rename-Item a b -WhatIf",
])
def test_powershell_with_no_decision(command):
    assert ps(command) is None


def test_a_link_reached_through_a_brace(repo):  # noqa: F811
    assert bash("rm -rf {link,own}/sub", repo) == "deny"


def test_powershell_invoke_expression_starts_where_the_line_is():
    assert ps("cd /etc; Invoke-Expression 'Remove-Item sub -Recurse -Force'") == "deny"


@pytest.mark.parametrize("command, want", [
    ("r{m,} -rf /etc", "deny"), ("/bin/{rm,} -rf /etc", "deny"), ("tar -xC /etc -f a.tar", "ask"),
    ("tar xC /etc -f a.tar", "ask"), ("tar xfC a.tar /etc", "ask"), ("unzip -qd /etc a.zip", "ask"),
    ("tar --dir=/etc -xf a.tar", "ask"), ("cd /etc && tar xf a.tar", "ask"), ("cd /etc && unzip a.zip", "ask"),
    ("tar -cf /etc/passwd own", "ask"), ("tar --create --file=/etc/x own", "ask"),
    ("install -gdocker a /etc/x", "ask"), ("install -odeploy a /etc/x", "ask"), ("install -gbin a /etc/x", "ask"),
    ("install -Dt /etc a b", "ask"), ("cp -rt /etc a", "ask"),
    ("rsync -a --delete own/ /etc/ --out-format %n", "deny"), ("rsync -a --remove-source-files ~/x own/", "ask"),
    ("env -iC /etc rm -rf sub", "deny"), ("env -C own -C /etc rm -rf sub", "deny"),
    ("env -S 'rm -rf /etc'", "deny"), ("env --unset FOO rm -rf /etc", "deny"), ("env -u FOO rm -rf /etc", "deny"),
])
def test_found_in_review(command, want):
    assert decision(command) == want


def test_find_h_goes_behind_a_link_it_starts_on(repo):  # noqa: F811
    assert bash("find -H link -type f -exec rm -f {} +", repo) == "deny"


@pytest.mark.parametrize("command", [
    "env FOO=1 git -C ../other status && rm -rf build", "env CC=gcc make -C /opt/x && rm -rf build",
    "env -C /opt ls && rm -rf build", "rsync -a --delay-updates own/ host:/srv",
    "rsync --dry-run --delete own/ /etc/x", "rsync -n --delete own/ /etc/x", "tar -czf a.tgz -Tfiles.txt -C /etc",
    "tar -czfbox.tgz -C ../other .", "rm -f own/{1,2,3,4,5,6,7,8,9}{1,2,3,4,5,6,7,8,9}.tmp", "tar -cf - own",
])
def test_no_decision_found_in_review(command):
    assert decision(command) is None


def test_delay_updates_is_not_delete():
    assert decision("rsync -a --delay-updates own/ /etc/x") == "ask"


def test_a_remote_named_at_run_time_asks():
    assert decision("rsync -az --delete dist/ deploy@$HOST:/var/www/") == "ask"


def test_a_very_long_brace_word_is_a_path_not_known():
    assert decision("rm -rf x" + "{" * 20000) == "deny"


@pytest.mark.parametrize("command", [
    "[IO.File]::Move('a', '/etc/x')", "[IO.File]::Replace('a', '/etc/x', 'b')", "[IO.Directory]::Move('a', '/etc/x')",
    "[IO.File]::Copy('a', '/etc/x', $true)", "[IO.File]::Create('/etc/x')", "[IO.File]::OpenWrite('/etc/x')",
    "[IO.File]::WriteAllText(('/etc/x'), 'y')", "[IO.File]::Move($a, '/etc/x')", "[IO.File]::Delete(\"$x\\a.txt\")",
])
def test_powershell_dotnet_found_in_review(command):
    assert ps(command) == "ask"


@pytest.mark.parametrize("command", [
    "git commit -m \"use [IO.File]::Delete($path) instead\"", "# [IO.File]::Delete('/etc/x')",
    "Write-Host \"[IO.File]::Delete('/etc/x')\"", "[IO.File]::Delete(\"$PWD\\a.txt\")",
    "Get-ChildItem own -Filter *.tmp | Rename-Item -NewName { $_.Name + '.bak' }",
    "[IO.File]::WriteAllText('a.txt', '/etc/x')", "[IO.File]::Copy('/etc/x', 'a')",
])
def test_powershell_no_decision_found_in_review(command):
    assert ps(command) is None


@pytest.mark.parametrize("command, want", [
    ("env -uCC rm -rf /etc", "deny"), ("env -uPATHS rm -rf /etc", "deny"), ("env -uCC cat ~/.ssh/id_rsa", "ask"),
    ("cp -g a /etc/x", "ask"), ("mv -m a /etc/x", "ask"), ("install -oroot a /etc/x", "ask"),
    ("install -groot a /etc/x", "ask"), ("rsync -a --delete own/ /etc/ --max-delete 5", "deny"),
    ("rsync -a --delete -f'- node_modules' own/ /etc/", "deny"),
    ("rsync -a --delete -e'ssh -o StrictHostKeyChecking=no' own/ /etc/", "deny"),
    ("env -iS 'rm -rf /etc'", "deny"), ("env -S 'rm -rf' /etc", "deny"), ("env -C /etc -S 'rm -rf sub'", "deny"),
    ("cp -t/etc a", "ask"), ("mv -t/etc a", "ask"), ("tar -xf a.tar --one-top-level=/etc", "ask"),
])
def test_found_in_second_review(command, want):
    assert decision(command) == want


@pytest.mark.parametrize("command", [
    "unzip a.zip -dbuild", "unzip a.zip -dbuild/out", "tar -xzf a.tgz -C /tmp", "unzip a.zip -d /tmp",
    "cd /tmp && unzip -l a.zip", "cp -gx a b", "unzip -l /etc/a.zip",
])
def test_no_decision_found_in_second_review(command):
    assert decision(command) is None


@pytest.mark.parametrize("command", [
    "rm -rf /etc/" + "{a,b}" * 9 + "{" * 1990, "rm -rf " + "{a," * 680,
])
def test_brace_words_take_no_time(command):
    import time
    began = time.monotonic()
    decision(command)
    assert time.monotonic() - began < 5


@pytest.mark.parametrize("command", [
    "[IO.File]::Move('a', $b)", "[IO.File]::Copy('a', $b)", "[IO.File]::CreateText('/etc/x')",
    "$s = @'\ndon't\n'@\n[IO.File]::Delete('/etc/x')", "<# it's #> [IO.File]::Delete('/etc/x')",
    "Write-Host it`'s; [IO.File]::Delete('/etc/x')",
])
def test_powershell_found_in_second_review(command):
    assert ps(command) == "ask"
