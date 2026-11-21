"""A word that is just `==` (`echo ==`, a separator in output) trips the bash grammar: before a
line break it joined the next line to the command, so `echo ==` ⏎ `rm -rf ~` read as one
`echo` with no decision; before `;`, `|` or `&` the line could not be read and asked.
Such a `==` is now read as the word it is.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def bash(command):
    return evaluate(command, cwd="/work/proj", home="/home/me", rules=RULES)


def seen(verdict):
    return verdict.decision, sorted({f.rule for f in verdict.findings})


@pytest.mark.parametrize("command, alone", [
    ("echo ==\nrm -rf ~", "rm -rf ~"),
    ("echo x ==\nrm -rf /", "rm -rf /"),
    ("echo ==\ngit push --force", "git push --force"),
    ("echo ==\r\nrm -rf ~", "rm -rf ~"),
    ("echo ==; rm -rf ~", "rm -rf ~"),
    ("echo == && rm -rf ~", "rm -rf ~"),
    ("echo ==|bash -c 'rm -rf ~'", "bash -c 'rm -rf ~'"),
    ("bash -c 'echo ==\nrm -rf ~'", "rm -rf ~"),
])
def test_what_follows_a_lone_double_equals_is_judged_on_its_own(command, alone):
    assert seen(bash(command)) == seen(bash(alone))


@pytest.mark.parametrize("command, alone", [
    # a review found these: the same trip with `=~`, before a comment, after a continued line
    ("echo =~\nrm -rf ~", "rm -rf ~"),
    ("echo x =~\nrm -rf ~", "rm -rf ~"),
    ("echo == # c\nrm -rf ~", "rm -rf ~"),
    ("echo ==\t# c\nrm -rf ~", "rm -rf ~"),
    ("echo =~ #\nrm -rf ~", "rm -rf ~"),
    ("echo a \\\n==\nrm -rf ~", "rm -rf ~"),
    ("echo a \\\n=~\nrm -rf ~", "rm -rf ~"),
    # a second review: form feed and vertical tab are blanks to the grammar too
    ("echo\f==\nrm -rf ~", "rm -rf ~"),
    ("echo x\f==\nrm -rf ~", "rm -rf ~"),
    ("echo\v==\nrm -rf ~", "rm -rf ~"),
    ("echo x\f=~\nrm -rf ~", "rm -rf ~"),
])
def test_other_shapes_of_the_same_trip(command, alone):
    assert seen(bash(command)) == seen(bash(alone))


@pytest.mark.parametrize("command", [
    # `==` as a here-document's end mark is left alone: changing it moved where the document ended
    "cat <<- ==\nhi\n\t==\nrm -rf ~\n=\n",
    "cat <<- ==\nhi\n\t==\nrm -rf ~\n\t=\n",
    "cat << ==\nhi\n==\nrm -rf ~\n",
    # a second review: end marks that hold the word in other spellings
    "cat <<'a =='\nx\na ==\nrm -rf ~\n",
    'cat <<" =="\nx\n ==\nrm -rf ~\n',
    "cat <<' =~'\nx\n =~\nrm -rf ~\n",
    "cat <<-\\==\nx\n\t==\nrm -rf ~\n",
    "cat <<-'='=\nx\n\t==\nrm -rf ~\n",
    "cat <<-'x ==;'\nx\n\tx ==;\nrm -rf ~\n",
])
def test_a_here_document_ending_with_double_equals_still_judges_what_follows(command):
    assert bash(command).decision == "deny"


@pytest.mark.parametrize("command", [
    "cat <<EOF\nx\nEOF\necho ==\nrm -rf ~",
    "cat <<EOF > a.txt\nx\nEOF\necho ==\ngit push --force",
])
def test_on_a_line_with_a_here_document_a_lone_double_equals_is_not_passed(command):
    assert bash(command).decision in ("ask", "deny")


@pytest.mark.parametrize("command", [
    "echo ==",
    "sed -n 1,2p a; echo ==; sed -n 3,4p a",
    "git log -1; echo ==; git status --short",
    "echo == && ls",
])
def test_an_ordinary_separator_gets_no_decision(command):
    assert seen(bash(command)) == (None, [])


@pytest.mark.parametrize("command", ['[ "$a" == b ]', "[[ $a == b ]] && echo y", "echo a==b", "echo == x"])
def test_other_uses_of_double_equals_are_read_as_before(command):
    assert not any(f.rule == "parse.unreadable" for f in bash(command).findings)
