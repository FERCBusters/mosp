"""The regular-expression boundary: code patterns, supplied patterns, and
patterns the database matches."""

import re

import pytest

from myf.security import regex as rx

# -- code patterns ------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        r"a+",
        r"(?:ab)++",
        r"(?:ab){1,1024}",
        r"(?:a|b)+",
        r"(?>ab)c",
        r"(?=a)b",
        r"(?!a)b",
        r"(a)?(?(1)b|c)",
        r"(a)?(?(1)b)",
        r"(?:[ab]+)",
        r"(?:ab|cd)e",
        r"(?:ab){2}(?:cd){3}",
    ],
)
def test_code_patterns_that_hold_bounded_state_compile(pattern):
    assert rx.scan_pattern(pattern).pattern == pattern


@pytest.mark.parametrize(
    "pattern,problem",
    [
        (r"(?:ab)+", "possessively"),
        (r"(?:ab){1025}", "possessively"),
        (r"(?:(?:ab){40}){40}", "possessively"),
        (r"(?:a+)+", "possessively"),
        (r"(?:a+){2}", "nested repeats"),
        (r"(?>(?:ab)+)", "possessively"),
        (r"(?:x|(?:ab)+)", "possessively"),
        (r"(?=(?:ab)+)", "possessively"),
        (r"(a)?(?(1)(?:ab)+|c)", "possessively"),
        (r"(a)?(?(1)c|(?:ab)+)", "possessively"),
        (r"(?:(?:ab)+)++", "possessively"),
        (r"(", "Invalid pattern"),
    ],
)
def test_code_patterns_whose_state_grows_are_refused(pattern, problem):
    with pytest.raises(ValueError, match=re.escape(problem)):
        rx.check_scan_pattern(pattern)


def test_a_timed_pattern_compiles_with_the_regex_package():
    timed = rx.scan_pattern(r"a+b", timed=True)
    assert timed.search("xaab", timeout=1).group() == "aab"
    assert rx.scan_pattern(rb"a+").search(b"xa").group() == b"a"


# -- supplied patterns --------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [r"^error .*$", r"a{1000}", r"(?>ab)+", r"(?:ab|cd)z", r"(?=a)b", r"a++"],
)
def test_supplied_patterns_that_cannot_stall_are_accepted(pattern):
    rx.validate_pattern(pattern)


@pytest.mark.parametrize(
    "pattern,problem",
    [
        ("a" * 513, "at most 512 characters"),
        (r"(", "Invalid pattern"),
        (r"\b{start}", "Invalid pattern"),
        (r"(?x)a b", "Expanded mode"),
        (r"(?x:a b)", "Expanded mode"),
        (r"a{1001}", "at most 1000"),
        (r"(?:a+)+", "Nested repetition"),
        (r"(?:ab|c)+", "Repeated alternatives"),
        (r"(a)\1", "Backreferences are unsupported"),
        (r"(a)?(?(1)b|c)", "Backreferences are unsupported"),
        (r".*a.*", "one unbounded repetition"),
        (r"(?>a+)+", "Nested repetition"),
        (r"(?=a+)+b", "Nested repetition"),
    ],
)
def test_supplied_patterns_that_could_stall_are_refused(pattern, problem):
    with pytest.raises(ValueError, match=re.escape(problem)):
        rx.validate_pattern(pattern)


def test_the_database_reads_neither_backreferences_nor_lookaround():
    rx.validate_database_pattern(r"^a\x41$")
    with pytest.raises(ValueError, match="hexadecimal escape"):
        rx.validate_database_pattern(r"(a)\101")
    with pytest.raises(ValueError, match="Lookahead and lookbehind"):
        rx.validate_database_pattern(r"(?<!a)b")


# -- matching supplied patterns -----------------------------------------------


def test_a_supplied_pattern_searches_a_bounded_window():
    pattern = rx.compile_pattern(r"needle")
    assert pattern.search("hay needle").group() == "needle"
    beyond = "x" * rx.MATCH_WINDOW_CHARS + "needle"
    assert pattern.search(beyond) is None


def test_a_pattern_that_fails_its_checks_is_unmatchable():
    with pytest.raises(rx.InvalidMatchPattern) as refused:
        rx.compile_pattern(r"(?:a+)+")
    assert isinstance(refused.value, rx.UNMATCHABLE)


class _Slow:
    def __init__(self, clock, spent):
        self.clock, self.spent, self.calls = clock, spent, 0

    def search(self, value, timeout, concurrent):
        self.calls += 1
        self.clock[0] += self.spent
        raise TimeoutError


@pytest.mark.parametrize(
    "spent,calls",
    [(rx.MATCH_TIMEOUT_SECONDS, 1), (0.0, rx.MATCH_ATTEMPTS)],
    ids=["own-time", "other-threads-time"],
)
def test_a_match_over_its_budget_is_given_up(monkeypatch, spent, calls):
    # A timeout charged to the matching thread itself ends the match; one
    # charged to other work in the process is tried again, a few times.
    clock = [0.0]
    monkeypatch.setattr(rx.time, "thread_time", lambda: clock[0])
    slow = _Slow(clock, spent)
    with pytest.raises(rx.MatchBudgetExceeded):
        rx.BoundedPattern(slow).search("text")
    assert slow.calls == calls
