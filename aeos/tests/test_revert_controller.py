#!/usr/bin/env python3
"""Focused, deterministic tests for the AEOS post-main circuit breaker."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main_smoke as smoke  # noqa: E402
import revert_controller as rc  # noqa: E402

GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "aeos-test",
    "GIT_AUTHOR_EMAIL": "aeos-test@example.invalid",
    "GIT_COMMITTER_NAME": "aeos-test",
    "GIT_COMMITTER_EMAIL": "aeos-test@example.invalid",
    "GIT_TERMINAL_PROMPT": "0",
}
SIG_A = "a" * 64
SIG_B = "b" * 64
AUTH = {"GH_TOKEN": "ghs-installation-token",
        "AEOS_REVERT_GIT_NAME": "aeos-revert[bot]",
        "AEOS_REVERT_GIT_EMAIL": "1234+aeos-revert[bot]@users.noreply.github.com"}


def git(repo, *args, check=True):
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=GIT_ENV)
    if check and proc.returncode != 0:
        raise AssertionError(f"git {args}: {proc.stderr.decode()}")
    return proc.stdout.decode().strip()


def outcome(sha, result, signature=None, checks=()):
    doc = {"schema_version": "1", "check_context": rc.CHECK_CONTEXT, "sha": sha,
           "outcome": result, "signature": signature, "checks": list(checks)}
    return doc


def failure_check(cid, reason):
    return {"id": cid, "status": "CODE_FAILURE", "reason": reason, "detail": "", "items": []}


def pass_check(cid):
    return {"id": cid, "status": "PASS", "reason": "PASS", "detail": "", "items": []}


def infra_check(cid, reason):
    return {"id": cid, "status": "INFRA_UNAVAILABLE", "reason": reason, "detail": "", "items": []}


def measured(sha, checks):
    """An outcome as the smoke writes it: outcome and signature from its checks."""
    result = smoke.classify(checks)
    return {"schema_version": "1", "check_context": rc.CHECK_CONTEXT, "sha": sha,
            "outcome": result, "source": "floor:python+declared",
            "signature": smoke.signature(checks) if result == "CODE_FAILURE" else None,
            "checks": [pass_check("identity"), *checks]}


HANG = infra_check("collectability", "TIMEOUT:python3 scripts/ci/smoke_collectability.py")


class FakeGh:
    """Recording ``gh`` shim: scripted results, and every call is inspectable."""

    def __init__(self, results=None):
        self.results = results or {}
        self.calls = []

    def run(self, *args, timeout=120):
        self.calls.append(list(args))
        for key, value in self.results.items():
            if key in " ".join(args):
                rcode, out = value
                return subprocess.CompletedProcess(args, rcode, out, "")
        return subprocess.CompletedProcess(args, 0, "https://github.com/o/r/pull/77", "")


class DecideTestCase(unittest.TestCase):
    """`decide` is pure given git plus the evidence files."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        git(self.root, "init", "-q", "-b", "main")
        self._write("README.md", "base\n")
        self.before = self._commit("base")
        self._write("app.py", "x = 1\n")
        self.sha = self._commit("feat: the offending squash")

    def _write(self, rel, content):
        path = os.path.join(self.root, rel)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def _commit(self, message):
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "--allow-empty", "-m", message)
        return git(self.root, "rev-parse", "HEAD")

    def decide(self, first=None, second=None, parent=None, sha=None, before=None):
        sha = sha or self.sha
        before = before or self.before
        failing = [failure_check("unit", "COMMAND_FAILURE:unit:exit1")]
        if first is None:
            first = outcome(sha, "CODE_FAILURE", SIG_A, failing)
        if second is False:
            second = None
        elif second is None:
            second = outcome(sha, "CODE_FAILURE", SIG_A, failing)
        if parent is False:
            parent = None
        elif parent is None:
            # A real PASS outcome lists the checks it ran, which is what gives
            # the child's failing checks a baseline to be compared against.
            parent = outcome(before, "PASS", checks=[pass_check("unit")])
        return rc.decide(first, second, parent, sha, before, self.root)

    # -- not a failure -----------------------------------------------------
    def test_pass_is_nothing_to_do(self) -> None:
        self.assertEqual(self.decide(first=outcome(self.sha, "PASS"))["decision"],
                         "PASS_NOTHING_TO_DO")

    def test_an_outage_never_reverts(self) -> None:
        for label, first, second in [
            ("first", outcome(self.sha, "INFRA_UNAVAILABLE"), None),
            ("second", None, outcome(self.sha, "INFRA_UNAVAILABLE")),
        ]:
            with self.subTest(label=label):
                self.assertEqual(self.decide(first=first, second=second)["decision"],
                                 "INFRA_UNAVAILABLE")

    # -- confirmation ------------------------------------------------------
    def test_a_single_failure_never_reverts(self) -> None:
        self.assertEqual(self.decide(second=False)["decision"], "NOT_CONFIRMED_FLAKY")

    def test_a_rerun_that_passes_is_flaky(self) -> None:
        self.assertEqual(self.decide(second=outcome(self.sha, "PASS"))["decision"],
                         "NOT_CONFIRMED_FLAKY")

    def test_a_different_signature_is_flaky(self) -> None:
        result = self.decide(second=outcome(self.sha, "CODE_FAILURE", SIG_B))
        self.assertEqual(result["decision"], "NOT_CONFIRMED_FLAKY")
        self.assertEqual(result["first_signature"], SIG_A)
        self.assertEqual(result["second_signature"], SIG_B)

    # -- evidence validity -------------------------------------------------
    def test_evidence_for_another_sha_is_invalid(self) -> None:
        self.assertEqual(self.decide(second=outcome("f" * 40, "CODE_FAILURE", SIG_A))["decision"],
                         "SMOKE_EVIDENCE_INVALID")

    def test_a_code_failure_without_a_signature_is_invalid(self) -> None:
        self.assertEqual(self.decide(first=outcome(self.sha, "CODE_FAILURE", None))["decision"],
                         "SMOKE_EVIDENCE_INVALID")

    def test_a_foreign_check_context_is_invalid(self) -> None:
        alien = outcome(self.sha, "CODE_FAILURE", SIG_A)
        alien["check_context"] = "some-other-gate"
        self.assertEqual(self.decide(first=alien)["decision"], "SMOKE_EVIDENCE_INVALID")

    def test_non_object_evidence_is_invalid(self) -> None:
        self.assertEqual(self.decide(first=["not", "an", "object"])["decision"],
                         "SMOKE_EVIDENCE_INVALID")

    # -- attribution -------------------------------------------------------
    def test_a_zero_before_cannot_bound_the_push(self) -> None:
        result = self.decide(before=rc.ZERO_SHA,
                             parent=outcome(rc.ZERO_SHA, "PASS"))
        self.assertEqual(result["decision"], "REVERT_ATTRIBUTION_AMBIGUOUS")

    def test_more_than_one_commit_in_the_push_is_ambiguous(self) -> None:
        self._write("more.py", "y = 2\n")
        second_sha = self._commit("a second commit in the same push")
        first = outcome(second_sha, "CODE_FAILURE", SIG_A)
        result = rc.decide(first, first, outcome(self.before, "PASS"),
                           second_sha, self.before, self.root)
        self.assertEqual(result["decision"], "REVERT_ATTRIBUTION_AMBIGUOUS")
        self.assertIn("more than one commit landed", result["detail"])

    def test_a_merge_commit_is_never_reverted_automatically(self) -> None:
        git(self.root, "checkout", "-q", "-b", "side", self.before)
        self._write("side.py", "z = 3\n")
        self._commit("side")
        git(self.root, "checkout", "-q", "main")
        git(self.root, "merge", "-q", "--no-ff", "side", "-m", "merge")
        merge_sha = git(self.root, "rev-parse", "HEAD")
        first = outcome(merge_sha, "CODE_FAILURE", SIG_A)
        result = rc.decide(first, first, outcome(self.sha, "PASS"), merge_sha, self.sha, self.root)
        self.assertEqual(result["decision"], "REVERT_ATTRIBUTION_AMBIGUOUS")
        self.assertIn("parent(s)", result["detail"])

    # -- origin ------------------------------------------------------------
    def test_no_parent_evidence_leaves_the_origin_unproven(self) -> None:
        self.assertEqual(self.decide(parent=False)["decision"], "ORIGIN_UNPROVEN")

    def test_a_parent_outage_leaves_the_origin_unproven(self) -> None:
        self.assertEqual(
            self.decide(parent=outcome(self.before, "INFRA_UNAVAILABLE"))["decision"],
            "ORIGIN_UNPROVEN")

    def test_an_identical_parent_failure_is_inherited_not_originated(self) -> None:
        result = self.decide(parent=outcome(self.before, "CODE_FAILURE", SIG_A,
                                            [failure_check("unit", "COMMAND_FAILURE:unit:exit1")]))
        self.assertEqual(result["decision"], "INHERITED_FAILURE_NOT_ORIGIN")

    def test_a_red_parent_with_no_new_failure_is_inherited(self) -> None:
        """Origin is decided by failing SETS, not by signature equality: on an
        already-red branch a commit that adds nothing new is innocent."""
        shared = [failure_check("unit", "COMMAND_FAILURE:unit:exit1")]
        result = self.decide(
            first=outcome(self.sha, "CODE_FAILURE", SIG_A, shared),
            second=outcome(self.sha, "CODE_FAILURE", SIG_A, shared),
            parent=outcome(self.before, "CODE_FAILURE", SIG_B, shared))
        self.assertEqual(result["decision"], "INHERITED_FAILURE_NOT_ORIGIN")

    def test_a_commit_is_the_origin_only_of_what_it_introduced(self) -> None:
        inherited = failure_check("unit", "COMMAND_FAILURE:unit:exit1")
        introduced = failure_check("lint", "LINT_FAILURE")
        both = [inherited, introduced]
        result = self.decide(
            first=outcome(self.sha, "CODE_FAILURE", SIG_A, both),
            second=outcome(self.sha, "CODE_FAILURE", SIG_A, both),
            parent=outcome(self.before, "CODE_FAILURE", SIG_B, [inherited, pass_check("lint")]))
        self.assertEqual(result["decision"], "REVERT")
        self.assertEqual(result["introduced_failures"], ["lint"])
        self.assertIn("already-red", result["detail"])

    def test_a_shifted_exit_code_on_a_pre_existing_failure_is_still_inherited(self) -> None:
        """pytest reports 1 for failures and 2 when the same broken suite is
        interrupted. Folding the reason into the origin comparison would call
        that a failure this commit introduced."""
        child = [failure_check("unit", "COMMAND_FAILURE:unit:exit2")]
        parent = [failure_check("unit", "COMMAND_FAILURE:unit:exit1")]
        result = self.decide(
            first=outcome(self.sha, "CODE_FAILURE", SIG_A, child),
            second=outcome(self.sha, "CODE_FAILURE", SIG_A, child),
            parent=outcome(self.before, "CODE_FAILURE", SIG_B, parent))
        self.assertEqual(result["decision"], "INHERITED_FAILURE_NOT_ORIGIN")

    def test_a_check_the_parent_never_ran_has_no_baseline(self) -> None:
        """A commit that adds the first test cannot be shown to have broken it."""
        new_check = [failure_check("npm-test", "COMMAND_FAILURE:npm-test:exit1")]
        result = self.decide(
            first=outcome(self.sha, "CODE_FAILURE", SIG_A, new_check),
            second=outcome(self.sha, "CODE_FAILURE", SIG_A, new_check),
            parent=outcome(self.before, "PASS", checks=[pass_check("unit")]))
        self.assertEqual(result["decision"], "ORIGIN_UNPROVEN")
        self.assertIn("npm-test", result["detail"])

    def test_a_parent_that_ran_a_different_plan_is_not_a_baseline(self) -> None:
        first = outcome(self.sha, "CODE_FAILURE", SIG_A, [failure_check("compile", "COMPILE_FAILURE")])
        first["source"] = "derived:python+node"
        parent = outcome(self.before, "PASS", checks=[pass_check("compile")])
        parent["source"] = "derived:python"
        result = self.decide(first=first, second=first, parent=parent)
        self.assertEqual(result["decision"], "ORIGIN_UNPROVEN")
        self.assertIn("different smoke plan", result["detail"])

    def test_unreadable_changed_paths_never_read_as_touching_nothing(self) -> None:
        """Failing open here would satisfy the control-plane conjunct vacuously
        and empty the containment guard `execute` compares against."""
        import gitobject
        original = gitobject.changed_paths
        gitobject.changed_paths = lambda *a, **k: (_ for _ in ()).throw(
            gitobject.GitUnavailable("object store unreadable"))
        try:
            result = self.decide()
        finally:
            gitobject.changed_paths = original
        self.assertEqual(result["decision"], "REVERT_ATTRIBUTION_AMBIGUOUS")
        self.assertIn("could not report what this commit touched", result["detail"])

    def test_tampering_shaped_evidence_exits_non_zero(self) -> None:
        result = self.decide(first=outcome(self.sha, "CODE_FAILURE", None))
        self.assertEqual(result["decision"], "SMOKE_EVIDENCE_INVALID")
        self.assertEqual(result.get("exit_code"), 1)
        # A normal stop stays green.
        self.assertEqual(self.decide(second=False).get("exit_code", 0), 0)

    # -- control plane -----------------------------------------------------
    def test_a_control_plane_commit_is_operator_governed(self) -> None:
        for path in (".github/workflows/ci.yml", ".github/actions/x/action.yml",
                     ".github/aeos-gate.json", ".github/aeos-smoke.json",
                     ".GitHub/Workflows/CI.yml"):
            with self.subTest(path=path):
                self.setUp()
                self._write(path, "x\n")
                sha = self._commit("touch the control plane")
                first = outcome(sha, "CODE_FAILURE", SIG_A)
                result = rc.decide(first, first, outcome(self.sha, "PASS"), sha, self.sha, self.root)
                self.assertEqual(result["decision"], "CONTROL_PLANE_REVERT_REQUIRES_OPERATOR")
                self.assertTrue(result["touched"])

    def test_ordinary_dot_github_files_are_not_protected(self) -> None:
        self._write(".github/CODEOWNERS", "* @org/team\n")
        sha = self._commit("codeowners")
        first = outcome(sha, "CODE_FAILURE", SIG_A)
        result = rc.decide(first, first, outcome(self.sha, "PASS"), sha, self.sha, self.root)
        self.assertEqual(result["decision"], "REVERT")

    # -- a repeated outage ------------------------------------------------
    def test_the_same_outage_on_this_commit_and_its_parent_is_promoted_and_inherited(self) -> None:
        """Promoted to CODE_FAILURE, then judged like one. The parent fails the
        same way by definition, so the later commit is never reverted for it."""
        first = measured(self.sha, [HANG])
        result = self.decide(first=first, second=first, parent=measured(self.before, [HANG]))
        self.assertEqual(result["decision"], "INHERITED_FAILURE_NOT_ORIGIN")
        self.assertEqual(result["repeated_infra"], [["collectability", HANG["reason"]]])
        self.assertIn(["collectability", "REPEATED_INFRA:" + HANG["reason"]],
                      result["parent_failures"])

    def test_a_spent_budget_never_reverts_on_its_own(self) -> None:
        spent = infra_check("tests", "SMOKE_BUDGET_EXHAUSTED")
        first = measured(self.sha, [spent])
        both = self.decide(first=first, second=first, parent=measured(self.before, [spent]))
        self.assertEqual(both["decision"], "INHERITED_FAILURE_NOT_ORIGIN")
        alone = self.decide(first=first, second=first, parent=measured(self.before, [pass_check("tests")]))
        self.assertEqual(alone["decision"], "INFRA_UNAVAILABLE")

    def test_a_repeated_outage_no_longer_masks_a_failure_this_commit_introduced(self) -> None:
        broken = failure_check("unit", "COMMAND_FAILURE:unit:exit1")
        first = measured(self.sha, [HANG, broken])
        self.assertEqual(first["outcome"], "INFRA_UNAVAILABLE")
        result = self.decide(first=first, second=first,
                             parent=measured(self.before, [HANG, pass_check("unit")]))
        self.assertEqual(result["decision"], "REVERT")
        self.assertEqual(result["introduced_failures"], ["unit"])

    def test_a_repeated_outage_still_needs_the_confirming_rerun(self) -> None:
        first = measured(self.sha, [HANG])
        parent = measured(self.before, [HANG])
        for label, second, decision in [
            ("the rerun passed", measured(self.sha, [pass_check("collectability")]),
             "NOT_CONFIRMED_FLAKY"),
            ("no rerun evidence", False, "NOT_CONFIRMED_FLAKY"),
            ("the rerun hit another outage",
             measured(self.sha, [infra_check("collectability", "TOOL_MISSING:pytest")]),
             "INFRA_UNAVAILABLE"),
        ]:
            with self.subTest(label=label):
                self.assertEqual(
                    self.decide(first=first, second=second, parent=parent)["decision"], decision)

    def test_a_promoted_repeat_still_needs_one_attributable_squash(self) -> None:
        """The rerun is promoted with the first run, so a repeat reaches the
        attribution conjunct, which stops it before the parent is read."""
        self._write("more.py", "y = 2\n")
        later = self._commit("a second commit in the same push")
        first = measured(later, [HANG])
        result = rc.decide(first, first, measured(self.before, [HANG]), later, self.before, self.root)
        self.assertEqual(result["decision"], "REVERT_ATTRIBUTION_AMBIGUOUS")

    def test_malformed_findings_promote_nothing_and_still_decide(self) -> None:
        """Valid JSON a producer never writes must end in a typed decision, never
        a traceback from sorting findings of mixed types."""
        odd = [{**failure_check("dup", "X"), "items": ["x"]}, {**failure_check("dup", "X"), "items": [1]}]
        first = measured(self.sha, [HANG, *odd])
        result = self.decide(first=first, second=first, parent=measured(self.before, [HANG]))
        self.assertEqual(result["decision"], "INFRA_UNAVAILABLE")

    def test_an_outage_the_parent_does_not_share_still_never_reverts(self) -> None:
        first = measured(self.sha, [HANG])
        for label, parent in [
            ("the parent passed", measured(self.before, [pass_check("collectability")])),
            ("the parent failed another way",
             measured(self.before, [infra_check("collectability", "TOOL_MISSING:pytest")])),
            ("no parent evidence", False),
            ("parent evidence for another commit", measured("f" * 40, [HANG])),
        ]:
            with self.subTest(label=label):
                result = self.decide(first=first, second=first, parent=parent)
                self.assertEqual(result["decision"], "INFRA_UNAVAILABLE")
                self.assertNotIn("repeated_infra", result)

    # -- the happy path ----------------------------------------------------
    def test_a_confirmed_originating_failure_reverts(self) -> None:
        result = self.decide()
        self.assertEqual(result["decision"], "REVERT")
        self.assertEqual(result["branch"], f"{rc.BRANCH_PREFIX}{self.sha[:12]}")
        self.assertEqual(result["subject"], "feat: the offending squash")
        self.assertEqual(result["signature"], SIG_A)
        self.assertIn("app.py", result["changed_paths"])

    def test_every_decision_is_in_the_closed_vocabulary(self) -> None:
        for result in [self.decide(), self.decide(first=outcome(self.sha, "PASS")),
                       self.decide(second=False), self.decide(parent=False)]:
            self.assertIn(result["decision"], rc.DECISIONS)


#: A repository's collection leg, standing in for ``pytest --collect-only -q``:
#: it prints what pytest prints for a module that fails at import and for two
#: test modules sharing a basename, and exits 2 as pytest does. The suite needs
#: no third-party runner, and the shape is pinned to pytest's own output in
#: ``test_main_smoke.PYTEST_COLLECTION_OUTPUT``.
COLLECT_PY = """\
import os, sys, time
print(time.time_ns(), file=sys.stderr)
errors, seen, collected = [], {}, []
for dirpath, dirs, files in os.walk("tests"):
    dirs.sort()
    for name in sorted(files):
        if not (name.startswith("test_") and name.endswith(".py")):
            continue
        path = os.path.join(dirpath, name).replace(os.sep, "/")
        text = open(path, encoding="utf-8").read()
        if name in seen:
            errors.append((path, "import file mismatch:"))
            continue
        seen[name] = path
        if "raise ImportError" in text:
            errors.append((path, "ImportError while importing test module"))
            continue
        collected += [path + "::" + line[4:].split("(")[0] for line in text.splitlines()
                      if line.startswith("def test_")]
for item in collected:
    print(item)
if not errors:
    print("%d tests collected in 0.01s" % len(collected))
    sys.exit(0)
plural = "" if len(errors) == 1 else "s"
print("=" * 36 + " ERRORS " + "=" * 36)
for path, why in errors:
    print("_" * 20 + " ERROR collecting " + path + " " + "_" * 20)
    print(why)
print("=" * 27 + " short test summary info " + "=" * 28)
for path, _ in errors:
    print("ERROR " + path)
print("!" * 19 + " Interrupted: %d error%s during collection " % (len(errors), plural) + "!" * 19)
print("%d tests collected, %d error%s in 0.03s" % (len(collected), len(errors), plural))
sys.exit(2)
"""


class SameCheckAttributionTestCase(unittest.TestCase):
    """Two independent breaks inside one declared check, on a real repository.

    Every outcome is the real smoke at a real squash SHA, judged by the real
    breaker over that repository's own history.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        git(self.root, "init", "-q", "-b", "main")
        self.write("collect.py", COLLECT_PY)
        self.write(".github/aeos-smoke.json", json.dumps({
            "schema_version": "1", "language_floor": False,
            "commands": [{"name": "collectability", "run": f"{sys.executable} collect.py"}]}))
        self.write("tests/a/test_cycle.py", "def test_cycle_a():\n    pass\n")
        self.write("tests/test_base.py", "def test_base():\n    pass\n")
        self.green = self.commit("base")

    def write(self, rel, content):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path) or self.root, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def commit(self, message):
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "--allow-empty", "-m", message)
        return git(self.root, "rev-parse", "HEAD")

    def smoke(self, sha):
        git(self.root, "checkout", "-q", "--detach", sha)
        try:
            return smoke.run_smoke(self.root, sha)
        finally:
            git(self.root, "checkout", "-q", "main")

    def judge(self, sha, before=None):
        before = before or git(self.root, "rev-parse", f"{sha}^")
        first, second, parent = self.smoke(sha), self.smoke(sha), self.smoke(before)
        return rc.decide(first, second, parent, sha, before, self.root), first, parent

    def break_a(self):
        self.write("tests/test_handoff.py", "raise ImportError('a path the commit moved')\n")
        return self.commit("feat: A, a module that no longer collects")

    def break_b(self):
        self.write("tests/b/test_cycle.py", "def test_cycle_b():\n    pass\n")
        return self.commit("feat: B, a second test_cycle module")

    def test_the_twentieth_october_sequence_attributes_each_break_to_its_own_commit(self) -> None:
        a = self.break_a()
        self.write("README.md", "unrelated\n")
        innocent = self.commit("fix: an unrelated change")
        b = self.break_b()
        git(self.root, "revert", "--no-edit", a)
        revert_of_a = git(self.root, "rev-parse", "HEAD")

        decided, first, parent = self.judge(a)
        self.assertEqual(decided["decision"], "REVERT")
        self.assertEqual(decided["introduced_failures"], ["collectability"])
        self.assertEqual(first["checks"][-1]["items"], ["ERROR tests/test_handoff.py"])
        self.assertEqual(parent["outcome"], "PASS")

        self.assertEqual(self.judge(innocent)[0]["decision"], "INHERITED_FAILURE_NOT_ORIGIN")

        decided, first, parent = self.judge(b)
        self.assertEqual(decided["decision"], "REVERT")
        self.assertEqual(decided["introduced_items"], {"collectability": ["ERROR tests/b/test_cycle.py"]})
        self.assertEqual(decided["introduced_failures"], ["collectability"])
        self.assertIn("1 new finding(s)", decided["detail"])
        self.assertEqual(first["checks"][-1]["reason"], parent["checks"][-1]["reason"])

        decided, first, _ = self.judge(revert_of_a)
        self.assertEqual(decided["decision"], "INHERITED_FAILURE_NOT_ORIGIN")
        self.assertEqual(first["checks"][-1]["items"], ["ERROR tests/b/test_cycle.py"])

    def test_without_the_findings_the_second_break_reads_as_inherited(self) -> None:
        """The outcome the rail decided on 2026-10-20: one check id, one exit
        code, one signature for all three commits."""
        self.break_a()
        b = self.break_b()
        decided, first, parent = self.judge(b)
        self.assertEqual(decided["decision"], "REVERT")
        blind = []
        for doc in (first, parent):
            checks = [{**c, "items": []} for c in doc["checks"]]
            for c in checks:
                c.pop("item_kind", None)
            blind.append({**doc, "checks": checks, "signature": smoke.signature(checks)})
        self.assertEqual(blind[0]["signature"], blind[1]["signature"])
        old = rc.decide(blind[0], blind[0], blind[1], b, git(self.root, "rev-parse", f"{b}^"), self.root)
        self.assertEqual(old["decision"], "INHERITED_FAILURE_NOT_ORIGIN")

    def test_two_new_breaks_in_one_squash_are_both_attributed(self) -> None:
        self.break_a()
        self.write("tests/b/test_cycle.py", "def test_cycle_b():\n    pass\n")
        self.write("tests/test_other.py", "raise ImportError('a second one')\n")
        both = self.commit("feat: two independent breaks in one squash")
        decided = self.judge(both)[0]
        self.assertEqual(decided["decision"], "REVERT")
        self.assertEqual(decided["introduced_items"], {
            "collectability": ["ERROR tests/b/test_cycle.py", "ERROR tests/test_other.py"]})

    def test_two_regressions_pushed_together_stay_unattributable(self) -> None:
        a = self.break_a()
        self.break_b()
        self.write("tests/test_other.py", "raise ImportError('a third one')\n")
        tip = self.commit("feat: pushed with B")
        decided = self.judge(tip, before=a)[0]
        self.assertEqual(decided["decision"], "REVERT_ATTRIBUTION_AMBIGUOUS")

    def test_two_concurrent_regressions_landing_back_to_back_are_each_their_own(self) -> None:
        self.break_a()
        b = self.break_b()
        self.write("tests/test_other.py", "raise ImportError('landed a minute later')\n")
        c = self.commit("feat: C, a third break")
        self.assertEqual(self.judge(b)[0]["introduced_items"],
                         {"collectability": ["ERROR tests/b/test_cycle.py"]})
        self.assertEqual(self.judge(c)[0]["introduced_items"],
                         {"collectability": ["ERROR tests/test_other.py"]})

    def test_a_revert_that_leaves_another_break_behind_inherits_it(self) -> None:
        self.break_a()
        b = self.break_b()
        git(self.root, "revert", "--no-edit", b)
        revert_of_b = git(self.root, "rev-parse", "HEAD")
        decided, first, parent = self.judge(revert_of_b)
        self.assertEqual(decided["decision"], "INHERITED_FAILURE_NOT_ORIGIN")
        self.assertEqual(first["checks"][-1]["items"], ["ERROR tests/test_handoff.py"])

    def test_a_fix_inside_a_red_check_is_never_a_new_failure(self) -> None:
        self.break_a()
        self.break_b()
        os.remove(os.path.join(self.root, "tests/b/test_cycle.py"))
        fix = self.commit("fix: B's module renamed away")
        self.assertEqual(self.judge(fix)[0]["decision"], "INHERITED_FAILURE_NOT_ORIGIN")

    def test_output_with_no_summary_fails_closed_to_the_check_id(self) -> None:
        """Never green and never more than before: the check still fails, and
        with nothing to compare it is judged on its id alone."""
        self.break_a()
        self.write("collect.py", COLLECT_PY.replace(" short test summary info ", " its own summary "))
        unparseable = self.commit("chore: the leg prints its own summary")
        decided, first, parent = self.judge(unparseable)
        self.assertEqual(first["outcome"], "CODE_FAILURE")
        self.assertEqual(first["checks"][-1]["items"], [])
        self.assertIn("item_kind", parent["checks"][-1])
        self.assertEqual(decided["decision"], "INHERITED_FAILURE_NOT_ORIGIN")
        self.write("tests/b/test_cycle.py", "def test_cycle_b():\n    pass\n")
        hidden = self.commit("feat: a break the unreadable leg cannot name")
        self.assertEqual(self.judge(hidden)[0]["decision"], "INHERITED_FAILURE_NOT_ORIGIN")


class ComparableItemsTestCase(unittest.TestCase):
    """What the breaker accepts as a finding it may compare across commits."""

    def check(self, items, kind=smoke.PYTEST_ITEMS, cid="unit"):
        c = failure_check(cid, "COMMAND_FAILURE:unit:exit1")
        c["items"] = list(items)
        if kind is not None:
            c["item_kind"] = kind
        return c

    def doc(self, *checks):
        return {"checks": [pass_check("identity"), *checks]}

    def test_a_new_finding_inside_the_same_check_is_introduced(self) -> None:
        self.assertEqual(rc.introduced_items(self.doc(self.check(["FAILED t.py::a", "FAILED t.py::b"])),
                                             self.doc(self.check(["FAILED t.py::a"]))),
                         {"unit": ["FAILED t.py::b"]})

    def test_unchanged_or_fewer_findings_introduce_nothing(self) -> None:
        parent = self.doc(self.check(["FAILED t.py::a", "FAILED t.py::b"]))
        for items in (["FAILED t.py::a", "FAILED t.py::b"], ["FAILED t.py::b"]):
            with self.subTest(items=items):
                self.assertEqual(rc.introduced_items(self.doc(self.check(items)), parent), {})

    def test_findings_without_a_comparable_kind_on_either_side_compare_nothing(self) -> None:
        new = self.doc(self.check(["FAILED t.py::a", "FAILED t.py::b"]))
        old = self.doc(self.check(["FAILED t.py::a"]))
        for first, parent in (
                (self.doc(self.check(["FAILED t.py::a", "FAILED t.py::b"], kind=None)), old),
                (new, self.doc(self.check(["FAILED t.py::a"], kind=None))),
                (self.doc(self.check(["FAILED t.py::b"], kind="ruff")), old),
                (self.doc(self.check(["FAILED t.py::b"], cid="other")), old),
                (self.doc(self.check(["x"] * 0)), old),
                (self.doc({**self.check(["FAILED t.py::b"]), "status": "PASS"}), old)):
            with self.subTest(first=first, parent=parent):
                self.assertEqual(rc.introduced_items(first, parent), {})

    def test_malformed_or_oversized_findings_compare_nothing(self) -> None:
        old = self.doc(self.check(["FAILED t.py::a"]))
        oversized = [f"FAILED t.py::n{i:04d}" for i in range(smoke.MAX_ITEMS + 1)]
        for first in (self.doc(self.check(oversized)), self.doc({**self.check([]), "items": [1, 2]}),
                      self.doc({**self.check([]), "items": "FAILED t.py::b"}), None, {"checks": "x"}):
            with self.subTest(first=str(first)[:60]):
                self.assertEqual(rc.introduced_items(first, old), {})

    def test_a_parent_stopped_at_collection_is_no_baseline_for_tests_that_ran(self) -> None:
        first = self.doc(self.check(["FAILED t.py::masked"]))
        parent = self.doc(self.check(["ERROR t.py"], kind=smoke.PYTEST_COLLECTION_ITEMS))
        self.assertEqual(rc.introduced_items(first, parent), {})
        both = self.doc(self.check(["ERROR t.py", "ERROR u.py"], kind=smoke.PYTEST_COLLECTION_ITEMS))
        self.assertEqual(rc.introduced_items(both, parent), {"unit": ["ERROR u.py"]})
        finished = self.doc(self.check(["FAILED t.py::x"]))
        stopped = self.doc(self.check(["ERROR u.py"], kind=smoke.PYTEST_COLLECTION_ITEMS))
        self.assertEqual(rc.introduced_items(stopped, finished), {"unit": ["ERROR u.py"]})

    def test_a_red_parent_without_findings_still_decides_on_check_ids(self) -> None:
        """Evidence a rail wrote before findings existed is judged exactly as before."""
        with tempfile.TemporaryDirectory() as root:
            git(root, "init", "-q", "-b", "main")
            git(root, "commit", "-q", "--allow-empty", "-m", "base")
            before = git(root, "rev-parse", "HEAD")
            git(root, "commit", "-q", "--allow-empty", "-m", "child")
            sha = git(root, "rev-parse", "HEAD")
            first = measured(sha, [self.check(["FAILED t.py::a", "FAILED t.py::b"])])
            old_rail = measured(before, [failure_check("unit", "COMMAND_FAILURE:unit:exit1")])
            self.assertEqual(rc.decide(first, first, old_rail, sha, before, root)["decision"],
                             "INHERITED_FAILURE_NOT_ORIGIN")
            parent = measured(before, [self.check(["FAILED t.py::a"])])
            decided = rc.decide(first, first, parent, sha, before, root)
            self.assertEqual(decided["decision"], "REVERT")
            self.assertEqual(decided["introduced_items"], {"unit": ["FAILED t.py::b"]})


class ExecuteTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.origin = os.path.join(self._tmp.name, "origin.git")
        self.root = os.path.join(self._tmp.name, "work")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", self.origin],
                       check=True, env=GIT_ENV)
        subprocess.run(["git", "clone", "-q", self.origin, self.root], check=True, env=GIT_ENV)
        self._write("README.md", "base\n")
        self.before = self._commit("base")
        self._write("app.py", "x = 1\n")
        self.sha = self._commit("feat: offending")
        git(self.root, "push", "-q", "origin", "main")
        git(self.root, "fetch", "-q", "origin", "main")

    def _write(self, rel, content):
        path = os.path.join(self.root, rel)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def _commit(self, message):
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", message)
        return git(self.root, "rev-parse", "HEAD")

    def decision(self, **over):
        base = {"schema_version": "1", "decision": "REVERT", "sha": self.sha,
                "before": self.before, "signature": SIG_A, "subject": "feat: offending",
                "branch": f"{rc.BRANCH_PREFIX}{self.sha[:12]}", "changed_paths": ["app.py"]}
        base.update(over)
        return base

    def execute(self, decision=None, environ=None, gh=None, dry_run=False):
        return rc.execute(decision or self.decision(), self.root, "o/r", dry_run=dry_run,
                          gh=gh or FakeGh(), environ=environ if environ is not None else dict(AUTH))

    # -- refusals ----------------------------------------------------------
    def test_a_non_revert_decision_executes_nothing(self) -> None:
        result = self.execute(self.decision(decision="NOT_CONFIRMED_FLAKY"))
        self.assertEqual(result["execution"], "NOT_A_REVERT_DECISION")

    def test_a_missing_token_is_typed_and_fails_closed(self) -> None:
        result = self.execute(environ={})
        self.assertEqual(result["execution"], "AUTOREVERT_AUTH_UNAVAILABLE")
        self.assertEqual(result["exit_code"], 5)

    def test_the_repository_token_is_never_accepted_as_a_fallback(self) -> None:
        """A PR opened with GITHUB_TOKEN fires no workflow, so the required gate
        could never report on the revert."""
        self.assertFalse(rc.auth_available({"GITHUB_TOKEN": "x"}))
        self.assertTrue(rc.auth_available({"GH_TOKEN": "x"}))
        result = self.execute(environ={"GITHUB_TOKEN": "x", **{k: v for k, v in AUTH.items()
                                                               if k != "GH_TOKEN"}})
        self.assertEqual(result["execution"], "AUTOREVERT_AUTH_UNAVAILABLE")

    def test_a_missing_bot_identity_is_typed_and_fails_closed(self) -> None:
        result = self.execute(environ={"GH_TOKEN": "t"})
        self.assertEqual(result["execution"], "AUTOREVERT_IDENTITY_UNAVAILABLE")
        self.assertEqual(result["exit_code"], 5)

    def test_an_email_shaped_identity_is_required(self) -> None:
        self.assertIsNone(rc.git_identity({"AEOS_REVERT_GIT_NAME": "n",
                                           "AEOS_REVERT_GIT_EMAIL": "not-an-email"}))

    # -- dry run -----------------------------------------------------------
    def test_a_dry_run_prepares_but_never_writes_outward(self) -> None:
        gh = FakeGh()
        result = rc.execute(self.decision(), self.root, "o/r", dry_run=True, gh=gh, environ={})
        self.assertEqual(result["execution"], "DRY_RUN")
        self.assertEqual(gh.calls, [])
        self.assertEqual(result["commits_ahead"], "1")
        self.assertEqual(git(self.origin, "rev-parse", "main"), self.sha)

    # -- idempotence -------------------------------------------------------
    def test_an_already_reverted_commit_is_a_no_op(self) -> None:
        self._write("app.py", "reverted\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", f"revert\n\n{rc.REVERT_TRAILER}: {self.sha}")
        git(self.root, "push", "-q", "origin", "main")
        result = self.execute()
        self.assertEqual(result["execution"], "ALREADY_REVERTED")

    def test_an_open_revert_pr_is_a_no_op(self) -> None:
        gh = FakeGh({"pr list": (0, json.dumps([{"number": 5, "url": "https://x/pull/5"}]))})
        result = self.execute(gh=gh)
        self.assertEqual(result["execution"], "REVERT_PR_EXISTS")
        self.assertEqual(result["pr_number"], 5)

    # -- conflict ----------------------------------------------------------
    def test_a_revert_conflict_is_a_typed_hard_stop(self) -> None:
        self._write("app.py", "a totally different line\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "later change to the same lines")
        git(self.root, "push", "-q", "origin", "main")
        git(self.root, "fetch", "-q", "origin", "main")
        result = self.execute()
        self.assertEqual(result["execution"], "REVERT_CONFLICT")
        self.assertEqual(result["exit_code"], 3)
        self.assertEqual(git(self.origin, "rev-parse", "main"),
                         git(self.root, "rev-parse", "origin/main"),
                         "the default branch must be untouched")

    def test_the_default_branch_is_never_pushed_directly(self) -> None:
        before_main = git(self.origin, "rev-parse", "main")
        self.execute()
        self.assertEqual(git(self.origin, "rev-parse", "main"), before_main)

    # -- the happy path ----------------------------------------------------
    def test_a_revert_pr_is_opened_and_auto_merge_armed(self) -> None:
        gh = FakeGh({"pr list": (0, "[]")})
        result = self.execute(gh=gh)
        self.assertEqual(result["execution"], "REVERT_PR_OPENED")
        self.assertEqual(result["pr_number"], 77)
        self.assertTrue(result["auto_merge_armed"])
        self.assertEqual(result["commits_ahead"], "1")
        self.assertEqual(result["changed_paths"], ["app.py"])
        self.assertEqual(result["author"], f"{AUTH['AEOS_REVERT_GIT_NAME']} "
                                           f"<{AUTH['AEOS_REVERT_GIT_EMAIL']}>")
        merged = [c for c in gh.calls if c[:2] == ["pr", "merge"]]
        self.assertTrue(merged and "--auto" in merged[0] and "--squash" in merged[0])
        # The branch, not the default branch, received the push.
        self.assertEqual(git(self.origin, "rev-parse", result["branch"]), result["revert_sha"])

    def test_the_revert_commit_carries_the_trailer(self) -> None:
        result = self.execute(gh=FakeGh({"pr list": (0, "[]")}))
        body = git(self.origin, "log", "-n", "1", "--format=%B", result["branch"])
        self.assertIn(f"{rc.REVERT_TRAILER}: {self.sha}", body)

    def test_an_unarmed_auto_merge_is_a_typed_red_not_a_green(self) -> None:
        """An un-armed revert PR would sit open with nobody watching it."""
        gh = FakeGh({"pr list": (0, "[]"), "pr merge": (1, "")})
        result = self.execute(gh=gh)
        self.assertEqual(result["execution"], "AUTOMERGE_ARM_FAILED")
        self.assertEqual(result["exit_code"], 4)
        self.assertFalse(result["auto_merge_armed"])

    def test_a_failed_pr_create_withholds_the_tool_output(self) -> None:
        """This result is uploaded as an artifact, where log masking does not apply."""
        gh = FakeGh({"pr list": (0, "[]"), "pr create": (1, "fatal: token ghs_leaky https://x")})
        result = self.execute(gh=gh)
        self.assertEqual(result["execution"], "PR_CREATE_FAILED")
        self.assertNotIn("ghs_leaky", json.dumps(result))
        self.assertIn("withheld", result["detail"])

    def test_every_execution_is_in_the_closed_vocabulary(self) -> None:
        for result in [self.execute(gh=FakeGh({"pr list": (0, "[]")})),
                       self.execute(environ={}),
                       self.execute(self.decision(decision="INFRA_UNAVAILABLE"))]:
            self.assertIn(result["execution"], rc.EXECUTIONS)

    def test_the_commit_subject_cannot_inject_mentions_or_break_the_code_span(self) -> None:
        """The subject is written by whoever authored the commit being reverted."""
        hostile = "fix `x` @everyone @First-AI-Movers/security\nand more"
        safe = rc.safe_subject({"subject": hostile, "sha": "a" * 40})
        self.assertNotIn("`", safe)
        self.assertNotIn("\n", safe)
        self.assertNotIn("@e", safe)
        self.assertNotIn("@F", safe)
        self.assertLessEqual(len(safe), 160)

    def test_a_missing_subject_falls_back_to_the_sha(self) -> None:
        self.assertEqual(rc.safe_subject({"sha": "b" * 40}), "b" * 12)
        self.assertEqual(rc.safe_subject({"subject": "```", "sha": "c" * 40}), "c" * 12)

    def test_execute_refuses_a_branch_that_is_not_this_rails_branch(self) -> None:
        """This is the function that turns a string into `push HEAD:refs/heads/X`."""
        for branch in ("main", "master", f"{rc.BRANCH_PREFIX}deadbeefdead"):
            with self.subTest(branch=branch):
                result = self.execute(self.decision(branch=branch))
                if branch == f"{rc.BRANCH_PREFIX}{self.sha[:12]}":
                    continue
                self.assertEqual(result["execution"], "NOT_A_REVERT_DECISION")
        self.assertEqual(git(self.origin, "rev-parse", "main"), self.sha)

    def test_execute_refuses_a_decision_without_a_full_sha(self) -> None:
        result = self.execute(self.decision(sha="abc1234", branch=f"{rc.BRANCH_PREFIX}abc1234"))
        self.assertEqual(result["execution"], "NOT_A_REVERT_DECISION")

    def test_already_reverted_needs_an_anchored_trailer_line(self) -> None:
        """An unanchored substring match is writable by anyone who can land a
        commit, and it is a proof that exits 0."""
        self._write("docs.md", f"Example trailer: {rc.REVERT_TRAILER}: {self.sha} inline\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m",
            f"docs: quote the format ({rc.REVERT_TRAILER}: {self.sha} in prose)")
        git(self.root, "push", "-q", "origin", "main")
        git(self.root, "fetch", "-q", "origin", "main")
        self.assertFalse(rc.already_reverted(self.root, self.sha, "origin/main"))

    def test_protected_paths_match_case_insensitively(self) -> None:
        self.assertTrue(rc.is_protected(".GITHUB/WORKFLOWS/ci.yml"))
        self.assertTrue(rc.is_protected(".github/aeos-gate.json"))
        self.assertTrue(rc.is_protected(".github/aeos-smoke.json"))
        self.assertFalse(rc.is_protected(".github/CODEOWNERS"))
        self.assertFalse(rc.is_protected("src/github/workflows/x.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
