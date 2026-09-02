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
