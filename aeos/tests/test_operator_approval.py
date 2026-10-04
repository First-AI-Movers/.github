#!/usr/bin/env python3
"""The operator's approval of an exact machine-authored head (agent-toolkit #3052, paperwork removal).

Every conjunct of ``operator_approval.refusal`` has a violation that must refuse with its own reason and a
near-miss that must stay admitted. Then the route is exercised where it is used: the derivation machine route
(an Agent Toolkit protected path) and lock 5 of the merge-ready gate (a change to the judge in this repository),
including the parts that must NOT change: a grant-marked pull request, an operator-authored pull request, the
predecessor rule and a control-plane deletion.

    python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import derivation_policy as dp  # noqa: E402
import merge_ready_gate as gate  # noqa: E402
import operator_approval as oa  # noqa: E402
import scoped_grant  # noqa: E402
import workflow_policy  # noqa: E402
from test_merge_ready_gate import Repo  # noqa: E402

MACHINE = "aeos-autonomous-main[bot]"
OPERATOR = "hpcosta"
REPO = "First-AI-Movers/agent-toolkit"
HEAD = "a" * 40
OLDER = "b" * 40
POLICY_FILE = Path(__file__).resolve().parents[1] / dp.POLICY_FILE
WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def policy(activation: str | None = "enabled") -> SimpleNamespace:
    binding = None if activation is None else {"schema": oa.SCHEMA, "activation": activation}
    return SimpleNamespace(operator_approval=binding, machine_principals=((MACHINE, "Bot"),),
                           operator_principals=frozenset({OPERATOR}))


def review(rid: int, state: str = "APPROVED", login: str = OPERATOR, kind: str = "User",
           commit: str = HEAD, at: str = "2026-10-03T12:00:00Z") -> dict:
    return {"id": rid, "login": login, "type": kind, "state": state, "commit_id": commit, "submitted_at": at}


_ONE_APPROVAL = object()


def evidence(reviews=_ONE_APPROVAL, *, author=MACHINE, author_type="Bot", actor=MACHINE, head_commit=MACHINE,
             head=HEAD, repository=REPO, event="pull_request", body="", context=oa.CONTEXT_CURRENT) -> dict:
    return {"schema": dp.EVIDENCE_SCHEMA, "event": event, "repository": repository, "actor": actor,
            "pull_request": {"number": 7, "author_login": author, "author_type": author_type, "head_sha": head,
                             "head_commit_author_login": head_commit, "body": body,
                             "approval": {"context": context,
                                          "reviews": [review(1)] if reviews is _ONE_APPROVAL else reviews}}}


class RefusalTests(unittest.TestCase):
    def judge(self, ev, pol=None, head=HEAD, repository=REPO):
        return oa.refusal(pol or policy(), ev, repository, head)

    def test_an_exact_head_operator_approval_on_a_machine_change_admits(self):
        self.assertIsNone(self.judge(evidence()))

    def test_the_route_exists_only_when_bound_and_enabled(self):
        self.assertEqual(self.judge(evidence(), policy(None)), oa.OPERATOR_APPROVAL_UNBOUND)
        self.assertEqual(self.judge(evidence(), policy("disabled")), oa.OPERATOR_APPROVAL_DISABLED)

    def test_only_a_pull_request_event_is_provable(self):
        self.assertEqual(self.judge(evidence(event="merge_group")), oa.OPERATOR_APPROVAL_EVENT_UNPROVABLE)
        self.assertEqual(self.judge(None), oa.OPERATOR_APPROVAL_EVENT_UNPROVABLE)
        missing = evidence()
        missing.pop("pull_request")
        self.assertEqual(self.judge(missing), oa.OPERATOR_APPROVAL_EVENT_UNPROVABLE)

    def test_the_machine_authors_runs_and_commits_it(self):
        for kw, reason in (
            ({"author": OPERATOR, "author_type": "User"}, oa.OPERATOR_APPROVAL_AUTHOR_NOT_MACHINE),
            ({"author": "other[bot]"}, oa.OPERATOR_APPROVAL_AUTHOR_NOT_MACHINE),
            ({"author_type": "User"}, oa.OPERATOR_APPROVAL_AUTHOR_NOT_MACHINE),
            ({"actor": OPERATOR}, oa.OPERATOR_APPROVAL_TRIGGER_NOT_MACHINE),
            ({"actor": ""}, oa.OPERATOR_APPROVAL_TRIGGER_NOT_MACHINE),
            ({"head_commit": OPERATOR}, oa.OPERATOR_APPROVAL_HEAD_COMMIT_NOT_MACHINE),
            ({"head_commit": None}, oa.OPERATOR_APPROVAL_HEAD_COMMIT_NOT_MACHINE),
        ):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                self.assertEqual(self.judge(evidence(**kw)), reason)

    def test_the_evidence_names_this_repository_and_this_head(self):
        self.assertEqual(self.judge(evidence(repository="First-AI-Movers/other")),
                         oa.OPERATOR_APPROVAL_REPOSITORY_MISMATCH)
        self.assertIsNone(self.judge(evidence(repository="first-ai-movers/AGENT-toolkit")))   # near-miss: case
        self.assertEqual(self.judge(evidence(head=OLDER)), oa.OPERATOR_APPROVAL_HEAD_MISMATCH)
        self.assertEqual(self.judge(evidence(), head="not-a-sha"), oa.OPERATOR_APPROVAL_HEAD_MISMATCH)
        self.assertEqual(self.judge(evidence(), head=""), oa.OPERATOR_APPROVAL_HEAD_MISMATCH)

    def test_an_unreadable_review_list_is_never_no_review(self):
        bad_rows = (
            None, "x", [None], [dict(review(1), extra=1)], [{k: v for k, v in review(1).items() if k != "id"}],
            [review(1, commit="short")], [review(1, at="yesterday")], [review(1, state="MERGED")],
            [dict(review(1), id=True)], [dict(review(1), id=0)], [review(1), review(1, "COMMENTED")],
            [dict(review(1), login=None)],
        )
        for rows in bad_rows:
            with self.subTest(rows=str(rows)[:60]):
                self.assertEqual(self.judge(evidence(rows)), oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE)
        for broken in (None, "x", {}, {"context": "CURRENT"}, {"context": "LATER", "reviews": [review(1)]}):
            ev = evidence()
            ev["pull_request"]["approval"] = broken
            with self.subTest(approval=broken):
                self.assertEqual(self.judge(ev), oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE)
        ev = evidence()
        ev["pull_request"].pop("approval")
        self.assertEqual(self.judge(ev), oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE)
        self.assertEqual(self.judge(evidence(context=oa.CONTEXT_UNREAD)), oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE)

    def test_a_pull_request_that_changed_since_its_event_is_never_judged_as_it_was(self):
        """A re-run replays its original event: an edited body or a moved head refuses, typed."""
        for context in (oa.CONTEXT_HEAD_MOVED, oa.CONTEXT_BODY_CHANGED):
            with self.subTest(context=context):
                self.assertEqual(self.judge(evidence(context=context)), oa.OPERATOR_APPROVAL_CONTEXT_CHANGED)

    def test_only_a_pinned_human_operators_decisive_review_counts(self):
        for rows in ([], [review(1, login="contributor")], [review(1, kind="Bot")],
                     [review(1, state="COMMENTED")], [review(1, login=MACHINE, kind="Bot")]):
            with self.subTest(rows=rows):
                self.assertEqual(self.judge(evidence(rows)), oa.OPERATOR_APPROVAL_ABSENT)

    def test_a_later_change_request_or_dismissal_revokes_it(self):
        later = "2026-10-03T13:00:00Z"
        self.assertEqual(self.judge(evidence([review(1), review(2, "CHANGES_REQUESTED", at=later)])),
                         oa.OPERATOR_APPROVAL_NOT_APPROVED)
        self.assertEqual(self.judge(evidence([review(1, "DISMISSED")])), oa.OPERATOR_APPROVAL_NOT_APPROVED)

    def test_an_approval_of_an_earlier_head_is_stale(self):
        self.assertEqual(self.judge(evidence([review(1, commit=OLDER)])), oa.OPERATOR_APPROVAL_STALE_HEAD)

    def test_near_misses_stay_admitted(self):
        later, last = "2026-10-03T13:00:00Z", "2026-10-03T14:00:00Z"
        cases = {
            "comment after approval": [review(1), review(2, "COMMENTED", at=later)],
            "approval after change request": [review(1, "CHANGES_REQUESTED"), review(2, at=later)],
            "earlier approval dismissed, later one stands": [review(1, "DISMISSED"), review(2, at=later)],
            "pending review is not a decision": [review(1), {"id": 9, "login": OPERATOR, "type": "User",
                                                             "state": "PENDING", "commit_id": None,
                                                             "submitted_at": None}],
            "another human's change request is not the operator's": [
                review(1), review(2, "CHANGES_REQUESTED", login="contributor", at=later)],
            "same second, later id decides": [review(3, "CHANGES_REQUESTED"), review(4)],
            "old head approved, then the current one": [review(1, commit=OLDER), review(2, at=last)],
        }
        for name, rows in cases.items():
            with self.subTest(name):
                self.assertIsNone(self.judge(evidence(rows)))
        # and the mirror image of the tie-break refuses
        self.assertEqual(self.judge(evidence([review(4), review(3, "CHANGES_REQUESTED")])), None)
        self.assertEqual(self.judge(evidence([review(3), review(4, "CHANGES_REQUESTED")])),
                         oa.OPERATOR_APPROVAL_NOT_APPROVED)


class WithdrawnTests(unittest.TestCase):
    """The gate job's last step: an approval that admitted this run must still hold when it publishes."""

    def test_a_revocation_edit_or_push_before_publication_withdraws_it(self):
        later = "2026-10-03T13:00:00Z"
        cases = {
            "change requested": ({"context": oa.CONTEXT_CURRENT,
                                  "reviews": [review(1), review(2, "CHANGES_REQUESTED", at=later)]},
                                 oa.OPERATOR_APPROVAL_NOT_APPROVED),
            "dismissed": ({"context": oa.CONTEXT_CURRENT, "reviews": [review(1, "DISMISSED")]},
                          oa.OPERATOR_APPROVAL_NOT_APPROVED),
            "description edited": ({"context": oa.CONTEXT_BODY_CHANGED, "reviews": None},
                                   oa.OPERATOR_APPROVAL_CONTEXT_CHANGED),
            "head pushed": ({"context": oa.CONTEXT_HEAD_MOVED, "reviews": None}, oa.OPERATOR_APPROVAL_CONTEXT_CHANGED),
            "unreadable": ({"context": oa.CONTEXT_UNREAD, "reviews": None}, oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE),
        }
        for name, (fresh, reason) in cases.items():
            with self.subTest(name):
                self.assertEqual(oa.withdrawn(policy(), evidence(), REPO, HEAD, fresh), reason)

    def test_an_approval_that_still_holds_publishes(self):
        fresh = {"context": oa.CONTEXT_CURRENT,
                 "reviews": [review(1), review(2, "COMMENTED", at="2026-10-03T13:00:00Z")]}
        self.assertIsNone(oa.withdrawn(policy(), evidence(), REPO, HEAD, fresh))

    def test_a_verdict_that_never_rested_on_an_approval_is_untouched(self):
        revoked = {"context": oa.CONTEXT_CURRENT, "reviews": [review(1, "DISMISSED")]}
        for ev in (evidence([]), evidence(author=OPERATOR, author_type="User"), evidence(context=oa.CONTEXT_UNREAD)):
            self.assertIsNone(oa.withdrawn(policy(), ev, REPO, HEAD, revoked))
        self.assertIsNone(oa.withdrawn(policy("disabled"), evidence(), REPO, HEAD, revoked))


class BindingAndCollectionTests(unittest.TestCase):
    def test_the_binding_is_exactly_schema_and_activation(self):
        oa.validate_binding({"schema": oa.SCHEMA, "activation": "enabled"})
        oa.validate_binding({"schema": oa.SCHEMA, "activation": "disabled"})
        for bad in (None, {}, {"schema": oa.SCHEMA}, {"schema": "x", "activation": "enabled"},
                    {"schema": oa.SCHEMA, "activation": "on"},
                    {"schema": oa.SCHEMA, "activation": "enabled", "paths": ["aeos/"]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                oa.validate_binding(bad)

    def test_the_shipped_policy_binds_the_route_enabled(self):
        parsed = dp.parse_policy(POLICY_FILE.read_bytes())
        self.assertEqual(parsed.operator_approval, {"schema": oa.SCHEMA, "activation": "enabled"})

    def test_a_malformed_binding_is_a_gate_config_defect(self):
        document = json.loads(POLICY_FILE.read_text())
        document["machine_route"]["operator_approval"] = {"schema": oa.SCHEMA, "activation": "always"}
        with self.assertRaises(dp.PolicyError) as caught:
            dp.parse_policy(json.dumps(document).encode())
        self.assertEqual(caught.exception.code, dp.GATE_CONFIG_INVALID)
        document["machine_route"].pop("operator_approval")
        self.assertIsNone(dp.parse_policy(json.dumps(document).encode()).operator_approval)

    def test_collection_reads_every_page_or_nothing(self):
        def row(i):
            return {"id": i, "user": {"login": OPERATOR, "type": "User"}, "state": "COMMENTED",
                    "commit_id": HEAD, "submitted_at": "2026-10-03T12:00:00Z", "body": "ignored"}
        pages = {1: [row(i) for i in range(1, 101)], 2: [row(i) for i in range(101, 131)]}
        current = {"head": {"sha": HEAD}, "body": "B"}
        calls = []

        def api(path):
            calls.append(path)
            if path == f"repos/{REPO}/pulls/7":
                return current
            return pages.get(int(path.rsplit("page=", 1)[1]), [])
        got = oa.collect(api, REPO, 7, HEAD, "B")
        self.assertEqual(got["context"], oa.CONTEXT_CURRENT)
        self.assertEqual(len(got["reviews"]), 130)
        self.assertEqual(set(got["reviews"][0]), {"id", "login", "type", "state", "commit_id", "submitted_at"})
        self.assertEqual(calls, [f"repos/{REPO}/pulls/7"] + [
            f"repos/{REPO}/pulls/7/reviews?per_page=100&page={n}" for n in (1, 2)] + [f"repos/{REPO}/pulls/7"])
        # a page that ends exactly full asks once more; an empty next page ends the read
        pages = {1: [row(i) for i in range(1, 101)]}
        self.assertEqual(len(oa.collect(api, REPO, 7, HEAD, "B")["reviews"]), 100)
        # more than the bound is unreadable, never truncated into "no decisive review"
        pages = {n: [row(n * 1000 + i) for i in range(100)] for n in range(1, oa.MAX_REVIEW_PAGES + 2)}
        self.assertEqual(oa.collect(api, REPO, 7, HEAD, "B"), {"context": oa.CONTEXT_CURRENT, "reviews": None})
        pages = {1: [row(1)]}
        for rows in (None, {"message": "rate limited"}, [None]):
            pages = {1: rows}
            self.assertEqual(oa.collect(api, REPO, 7, HEAD, "B"), {"context": oa.CONTEXT_CURRENT, "reviews": None})

    def test_collection_binds_the_pull_request_as_it_is_now(self):
        def api_for(current):
            return lambda path: current if path.endswith("/pulls/7") else []
        cases = (({"head": {"sha": OLDER}, "body": "B"}, oa.CONTEXT_HEAD_MOVED),
                 ({"head": {"sha": HEAD}, "body": "B + a grant marker"}, oa.CONTEXT_BODY_CHANGED),
                 (None, oa.CONTEXT_UNREAD), ({"body": "B"}, oa.CONTEXT_UNREAD),
                 ({"head": {"sha": HEAD}, "body": None}, oa.CONTEXT_BODY_CHANGED))
        for current, context in cases:
            with self.subTest(context=context, current=current):
                self.assertEqual(oa.collect(api_for(current), REPO, 7, HEAD, "B"), {"context": context, "reviews": None})
        # an empty body and a null one are the same body (GitHub returns null for an empty description)
        self.assertEqual(oa.collect(api_for({"head": {"sha": HEAD}, "body": None}), REPO, 7, HEAD, ""),
                         {"context": oa.CONTEXT_CURRENT, "reviews": []})
        for number in (None, 0, -1, True, "7"):
            self.assertEqual(oa.collect(api_for({}), REPO, number, HEAD, "B"), {"context": oa.CONTEXT_UNREAD, "reviews": None})

    def test_a_change_that_lands_while_the_reviews_are_read_is_never_current(self):
        """Review round 2 P1: the pull request is read before AND after the reviews; both must match."""
        approval = [{"id": 1, "user": {"login": OPERATOR, "type": "User"}, "state": "APPROVED",
                     "commit_id": HEAD, "submitted_at": "2026-10-03T12:00:00Z"}]
        marker = "<!-- scoped-machine-grant: First-AI-Movers/agent-toolkit#9@sha256:" + "c" * 64 + " -->"
        for second, context in (({"head": {"sha": HEAD}, "body": marker}, oa.CONTEXT_BODY_CHANGED),
                                ({"head": {"sha": OLDER}, "body": ""}, oa.CONTEXT_HEAD_MOVED),
                                (None, oa.CONTEXT_UNREAD)):
            reads = [{"head": {"sha": HEAD}, "body": ""}, second]

            def api(path, reads=reads):
                return reads.pop(0) if path.endswith("/pulls/7") else approval
            with self.subTest(context=context):
                self.assertEqual(oa.collect(api, REPO, 7, HEAD, ""), {"context": context, "reviews": None})

    def test_only_enabled_switches_collection_on(self):
        self.assertTrue(oa.enabled({"schema": oa.SCHEMA, "activation": "enabled"}))
        for binding in (None, {}, {"schema": oa.SCHEMA, "activation": "disabled"}, "enabled"):
            self.assertFalse(oa.enabled(binding))


class MachineRouteTests(unittest.TestCase):
    """Route 1 of the derivation conjunct, for an Agent Toolkit protected path."""

    def setUp(self):
        document = json.loads(POLICY_FILE.read_text())
        self.policy = dp.parse_policy(json.dumps(document).encode())
        document["machine_route"].pop("operator_approval")
        self.unbound = dp.parse_policy(json.dumps(document).encode())
        self.entry = dp.Entry("scripts/flight_deck/node_resources.py", "M", "0" * 64, "1" * 64, None)

    def route(self, ev, pol=None, head=HEAD):
        return dp.machine_route(pol or self.policy, ev, None, REPO, [self.entry], 0.0, head_sha=head)

    def test_an_approved_exact_head_needs_no_programme_envelope(self):
        self.assertIsNone(self.route(evidence()))
        marked = evidence(body="<!-- aeos-programme: First-AI-Movers/agent-toolkit#6246 -->")
        self.assertIsNone(self.route(marked))

    def test_the_route_records_that_the_approval_admitted_it(self):
        admission = {}
        self.assertIsNone(dp.machine_route(self.policy, evidence(), None, REPO, [self.entry], 0.0, head_sha=HEAD,
                                           admission=admission))
        self.assertEqual(admission, {"operator_approval": True})
        admission = {}
        dp.machine_route(self.policy, evidence([]), None, REPO, [self.entry], 0.0, head_sha=HEAD, admission=admission)
        self.assertEqual(admission, {})

    def test_without_the_approval_the_route_says_why(self):
        self.assertEqual(self.route(evidence([])), oa.OPERATOR_APPROVAL_ABSENT)
        self.assertEqual(self.route(evidence([review(1, commit=OLDER)])), oa.OPERATOR_APPROVAL_STALE_HEAD)
        self.assertEqual(self.route(evidence(), head=None), oa.OPERATOR_APPROVAL_HEAD_MISMATCH)
        # unbound, the route is exactly today's
        self.assertEqual(self.route(evidence(), pol=self.unbound), dp.MACHINE_ROUTE_PROGRAMME_ABSENT)

    def test_a_failed_approval_falls_through_to_the_programme_route(self):
        marked = evidence([], body="<!-- aeos-programme: First-AI-Movers/agent-toolkit#6246 -->")
        self.assertEqual(self.route(marked), dp.MACHINE_ROUTE_PROGRAMME_UNAVAILABLE)

    def test_the_machine_identity_conjuncts_still_come_first(self):
        self.assertEqual(self.route(evidence(author=OPERATOR, author_type="User")), dp.MACHINE_ROUTE_ACTOR_IS_OPERATOR)
        self.assertEqual(self.route(evidence(actor=OPERATOR)), dp.MACHINE_ROUTE_TRIGGER_NOT_MACHINE)
        self.assertEqual(self.route(evidence(head_commit="someone")), dp.MACHINE_ROUTE_HEAD_COMMIT_NOT_MACHINE)

    def test_a_grant_marked_pull_request_is_never_admitted_by_an_approval(self):
        valid = "<!-- scoped-machine-grant: First-AI-Movers/agent-toolkit#9@sha256:" + "c" * 64 + " -->"
        self.assertIsInstance(scoped_grant.marker_state(valid), tuple)   # the marker grammar the publisher composes
        for marker in (valid, "<!-- scoped-machine-grant: malformed -->"):
            body = "<!-- aeos-programme: First-AI-Movers/agent-toolkit#3752 -->\n" + marker
            with self.subTest(marker=marker[:40]):
                self.assertNotEqual(scoped_grant.marker_state(body), scoped_grant.MARKER_ABSENT)
                self.assertIsNotNone(self.route(evidence(body=body)))
                # a different programme fails before the scoped judge is even reached
                other = body.replace("#3752", "#6246")
                self.assertEqual(self.route(evidence(body=other)), scoped_grant.SCOPED_GRANT_PROGRAMME_MISMATCH)

    def test_the_derivation_conjunct_passes_the_evaluated_head(self):
        seen = {}
        real = dp.machine_route

        def spy(*args, **kwargs):
            seen.update(kwargs)
            return real(*args, **kwargs)
        with tempfile.TemporaryDirectory() as temp:
            repo = Repo(temp)
            repo.write("scripts/x.py", "X = 1\n")
            repo.base = repo.commit("seed")
            repo.write("scripts/x.py", "X = 2\n")
            head = repo.commit("protected change")
            policy_dir = tempfile.mkdtemp(dir=temp)
            document = json.loads(POLICY_FILE.read_text())
            document["derivation_policy"].update(roots=["scripts/x.py"], allowlist_prefixes=[],
                                                 allowlist_files=["scripts/x.py"], members=["scripts/x.py"])
            document["machine_route"].pop("authority_compiler")
            document["machine_route"].pop("scoped_grant")
            document["machine_route"].pop("accepted_changes", None)
            Path(policy_dir, dp.POLICY_FILE).write_text(json.dumps(document))
            path = Path(tempfile.mkdtemp(prefix="aeos-evidence-")) / "evidence.json"
            path.write_text(json.dumps(evidence([review(1, commit=head)], head=head)))
            with mock.patch.object(dp, "machine_route", spy):
                findings = dp.evaluate_derivation_policy(repo.root, REPO, repo.base, head, policy_dir,
                                                         now=lambda: 0.0, evidence_path=str(path))
            self.assertEqual(seen.get("head_sha"), head)
            self.assertEqual(findings, [])
            path.write_text(json.dumps(evidence([review(1, commit=repo.base)], head=head)))
            findings = dp.evaluate_derivation_policy(repo.root, REPO, repo.base, head, policy_dir,
                                                     now=lambda: 0.0, evidence_path=str(path))
            self.assertEqual([f[0] for f in findings], [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
            self.assertIn(oa.OPERATOR_APPROVAL_STALE_HEAD, findings[0][2])

    def test_a_protected_pass_through_the_gate_is_marked_approval_dependent(self):
        """The gate's report carries the derivation route's dependence, so the workflow rechecks it."""
        with tempfile.TemporaryDirectory() as temp:
            repo = Repo(temp)
            repo.write("scripts/x.py", "X = 1\n")
            repo.base = repo.commit("seed")
            repo.write("scripts/x.py", "X = 2\n")
            head = repo.commit("protected change")
            policy_dir = tempfile.mkdtemp(dir=temp)
            document = json.loads(POLICY_FILE.read_text())
            document["derivation_policy"].update(roots=["scripts/x.py"], allowlist_prefixes=[],
                                                 allowlist_files=["scripts/x.py"], members=["scripts/x.py"])
            document["machine_route"].pop("authority_compiler")
            document["machine_route"].pop("scoped_grant")
            document["machine_route"].pop("accepted_changes", None)
            Path(policy_dir, dp.POLICY_FILE).write_text(json.dumps(document))
            for rows, passed in (([review(1, commit=head)], True), ([], False)):
                with self.subTest(passed=passed):
                    path = Path(tempfile.mkdtemp(prefix="aeos-evidence-")) / "evidence.json"
                    path.write_text(json.dumps(evidence(rows, head=head)))
                    report = gate.evaluate(candidate_dir=repo.root, repository=REPO, base_sha=repo.base, head_sha=head,
                                           event_name="pull_request", policy_dir=policy_dir, evidence_path=str(path))
                    self.assertEqual((report.passed, report.approval_dependent), (passed, passed))


class JudgeChangeTests(unittest.TestCase):
    """Lock 5 in this repository: a change to the judge."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = Repo(self._tmp.name)
        self.policy_dir = tempfile.mkdtemp(dir=self._tmp.name)
        self.document = json.loads(POLICY_FILE.read_text())
        self.write_policy()

    def write_policy(self):
        Path(self.policy_dir, dp.POLICY_FILE).write_text(json.dumps(self.document))

    def gate_with(self, head, ev, repository="First-AI-Movers/.github"):
        path = Path(tempfile.mkdtemp(prefix="aeos-evidence-")) / "evidence.json"
        path.write_text(json.dumps(ev))
        return gate.evaluate(candidate_dir=self.repo.root, repository=repository, base_sha=self.repo.base,
                             head_sha=head, event_name="pull_request", policy_dir=self.policy_dir,
                             evidence_path=str(path))

    def codes(self, report):
        return {f.code for f in report.findings}

    def judge_change(self):
        self.repo.write("aeos/derivation_policy.py", "MACHINE = 'narrowed'\n")
        return self.repo.commit("machine prepares a judge change")

    def machine_evidence(self, head, rows):
        return evidence(rows, head=head, repository="First-AI-Movers/.github")

    def test_a_machine_judge_change_the_operator_approved_on_this_head_is_judged_on_content(self):
        head = self.judge_change()
        report = self.gate_with(head, self.machine_evidence(head, [review(1, commit=head)]))
        self.assertNotIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, self.codes(report))

    def test_the_report_says_when_a_pass_rests_on_the_approval(self):
        """Round 4 P2: only a pass the approval actually admitted is rechecked before it publishes."""
        head = self.judge_change()
        report = self.gate_with(head, self.machine_evidence(head, [review(1, commit=head)]))
        self.assertTrue(report.approval_dependent)
        operator = evidence([review(1, commit=head)], author=OPERATOR, author_type="User", actor=OPERATOR,
                            head_commit=OPERATOR, head=head, repository="First-AI-Movers/.github")
        self.assertFalse(self.gate_with(head, operator).approval_dependent)
        # an approved machine change that touches no control-plane path never rested on the approval
        self.repo.write("README.md", "# fixture, edited\n")
        readme = self.repo.commit("machine edits the readme")
        self.repo.base = head
        report = self.gate_with(readme, self.machine_evidence(readme, [review(1, commit=readme)]))
        self.assertTrue(report.passed)
        self.assertFalse(report.approval_dependent)

    def test_the_cli_records_the_dependence_only_on_a_pass(self):
        head = self.judge_change()
        for rows, passed in (([review(1, commit=head)], True), ([], False)):
            with self.subTest(passed=passed):
                path = Path(tempfile.mkdtemp(prefix="aeos-evidence-")) / "evidence.json"
                path.write_text(json.dumps(self.machine_evidence(head, rows)))
                marker = Path(tempfile.mkdtemp()) / "marker.json"
                with mock.patch.object(gate, "_evaluate_guarded",
                                       lambda **kw: gate.evaluate(policy_dir=self.policy_dir, **kw)), \
                        mock.patch("sys.stdout"), mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
                    code = gate.main(["--candidate-dir", self.repo.root, "--repository", "First-AI-Movers/.github",
                                      "--base-sha", self.repo.base, "--head-sha", head, "--event-name", "pull_request",
                                      "--evidence-file", str(path), "--approval-marker-file", str(marker)])
                self.assertEqual(code, 0 if passed else 1)
                if passed:
                    self.assertEqual(json.loads(marker.read_text()),
                                     {"schema": gate.APPROVAL_MARKER_SCHEMA, "approval_dependent": True,
                                      "accepted_change": None})
                else:
                    self.assertFalse(marker.exists())

    def test_without_that_approval_it_is_refused_and_says_why(self):
        head = self.judge_change()
        for rows, reason in (([], oa.OPERATOR_APPROVAL_ABSENT),
                             ([review(1, commit=self.repo.base)], oa.OPERATOR_APPROVAL_STALE_HEAD),
                             ([review(1, commit=head, state="CHANGES_REQUESTED")], oa.OPERATOR_APPROVAL_NOT_APPROVED),
                             (None, oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE)):
            with self.subTest(reason=reason):
                ev = self.machine_evidence(head, rows)
                if rows is None:
                    ev["pull_request"]["reviews"] = None
                report = self.gate_with(head, ev)
                found = [f for f in report.findings if f.code == gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR]
                self.assertEqual(len(found), 1)
                self.assertIn(reason, found[0].detail)

    def test_the_approval_never_admits_an_operator_push_or_another_bot(self):
        head = self.judge_change()
        for kw in ({"actor": OPERATOR}, {"head_commit": OPERATOR}, {"author": "other[bot]"}):
            with self.subTest(**kw):
                ev = evidence([review(1, commit=head)], head=head, repository="First-AI-Movers/.github", **kw)
                self.assertIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, self.codes(self.gate_with(head, ev)))

    def test_disabling_the_route_restores_the_predecessor_exactly(self):
        head = self.judge_change()
        self.document["machine_route"]["operator_approval"]["activation"] = "disabled"
        self.write_policy()
        report = self.gate_with(head, self.machine_evidence(head, [review(1, commit=head)]))
        self.assertIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, self.codes(report))
        operator = evidence([], author=OPERATOR, author_type="User", actor=OPERATOR, head_commit=OPERATOR,
                            head=head, repository="First-AI-Movers/.github")
        self.assertNotIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, self.codes(self.gate_with(head, operator)))

    def test_the_operator_authoring_and_running_it_still_works_unchanged(self):
        head = self.judge_change()
        operator = evidence([], author=OPERATOR, author_type="User", actor=OPERATOR, head_commit=OPERATOR,
                            head=head, repository="First-AI-Movers/.github")
        self.assertNotIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, self.codes(self.gate_with(head, operator)))

    def test_deleting_the_judge_stays_refused_even_when_approved(self):
        self.repo.write("aeos/merge_ready_gate.py", "CONTROL_PLANE_PREFIXES = ()\n")
        self.repo.base = self.repo.commit("seed the gate source")
        self.repo.remove("aeos/merge_ready_gate.py")
        head = self.repo.commit("delete the gate")
        report = self.gate_with(head, self.machine_evidence(head, [review(1, commit=head)]))
        self.assertIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, self.codes(report))


class WorkflowTests(unittest.TestCase):
    def evidence_script(self) -> str:
        workflow = (WORKFLOWS / "aeos-merge-ready.yml").read_text()
        script = workflow.split("python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
        return textwrap.dedent(script)

    def run_script(self, trusted, reviews, body="", current=None, raises=None):
        """Execute the workflow's evidence script with ``gh api`` answered in memory."""
        calls = []

        def run(argv, **kwargs):
            path = argv[2]
            calls.append(path)
            if raises is not None and raises(path):
                raise subprocess.TimeoutExpired(argv, 30)
            if "/commits/" in path:
                result = {"author": {"login": MACHINE}}
            elif "/reviews" in path:
                result = reviews
            elif path == f"repos/{REPO}/pulls/7":
                result = current if current is not None else {"head": {"sha": HEAD}, "body": body}
            elif path.startswith("repos/") and "/issues/" in path:
                result = {"state": "open", "body": "Programme", "user": {"login": OPERATOR, "type": "User"}}
            elif path == "graphql":
                result = {"data": {"repository": {"issue": {"userContentEdits": {"totalCount": 0, "nodes": []}}}}}
            else:
                result = None
            return SimpleNamespace(returncode=0 if result is not None else 1,
                                   stdout=json.dumps(result) if result is not None else "")
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp) / "event.json"
            output = Path(temp) / "evidence.json"
            event.write_text(json.dumps({"pull_request": {"number": 7, "user": {"login": MACHINE, "type": "Bot"},
                                                          "head": {"sha": HEAD}, "body": body}}))
            environment = dict(AEOS_EVENT_PATH=str(event), AEOS_ACTOR_EVIDENCE=str(output),
                               AEOS_EVENT_NAME="pull_request", AEOS_REPOSITORY=REPO, AEOS_ACTOR=MACHINE)
            with mock.patch.dict(os.environ, environment), mock.patch("subprocess.run", run), \
                    mock.patch.object(dp, "load_policy", side_effect=trusted) as load, \
                    mock.patch.object(sys, "path", sys.path[:]):
                exec(compile(self.evidence_script(), "<trusted evidence workflow>", "exec"), {})
            self.assertEqual(load.call_count, 1)
            return json.loads(output.read_text()), calls

    ROW = {"id": 1, "user": {"login": OPERATOR, "type": "User"}, "state": "APPROVED",
           "commit_id": HEAD, "submitted_at": "2026-10-03T12:00:00Z"}

    @staticmethod
    def bound(activation="enabled"):
        document = json.loads(POLICY_FILE.read_text())
        document["machine_route"]["operator_approval"]["activation"] = activation
        return dp.parse_policy(json.dumps(document).encode())

    def test_reviews_are_collected_only_when_the_route_is_switched_on(self):
        bound = self.bound()
        doc, calls = self.run_script(lambda _d: bound, [self.ROW])
        self.assertEqual(doc["pull_request"]["approval"], {"context": oa.CONTEXT_CURRENT, "reviews": [review(1)]})
        self.assertNotIn("unavailable", doc)
        self.assertIsNone(oa.refusal(bound, doc, REPO, HEAD))
        for trusted in (SimpleNamespace(), self.bound("disabled")):
            with self.subTest(trusted=type(trusted).__name__):
                doc, calls = self.run_script(lambda _d, t=trusted: t, [self.ROW])
                self.assertNotIn("approval", doc["pull_request"])
                self.assertFalse([c for c in calls if "/reviews" in c or c.endswith("/pulls/7")])

    def test_a_body_edited_since_the_event_is_not_judged_by_approval(self):
        """Review P1: a re-run replays the original body; the fresh pull request decides."""
        bound = self.bound()
        marker = "<!-- scoped-machine-grant: First-AI-Movers/agent-toolkit#9@sha256:" + "c" * 64 + " -->"
        doc, _calls = self.run_script(lambda _d: bound, [self.ROW], current={"head": {"sha": HEAD}, "body": marker})
        self.assertEqual(doc["pull_request"]["approval"], {"context": oa.CONTEXT_BODY_CHANGED, "reviews": None})
        self.assertEqual(oa.refusal(bound, doc, REPO, HEAD), oa.OPERATOR_APPROVAL_CONTEXT_CHANGED)
        doc, _calls = self.run_script(lambda _d: bound, [self.ROW], current={"head": {"sha": OLDER}, "body": ""})
        self.assertEqual(oa.refusal(bound, doc, REPO, HEAD), oa.OPERATOR_APPROVAL_CONTEXT_CHANGED)

    def test_a_failed_review_read_never_costs_the_other_evidence(self):
        """Review P2: a timeout on the review read records UNREAD; the programme is still collected."""
        bound = self.bound()
        programme = "<!-- aeos-programme: " + REPO + "#6246 -->"
        doc, _calls = self.run_script(lambda _d: bound, [self.ROW], body=programme,
                                      raises=lambda path: "/reviews" in path)
        self.assertEqual(doc["pull_request"]["approval"], {"context": "UNREAD", "reviews": None})
        self.assertNotIn("unavailable", doc)
        self.assertEqual(doc["programme"]["ref"], REPO + "#6246")
        self.assertEqual(oa.refusal(bound, doc, REPO, HEAD), oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE)

    def test_an_unreadable_policy_binds_nothing_and_breaks_nothing_else(self):
        def broken(_d):
            raise dp.PolicyError(dp.GATE_CONFIG_INVALID, dp.POLICY_FILE, "bad")
        doc, _calls = self.run_script(broken, [])
        self.assertNotIn("approval", doc["pull_request"])
        self.assertNotIn("unavailable", doc)   # no programme marker: the programme path never ran

    def test_an_unreadable_policy_still_fails_the_programme_read_closed(self):
        def broken(_d):
            raise dp.PolicyError(dp.GATE_CONFIG_INVALID, dp.POLICY_FILE, "bad")
        doc, _calls = self.run_script(broken, [], body="<!-- aeos-programme: " + REPO + "#6246 -->")
        self.assertEqual(doc.get("unavailable"), "PolicyError")
        bound = self.bound()
        doc, _calls = self.run_script(lambda _d: bound, [], body="<!-- aeos-programme: " + REPO + "#6246 -->")
        self.assertNotIn("unavailable", doc)
        self.assertEqual(doc["programme"]["ref"], REPO + "#6246")

    def test_an_incomplete_review_read_is_recorded_as_unreadable(self):
        bound = self.bound()
        doc, _calls = self.run_script(lambda _d: bound, None)
        self.assertEqual(doc["pull_request"]["approval"], {"context": oa.CONTEXT_CURRENT, "reviews": None})
        self.assertEqual(oa.refusal(bound, doc, REPO, HEAD), oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE)

    def rerun_document(self):
        import yaml
        return yaml.safe_load((WORKFLOWS / "aeos-approval-rerun.yml").read_text())

    def test_the_rerun_workflow_meets_the_workflow_floor_and_publishes_no_verdict(self):
        path = ".github/workflows/aeos-approval-rerun.yml"
        document = self.rerun_document()
        for repository in ("First-AI-Movers/.github", REPO):
            self.assertEqual(workflow_policy.evaluate_workflow(path, document, repository), [], repository)
        self.assertEqual(document["permissions"], {})
        [(name, job)] = document["jobs"].items()
        self.assertNotEqual(name, "aeos-merge-ready")
        self.assertNotEqual(job.get("name"), "aeos-merge-ready")
        self.assertEqual(job["permissions"], {"actions": "write"})

    def test_every_change_of_decision_or_description_re_judges_and_nothing_else_does(self):
        """Review P1s: a change request, a dismissal or an edited description re-runs a green verdict too."""
        document = self.rerun_document()
        triggers = document.get("on", document.get(True))
        self.assertEqual(triggers, {"pull_request_review": {"types": ["submitted", "dismissed"]},
                                    "pull_request": {"types": ["edited"]}})
        job = document["jobs"]["rerun"]
        condition = " ".join(job["if"].split())
        self.assertEqual(condition, "github.event_name == 'pull_request' || github.event.action == 'dismissed' "
                                    "|| github.event.review.state == 'approved' "
                                    "|| github.event.review.state == 'changes_requested'")
        # Review round 2 P2: the queue lives on the job, so a skipped (comment-only) event never displaces it.
        self.assertNotIn("concurrency", document)
        self.assertEqual(job["concurrency"]["cancel-in-progress"], False)
        self.assertIn("github.event.pull_request.number", job["concurrency"]["group"])

    GATE = ".github/workflows/aeos-merge-ready.yml"

    @staticmethod
    def listing(*runs, total=None):
        rows = [{"id": i, "status": s, "path": path, "name": "aeos-merge-ready", "created_at": f"2026-10-03T12:00:{i:02d}Z"}
                for i, s, path in runs]
        return json.dumps({"total_count": len(rows) if total is None else total, "workflow_runs": rows})

    def run_rerun(self, answers, posts_answers=None):
        """Run the job's script with a fake ``gh``: GETs answer the run listing from ``answers`` in order (JSON, or
        FAIL), POSTs answer from ``posts_answers`` (OK by default); the real ``jq`` filters the listing."""
        if not shutil.which("jq"):
            self.skipTest("jq is not installed here (it is on every GitHub-hosted runner)")
        script = self.rerun_document()["jobs"]["rerun"]["steps"][0]["run"]
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp, "bin")
            bin_dir.mkdir()
            queue, posts, post_queue = Path(temp, "queue"), Path(temp, "posts"), Path(temp, "post_queue")
            queue.write_text("".join(a + "\n" for a in answers))
            post_queue.write_text("".join(a + "\n" for a in (posts_answers or [])))
            posts.write_text("")
            (bin_dir / "gh").write_text(textwrap.dedent(f"""\
                #!/bin/bash
                pop() {{ head -n 1 "$1"; tail -n +2 "$1" > "$1.next"; mv "$1.next" "$1"; }}
                if [ "$3" = "POST" ]; then
                  echo "$4" >> {posts}
                  [ "$(pop {post_queue})" = "FAIL" ] && exit 1
                  exit 0
                fi
                answer="$(pop {queue})"
                case "$answer" in FAIL|"") exit 1 ;; *) echo "$answer" ;; esac
                """))
            (bin_dir / "sleep").write_text("#!/bin/bash\nexit 0\n")
            for tool in ("gh", "sleep"):
                (bin_dir / tool).chmod(0o755)
            env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "REPO": REPO, "HEAD_SHA": HEAD, "GH_TOKEN": "x"}
            proc = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
            return proc.returncode, posts.read_text().split()

    def test_the_helper_re_runs_the_settled_gate_and_only_the_gate(self):
        runs = f"repos/{REPO}/actions/runs/"
        gate_done = self.listing((11, "completed", self.GATE))
        decoy = self.listing((11, "completed", self.GATE), (40, "completed", ".github/workflows/look-alike.yml"))
        cases = {
            "completed now": ([gate_done], None, 0, [runs + "11/rerun"]),
            "a look-alike named aeos-merge-ready is never chosen": ([decoy], None, 0, [runs + "11/rerun"]),
            "in flight is waited for, never cancelled": (
                [self.listing((12, "in_progress", self.GATE)), self.listing((12, "queued", self.GATE)),
                 self.listing((12, "completed", self.GATE))], None, 0, [runs + "12/rerun"]),
            "the newest gate run is the one re-run": (
                [self.listing((13, "completed", self.GATE), (14, "completed", self.GATE))], None, 0, [runs + "14/rerun"]),
            "failed reads are retried": (["FAIL", "FAIL", gate_done], None, 0, [runs + "11/rerun"]),
            "an empty read is never believed": ([self.listing(), self.listing(), gate_done], None, 0,
                                                [runs + "11/rerun"]),
            "a failed re-run is asked again": ([gate_done, gate_done], ["FAIL", "OK"], 0,
                                               [runs + "11/rerun", runs + "11/rerun"]),
            "a re-run that never succeeds fails visibly": ([gate_done] * 60, ["FAIL"] * 60, 1,
                                                           [runs + "11/rerun"] * 60),
            "never found: a visible failure": ([self.listing()] * 60, None, 1, []),
            "never readable: a visible failure": (["FAIL"] * 60, None, 1, []),
            "never settles: a visible failure": ([self.listing((15, "in_progress", self.GATE))] * 60, None, 1, []),
            "more runs than one page: a visible failure": ([self.listing((11, "completed", self.GATE), total=101)],
                                                           None, 1, []),
        }
        for name, (answers, post_answers, code, posted) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.run_rerun(answers, post_answers), (code, posted))

    # -- the gate job's last step ------------------------------------------------------------------------------
    def recheck_script(self) -> str:
        import yaml
        document = yaml.safe_load((WORKFLOWS / "aeos-merge-ready.yml").read_text())
        steps = document["jobs"]["aeos-merge-ready"]["steps"]
        self.assertEqual(steps[-1]["name"], "Recheck the operator's approval before this verdict publishes")
        self.assertEqual(steps[-1]["if"], "success()")
        return steps[-1]["run"].split("python3 - <<'PY'\n", 1)[1].split("\nPY", 1)[0]

    def run_recheck(self, doc, *, repository=REPO, reads=None, raises=False, marker=None, unimportable=None):
        """Execute the last step with the evidence file ``doc`` and ``gh api`` answered from ``reads``."""
        calls = []
        reads = list(reads or [])

        def run(argv, **kwargs):
            calls.append(argv[2])
            if raises:
                raise subprocess.TimeoutExpired(argv, 30)
            result = reads.pop(0) if reads else None
            return SimpleNamespace(returncode=0 if result is not None else 1,
                                   stdout=json.dumps(result) if result is not None else "")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            path.write_text(json.dumps(doc) if doc is not None else "{not json")
            summary = Path(temp) / "summary.md"
            environment = dict(AEOS_ACTOR_EVIDENCE=str(path), AEOS_REPOSITORY=repository, AEOS_HEAD_SHA=HEAD,
                               GITHUB_STEP_SUMMARY=str(summary))
            if marker is not None:
                marker_path = Path(temp) / "marker.json"
                marker_path.write_text(marker if isinstance(marker, str) else json.dumps(marker))
                environment["AEOS_APPROVAL_MARKER"] = str(marker_path)
            modules = {name: None for name in (unimportable or ())}
            out = []
            with mock.patch.dict(os.environ, environment), mock.patch("subprocess.run", run), \
                    mock.patch.object(dp, "load_policy", return_value=self.bound()), \
                    mock.patch.object(sys, "path", sys.path[:]), mock.patch("builtins.print", out.append), \
                    mock.patch.dict(sys.modules, modules):
                try:
                    exec(compile(textwrap.dedent(self.recheck_script()), "<gate recheck>", "exec"), {})
                    code = 0
                except SystemExit as stop:
                    code = stop.code or 0
            return code, out, calls

    def test_the_last_step_fails_a_pass_whose_approval_was_withdrawn(self):
        pr_now = {"head": {"sha": HEAD}, "body": ""}
        approved = {"id": 1, "user": {"login": OPERATOR, "type": "User"}, "state": "APPROVED",
                    "commit_id": HEAD, "submitted_at": "2026-10-03T12:00:00Z"}
        revoked = dict(approved, id=2, state="CHANGES_REQUESTED", submitted_at="2026-10-03T13:00:00Z")
        doc = evidence()
        code, out, calls = self.run_recheck(doc, reads=[pr_now, [approved, revoked], pr_now])
        self.assertEqual(code, 1)
        self.assertEqual(out[0], "AEOS_MERGE_READY_RESULT: FAIL " + dp.DERIVATION_POLICY_DIFF_UNSIGNED)
        self.assertIn(oa.OPERATOR_APPROVAL_NOT_APPROVED, out[1])
        self.assertIn(gate.DERIVATION_POLICY_DIFF_UNSIGNED, gate.REASON_CODES)
        # in this repository the same withdrawal is lock 5's code
        policy_doc = evidence(repository="First-AI-Movers/.github")
        code, out, _calls = self.run_recheck(policy_doc, repository="First-AI-Movers/.github",
                                             reads=[pr_now, [approved, revoked], pr_now])
        self.assertEqual((code, out[0]), (1, "AEOS_MERGE_READY_RESULT: FAIL " + gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR))
        # an edit that landed meanwhile, or a re-read that fails, withdraws it too
        code, out, _calls = self.run_recheck(doc, reads=[{"head": {"sha": HEAD}, "body": "edited"}])
        self.assertEqual(code, 1)
        self.assertIn(oa.OPERATOR_APPROVAL_CONTEXT_CHANGED, out[1])
        code, out, _calls = self.run_recheck(doc, raises=True)
        self.assertEqual(code, 1)
        self.assertIn(oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE, out[1])

    def test_the_last_step_skips_only_on_an_explicit_not_dependent_marker(self):
        pr_now = {"head": {"sha": HEAD}, "body": ""}
        dismissed = {"id": 1, "user": {"login": OPERATOR, "type": "User"}, "state": "DISMISSED",
                     "commit_id": HEAD, "submitted_at": "2026-10-03T12:00:00Z"}
        not_dependent = {"schema": gate.APPROVAL_MARKER_SCHEMA, "approval_dependent": False}
        self.assertEqual(self.run_recheck(evidence(), marker=not_dependent, raises=True), (0, [], []))
        for marker in ({"schema": gate.APPROVAL_MARKER_SCHEMA, "approval_dependent": True}, "{garbled", [1]):
            with self.subTest(marker=marker):
                code, out, _calls = self.run_recheck(evidence(), marker=marker, reads=[pr_now, [dismissed], pr_now])
                self.assertEqual(code, 1)
                self.assertIn(oa.OPERATOR_APPROVAL_NOT_APPROVED, out[1])

    def test_an_unloadable_policy_fails_the_last_step_typed(self):
        """Round 4: an import failure is a typed refusal, never a traceback."""
        code, out, calls = self.run_recheck(evidence(), unimportable=["operator_approval"])
        self.assertEqual(code, 1)
        self.assertEqual(out[0], "AEOS_MERGE_READY_RESULT: FAIL EVIDENCE_UNREADABLE")
        self.assertIn("EVIDENCE_UNREADABLE", gate.REASON_CODES)
        self.assertEqual(calls, [])

    def test_the_deployed_definition_pairs_collection_with_its_barrier(self):
        """Round 4 P1: a definition that collects approvals always carries the recheck, so a re-run of an older
        definition has no approval evidence and the route refuses it."""
        import yaml
        document = yaml.safe_load((WORKFLOWS / "aeos-merge-ready.yml").read_text())
        steps = document["jobs"]["aeos-merge-ready"]["steps"]
        names = [s["name"] for s in steps]
        collect = next(s for s in steps if s["name"].startswith("Collect authenticated evidence"))
        gate_step = next(s for s in steps if s["name"] == "Gate")
        self.assertIn("operator_approval.collect(", collect["run"])
        self.assertIn("--approval-marker-file", gate_step["run"])
        self.assertEqual(names[-1], "Recheck the operator's approval before this verdict publishes")
        self.assertLess(names.index("Gate"), len(names) - 1)
        legacy = evidence()
        legacy["pull_request"].pop("approval")
        self.assertEqual(oa.refusal(policy(), legacy, REPO, HEAD), oa.OPERATOR_APPROVAL_REVIEWS_UNREADABLE)

    def test_the_last_step_lets_a_still_approved_pass_publish(self):
        pr_now = {"head": {"sha": HEAD}, "body": ""}
        approved = {"id": 1, "user": {"login": OPERATOR, "type": "User"}, "state": "APPROVED",
                    "commit_id": HEAD, "submitted_at": "2026-10-03T12:00:00Z"}
        code, out, calls = self.run_recheck(evidence(), reads=[pr_now, [approved], pr_now])
        self.assertEqual((code, out), (0, []))
        self.assertEqual(len(calls), 3)

    def test_the_last_step_never_touches_a_verdict_that_did_not_rest_on_an_approval(self):
        no_route = evidence()
        no_route["pull_request"].pop("approval")
        for doc in (no_route, evidence([]), evidence(author=OPERATOR, author_type="User"), None):
            with self.subTest(doc=str(doc)[:40]):
                self.assertEqual(self.run_recheck(doc, raises=True), (0, [], []))


if __name__ == "__main__":
    unittest.main()
