#!/usr/bin/env python3
"""An exact protected change the operator accepted in trusted policy (agent-toolkit #3052).

Every conjunct of ``accepted_change.refusal`` has a violation with its own reason and a near-miss that stays
admitted; the policy refuses to load an entry that is malformed, long-lived, aimed at another repository or at a
control plane; and the route sits in the machine route exactly where it should: after the machine-identity
conjuncts and the operator-approval route, never for a grant-marked pull request, and a digest the policy does not
list takes the unchanged route.

    python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import accepted_change as ac  # noqa: E402
import derivation_policy as dp  # noqa: E402
import scoped_grant  # noqa: E402

MACHINE = "aeos-autonomous-main[bot]"
OPERATOR = "hpcosta"
REPO = "First-AI-Movers/agent-toolkit"
DISPATCHER = "scripts/agent_relay/dispatcher.py"          # trust machinery the dispatcher of every write runs
CEILING = "scripts/agent_relay/standing_ceiling.py"
ISSUED = "2026-10-04T20:00:00Z"
NOT_AFTER = "2026-10-11T20:00:00Z"
POLICY_FILE = Path(__file__).resolve().parents[1] / dp.POLICY_FILE


def epoch(stamp: str) -> float:
    return dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()


NOW = epoch(ISSUED) + 3600


def change(path=DISPATCHER, rename_from=None, pre_mode="100644", post_mode="100644", pre="0" * 64, post="1" * 64):
    return dp.Entry(path, "M" if rename_from is None else "R", pre, post, rename_from, pre_mode, post_mode)


def entry(changes=None, **overrides) -> dict:
    changes = [change()] if changes is None else changes
    base = {"schema": ac.SCHEMA, "repository": REPO, "protected_diff_sha256": dp.protected_diff_digest(changes),
            "paths": sorted({p for c in changes for p in (c.path, c.rename_from) if p is not None}),
            "issued_at": ISSUED, "not_after": NOT_AFTER, "activation": "enabled", "decision": "test decision"}
    base.update(overrides)
    return base


def document(entries) -> bytes:
    doc = json.loads(POLICY_FILE.read_text())
    doc["machine_route"]["accepted_changes"] = entries
    return json.dumps(doc).encode()


def policy(entries=None):
    return dp.parse_policy(document([entry()] if entries is None else entries))


def evidence(*, body="A protected change.\n", actor=MACHINE, pr_author=MACHINE, head_commit=MACHINE,
             context="CURRENT", reviews=(), barrier=ac.BARRIER) -> dict:
    return {"schema": dp.EVIDENCE_SCHEMA, "event": "pull_request", "repository": REPO, "actor": actor,
            **({} if barrier is None else {"accepted_change_barrier": barrier}),
            "pull_request": {"number": 9, "author_login": pr_author,
                             "author_type": "Bot" if pr_author == MACHINE else "User",
                             "head_sha": "a" * 40, "head_commit_author_login": head_commit, "body": body,
                             "approval": None if context is None else {"context": context, "reviews": list(reviews)}}}


def route(ev, pol=None, entries=None, now=NOW, admission=None):
    return dp.machine_route(pol or policy(), ev, None, REPO, entries or [change()], now, head_sha="a" * 40,
                            admission=admission)


class ValidationTests(unittest.TestCase):
    def test_the_shipped_policy_loads_and_every_acceptance_is_short_lived_and_aimed_here(self):
        shipped = dp.parse_policy(POLICY_FILE.read_bytes())
        for item in shipped.accepted_changes:
            with self.subTest(digest=item["protected_diff_sha256"][:12]):
                self.assertEqual(item["repository"].lower(), shipped.target_repository)
                self.assertLessEqual(epoch(item["not_after"]) - epoch(item["issued_at"]), ac.MAX_LIFETIME_SECONDS)

    def test_the_trust_machinery_may_be_accepted_exactly_but_no_control_plane_ever(self):
        shipped = json.loads(POLICY_FILE.read_text())
        roots = shipped["derivation_policy"]["roots"]
        for path in (roots[0], roots[-1], DISPATCHER):    # near-misses: what no grant or envelope reaches, exactly
            with self.subTest(path=path):
                self.assertEqual(policy([entry([change(path)])]).accepted_changes[0]["paths"], [path])
        for path in ("aeos/derivation-policy-manifest.json", ".github/workflows/x.yml", "AEOS/x.py",
                     ".GITHUB/x.yml", "docs/outside-the-allowlist.md"):
            with self.subTest(path=path), self.assertRaises(dp.PolicyError) as caught:
                policy([entry([change(path)])])
            self.assertEqual(caught.exception.code, dp.GATE_CONFIG_INVALID)

    def test_a_control_plane_path_is_refused_even_where_the_allowlist_would_reach_it(self):
        """`allowlist_files` is not confined to `scripts/`: the control-plane floor holds on its own, in any case."""
        for path in ("aeos/derivation-policy-manifest.json", ".github/workflows/x.yml", "AEOS/x.py", ".GitHub/x.yml"):
            doc = json.loads(document([entry([change(path)])]))
            doc["derivation_policy"]["allowlist_files"] = sorted(doc["derivation_policy"]["allowlist_files"] + [path])
            with self.subTest(path=path), self.assertRaises(dp.PolicyError):
                dp.parse_policy(json.dumps(doc).encode())

    def test_a_malformed_entry_refuses_to_load(self):
        bad = [
            {"repository": REPO}, entry(schema="v0"), entry(repository="Other/repo"), entry(repository="no-slash"),
            entry(protected_diff_sha256="A" * 64), entry(protected_diff_sha256="a" * 63), entry(protected_diff_sha256=None),
            entry(activation="on"), entry(decision=""), entry(decision="   "), entry(decision="x" * 501),
            entry(paths=[]), entry(paths=[DISPATCHER] * 2), entry(paths=["scripts/agent_relay/"]),
            entry(paths=["scripts/agent_relay/../x.py"]), entry(paths=["/" + DISPATCHER]),
            entry(paths=[f"scripts/agent_relay/f{i}.py" for i in range(33)]),
            entry(issued_at="2026-10-04 20:00:00Z"), entry(not_after="2026-10-11T20:00:00+00:00"),
            entry(issued_at=NOT_AFTER, not_after=ISSUED), entry(not_after=ISSUED),
            entry(not_after="2026-10-11T20:00:01Z"),                    # seven days and one second
            entry(issued_at="2026-02-30T00:00:00Z"),
            dict(entry(), extra=1), "not-an-entry",
        ]
        for value in bad:
            with self.subTest(value=str(value)[:70]), self.assertRaises(dp.PolicyError):
                policy([value])
        with self.assertRaises(dp.PolicyError):
            policy([entry(), entry()])            # one change, one entry
        with self.assertRaises(dp.PolicyError):
            policy([entry([change(post=f"{i:064x}")]) for i in range(17)])
        self.assertEqual(policy([entry(not_after=NOT_AFTER)]).accepted_changes[0]["not_after"], NOT_AFTER)  # 7d exactly
        self.assertEqual(policy([entry(repository=REPO.lower())]).accepted_changes[0]["repository"], REPO.lower())
        self.assertEqual(policy([]).accepted_changes, [])
        doc = json.loads(document([]))
        doc["machine_route"].pop("accepted_changes")
        self.assertEqual(dp.parse_policy(json.dumps(doc).encode()).accepted_changes, [])


class RouteTests(unittest.TestCase):
    def test_a_machine_carrier_of_exactly_the_accepted_change_is_admitted(self):
        self.assertIsNone(route(evidence()))
        renamed = [change(CEILING, rename_from=DISPATCHER), change("scripts/agent_relay/cli.py")]
        self.assertIsNone(route(evidence(), policy([entry(renamed)]), renamed))
        self.assertIsNone(route(evidence(), policy([entry(repository=REPO.lower())])))   # GitHub's identity

    def test_each_conjunct_refuses_with_its_own_reason(self):
        cases = {
            ac.ACCEPTED_CHANGE_DISABLED: (evidence(), policy([entry(activation="disabled")]), None, NOW),
            ac.ACCEPTED_CHANGE_NOT_YET_VALID: (evidence(), None, None, epoch(ISSUED) - 1),
            ac.ACCEPTED_CHANGE_EXPIRED: (evidence(), None, None, epoch(NOT_AFTER)),
            ac.ACCEPTED_CHANGE_PATHS_MISMATCH: (evidence(), policy([entry(paths=[DISPATCHER, CEILING])]), None, NOW),
        }
        for reason, (ev, pol, entries, now) in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(route(ev, pol, entries, now), reason)
        # near-misses: the first and last valid instants
        self.assertIsNone(route(evidence(), now=epoch(ISSUED)))
        self.assertIsNone(route(evidence(), now=epoch(NOT_AFTER) - 1))

    def test_any_byte_that_differs_is_a_different_change(self):
        """The digest binds the bytes on both sides of every protected path. A different change takes the route an
        unlisted change takes today, byte for byte."""
        for other in ([change(post="2" * 64)], [change(pre="3" * 64)], [change(), change(CEILING)],
                      [change(CEILING)], [change(DISPATCHER, rename_from=CEILING)]):
            with self.subTest(paths=[c.path for c in other]):
                self.assertEqual(route(evidence(), entries=other), route(evidence(), policy([]), other))
                self.assertIsNotNone(route(evidence(), entries=other))

    def test_a_run_of_a_definition_without_the_publication_recheck_never_admits(self):
        """GitHub re-runs keep the original workflow definition. One that predates the recheck records no barrier
        capability in its evidence, so it can never admit through an acceptance it would not recheck."""
        for barrier in (None, "aeos-accepted-change-barrier/v0", "", 1):
            with self.subTest(barrier=barrier):
                self.assertEqual(route(evidence(barrier=barrier)), ac.ACCEPTED_CHANGE_BARRIER_ABSENT)

    def test_a_stale_or_unproven_pull_request_is_never_admitted(self):
        for context in ("BODY_CHANGED", "HEAD_MOVED", "UNREAD", None):
            with self.subTest(context=context):
                self.assertEqual(route(evidence(context=context)), ac.ACCEPTED_CHANGE_STALE_CONTEXT)

    def test_a_symlink_gitlink_or_unmoded_entry_is_never_admitted(self):
        """The digest carries no modes, so the regular-file conjunct is what keeps a link out."""
        for kw in ({"post_mode": "120000"}, {"pre_mode": "120000"}, {"post_mode": "160000"},
                   {"pre_mode": None, "post_mode": None}, {"post_mode": "000000"}):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                self.assertEqual(route(evidence(), entries=[change(**kw)]), ac.ACCEPTED_CHANGE_NOT_REGULAR_FILE)
        self.assertIsNone(route(evidence(), entries=[change(post_mode="100755")]))
        added = [change(pre="absent", pre_mode="000000")]
        self.assertIsNone(route(evidence(), policy([entry(added)]), added))

    def test_the_machine_identity_conjuncts_still_come_first(self):
        self.assertEqual(route(evidence(actor=OPERATOR)), dp.MACHINE_ROUTE_TRIGGER_NOT_MACHINE)
        self.assertEqual(route(evidence(head_commit=OPERATOR)), dp.MACHINE_ROUTE_HEAD_COMMIT_NOT_MACHINE)
        self.assertEqual(route(evidence(pr_author=OPERATOR)), dp.MACHINE_ROUTE_ACTOR_IS_OPERATOR)

    def test_a_grant_marked_pull_request_is_never_judged_here(self):
        """A grant-marked pull request is the scoped judge's alone, even under the grant's own programme and with
        exactly the accepted bytes."""
        grant_programme = json.loads(POLICY_FILE.read_text())["machine_route"]["scoped_grant"]["programme"]
        marker = f"<!-- scoped-machine-grant: {REPO}#9@sha256:" + "c" * 64 + " -->"
        self.assertNotEqual(scoped_grant.marker_state(marker), scoped_grant.MARKER_ABSENT)
        for body in (marker, f"<!-- aeos-programme: {grant_programme} -->\n" + marker):
            with self.subTest(body=body[:40]):
                self.assertEqual(route(evidence(body=body)), route(evidence(body=body), policy([])))
                self.assertIsNotNone(route(evidence(body=body)))

    def test_the_operator_approval_route_is_decided_first_and_alone_records_its_dependence(self):
        approved = [{"id": 1, "login": OPERATOR, "type": "User", "state": "APPROVED", "commit_id": "a" * 40,
                     "submitted_at": "2026-10-04T21:00:00Z"}]
        admission = {}
        self.assertIsNone(route(evidence(reviews=approved), admission=admission))
        self.assertEqual(admission, {"operator_approval": True})
        admission = {}
        self.assertIsNone(route(evidence(), admission=admission))
        self.assertEqual(admission, {"accepted_change": DEPENDENCE})
        admission = {}
        self.assertEqual(route(evidence(), admission=admission, now=epoch(NOT_AFTER)), ac.ACCEPTED_CHANGE_EXPIRED)
        self.assertEqual(admission, {})                     # a refusal records nothing

    def test_a_programme_marker_does_not_select_or_bypass_an_acceptance(self):
        body = f"<!-- aeos-programme: {REPO}#1530 -->\n"
        self.assertIsNone(route(evidence(body=body)))
        self.assertEqual(route(evidence(body=body), now=epoch(NOT_AFTER)), ac.ACCEPTED_CHANGE_EXPIRED)


if __name__ == "__main__":
    unittest.main()


# ── the dependence a pass records, and the publication recheck that reads it ────────────────────────────────────
import base64  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import textwrap  # noqa: E402
import time  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from unittest import mock  # noqa: E402

import merge_ready_gate as gate  # noqa: E402
from test_merge_ready_gate import Repo  # noqa: E402

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "aeos-merge-ready.yml"
STEP = "Recheck an accepted protected change before this verdict publishes"
DEPENDENCE = {"repository": REPO, "protected_diff_sha256": dp.protected_diff_digest([change()])}


def stamp(offset: float) -> str:
    return dt.datetime.fromtimestamp(time.time() + offset, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class WithdrawnTests(unittest.TestCase):
    def test_an_acceptance_still_current_at_publication_holds(self):
        self.assertIsNone(ac.withdrawn([entry()], DEPENDENCE, context="CURRENT", now=NOW))

    def test_each_change_since_the_run_read_its_policy_withholds_the_pass(self):
        cases = {
            ac.ACCEPTED_CHANGE_REVOKED: ([], DEPENDENCE, "CURRENT", NOW),
            ac.ACCEPTED_CHANGE_DISABLED: ([entry(activation="disabled")], DEPENDENCE, "CURRENT", NOW),
            ac.ACCEPTED_CHANGE_EXPIRED: ([entry()], DEPENDENCE, "CURRENT", epoch(NOT_AFTER)),
            ac.ACCEPTED_CHANGE_NOT_YET_VALID: ([entry()], DEPENDENCE, "CURRENT", epoch(ISSUED) - 1),
            ac.ACCEPTED_CHANGE_STALE_CONTEXT: ([entry()], DEPENDENCE, "BODY_CHANGED", NOW),
        }
        for reason, (entries, dependence, context, now) in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(ac.withdrawn(entries, dependence, context=context, now=now), reason)
        other = dict(DEPENDENCE, protected_diff_sha256="f" * 64)
        self.assertEqual(ac.withdrawn([entry()], other, context="CURRENT", now=NOW), ac.ACCEPTED_CHANGE_REVOKED)
        for broken in (None, "x", {}, {"repository": REPO}, {"protected_diff_sha256": "f" * 64}):
            with self.subTest(broken=broken):
                self.assertEqual(ac.withdrawn([entry()], broken, context="CURRENT", now=NOW),
                                 ac.ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE)


class GateRecordTests(unittest.TestCase):
    def test_a_pass_through_an_acceptance_records_it_and_only_it(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Repo(temp)
            repo.write("scripts/x.py", "X = 1\n")
            repo.base = repo.commit("seed")
            repo.write("scripts/x.py", "X = 2\n")
            head = repo.commit("protected change")
            base = dp.merge_base(repo.root, repo.base, head)
            changes, _ = dp.protected_diff(repo.root, base, head, frozenset({"scripts/x.py"}))
            digest = dp.protected_diff_digest(changes)
            document = json.loads(POLICY_FILE.read_text())
            document["derivation_policy"].update(roots=["scripts/x.py"], allowlist_prefixes=[],
                                                 allowlist_files=["scripts/x.py"], members=["scripts/x.py"])
            document["machine_route"].pop("authority_compiler")
            document["machine_route"].pop("scoped_grant")
            document["machine_route"]["accepted_changes"] = [entry(changes, issued_at=stamp(-3600),
                                                                   not_after=stamp(6 * 86400))]
            policy_dir = tempfile.mkdtemp(dir=temp)
            Path(policy_dir, dp.POLICY_FILE).write_text(json.dumps(document))
            outside = tempfile.TemporaryDirectory(prefix="aeos-evidence-")   # evidence is never inside the candidate
            self.addCleanup(outside.cleanup)
            path = Path(outside.name) / "evidence.json"
            ev = evidence()
            ev["pull_request"]["head_sha"] = head
            path.write_text(json.dumps(ev))
            report = gate.evaluate(candidate_dir=repo.root, repository=REPO, base_sha=repo.base, head_sha=head,
                                   event_name="pull_request", policy_dir=policy_dir, evidence_path=str(path))
            self.assertTrue(report.passed, [(f.code, f.detail[:200]) for f in report.findings])
            self.assertFalse(report.approval_dependent)
            self.assertEqual(report.accepted_change, {"repository": REPO, "protected_diff_sha256": digest})
            marker = Path(outside.name) / "marker.json"
            with mock.patch.object(gate, "_evaluate_guarded", lambda **kw: gate.evaluate(policy_dir=policy_dir, **kw)), \
                    mock.patch("sys.stdout"), mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
                code = gate.main(["--candidate-dir", repo.root, "--repository", REPO, "--base-sha", repo.base,
                                  "--head-sha", head, "--event-name", "pull_request", "--evidence-file", str(path),
                                  "--approval-marker-file", str(marker)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(marker.read_text()),
                             {"schema": gate.APPROVAL_MARKER_SCHEMA, "approval_dependent": False,
                              "accepted_change": {"repository": REPO, "protected_diff_sha256": digest}})


class PublicationRecheckTests(unittest.TestCase):
    def script(self) -> str:
        import yaml
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["aeos-merge-ready"]["steps"]
        names = [s["name"] for s in steps]
        self.assertLess(names.index("Gate"), names.index(STEP))
        step = steps[names.index(STEP)]
        self.assertEqual(step["if"], "success()")
        return step["run"].split("python3 - <<'PY'\n", 1)[1].split("\nPY", 1)[0]

    def run_step(self, *, marker, entries, reads_after_policy=None, policy_read=True, now=None, author=MACHINE,
                 repository=REPO, unimportable=(), evidence_readable=True, event="pull_request"):
        current = json.loads(POLICY_FILE.read_text())
        current["machine_route"]["accepted_changes"] = entries
        blob = {"content": base64.b64encode(json.dumps(current).encode()).decode()}
        pr_now = {"head": {"sha": "a" * 40}, "body": "A protected change.\n"}
        reads = list(reads_after_policy if reads_after_policy is not None else [pr_now, [], pr_now]) + \
            ([blob] if policy_read else [None])
        calls = []

        def run(argv, **kwargs):
            calls.append(argv[2])
            result = reads.pop(0) if reads else None
            return SimpleNamespace(returncode=0 if result is not None else 1,
                                   stdout=json.dumps(result) if result is not None else "")
        ev = evidence()
        ev["pull_request"]["author_login"] = author
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            if evidence_readable:
                path.write_text(json.dumps(ev))
            environment = dict(AEOS_ACTOR_EVIDENCE=str(path), AEOS_REPOSITORY=repository, AEOS_EVENT_AUTHOR=author,
                               AEOS_EVENT_NAME=event,
                               AEOS_APPROVAL_MARKER=str(Path(temp) / "marker.json"),
                               GITHUB_STEP_SUMMARY=str(Path(temp) / "summary.md"))
            if marker is not None:
                Path(environment["AEOS_APPROVAL_MARKER"]).write_text(
                    marker if isinstance(marker, str) else json.dumps(marker))
            out = []
            with mock.patch.dict(os.environ, environment), mock.patch("subprocess.run", run), \
                    mock.patch.object(dp, "load_policy", return_value=dp.parse_policy(POLICY_FILE.read_bytes())), \
                    mock.patch("time.time", return_value=NOW if now is None else now), \
                    mock.patch.object(sys, "path", sys.path[:]), mock.patch("builtins.print", out.append), \
                    mock.patch.dict(sys.modules, {name: None for name in unimportable}):
                try:
                    exec(compile(textwrap.dedent(self.script()), "<accepted recheck>", "exec"), {})
                    code = 0
                except SystemExit as stop:
                    code = stop.code or 0
            return code, out, calls

    def marker(self, dependence=DEPENDENCE):
        return {"schema": gate.APPROVAL_MARKER_SCHEMA, "approval_dependent": False, "accepted_change": dependence}

    def test_a_still_accepted_pass_publishes(self):
        code, out, calls = self.run_step(marker=self.marker(), entries=[entry()])
        self.assertEqual((code, out), (0, []))
        # the policy is the LAST external observation: a revocation during the context reads is still seen
        self.assertIn("standing-governor-policy.json", calls[-1])
        self.assertTrue(all("standing-governor-policy.json" not in c for c in calls[:-1]))

    def test_a_pass_that_rests_on_no_acceptance_is_untouched(self):
        self.assertEqual(self.run_step(marker=self.marker(None), entries=[]), (0, [], []))

    def test_a_revocation_disabling_expiry_or_moved_context_withholds_the_pass(self):
        edited = {"head": {"sha": "a" * 40}, "body": "edited"}
        cases = {
            ac.ACCEPTED_CHANGE_REVOKED: dict(entries=[]),
            ac.ACCEPTED_CHANGE_DISABLED: dict(entries=[entry(activation="disabled")]),
            ac.ACCEPTED_CHANGE_EXPIRED: dict(entries=[entry()], now=epoch(NOT_AFTER) + 1),
            ac.ACCEPTED_CHANGE_STALE_CONTEXT: dict(entries=[entry()], reads_after_policy=[edited]),
        }
        for reason, kwargs in cases.items():
            with self.subTest(reason=reason):
                code, out, _calls = self.run_step(marker=self.marker(), **kwargs)
                self.assertEqual((code, out[0]), (1, "AEOS_MERGE_READY_RESULT: FAIL DERIVATION_POLICY_DIFF_UNSIGNED"))
                self.assertIn(reason, out[1])

    def test_a_policy_that_cannot_be_re_read_or_a_broken_import_never_publishes(self):
        for kwargs in (dict(policy_read=False), dict(unimportable=["accepted_change"])):
            with self.subTest(**{k: str(v) for k, v in kwargs.items()}):
                code, out, _calls = self.run_step(marker=self.marker(), entries=[entry()], **kwargs)
                self.assertEqual(code, 1)
                self.assertIn(ac.ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE, out[1])

    def test_a_dependent_pass_whose_evidence_cannot_be_read_never_publishes(self):
        """Round 2 P1: unreadable evidence is not proof that nothing rested on an acceptance; the marker says it did."""
        code, out, calls = self.run_step(marker=self.marker(), entries=[entry()], evidence_readable=False)
        self.assertEqual(code, 1)
        self.assertIn(ac.ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE, out[1])
        self.assertEqual(self.run_step(marker=self.marker(None), entries=[], evidence_readable=False), (0, [], []))

    def test_an_unreadable_marker_fails_closed_only_where_an_acceptance_could_exist(self):
        for marker in ("{garbled", {"schema": gate.APPROVAL_MARKER_SCHEMA, "approval_dependent": False}, [1], None):
            with self.subTest(marker=str(marker)[:30]):
                code, out, calls = self.run_step(marker=marker, entries=[entry()], evidence_readable=False)
                self.assertEqual(code, 1)
                self.assertIn(ac.ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE, out[1])
                self.assertEqual(calls, [])
        self.assertEqual(self.run_step(marker=None, entries=[entry()], author=OPERATOR), (0, [], []))
        self.assertEqual(self.run_step(marker=None, entries=[entry()], repository="First-AI-Movers/other"),
                         (0, [], []))

    def test_the_deployed_definition_pairs_the_capability_with_its_recheck(self):
        """The capability and the step ship together: a definition that writes one always carries the other."""
        import yaml
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["aeos-merge-ready"]["steps"]
        names = [s["name"] for s in steps]
        collect = next(s for s in steps if s["name"].startswith("Collect authenticated evidence"))
        self.assertIn(f'"accepted_change_barrier": "{ac.BARRIER}"', collect["run"])
        self.assertLess(names.index(collect["name"]), names.index("Gate"))
        self.assertLess(names.index("Gate"), names.index(STEP))
        self.assertEqual(names[-1], "Recheck the operator's approval before this verdict publishes")

    def test_an_unreadable_marker_on_a_merge_group_in_the_target_repository_fails_closed(self):
        """Round 3 P1: a merge-group event has no pull-request author, an acceptance can admit it, and the approval
        barrier cannot cover it (an approval never admits a merge group). So the event, not the author, decides."""
        for marker in ("{garbled", None):
            with self.subTest(marker=marker):
                code, out, calls = self.run_step(marker=marker, entries=[entry()], author="", event="merge_group",
                                                 evidence_readable=False)
                self.assertEqual(code, 1)
                self.assertIn(ac.ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE, out[1])
        self.assertEqual(self.run_step(marker=None, entries=[entry()], author="", event="merge_group",
                                       repository="First-AI-Movers/other"), (0, [], []))
        self.assertEqual(self.run_step(marker=None, entries=[entry()], author="", event="pull_request"), (0, [], []))
