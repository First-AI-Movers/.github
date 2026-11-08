#!/usr/bin/env python3
"""Accepted-change maintenance (agent-toolkit #3052, principal direction 2026-11-07): refreshing and retiring
``machine_route.accepted_changes`` without an approving review.

Every conjunct of ``accepted_change_maintenance.refusal`` has a violation that must refuse with its own reason and a
near-miss that must stay admitted. The class is exercised where it is used: through ``merge_ready_gate.evaluate`` in
this policy repository, over a real git history, with the shipped policy as the trusted base. The carrier's digest
is recomputed by the real derivation functions over real git objects fetched into a throwaway repository. What must
NOT change is exercised too: an operator-authored change, the existing approval route, and every other key.

    PYTHONPATH=aeos python3 -m pytest aeos/tests/test_accepted_change_maintenance.py
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import json
import os
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

import accepted_change as ac  # noqa: E402
import accepted_change_maintenance as acm  # noqa: E402
import derivation_policy as dp  # noqa: E402
import merge_ready_gate as gate  # noqa: E402
import operator_approval as oa  # noqa: E402
from test_merge_ready_gate import Repo  # noqa: E402

MACHINE = "aeos-autonomous-main[bot]"
OPERATOR = "hpcosta"
POLICY_REPO = "First-AI-Movers/.github"
TOOLKIT = "First-AI-Movers/agent-toolkit"
SHIPPED = Path(__file__).resolve().parents[1] / dp.POLICY_FILE
WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
NOW = dt.datetime(2026, 11, 8, 12, 0, 0, tzinfo=dt.timezone.utc).timestamp()
DAY = 24 * 3600
CARRIER_HEAD = "c" * 40
OTHER_HEAD = "d" * 40
DIGEST = "1" * 64
OTHER_DIGEST = "2" * 64
ROOT = "scripts/agent_relay/standing_authority.py"
MEMBER = "scripts/agent_relay/dispatcher.py"
SECOND = "scripts/agent_relay/ledger.py"
FAILED_PREFIX = "accepted-change maintenance: "


def stamp(offset: float) -> str:
    return dt.datetime.fromtimestamp(NOW + offset, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry(digest=DIGEST, paths=(MEMBER,), *, pr=101, head=CARRIER_HEAD, issued=-3600, lifetime=6 * DAY - 3600,
          activation="enabled", repository=TOOLKIT, carrier=True) -> dict:
    record = {"schema": ac.SCHEMA, "repository": repository, "protected_diff_sha256": digest, "paths": list(paths),
              "issued_at": stamp(issued), "not_after": stamp(issued + lifetime), "activation": activation,
              "decision": "Machine-settled refresh under accepted-change maintenance (test)."}
    if carrier:
        record["carrier"] = {"pull_request": pr, "head_sha": head}
    return record


def carrier(digest=DIGEST, paths=(MEMBER,), *, pr=101, head=CARRIER_HEAD, state="open", merged=False,
            author=MACHINE, kind="Bot", deleted=(), repository=TOOLKIT) -> dict:
    return {"repository": repository, "pull_request": pr, "state": state, "merged": merged, "author_login": author,
            "author_type": kind, "head_sha": head, "digest": digest, "paths": list(paths),
            "deleted_paths": list(deleted)}


def evidence(head, carriers=(), *, author=MACHINE, author_type="Bot", actor=MACHINE, head_commit=MACHINE,
             context=oa.CONTEXT_CURRENT, event="pull_request", unavailable=None) -> dict:
    block = {"schema": acm.EVIDENCE_SCHEMA, "context": context, "carriers": list(carriers)}
    if unavailable:
        block["unavailable"] = unavailable
    return {"schema": dp.EVIDENCE_SCHEMA, "event": event, "repository": POLICY_REPO, "actor": actor,
            "pull_request": {"number": 7, "author_login": author, "author_type": author_type, "head_sha": head,
                             "head_commit_author_login": head_commit, "body": "",
                             "approval": {"context": oa.CONTEXT_CURRENT, "reviews": []}},
            "accepted_change_maintenance": block}


class GateCase(unittest.TestCase):
    """A policy repository whose base commit carries the trusted policy, and a head that the machine prepared."""

    base_entries: tuple = ()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # Evidence and trusted policy live OUTSIDE the candidate tree: evidence inside it is malformed by rule.
        self._outside = tempfile.TemporaryDirectory()
        self.addCleanup(self._outside.cleanup)
        self.trusted = json.loads(SHIPPED.read_text())
        self.trusted["machine_route"]["accepted_changes"] = [copy.deepcopy(e) for e in self.base_entries]
        self.repo = Repo(self._tmp.name)
        self.policy_dir = tempfile.mkdtemp(dir=self._outside.name)
        self.write_trusted()
        self.repo.write("aeos/standing-governor-policy.json", self.dump(self.trusted))
        self.repo.base = self.repo.commit("base carries the trusted policy")
        self.head_doc = copy.deepcopy(self.trusted)

    @staticmethod
    def dump(document) -> str:
        return json.dumps(document, indent=2, ensure_ascii=False) + "\n"

    def write_trusted(self):
        Path(self.policy_dir, dp.POLICY_FILE).write_text(self.dump(self.trusted))

    def commit_head(self, text=None) -> str:
        self.repo.write("aeos/standing-governor-policy.json", self.dump(self.head_doc) if text is None else text)
        return self.repo.commit("machine refreshes the accepted changes")

    def judge(self, head, ev):
        path = Path(tempfile.mkdtemp(dir=self._outside.name)) / "evidence.json"
        path.write_text(json.dumps(ev))
        return gate.evaluate(candidate_dir=self.repo.root, repository=POLICY_REPO, base_sha=self.repo.base,
                             head_sha=head, event_name="pull_request", policy_dir=self.policy_dir,
                             evidence_path=str(path), now=lambda: NOW)

    def set_head_entries(self, entries):
        self.head_doc["machine_route"]["accepted_changes"] = entries

    def run_refresh(self, entries, carriers=(), **kw):
        self.set_head_entries(entries)
        head = self.commit_head()
        return self.judge(head, evidence(head, carriers, **kw))

    @staticmethod
    def reason(report):
        """The class's own refusal inside the control-plane finding, or ``None`` when it admitted (or never ran)."""
        found = [f for f in report.findings
                 if f.code == gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR and FAILED_PREFIX in f.detail]
        if not found:
            return None
        assert len(found) == 1, found
        return found[0].detail.split(FAILED_PREFIX, 1)[1].strip()

    def assertAdmitted(self, report):
        self.assertEqual(self.reason(report), None, [(f.code, f.detail) for f in report.findings])
        self.assertTrue(report.passed, [(f.code, f.detail) for f in report.findings])
        self.assertFalse(report.approval_dependent)

    def assertRefused(self, report, reason):
        self.assertEqual(self.reason(report), reason, [(f.code, f.detail) for f in report.findings])
        self.assertFalse(report.passed)
        self.assertEqual(report.primary, gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR)


class PositiveTests(GateCase):
    def test_an_exact_in_class_refresh_needs_no_approval(self):
        report = self.run_refresh([entry()], [carrier()])
        self.assertAdmitted(report)
        self.assertTrue(any("accepted-change maintenance" in note for note in report.notes))
        self.assertEqual(report.control_plane, ["aeos/standing-governor-policy.json"])

    def test_a_batch_that_adds_two_and_keeps_the_trusted_ones_is_one_refresh(self):
        report = self.run_refresh([entry(), entry(OTHER_DIGEST, (SECOND,), pr=102)],
                                  [carrier(), carrier(OTHER_DIGEST, (SECOND,), pr=102)])
        self.assertAdmitted(report)

    def test_a_renewal_of_an_open_carriers_entry_is_a_refresh(self):
        """Near-miss: the same digest with a later expiry is a changed entry, proved like a new one."""
        base = entry()
        self.trusted["machine_route"]["accepted_changes"] = [base]
        self.write_trusted()
        self.repo.write("aeos/standing-governor-policy.json", self.dump(self.trusted))
        self.repo.base = self.repo.commit("trusted gains the entry")
        renewed = dict(base, not_after=stamp(5 * DAY))
        report = self.run_refresh([renewed], [carrier()])
        self.assertAdmitted(report)


class SpentEntryRetirementTests(GateCase):
    base_entries = (entry(), entry(OTHER_DIGEST, (SECOND,), pr=102, issued=-9 * DAY, lifetime=7 * DAY),
                    entry("3" * 64, ("scripts/agent_relay/models.py",), pr=103, activation="disabled"))

    def test_a_merged_or_closed_carrier_retires_its_entry(self):
        for merged in (True, False):
            with self.subTest(merged=merged):
                self.setUp()
                kept = self.trusted["machine_route"]["accepted_changes"][1:]
                report = self.run_refresh(kept, [carrier(state="closed", merged=merged)])
                self.assertAdmitted(report)

    def test_a_lapsed_entry_retires_without_any_carrier_evidence(self):
        kept = [self.trusted["machine_route"]["accepted_changes"][0], self.trusted["machine_route"]["accepted_changes"][2]]
        self.assertAdmitted(self.run_refresh(kept, []))

    def test_a_never_live_entry_retires_freely(self):
        kept = self.trusted["machine_route"]["accepted_changes"][:2]
        self.assertAdmitted(self.run_refresh(kept, []))

    def test_retiring_everything_at_once_is_still_a_refresh(self):
        report = self.run_refresh([], [carrier(state="closed", merged=True)])
        self.assertAdmitted(report)

    def test_an_unspent_live_entry_is_never_removed_by_the_class(self):
        for rows in ([carrier()], []):
            with self.subTest(rows=len(rows)):
                self.setUp()
                kept = self.trusted["machine_route"]["accepted_changes"][1:]
                self.assertRefused(self.run_refresh(kept, rows), acm.UNSPENT_ENTRY_REMOVED)

    def test_a_removed_entry_with_no_pinned_carrier_cannot_be_called_spent(self):
        pinless = entry(carrier=False)
        self.trusted["machine_route"]["accepted_changes"] = [pinless]
        self.write_trusted()
        self.repo.write("aeos/standing-governor-policy.json", self.dump(self.trusted))
        self.repo.base = self.repo.commit("trusted gains a legacy entry")
        self.assertRefused(self.run_refresh([], [carrier(state="closed", merged=True)]), acm.UNSPENT_ENTRY_REMOVED)


class CarrierProofTests(GateCase):
    """The carrier the entry pins decides it, read by the trusted workflow, never the candidate."""

    def refused(self, row=None, new=None, rows=None, **kw):
        report = self.run_refresh([new or entry()], rows if rows is not None else [row or carrier()], **kw)
        return self.reason(report)

    def test_a_stale_or_swapped_head_is_refused(self):
        self.assertEqual(self.refused(carrier(head=OTHER_HEAD)), acm.CARRIER_HEAD_MISMATCH)

    def test_a_stale_or_swapped_digest_is_refused(self):
        self.assertEqual(self.refused(carrier(digest=OTHER_DIGEST)), acm.CARRIER_DIGEST_MISMATCH)

    def test_the_carriers_paths_must_be_exactly_the_entrys(self):
        self.assertEqual(self.refused(carrier(paths=(MEMBER, SECOND))), acm.CARRIER_PATHS_MISMATCH)
        self.assertEqual(self.refused(carrier(paths=())), acm.CARRIER_PATHS_MISMATCH)

    def test_a_carrier_that_is_not_open_is_refused(self):
        self.assertEqual(self.refused(carrier(state="closed")), acm.CARRIER_NOT_OPEN)
        self.assertEqual(self.refused(carrier(state="closed", merged=True)), acm.CARRIER_NOT_OPEN)
        self.assertEqual(self.refused(carrier(merged=True)), acm.CARRIER_NOT_OPEN)
        self.assertEqual(self.refused(carrier(state=None)), acm.CARRIER_NOT_OPEN)

    def test_a_carrier_a_human_or_another_bot_authored_is_refused(self):
        for who, kind in ((OPERATOR, "User"), ("other[bot]", "Bot"), (MACHINE, "User"), (None, None)):
            with self.subTest(author=who):
                self.assertEqual(self.refused(carrier(author=who, kind=kind)), acm.CARRIER_NOT_MACHINE)

    def test_an_unread_or_ambiguous_carrier_is_never_a_proof(self):
        self.assertEqual(self.refused(rows=[]), acm.CARRIER_UNREAD)
        self.assertEqual(self.refused(rows=[carrier(pr=999)]), acm.CARRIER_UNREAD)
        self.assertEqual(self.refused(rows=[carrier(), carrier()]), acm.CARRIER_UNREAD)
        self.assertEqual(self.refused(carrier(digest=None)), acm.CARRIER_UNREAD)
        self.assertEqual(self.refused(rows=[], unavailable="no read credential"), acm.CARRIER_UNREAD)
        for bad in ({"carriers": "x"}, {"carriers": None}):
            with self.subTest(bad=bad):
                self.setUp()
                self.set_head_entries([entry()])
                head = self.commit_head()
                ev = evidence(head, [carrier()])
                ev["accepted_change_maintenance"].update(bad)
                self.assertRefused(self.judge(head, ev), acm.CARRIER_UNREAD)

    def test_an_entry_must_pin_its_carrier(self):
        self.assertEqual(self.refused(new=entry(carrier=False)), acm.CARRIER_UNPINNED)

    def test_a_deleted_protected_path_is_out_of_class(self):
        self.assertEqual(self.refused(carrier(deleted=(MEMBER,))), acm.CARRIER_DELETES_PROTECTED_PATH)

    def test_a_secret_or_control_plane_deletion_is_out_of_class(self):
        for path in (".github/workflows/ci.yml", "aeos/derivation_policy.py", ".env", "config/.env.production",
                     "deploy/server.pem", "keys/id_ed25519", "secrets/token.txt", ".gitattributes"):
            with self.subTest(path=path):
                self.assertEqual(self.refused(carrier(deleted=(path,))), acm.CARRIER_DELETES_CONTROL_PLANE)

    def test_an_ordinary_deletion_elsewhere_is_a_near_miss_that_stays_admitted(self):
        report = self.run_refresh([entry()], [carrier(deleted=("scripts/old_helper.py", "docs/old.md"))])
        self.assertAdmitted(report)

    def test_a_derivation_root_is_out_of_class(self):
        report = self.run_refresh([entry(paths=(ROOT,))], [carrier(paths=(ROOT,))])
        self.assertRefused(report, acm.PATH_OUT_OF_CLASS)

    def test_a_package_replacing_a_root_is_out_of_class(self):
        shadow = "scripts/agent_relay/standing_authority/__init__.py"
        report = self.run_refresh([entry(paths=(shadow,))], [carrier(paths=(shadow,))])
        self.assertRefused(report, acm.PATH_OUT_OF_CLASS)

    def test_a_path_outside_the_allowlist_or_in_a_control_plane_never_loads(self):
        for path in ("scripts/other_tool.py", "aeos/merge_ready_gate.py", ".github/workflows/x.yml"):
            with self.subTest(path=path):
                self.setUp()
                report = self.run_refresh([entry(paths=(path,))], [carrier(paths=(path,))])
                self.assertRefused(report, acm.HEAD_POLICY_INVALID)

    def test_another_repository_is_out_of_class(self):
        """Tailnet-policy entries bind every changed path with no allowlist: they keep the approval route."""
        report = self.run_refresh([entry(repository=ac.TAILNET_REPOSITORY.replace("first-ai-movers", "First-AI-Movers"))],
                                  [carrier(repository="First-AI-Movers/tailnet-policy")])
        self.assertRefused(report, acm.REPOSITORY_OUT_OF_CLASS)


class EntryBoundsTests(GateCase):
    def refused(self, new, rows=None):
        return self.reason(self.run_refresh([new], rows if rows is not None else [carrier()]))

    def test_an_expired_entry_is_refused(self):
        self.assertEqual(self.refused(entry(issued=-3 * DAY, lifetime=DAY)), acm.ENTRY_EXPIRED)

    def test_an_entry_not_yet_valid_is_refused(self):
        self.assertEqual(self.refused(entry(issued=3600)), acm.ENTRY_NOT_YET_VALID)

    def test_the_lifetime_ceiling_lives_in_the_base_policy(self):
        self.trusted["machine_route"]["accepted_change_maintenance"]["max_lifetime_seconds"] = 2 * DAY
        self.write_trusted()
        self.repo.write("aeos/standing-governor-policy.json", self.dump(self.trusted))
        self.repo.base = self.repo.commit("base with a two day ceiling")
        self.head_doc = copy.deepcopy(self.trusted)
        self.assertEqual(self.refused(entry(issued=-3600, lifetime=4 * DAY)), acm.LIFETIME_EXCEEDED)
        self.setUp()
        self.trusted["machine_route"]["accepted_change_maintenance"]["max_lifetime_seconds"] = 2 * DAY
        self.write_trusted()
        self.repo.write("aeos/standing-governor-policy.json", self.dump(self.trusted))
        self.repo.base = self.repo.commit("base with a two day ceiling")
        self.head_doc = copy.deepcopy(self.trusted)
        self.assertEqual(self.refused(entry(issued=-3600, lifetime=DAY)), None)   # near-miss: inside the ceiling

    def test_the_hard_seven_day_limit_still_rejects_a_longer_entry_at_load(self):
        self.assertEqual(self.refused(entry(issued=0, lifetime=8 * DAY)), acm.HEAD_POLICY_INVALID)

    def test_the_entry_ceiling_lives_in_the_base_policy(self):
        self.trusted["machine_route"]["accepted_change_maintenance"]["max_entries"] = 2
        self.write_trusted()
        self.repo.write("aeos/standing-governor-policy.json", self.dump(self.trusted))
        self.repo.base = self.repo.commit("base with a two entry ceiling")
        self.head_doc = copy.deepcopy(self.trusted)
        three = [entry(str(i) * 64, (MEMBER,), pr=100 + i) for i in (4, 5, 6)]
        rows = [carrier(str(i) * 64, (MEMBER,), pr=100 + i) for i in (4, 5, 6)]
        self.assertRefused(self.run_refresh(three, rows), acm.CEILING_EXCEEDED)

    def test_two_entries_under_a_two_entry_ceiling_is_a_near_miss_that_stays_admitted(self):
        self.trusted["machine_route"]["accepted_change_maintenance"]["max_entries"] = 2
        self.write_trusted()
        self.repo.write("aeos/standing-governor-policy.json", self.dump(self.trusted))
        self.repo.base = self.repo.commit("base with a two entry ceiling")
        self.head_doc = copy.deepcopy(self.trusted)
        two = [entry(str(i) * 64, (MEMBER,), pr=100 + i) for i in (4, 5)]
        rows = [carrier(str(i) * 64, (MEMBER,), pr=100 + i) for i in (4, 5)]
        self.assertAdmitted(self.run_refresh(two, rows))


class ScopeTests(GateCase):
    """Nothing but the accepted-change list moves: every other key stays the operator's."""

    def refused_with(self, mutate):
        if "machine_route" in self.head_doc:
            self.head_doc["machine_route"]["accepted_changes"] = [entry()]
        mutate(self.head_doc)
        head = self.commit_head()
        return self.reason(self.judge(head, evidence(head, [carrier()])))

    def test_a_second_key_changed_in_the_same_change_falls_through(self):
        def edit(path, value):
            def go(doc):
                node = doc
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
            return go
        cases = {
            "top decision": edit(("decision",), "edited"),
            "target repository": edit(("target_repository",), "First-AI-Movers/other"),
            "root added": edit(("derivation_policy", "roots"),
                               copy.deepcopy(self.trusted["derivation_policy"]["roots"]) + ["scripts/launch_x.py"]),
            "allowlist prefix": edit(("derivation_policy", "allowlist_prefixes"),
                                     self.trusted["derivation_policy"]["allowlist_prefixes"] + ["scripts/wide/"]),
            "allowlist file": edit(("derivation_policy", "allowlist_files"),
                                   self.trusted["derivation_policy"]["allowlist_files"] + ["scripts/more.py"]),
            "members": edit(("derivation_policy", "measured_bounded_count"), 1),
            "signer not_after": edit(("accepted_signers", 0, "not_after"), "2030-01-01T00:00:00Z"),
            "signer label": edit(("accepted_signers", 0, "label"), "other-signer"),
            "machine principal": edit(("machine_route", "machine_principals"),
                                      [{"login": "evil[bot]", "type": "Bot"}]),
            "operator principal": edit(("machine_route", "operator_principals"), ["hpcosta", "friend"]),
            "operator approval activation": edit(("machine_route", "operator_approval", "activation"), "disabled"),
            "scoped grant activation": edit(("machine_route", "scoped_grant", "activation"), "disabled"),
            "authority compiler": edit(("machine_route", "authority_compiler", "programme"),
                                       "First-AI-Movers/agent-toolkit#1"),
            "route decision": edit(("machine_route", "decision"), "edited"),
            "class activation flipped": edit(("machine_route", "accepted_change_maintenance", "activation"), "disabled"),
            "class ceiling raised": edit(("machine_route", "accepted_change_maintenance", "max_entries"), 16),
            "class lifetime raised": edit(("machine_route", "accepted_change_maintenance", "max_lifetime_seconds"), 1),
            "class removed": lambda doc: doc["machine_route"].pop("accepted_change_maintenance"),
            "route removed": lambda doc: doc.pop("machine_route"),
        }
        for name, mutate in cases.items():
            with self.subTest(change=name):
                self.setUp()
                self.assertIn(self.refused_with(mutate),
                              (acm.OTHER_KEYS_CHANGED, acm.HEAD_POLICY_INVALID), name)

    def test_the_policy_sources_and_signers_specifically_fall_through_typed(self):
        for name, mutate in (("signer fingerprint",
                              lambda d: d["accepted_signers"][0].update(fingerprint="SHA256:" + "A" * 43)),
                             ("signer key", lambda d: d["accepted_signers"][0].update(public_key="ssh-ed25519 AAAA")),
                             ("manifest path", lambda d: d.update(manifest_path="aeos/other.json"))):
            with self.subTest(change=name):
                self.setUp()
                self.assertIn(self.refused_with(mutate), (acm.OTHER_KEYS_CHANGED, acm.HEAD_POLICY_INVALID))
        self.setUp()
        self.assertEqual(self.refused_with(lambda d: d["accepted_signers"][0].update(not_after="2030-01-01T00:00:00Z")),
                         acm.OTHER_KEYS_CHANGED)

    def test_a_second_file_in_the_same_change_falls_through(self):
        self.repo.write("README.md", "# fixture, edited\n")
        report = self.run_refresh([entry()], [carrier()])
        self.assertRefused(report, acm.NOT_ONLY_POLICY_FILE)

    def test_the_judge_or_its_tests_are_never_in_class(self):
        for path in ("aeos/accepted_change_maintenance.py", "aeos/tests/test_x.py", ".github/workflows/aeos-merge-ready.yml"):
            with self.subTest(path=path):
                self.setUp()
                self.repo.write(path, "x = 1\n")
                self.assertRefused(self.run_refresh([entry()], [carrier()]), acm.NOT_ONLY_POLICY_FILE)

    def test_a_lone_change_to_another_control_plane_file_is_never_in_class(self):
        for path in ("aeos/merge_ready_gate.py", ".github/workflows/aeos-merge-ready.yml", ".github/aeos-gate.json"):
            with self.subTest(path=path):
                self.setUp()
                self.repo.write(path, "{}\n" if path.endswith(".json") else "x = 1\n")
                head = self.repo.commit("lone control-plane change")
                self.assertRefused(self.judge(head, evidence(head, [carrier()])), acm.NOT_ONLY_POLICY_FILE)

    def test_only_a_modification_of_a_regular_policy_file_is_in_class_at_the_module_boundary(self):
        """The judge's own contract, below the gate: status and both modes are checked, not inferred."""
        raw = self.dump(self.trusted).encode()
        policy = dp.parse_policy(raw)
        self.head_doc["machine_route"]["accepted_changes"] = [entry()]
        head_raw = self.dump(self.head_doc).encode()
        head_policy = dp.parse_policy(head_raw)
        ev = evidence("a" * 40, [carrier()])

        def judge(**change):
            one = SimpleNamespace(**dict({"path": acm.POLICY_PATH, "status": "M", "mode": "100644",
                                          "base_mode": "100644"}, **change))
            return acm.refusal(policy, ev, POLICY_REPO, "a" * 40, changed=[one], trusted_raw=raw, base_raw=raw,
                               head_policy=head_policy, head_raw=head_raw, now=NOW)
        self.assertIsNone(judge())
        for change in ({"status": "A"}, {"status": "D"}, {"status": "T"}, {"mode": "100755"},
                       {"base_mode": "120000"}, {"mode": "120000"}, {"path": "aeos/other.json"}):
            with self.subTest(change=change):
                self.assertEqual(judge(**change), acm.NOT_ONLY_POLICY_FILE)

    def test_deleting_the_policy_file_or_a_control_plane_path_is_never_in_class(self):
        self.repo.write("aeos/merge_ready_gate.py", "X = 1\n")
        self.repo.base = self.repo.commit("seed")
        self.repo.remove("aeos/merge_ready_gate.py")
        self.set_head_entries([entry()])
        head = self.commit_head()
        self.assertRefused(self.judge(head, evidence(head, [carrier()])), acm.NOT_ONLY_POLICY_FILE)
        self.setUp()
        self.repo.remove("aeos/standing-governor-policy.json")
        head = self.repo.commit("delete the policy")
        report = self.judge(head, evidence(head, [carrier()]))
        self.assertEqual(self.reason(report), acm.NOT_ONLY_POLICY_FILE)
        self.assertFalse(report.passed)

    def test_a_symlink_or_mode_change_is_never_in_class(self):
        self.set_head_entries([entry()])
        self.commit_head()
        os.chmod(os.path.join(self.repo.root, "aeos/standing-governor-policy.json"), 0o755)
        head = self.repo.commit("mode change")
        self.assertRefused(self.judge(head, evidence(head, [carrier()])), acm.NOT_ONLY_POLICY_FILE)

    def test_an_unparseable_or_invalid_head_policy_falls_through(self):
        head = self.commit_head("{ not json")
        self.assertRefused(self.judge(head, evidence(head, [carrier()])), acm.HEAD_POLICY_INVALID)
        self.setUp()
        self.assertRefused(self.run_refresh([dict(entry(), extra=1)], [carrier()]), acm.HEAD_POLICY_INVALID)

    def test_a_change_with_no_entry_difference_is_not_a_refresh(self):
        self.head_doc["machine_route"]["accepted_changes"] = []
        head = self.commit_head(self.dump(self.head_doc).replace("\n", "\n\n", 1))
        self.assertRefused(self.judge(head, evidence(head)), acm.NO_CHANGE)

    def test_a_pull_request_not_built_on_the_trusted_policy_falls_through(self):
        """main moved after the branch was cut: the trusted policy is not the pull request's base."""
        moved = copy.deepcopy(self.trusted)
        moved["machine_route"]["accepted_changes"] = [entry(OTHER_DIGEST, (SECOND,), pr=102)]
        self.trusted = moved
        self.write_trusted()
        self.assertRefused(self.run_refresh([entry()], [carrier()]), acm.BASE_NOT_CURRENT)


class IdentityTests(GateCase):
    def test_a_human_authored_or_triggered_head_is_never_admitted_by_the_class(self):
        for kw, reason in (
            ({"actor": OPERATOR}, oa.OPERATOR_APPROVAL_TRIGGER_NOT_MACHINE),
            ({"head_commit": OPERATOR}, oa.OPERATOR_APPROVAL_HEAD_COMMIT_NOT_MACHINE),
            ({"author": "other[bot]"}, oa.OPERATOR_APPROVAL_AUTHOR_NOT_MACHINE),
            ({"author": OPERATOR, "author_type": "User"}, oa.OPERATOR_APPROVAL_AUTHOR_NOT_MACHINE),
            ({"event": "merge_group"}, oa.OPERATOR_APPROVAL_EVENT_UNPROVABLE),
        ):
            with self.subTest(**kw):
                self.setUp()
                report = self.run_refresh([entry()], [carrier()], **kw)
                if kw.get("author") == OPERATOR:
                    # the operator authoring and running a policy change is judged by the predecessor rule, unchanged
                    continue
                self.assertRefused(report, reason)

    def test_the_operator_authoring_and_running_it_is_unchanged(self):
        self.set_head_entries([entry()])
        head = self.commit_head()
        ev = evidence(head, [], author=OPERATOR, author_type="User", actor=OPERATOR, head_commit=OPERATOR)
        report = self.judge(head, ev)
        self.assertNotIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, {f.code for f in report.findings})

    def test_a_pull_request_that_moved_since_its_event_is_never_judged_as_it_was(self):
        for context in (oa.CONTEXT_HEAD_MOVED, oa.CONTEXT_BODY_CHANGED, oa.CONTEXT_UNREAD, "LATER"):
            with self.subTest(context=context):
                self.setUp()
                self.assertRefused(self.run_refresh([entry()], [carrier()], context=context), acm.STALE_CONTEXT)

    def test_evidence_without_the_block_is_the_predecessor_workflow_definition(self):
        self.set_head_entries([entry()])
        head = self.commit_head()
        ev = evidence(head, [carrier()])
        ev.pop("accepted_change_maintenance")
        self.assertRefused(self.judge(head, ev), acm.STALE_CONTEXT)

    def test_the_class_exists_only_when_bound_and_enabled(self):
        self.trusted["machine_route"]["accepted_change_maintenance"]["activation"] = "disabled"
        self.write_trusted()
        self.assertRefused(self.run_refresh([entry()], [carrier()]), acm.DISABLED)
        self.setUp()
        self.trusted["machine_route"].pop("accepted_change_maintenance")
        self.write_trusted()
        self.assertRefused(self.run_refresh([entry()], [carrier()]), acm.UNBOUND)


class ApprovalRouteUnchangedTests(GateCase):
    def test_an_approved_head_that_the_class_refuses_still_passes_on_the_approval(self):
        self.set_head_entries([entry()])
        head = self.commit_head()
        ev = evidence(head, [carrier(digest=OTHER_DIGEST)])      # the class refuses: wrong digest
        ev["pull_request"]["approval"] = {"context": oa.CONTEXT_CURRENT, "reviews": [
            {"id": 1, "login": OPERATOR, "type": "User", "state": "APPROVED", "commit_id": head,
             "submitted_at": "2026-11-08T11:00:00Z"}]}
        report = self.judge(head, ev)
        self.assertTrue(report.passed, [(f.code, f.detail) for f in report.findings])
        self.assertTrue(report.approval_dependent)

    def test_an_approved_head_is_admitted_by_the_approval_not_by_the_class(self):
        """The approval route is decided first; a pass that rests on it is rechecked before it publishes."""
        self.set_head_entries([entry()])
        head = self.commit_head()
        ev = evidence(head, [carrier()])         # the class would admit this too
        ev["pull_request"]["approval"] = {"context": oa.CONTEXT_CURRENT, "reviews": [
            {"id": 1, "login": OPERATOR, "type": "User", "state": "APPROVED", "commit_id": head,
             "submitted_at": "2026-11-08T11:00:00Z"}]}
        report = self.judge(head, ev)
        self.assertTrue(report.passed)
        self.assertTrue(report.approval_dependent)
        self.assertFalse(any("accepted-change maintenance" in note for note in report.notes))

    def test_without_the_class_or_an_approval_a_policy_refresh_is_refused_as_before(self):
        self.set_head_entries([entry()])
        head = self.commit_head()
        report = self.judge(head, evidence(head, [carrier(digest=OTHER_DIGEST)]))
        self.assertIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, {f.code for f in report.findings})
        self.assertIn(oa.OPERATOR_APPROVAL_ABSENT, report.findings[0].detail)


class RobustnessTests(GateCase):
    def direct(self, head, patch=None):
        """``merge_ready_gate.maintenance_refusal`` for a prepared head, as the gate calls it."""
        changes = gate.changed_records(self.repo.root, self.repo.base, head, "pull_request")
        policy = dp.load_policy(self.policy_dir)
        with (patch or mock.patch.object(gate, "NOTHING_PATCHED", True, create=True)):
            return gate.maintenance_refusal(self.repo.root, changes, policy, self.policy_dir,
                                            evidence(head, [carrier()]), POLICY_REPO, head, NOW)

    def test_an_unreadable_change_is_never_admitted(self):
        self.set_head_entries([entry()])
        head = self.commit_head()
        self.assertIsNone(self.direct(head))   # the same call admits when nothing is broken
        for broken in ("blob_sizes", "read_blobs"):
            with self.subTest(broken=broken):
                patch = mock.patch.object(gate, broken, side_effect=OSError("disk"))
                self.assertEqual(self.direct(head, patch), acm.HEAD_POLICY_INVALID)

    def test_an_oversized_policy_blob_is_never_admitted(self):
        self.set_head_entries([entry()])
        head = self.commit_head()
        reads = mock.patch.object(gate, "read_blobs", wraps=gate.read_blobs)
        with reads as spy:
            self.assertEqual(self.direct(head, mock.patch.object(dp, "MAX_POLICY_BYTES", 10)),
                             acm.HEAD_POLICY_INVALID)
        self.assertFalse(spy.called, "an oversized blob is refused before it is read")

    def test_a_credential_named_path_inside_the_allowlist_is_out_of_class(self):
        for path in ("scripts/agent_relay/deploy.pem", "scripts/agent_relay/.env", "scripts/agent_relay/id_ed25519",
                     "scripts/agent_relay/secrets/token.py", "scripts/agent_relay/.gitattributes"):
            with self.subTest(path=path):
                self.setUp()
                self.assertRefused(self.run_refresh([entry(paths=(path,))], [carrier(paths=(path,))]),
                                   acm.PATH_OUT_OF_CLASS)

    def test_the_path_checks_hold_below_the_loader_too(self):
        """Defence in depth: the judge does not rest on the loader having refused an out-of-allowlist path."""
        raw = self.dump(self.trusted).encode()
        policy = dp.parse_policy(raw)
        ev = evidence("a" * 40)
        for path in ("scripts/other_tool.py", "aeos/merge_ready_gate.py", ".github/workflows/x.yml"):
            with self.subTest(path=path):
                head_doc = copy.deepcopy(self.trusted)
                head_doc["machine_route"]["accepted_changes"] = [entry(paths=(path,))]
                ev["accepted_change_maintenance"]["carriers"] = [carrier(paths=(path,))]
                change = SimpleNamespace(path=acm.POLICY_PATH, status="M", mode="100644", base_mode="100644")
                self.assertEqual(
                    acm.refusal(policy, ev, POLICY_REPO, "a" * 40, changed=[change], trusted_raw=raw, base_raw=raw,
                                head_policy=object(), head_raw=self.dump(head_doc).encode(), now=NOW),
                    acm.PATH_OUT_OF_CLASS)


class BindingAndEntryShapeTests(unittest.TestCase):
    def binding(self, **kw):
        return dict({"schema": acm.SCHEMA, "activation": "enabled", "max_entries": 12,
                     "max_lifetime_seconds": 7 * DAY}, **kw)

    def test_the_binding_is_exactly_schema_activation_and_two_bounds(self):
        acm.validate_binding(self.binding())
        acm.validate_binding(self.binding(activation="disabled", max_entries=1, max_lifetime_seconds=1))
        for bad in (None, {}, {"schema": acm.SCHEMA, "activation": "enabled"}, self.binding(extra=1),
                    self.binding(schema="x"), self.binding(activation="on"), self.binding(max_entries=0),
                    self.binding(max_entries=17), self.binding(max_entries=True), self.binding(max_entries="3"),
                    self.binding(max_lifetime_seconds=0), self.binding(max_lifetime_seconds=7 * DAY + 1),
                    self.binding(max_lifetime_seconds=1.5)):
            with self.subTest(bad=str(bad)[:60]):
                with self.assertRaises(ValueError):
                    acm.validate_binding(bad)

    def test_only_enabled_switches_collection_on(self):
        self.assertTrue(acm.enabled(self.binding()))
        for binding in (None, self.binding(activation="disabled"), {}, "enabled"):
            self.assertFalse(acm.enabled(binding))

    def test_the_shipped_policy_binds_the_class_with_bounds_inside_the_hard_limits(self):
        policy = dp.parse_policy(SHIPPED.read_bytes())
        self.assertEqual(policy.accepted_change_maintenance["activation"], "enabled")
        self.assertLessEqual(policy.accepted_change_maintenance["max_entries"], ac.MAX_ENTRIES)
        self.assertLessEqual(policy.accepted_change_maintenance["max_lifetime_seconds"], ac.MAX_LIFETIME_SECONDS)

    def test_a_malformed_binding_is_a_gate_config_defect(self):
        document = json.loads(SHIPPED.read_text())
        document["machine_route"]["accepted_change_maintenance"]["max_entries"] = 99
        with self.assertRaises(dp.PolicyError) as caught:
            dp.parse_policy(json.dumps(document).encode())
        self.assertEqual(caught.exception.code, dp.GATE_CONFIG_INVALID)

    def test_an_entrys_carrier_is_optional_and_exactly_a_pull_request_and_a_head(self):
        def check(record):
            ac.validate([record], target_repository=TOOLKIT.lower(), in_allowlist=lambda p: p.startswith("scripts/"))
        check(entry())
        check(entry(carrier=False))
        for bad in (None, {}, {"pull_request": 1}, {"pull_request": 0, "head_sha": CARRIER_HEAD},
                    {"pull_request": True, "head_sha": CARRIER_HEAD}, {"pull_request": 1, "head_sha": "abc"},
                    {"pull_request": 1, "head_sha": CARRIER_HEAD.upper()},
                    {"pull_request": 1, "head_sha": CARRIER_HEAD, "x": 1}):
            with self.subTest(carrier=bad):
                with self.assertRaises(ValueError):
                    check(dict(entry(carrier=False), carrier=bad))

    def test_the_acceptance_route_ignores_the_carrier_pin(self):
        """The digest alone selects an entry: pinned or not, the existing route reads the same fields."""
        pinned, bare = entry(), entry(carrier=False)
        self.assertIs(ac.entry_for([pinned], TOOLKIT, DIGEST), pinned)
        self.assertIs(ac.entry_for([bare], TOOLKIT, DIGEST), bare)


# --------------------------------------------------------------------------
# The collector: real git objects, a real fetch, the real derivation functions
# --------------------------------------------------------------------------
def run_git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        # The shipped policy's declared roots are agent-toolkit's; this carrier is a small repository of its own, so
        # the same policy shape is built around it: one root, one allowlisted directory, the closure it reaches.
        document = json.loads(SHIPPED.read_text())
        document["derivation_policy"].update(
            roots=[ROOT], allowlist_prefixes=["scripts/agent_relay/"], allowlist_files=[],
            members=sorted([ROOT, MEMBER, SECOND]))
        document["machine_route"]["accepted_changes"] = []
        self.policy = dp.parse_policy(json.dumps(document).encode())
        self.remote = self.tmp / "remote"
        self.remote.mkdir()
        run_git(self.remote, "init", "-q", "-b", "main")
        run_git(self.remote, "config", "uploadpack.allowFilter", "true")
        run_git(self.remote, "config", "uploadpack.allowAnySHA1InWant", "true")
        self.write(ROOT, "import agent_relay.dispatcher\nimport agent_relay.ledger\n")
        self.write("scripts/agent_relay/dispatcher.py", "VALUE = 1\n")
        self.write("scripts/agent_relay/ledger.py", "VALUE = 1\n")
        self.write("scripts/agent_relay/__init__.py", "")
        self.write("scripts/unrelated.py", "OLD = 1\n")
        self.write("docs/old.md", "old\n")
        run_git(self.remote, "add", "-A")
        run_git(self.remote, "commit", "-qm", "base")
        self.base = run_git(self.remote, "rev-parse", "HEAD")
        self.write("scripts/agent_relay/dispatcher.py", "VALUE = 2\n")
        os.remove(self.remote / "scripts/unrelated.py")
        run_git(self.remote, "add", "-A")
        run_git(self.remote, "commit", "-qm", "carrier head")
        self.head = run_git(self.remote, "rev-parse", "HEAD")
        self.url = f"file://{self.remote}"

    def write(self, rel, text):
        path = self.remote / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def expected_digest(self):
        """What the consumer's judge computes for the carrier: the digest, from the real derivation functions."""
        protected, entering, _drift = dp.candidate_protected_sets(str(self.remote), self.base, self.head, self.policy)
        entries = dp.candidate_entries(str(self.remote), self.base, self.head, protected, entering)
        return dp.protected_diff_digest(entries), sorted(e.path for e in entries)

    def test_the_recomputed_digest_is_the_consumer_judges_digest(self):
        digest, paths = self.expected_digest()
        self.assertEqual(paths, ["scripts/agent_relay/dispatcher.py"])
        work = tempfile.mkdtemp(dir=self.tmp)
        acm.fetch_commits(self.url, (self.base, self.head), "", work)
        facts = acm.recompute(self.policy, work, self.base, self.head)
        self.assertEqual(facts["digest"], digest)
        self.assertEqual(facts["paths"], paths)
        self.assertEqual(facts["deleted_paths"], ["scripts/unrelated.py"])

    def test_only_allowlisted_modules_are_requested_up_front(self):
        work = tempfile.mkdtemp(dir=self.tmp)
        asked = []
        real = subprocess.run

        def spy(argv, *args, **kwargs):
            asked.append(list(argv))
            return real(argv, *args, **kwargs)
        with mock.patch("subprocess.run", spy):
            acm.fetch_commits(self.url, (self.base, self.head), "", work, wanted=self.policy.in_allowlist)
        blob = run_git(self.remote, "rev-parse", f"{self.base}:scripts/unrelated.py")
        wanted = run_git(self.remote, "rev-parse", f"{self.base}:scripts/agent_relay/ledger.py")
        requested = [part for argv in asked for part in argv]
        self.assertIn(wanted, requested)
        self.assertNotIn(blob, requested)

    def test_a_different_head_is_a_different_digest(self):
        digest, _ = self.expected_digest()
        self.write("scripts/agent_relay/dispatcher.py", "VALUE = 3\n")
        run_git(self.remote, "commit", "-qam", "swap")
        swapped = run_git(self.remote, "rev-parse", "HEAD")
        work = tempfile.mkdtemp(dir=self.tmp)
        acm.fetch_commits(self.url, (self.base, swapped), "", work)
        self.assertNotEqual(acm.recompute(self.policy, work, self.base, swapped)["digest"], digest)

    def api_for(self, state="open", merged=False, author=MACHINE, kind="Bot", head=None, current_head="h" * 40):
        calls = []

        def api(path, *args):
            calls.append(path)
            if path.endswith("/pulls/7"):
                return {"head": {"sha": current_head}, "body": "body"}
            if path.endswith("/pulls/101"):
                return {"state": state, "merged": merged, "user": {"login": author, "type": kind},
                        "head": {"sha": head or self.head}, "base": {"sha": self.base}}
            if "/compare/" in path:
                return {"merge_base_commit": {"sha": self.base}}
            return None
        return api, calls

    def collect(self, head_entries, *, api=None, carrier_api=None, **kw):
        api = api or self.api_for()[0]
        head_raw = json.dumps({"machine_route": {"accepted_changes": head_entries}}).encode()
        return acm.collect(self.policy, POLICY_REPO, head_raw, api, carrier_api or api, 7, "h" * 40, "body",
                           token="", remote_url=self.url, **kw)

    def test_collection_reads_the_carrier_and_recomputes_its_digest(self):
        digest, paths = self.expected_digest()
        block = self.collect([entry(digest, paths, head=self.head)])
        self.assertEqual(block["context"], acm.CONTEXT_CURRENT)
        self.assertNotIn("unavailable", block)
        (row,) = block["carriers"]
        self.assertEqual((row["digest"], row["paths"], row["state"], row["merged"], row["head_sha"]),
                         (digest, paths, "open", False, self.head))

    def test_collected_evidence_admits_the_exact_refresh_through_the_gate(self):
        digest, paths = self.expected_digest()
        block = self.collect([entry(digest, paths, head=self.head)])
        case = GateCase()
        case.setUp()
        self.addCleanup(case._tmp.cleanup)
        case.set_head_entries([entry(digest, paths, head=self.head)])
        head = case.commit_head()
        ev = evidence(head)
        ev["accepted_change_maintenance"] = block
        self.assertAdmitted_or_fail(case, case.judge(head, ev))
        # the same evidence for a swapped digest in the entry is refused
        case.setUp()
        case.set_head_entries([entry(OTHER_DIGEST, paths, head=self.head)])
        head = case.commit_head()
        ev = evidence(head)
        ev["accepted_change_maintenance"] = block
        self.assertEqual(case.reason(case.judge(head, ev)), acm.CARRIER_DIGEST_MISMATCH)

    def assertAdmitted_or_fail(self, case, report):
        case.assertAdmitted(report)

    def test_no_carrier_credential_records_the_carrier_unread_and_the_class_refuses(self):
        block = acm.collect(self.policy, POLICY_REPO,
                            json.dumps({"machine_route": {"accepted_changes": [entry()]}}).encode(),
                            self.api_for()[0], None, 7, "h" * 40, "body", token="", remote_url=self.url)
        self.assertEqual(block["carriers"], [])
        self.assertIn("credential", block["unavailable"])
        self.assertEqual(block["context"], acm.CONTEXT_CURRENT)

    def test_a_carrier_that_cannot_be_recomputed_has_no_digest(self):
        api, _calls = self.api_for()
        def broken_fetch(url, shas, token, dest, wanted=None):
            raise RuntimeError("network")
        (row,) = self.collect([entry(head=self.head)], api=api, fetch=broken_fetch)["carriers"]
        self.assertIsNone(row["digest"])
        self.assertEqual(row["paths"], [])

    def test_a_removed_entrys_carrier_state_is_read_without_a_fetch(self):
        base_entry = entry(head=self.head)
        self.policy.accepted_changes = [base_entry]
        api, calls = self.api_for(state="closed", merged=True)
        def no_fetch(*args):
            raise AssertionError("a spent-state read needs no bytes")
        block = self.collect([], api=api, fetch=no_fetch)
        (row,) = block["carriers"]
        self.assertEqual((row["state"], row["merged"], row["digest"]), ("closed", True, None))
        self.assertFalse([c for c in calls if "/compare/" in c])

    def test_a_pull_request_that_moves_during_collection_is_never_current(self):
        for moved in ("other", ):
            with self.subTest(moved=moved):
                state = {"n": 0}
                def api(path, *args, state=state):
                    if path.endswith("/pulls/7"):
                        state["n"] += 1
                        return {"head": {"sha": "h" * 40 if state["n"] == 1 else "i" * 40}, "body": "body"}
                    return self.api_for()[0](path, *args)
                block = self.collect([entry(head=self.head)], api=api)
                self.assertEqual(block["context"], oa.CONTEXT_HEAD_MOVED)
        api = self.api_for(current_head="z" * 40)[0]
        block = self.collect([entry(head=self.head)], api=api)
        self.assertEqual((block["context"], block["carriers"]), (oa.CONTEXT_HEAD_MOVED, []))

    def test_only_the_policy_repositorys_own_carriers_are_ever_read(self):
        api, calls = self.api_for()
        foreign = entry(repository="First-AI-Movers/other")
        block = self.collect([foreign, entry(head=self.head, carrier=False)], api=api)
        self.assertEqual(block["carriers"], [])
        self.assertFalse([c for c in calls if "/pulls/101" in c])

    def test_an_unreadable_head_policy_records_a_current_context_and_no_carriers(self):
        api = self.api_for()[0]
        block = acm.collect(self.policy, POLICY_REPO, b"{ nope", api, api, 7, "h" * 40, "body")
        self.assertEqual((block["context"], block["carriers"]), (acm.CONTEXT_CURRENT, []))

    def test_the_credential_never_reaches_a_command_line(self):
        seen = []
        real = subprocess.run

        def spy(argv, *args, **kwargs):
            seen.append(list(argv))
            return real(argv, *args, **kwargs)
        work = tempfile.mkdtemp(dir=self.tmp)
        token = "SECRET-TOKEN-VALUE"
        header = "AUTHORIZATION: basic " + base64.b64encode(f"x-access-token:{token}".encode()).decode()
        with mock.patch("subprocess.run", spy):
            acm.fetch_commits(self.url, (self.base, self.head), token, work)   # a file:// remote ignores the header
        self.assertTrue(seen)
        for argv in seen:
            for part in argv:
                self.assertNotIn(token, part)
                self.assertNotIn(header, part)
                self.assertNotIn(header.split(" ")[-1], part)
        # it is in the throwaway repository's own config instead, which the caller removes with the repository
        self.assertEqual(run_git(work, "config", "--local", "--get", "http.extraheader"), header)

    def test_a_carrier_whose_members_have_drifted_is_unread_not_guessed(self):
        document = json.loads(SHIPPED.read_text())
        document["derivation_policy"].update(
            roots=[ROOT], allowlist_prefixes=["scripts/agent_relay/"], allowlist_files=[],
            members=sorted([ROOT, MEMBER, SECOND, "scripts/agent_relay/ghost.py"]))
        document["machine_route"]["accepted_changes"] = []
        drifted = dp.parse_policy(json.dumps(document).encode())
        work = tempfile.mkdtemp(dir=self.tmp)
        acm.fetch_commits(self.url, (self.base, self.head), "", work)
        with self.assertRaises(dp.PolicyError) as caught:
            acm.recompute(drifted, work, self.base, self.head)
        self.assertEqual(caught.exception.code, dp.DERIVATION_POLICY_DRIFT)
        api = self.api_for()[0]
        head_raw = json.dumps({"machine_route": {"accepted_changes": [entry(head=self.head)]}}).encode()
        block = acm.collect(drifted, POLICY_REPO, head_raw, api, api, 7, "h" * 40, "body", token="",
                            remote_url=self.url)
        self.assertIsNone(block["carriers"][0]["digest"])

    def test_a_renamed_source_counts_as_a_deletion(self):
        self.write("docs/new.md", (self.remote / "docs/old.md").read_text())
        os.remove(self.remote / "docs/old.md")
        run_git(self.remote, "add", "-A")
        run_git(self.remote, "commit", "-qm", "rename")
        renamed = run_git(self.remote, "rev-parse", "HEAD")
        work = tempfile.mkdtemp(dir=self.tmp)
        acm.fetch_commits(self.url, (self.head, renamed), "", work)
        self.assertEqual(acm.recompute(self.policy, work, self.head, renamed)["deleted_paths"], ["docs/old.md"])


# --------------------------------------------------------------------------
# The deployed workflow
# --------------------------------------------------------------------------
class WorkflowTests(unittest.TestCase):
    def evidence_script(self) -> str:
        workflow = (WORKFLOWS / "aeos-merge-ready.yml").read_text()
        script = workflow.split("python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
        return textwrap.dedent(script)

    def run_script(self, policy, *, token="", shown=b""):
        calls, envs = [], []

        def run(argv, **kwargs):
            calls.append(list(argv))
            envs.append((kwargs.get("env") or {}).get("GH_TOKEN"))
            if argv[0] == "git":
                return SimpleNamespace(returncode=0 if shown else 1, stdout=shown)
            path = argv[2]
            if "/commits/" in path:
                result = {"author": {"login": MACHINE}}
            elif path == f"repos/{POLICY_REPO}/pulls/7":
                result = {"head": {"sha": "a" * 40}, "body": ""}
            else:
                result = None
            return SimpleNamespace(returncode=0 if result is not None else 1,
                                   stdout=json.dumps(result) if result is not None else "")
        with tempfile.TemporaryDirectory() as temp:
            event, output = Path(temp) / "event.json", Path(temp) / "evidence.json"
            event.write_text(json.dumps({"pull_request": {"number": 7, "user": {"login": MACHINE, "type": "Bot"},
                                                          "head": {"sha": "a" * 40}, "body": ""}}))
            environment = dict(AEOS_EVENT_PATH=str(event), AEOS_ACTOR_EVIDENCE=str(output),
                               AEOS_EVENT_NAME="pull_request", AEOS_REPOSITORY=POLICY_REPO, AEOS_ACTOR=MACHINE,
                               AEOS_CARRIER_READ_TOKEN=token)
            with mock.patch.dict(os.environ, environment), mock.patch("subprocess.run", run), \
                    mock.patch.object(dp, "load_policy", return_value=policy), \
                    mock.patch.object(sys, "path", sys.path[:]):
                exec(compile(self.evidence_script(), "<trusted evidence workflow>", "exec"), {})
            return json.loads(output.read_text()), calls, envs

    @staticmethod
    def policy(activation="enabled"):
        document = json.loads(SHIPPED.read_text())
        document["machine_route"]["accepted_change_maintenance"]["activation"] = activation
        return dp.parse_policy(json.dumps(document).encode())

    def test_the_block_is_collected_only_when_the_class_is_switched_on(self):
        doc, calls, _envs = self.run_script(self.policy())
        self.assertEqual(doc["accepted_change_maintenance"]["context"], acm.CONTEXT_CURRENT)
        self.assertEqual(doc["accepted_change_maintenance"]["carriers"], [])
        self.assertFalse(doc.get("unavailable"))
        for trusted in (SimpleNamespace(), self.policy("disabled")):
            with self.subTest(trusted=type(trusted).__name__):
                doc, calls, _envs = self.run_script(trusted)
                self.assertNotIn("accepted_change_maintenance", doc)
                self.assertFalse([c for c in calls if c[0] == "git"])

    def test_without_the_secret_the_class_reads_no_carrier_and_the_approval_route_stands(self):
        head_policy = json.dumps({"machine_route": {"accepted_changes": [entry()]}}).encode()
        doc, calls, envs = self.run_script(self.policy(), token="", shown=head_policy)
        block = doc["accepted_change_maintenance"]
        self.assertIn("credential", block.get("unavailable", ""))
        self.assertEqual(block["carriers"], [])
        self.assertFalse([c for c in calls if len(c) > 2 and "/pulls/101" in c[2]])

    def test_the_head_policy_is_read_from_the_pinned_head_as_data(self):
        _doc, calls, _envs = self.run_script(self.policy(), shown=b"{}")
        (shown,) = [c for c in calls if c[0] == "git"]
        self.assertEqual(shown, ["git", "-C", "candidate", "show", f"{'a' * 40}:aeos/standing-governor-policy.json"])

    def test_the_credential_reaches_only_the_evidence_step_and_never_a_run_body(self):
        import yaml
        document = yaml.safe_load((WORKFLOWS / "aeos-merge-ready.yml").read_text())
        steps = document["jobs"]["aeos-merge-ready"]["steps"]
        holders = [s["name"] for s in steps if "secrets.AEOS_CARRIER_READ_TOKEN" in json.dumps(s.get("env", {}))]
        self.assertEqual(holders, ["Collect authenticated evidence (trusted; machine route)"])
        for step in steps:
            self.assertNotIn("secrets.", step.get("run", ""))
        gate_step = next(s for s in steps if s["name"] == "Gate")
        self.assertNotIn("AEOS_CARRIER_READ_TOKEN", gate_step.get("env", {}))
        self.assertNotIn("secrets", json.dumps(document["jobs"]["aeos-merge-ready"].get("permissions", {})))


if __name__ == "__main__":
    unittest.main()
