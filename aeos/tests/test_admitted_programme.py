#!/usr/bin/env python3
"""A programme the operator admitted in trusted policy (agent-toolkit #3052): its operational carriers are
system-owned on the entry's exact envelope.

Every conjunct of ``admitted_programme.refusal`` has a violation with its own reason and a near-miss that stays
admitted; the policy refuses to load an envelope that could reach the trust machinery; and the route sits in the
machine route exactly where it should: after the machine-identity conjuncts, never for a grant-marked pull request,
and never for a programme the policy does not list.

    python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import admitted_programme as ap  # noqa: E402
import derivation_policy as dp  # noqa: E402
import scoped_grant  # noqa: E402

MACHINE = "aeos-autonomous-main[bot]"
OPERATOR = "hpcosta"
REPO = "First-AI-Movers/agent-toolkit"
MC = f"{REPO}#1530"
READER = "scripts/flight_deck/node_resources.py"
POLICY_FILE = Path(__file__).resolve().parents[1] / dp.POLICY_FILE


def entry(**overrides) -> dict:
    base = {"schema": ap.SCHEMA, "programme": MC, "path_envelope": [READER], "activation": "enabled",
            "decision": "test decision"}
    base.update(overrides)
    return base


def document(entries) -> bytes:
    doc = json.loads(POLICY_FILE.read_text())
    doc["machine_route"]["admitted_programmes"] = entries
    return json.dumps(doc).encode()


def policy(entries=None):
    return dp.parse_policy(document([entry()] if entries is None else entries))


def evidence(*, ref=MC, state="open", author=OPERATOR, author_type="User", editors=(), body=None, actor=MACHINE,
             pr_author=MACHINE, head_commit=MACHINE, unavailable=False, context="CURRENT") -> dict:
    programme = {"ref": ref, "state": state, "author_login": author, "author_type": author_type,
                 "body": "Mission Control", "updated_at": "2026-10-04T00:00:00Z",
                 "editors": None if editors is None else list(editors)}
    if unavailable:
        programme = {"ref": ref, "unavailable": "programme issue could not be read"}
    return {"schema": dp.EVIDENCE_SCHEMA, "event": "pull_request", "repository": REPO, "actor": actor,
            "pull_request": {"number": 9, "author_login": pr_author, "author_type": "Bot" if pr_author == MACHINE else "User",
                             "head_sha": "a" * 40, "head_commit_author_login": head_commit,
                             "body": body if body is not None else f"Roster.\n\n<!-- aeos-programme: {ref} -->\n",
                             "approval": None if context is None else {"context": context, "reviews": []}},
            "programme": programme}


def change(path=READER, rename_from=None, pre_mode="100644", post_mode="100644", pre="0" * 64, post="1" * 64):
    return dp.Entry(path, "M" if rename_from is None else "R", pre, post, rename_from, pre_mode, post_mode)


def route(ev, pol=None, entries=None):
    return dp.machine_route(pol or policy(), ev, None, REPO, entries or [change()], 0.0, head_sha="a" * 40)


class ValidationTests(unittest.TestCase):
    def test_the_shipped_policy_admits_mission_control_on_the_node_reader_only(self):
        shipped = dp.parse_policy(POLICY_FILE.read_bytes())
        [only] = shipped.admitted_programmes
        self.assertEqual((only["programme"], only["path_envelope"], only["activation"]), (MC, [READER], "enabled"))

    def test_an_envelope_can_never_reach_the_trust_machinery(self):
        shipped = json.loads(POLICY_FILE.read_text())
        root = shipped["derivation_policy"]["roots"][0]
        excluded = shipped["machine_route"]["scoped_grant"]["excluded_paths"][0]
        for path in (root, excluded, "aeos/derivation_policy.py", ".github/workflows/x.yml",
                     "AEOS/derivation_policy.py", "docs/outside-the-allowlist.md"):
            with self.subTest(path=path), self.assertRaises(dp.PolicyError) as caught:
                policy([entry(path_envelope=[path])])
            self.assertEqual(caught.exception.code, dp.GATE_CONFIG_INVALID)

    def test_a_malformed_entry_refuses_to_load(self):
        bad = [
            {"programme": MC}, entry(schema="v0"), entry(programme="1530"), entry(programme=f"{MC} "),
            entry(activation="on"), entry(decision=""), entry(decision="   "), entry(decision="x" * 501),
            entry(path_envelope=[]), entry(path_envelope=[READER] * 2), entry(path_envelope=["scripts/flight_deck/"]),
            entry(path_envelope=["scripts/flight_deck/../agent_relay/x.py"]), entry(path_envelope=["/" + READER]),
            entry(path_envelope=[f"scripts/flight_deck/f{i}.py" for i in range(17)]),
            dict(entry(), extra=1), "not-an-entry",
        ]
        for value in bad:
            with self.subTest(value=str(value)[:60]), self.assertRaises(dp.PolicyError):
                policy([value])
        with self.assertRaises(dp.PolicyError):
            policy([entry(), entry()])            # one programme, one entry
        with self.assertRaises(dp.PolicyError):
            policy([entry()] * 33)
        self.assertEqual(policy([]).admitted_programmes, [])
        doc = json.loads(document([]))
        doc["machine_route"].pop("admitted_programmes")
        self.assertEqual(dp.parse_policy(json.dumps(doc).encode()).admitted_programmes, [])


class RouteTests(unittest.TestCase):
    def test_a_machine_carrier_of_the_admitted_programme_on_its_envelope_is_admitted(self):
        self.assertIsNone(route(evidence()))
        self.assertIsNone(route(evidence(editors=[OPERATOR, OPERATOR])))      # operator edits are fine

    def test_each_conjunct_refuses_with_its_own_reason(self):
        cases = {
            ap.ADMITTED_PROGRAMME_DISABLED: (evidence(), policy([entry(activation="disabled")]), None),
            ap.ADMITTED_PROGRAMME_PATH_OUTSIDE_ENVELOPE: (evidence(), None, [change("scripts/flight_deck/models.py")]),
            ap.ADMITTED_PROGRAMME_NOT_OPEN: (evidence(state="closed"), None, None),
            ap.ADMITTED_PROGRAMME_NOT_OPERATOR: (evidence(author="someone"), None, None),
            ap.ADMITTED_PROGRAMME_EDITED_BY_NON_OPERATOR: (evidence(editors=[OPERATOR, "someone"]), None, None),
            ap.ADMITTED_PROGRAMME_UNAVAILABLE: (evidence(editors=None), None, None),
        }
        for reason, (ev, pol, entries) in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(route(ev, pol, entries), reason)
        self.assertEqual(route(evidence(unavailable=True)), ap.ADMITTED_PROGRAMME_UNAVAILABLE)
        self.assertEqual(route(evidence(author_type="Bot")), ap.ADMITTED_PROGRAMME_NOT_OPERATOR)
        missing = evidence()
        missing.pop("programme")
        self.assertEqual(route(missing), ap.ADMITTED_PROGRAMME_UNAVAILABLE)

    def test_every_side_of_every_change_must_be_on_the_envelope(self):
        self.assertEqual(route(evidence(), entries=[change(READER, rename_from="scripts/flight_deck/old.py")]),
                         ap.ADMITTED_PROGRAMME_PATH_OUTSIDE_ENVELOPE)
        self.assertEqual(route(evidence(), entries=[change(), change("scripts/flight_deck/models.py")]),
                         ap.ADMITTED_PROGRAMME_PATH_OUTSIDE_ENVELOPE)
        self.assertEqual(route(evidence(), entries=[change(READER.upper())]), ap.ADMITTED_PROGRAMME_PATH_OUTSIDE_ENVELOPE)

    def test_a_programme_of_another_repository_never_admits_here(self):
        other = "Other/repo#1530"
        pol = policy([entry(programme=other)])
        self.assertEqual(route(evidence(ref=other, body=f"<!-- aeos-programme: {other} -->"), pol),
                         ap.ADMITTED_PROGRAMME_REPOSITORY_MISMATCH)

    def test_the_machine_identity_conjuncts_still_come_first(self):
        self.assertEqual(route(evidence(actor=OPERATOR)), dp.MACHINE_ROUTE_TRIGGER_NOT_MACHINE)
        self.assertEqual(route(evidence(head_commit=OPERATOR)), dp.MACHINE_ROUTE_HEAD_COMMIT_NOT_MACHINE)
        self.assertEqual(route(evidence(pr_author=OPERATOR)), dp.MACHINE_ROUTE_ACTOR_IS_OPERATOR)

    def test_a_programme_the_policy_does_not_list_takes_the_unchanged_route(self):
        other = f"{REPO}#6246"
        self.assertEqual(route(evidence(ref=other, body=f"<!-- aeos-programme: {other} -->")),
                         dp.MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID)
        self.assertEqual(route(evidence(), policy([])), dp.MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID)

    def test_a_grant_marked_pull_request_is_never_judged_here(self):
        marker = f"<!-- scoped-machine-grant: {REPO}#9@sha256:" + "c" * 64 + " -->"
        self.assertNotEqual(scoped_grant.marker_state(marker), scoped_grant.MARKER_ABSENT)
        body = f"<!-- aeos-programme: {MC} -->\n" + marker
        self.assertEqual(route(evidence(body=body)), scoped_grant.SCOPED_GRANT_PROGRAMME_MISMATCH)

    def test_an_admitted_grant_programme_never_takes_a_grant_marked_pull_request_from_the_scoped_judge(self):
        """Even if the scoped-grant programme itself were admitted, a grant-marked pull request is the scoped
        judge's alone: this route never admits it."""
        grant_programme = json.loads(POLICY_FILE.read_text())["machine_route"]["scoped_grant"]["programme"]
        pol = policy([entry(programme=grant_programme)])
        marker = f"<!-- scoped-machine-grant: {REPO}#9@sha256:" + "c" * 64 + " -->"
        body = f"<!-- aeos-programme: {grant_programme} -->\n" + marker
        self.assertIsNotNone(route(evidence(ref=grant_programme, body=body), pol))
        # the same programme without a marker IS admitted on its envelope
        plain = f"<!-- aeos-programme: {grant_programme} -->"
        self.assertIsNone(route(evidence(ref=grant_programme, body=plain), pol))

    def test_a_symlink_gitlink_or_unmoded_entry_at_a_listed_path_is_never_admitted(self):
        """Review P1: the envelope names a file, so only a regular file may stand there, on every side."""
        for kw in ({"post_mode": "120000"}, {"pre_mode": "120000"}, {"post_mode": "160000"},
                   {"pre_mode": None, "post_mode": None}, {"post_mode": "000000"}):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                self.assertEqual(route(evidence(), entries=[change(**kw)]), ap.ADMITTED_PROGRAMME_NOT_REGULAR_FILE)
        # near-misses: an executable regular file, an add and a delete with absent sides marked absent
        self.assertIsNone(route(evidence(), entries=[change(post_mode="100755")]))
        self.assertIsNone(route(evidence(), entries=[change(pre="absent", pre_mode="000000")]))
        self.assertIsNone(route(evidence(), entries=[change(post="absent", post_mode="000000")]))

    def test_a_stale_or_unproven_description_is_never_judged(self):
        """Review P1: a re-run replays its original description; only the fresh, head-matched one may admit."""
        for context in ("BODY_CHANGED", "HEAD_MOVED", "UNREAD", None):
            with self.subTest(context=context):
                self.assertEqual(route(evidence(context=context)), ap.ADMITTED_PROGRAMME_STALE_CONTEXT)

    def test_programme_identity_follows_github_not_spelling(self):
        """Review P2: one Issue, one entry, whatever the case of its repository."""
        with self.assertRaises(dp.PolicyError):
            policy([entry(), entry(programme=MC.lower())])
        lower = MC.lower()
        body = f"<!-- aeos-programme: {lower} -->"
        self.assertIsNone(route(evidence(ref=lower, body=body)))
        self.assertEqual(route(evidence(ref=lower, body=body), policy([entry(activation="disabled")])),
                         ap.ADMITTED_PROGRAMME_DISABLED)

    def test_no_entry_loads_without_the_exclusion_list(self):
        """Review P2: the exclusion floor never silently disappears."""
        doc = json.loads(document([entry()]))
        doc["machine_route"].pop("scoped_grant")
        doc["machine_route"].pop("authority_compiler")
        with self.assertRaises(dp.PolicyError):
            dp.parse_policy(json.dumps(doc).encode())
        doc["machine_route"]["admitted_programmes"] = []
        self.assertEqual(dp.parse_policy(json.dumps(doc).encode()).admitted_programmes, [])

    def test_an_admission_does_not_record_approval_dependence(self):
        admission = {}
        self.assertIsNone(dp.machine_route(policy(), evidence(), None, REPO, [change()], 0.0, head_sha="a" * 40,
                                           admission=admission))
        self.assertEqual(admission, {})


if __name__ == "__main__":
    unittest.main()
