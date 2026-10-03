#!/usr/bin/env python3
"""Tests for the scoped-machine-grant judge (agent-toolkit #3052 Class B).

Plain ``unittest``. The policy is the REAL ``standing-governor-policy.json`` beside the gate, which ships the
binding ``activation: enabled``; only the operator's directive digest is replaced, in memory, by a stand-in's.
GitHub is an in-process fake that answers exactly the reads ``scoped_grant.collect`` makes, so nothing here
reaches a network. Each case changes one fact of an otherwise admitted world and asserts the one typed reason.

The three negative controls the #3052 HOLD review (5931392715) found ACCEPTED by the lost packet are
distinct cases here: an operator-authored note that was never admitted, an activator session that never
existed, and an activation time that is not GitHub's creation of the record.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import derivation_policy as dp  # noqa: E402
import scoped_grant as sg  # noqa: E402

REPO = "First-AI-Movers/agent-toolkit"
MACHINE = "aeos-autonomous-main[bot]"
GQL_MACHINE = {"login": "aeos-autonomous-main", "__typename": "Bot"}
SERVED = REPO + "#2894"
SERVED_BODY = "Mission"
# The served Issue's CURRENT admitted generation, as agent-toolkit's dispatcher mints it
# (auto_execute_queue.generation_key over intent_digest; the projection of a plain root is the body).
DIGEST = "intent-v1:sha256:" + hashlib.sha256(SERVED_BODY.encode()).hexdigest()
GENERATION = SERVED + "@" + DIGEST
CLAIM_SHA = "d" * 40
RECORD = 6300
CREATED = "2026-10-01T10:00:00Z"
NOW = 1_790_000_000.0  # set per world from CREATED below
DIRECTIVE = "operator directive body"
PATH = "scripts/flight_deck/node_resources.py"


def stamp(minutes: int) -> str:
    import datetime as _dt
    base = _dt.datetime(2026, 10, 1, 10, 0, tzinfo=_dt.timezone.utc)
    return (base + _dt.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch(minutes: int) -> float:
    import datetime as _dt
    return (_dt.datetime(2026, 10, 1, 10, 0, tzinfo=_dt.timezone.utc) + _dt.timedelta(minutes=minutes)).timestamp()


def load_policy(**binding_changes):
    with open(os.path.join(HERE, dp.POLICY_FILE), "rb") as handle:
        document = json.loads(handle.read())
    grant = document["machine_route"]["scoped_grant"]
    grant.update(activation="enabled", directive_body_sha256=hashlib.sha256(DIRECTIVE.encode()).hexdigest())
    grant.update(binding_changes)
    return dp.parse_policy(json.dumps(document).encode())


def shipped_policy(**binding_changes):
    """The shipped policy as committed, with ``binding_changes`` applied to its grant binding. Revocation is
    the one edit ``activation="disabled"``."""
    with open(os.path.join(HERE, dp.POLICY_FILE), "rb") as handle:
        document = json.loads(handle.read())
    document["machine_route"]["scoped_grant"].update(binding_changes)
    return dp.parse_policy(json.dumps(document).encode())


def render_record(policy, **changes) -> str:
    binding = policy.scoped_grant
    block = dict(schema="standing-authority/v2", state="ACTIVE", repository=REPO, issue=RECORD,
                 not_after=stamp(6 * 24 * 60), path_envelope=[PATH])
    receipt = dict(schema=sg.RECEIPT_SCHEMA, programme=binding["programme"],
                   directive_comment_id=binding["directive_comment_id"], serves=SERVED, generation=GENERATION,
                   claim_ref=sg.claim_ref(GENERATION), claim_commit=CLAIM_SHA, scope=sg.SCOPE,
                   activated_by="node-a", activated_at=CREATED)
    for key, value in changes.items():
        target, _, field = key.partition("__")
        (block if target == "block" else receipt)[field] = value
    return ("## Scoped machine grant activation\n\n"
            f"```standing-authority\n{json.dumps(block, indent=2)}\n```\n\n"
            f"```{sg.RECEIPT_SCHEMA}\n{json.dumps(receipt, indent=2)}\n```\n")


def served_node(operator, label, **changes):
    node = {"number": 2894, "repository": {"nameWithOwner": REPO}, "body": SERVED_BODY, "state": "OPEN",
            "createdAt": stamp(-120), "lastEditedAt": stamp(-60), "author": {"login": operator, "__typename": "User"},
            "editor": {"login": operator}, "parent": None,
            "labels": {"nodes": [{"id": "LA_1", "name": label}], "pageInfo": {"hasNextPage": False}},
            "userContentEdits": {"totalCount": 1, "pageInfo": {"hasNextPage": False}, "nodes": [
                {"editedAt": stamp(-60), "deletedAt": None, "editor": {"login": operator, "__typename": "User"}}]},
            "timelineItems": {"pageInfo": {"hasPreviousPage": False}, "nodes": [
                {"actor": {"login": operator, "__typename": "User"}, "label": {"id": "LA_1", "name": label},
                 "createdAt": stamp(-50)}]}}
    node.update(changes)
    return node


HOSTILE = ({}, [], [{}], [[]], {"": {}}, None, True, False, 0, -1, 10 ** 400, 1.5, float("nan"), float("inf"),
           "", "x", "\ud800")
"""Shapes no GitHub reading should carry, each one a value the judge must refuse typed and never raise on."""
VOCABULARY = frozenset(value for name, value in vars(sg).items()
                       if isinstance(value, str) and value.startswith("MACHINE_ROUTE_"))


def addresses(node, here=()):
    """Every address in a JSON document, the root and every container included."""
    yield here
    if isinstance(node, dict):
        for key, value in node.items():
            yield from addresses(value, here + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from addresses(value, here + (index,))


def replaced(document, address, value):
    if not address:
        return value
    result = copy.deepcopy(document)
    target = result
    for step in address[:-1]:
        target = target[step]
    target[address[-1]] = value
    return result


class World:
    """GitHub as the incumbent machinery leaves it after one lawful activation."""

    def __init__(self, policy):
        self.policy = policy
        self.operator = sorted(policy.operator_principals)[0]
        self.record_body = render_record(policy)
        self.record = {"number": RECORD, "repository": {"nameWithOwner": REPO}, "state": "OPEN",
                       "body": self.record_body, "author": dict(GQL_MACHINE), "createdAt": CREATED,
                       "lastEditedAt": CREATED,
                       "userContentEdits": {"totalCount": 1, "nodes": [
                           {"editedAt": CREATED, "deletedAt": None, "editor": dict(GQL_MACHINE)}]}}
        self.served = served_node(self.operator, policy.scoped_grant["admission_label"])
        self.directive = {"databaseId": policy.scoped_grant["directive_comment_id"], "body": DIRECTIVE,
                          "createdAt": stamp(-3000), "lastEditedAt": None,
                          "author": {"login": self.operator, "__typename": "User"},
                          "issue": {"number": 3752, "repository": {"nameWithOwner": REPO}},
                          "userContentEdits": {"totalCount": 0}}
        self.comment = {"id": policy.scoped_grant["directive_comment_id"], "node_id": "IC_x",
                        "issue_url": f"https://api.github.com/repos/{REPO}/issues/3752"}
        self.claim_sha = CLAIM_SHA
        self.claim_type = "commit"
        self.commit = {"sha": CLAIM_SHA, "author": {"login": MACHINE, "type": "Bot"},
                       "committer": {"login": "web-flow", "type": "User"},
                       "commit": {"message": "aeos-claim: generation claim (#5731)\n\nnode=node-a\n"
                                             f"generation={GENERATION}\nruntime=host:1\nattempt=1\n",
                                  "committer": {"name": "GitHub", "date": stamp(-30)},
                                  "verification": {"verified": True, "reason": "valid"}}}
        self.unreadable = set()

    def api(self, path, *args):
        if path in self.unreadable:
            return None
        if path == "graphql":
            query = next(a for a in args if a.startswith("query="))
            if "IssueComment" in query:
                return None if "directive" in self.unreadable else {"data": {"node": copy.deepcopy(self.directive)}}
            number = int(next(a[2:] for a in args if a.startswith("i=")))
            if number in self.unreadable:
                return None
            node = self.record if number == self.record["number"] else self.served
            return {"data": {"repository": {"issue": copy.deepcopy(node)}}}
        if path.endswith(f"/issues/comments/{self.comment['id']}"):
            return dict(self.comment)
        claim = sg.claim_ref(GENERATION)
        if path == f"repos/{REPO}/git/ref/{claim[len('refs/'):]}":
            return {"ref": claim, "object": {"sha": self.claim_sha, "type": self.claim_type}}
        if path == f"repos/{REPO}/commits/{self.claim_sha}":
            return copy.deepcopy(dict(self.commit, sha=self.claim_sha))
        if "/git/ref/aeos-claims/" in path or "/commits/" in path:
            return None  # GitHub answers 404 for a ref or commit that does not exist; the caller reads None
        raise AssertionError(path)

    def pr_body(self, *, record_body=None, record_ref=None) -> str:
        body = self.record_body if record_body is None else record_body
        ref = record_ref or f"{REPO}#{RECORD}"
        return (f"Fix.\n\n<!-- aeos-programme: {self.policy.scoped_grant['programme']} -->\n"
                f"<!-- scoped-machine-grant: {ref}@sha256:{hashlib.sha256(body.encode()).hexdigest()} -->\n")

    def programme(self):
        compiler = self.policy.authority_compiler
        block = dict(schema="standing-authority/v2", state="ACTIVE", repository=REPO, issue=3752,
                     not_after=None, path_envelope=["scripts/agent_relay/cli.py"])
        return {"ref": compiler["programme"], "state": "open", "author_login": self.operator, "author_type": "User",
                "body": f"**Policy / Programme ID:** `{compiler['programme_id']}`\n```standing-authority\n"
                        f"{json.dumps(block)}\n```\n", "updated_at": "t", "editors": []}

    def evidence(self, body=None, now=None):
        body = self.pr_body() if body is None else body
        doc = {"schema": dp.EVIDENCE_SCHEMA, "event": "pull_request", "repository": REPO, "actor": MACHINE,
               "pull_request": {"author_login": MACHINE, "author_type": "Bot", "head_commit_author_login": MACHINE,
                                "body": body},
               "programme": self.programme()}
        if self.policy.scoped_grant is not None:
            doc["scoped_grant"] = sg.collect(self.policy.scoped_grant, body, self.api, now or epoch(120))
        return doc


def entry(path=PATH, rename_from=None):
    return dp.Entry(path, "modified", "a" * 64, "b" * 64, rename_from, pre_mode="100644", post_mode="100644")


GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_TERMINAL_PROMPT": "0"}


class GitRepo:
    """A throwaway repository whose commits carry REAL git modes (regular, executable, symlink, gitlink)."""

    def __init__(self, directory):
        self.root = directory
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        return subprocess.run(["git", "-C", self.root, *args], check=True, capture_output=True,
                              env=GIT_ENV).stdout.decode().strip()

    def write(self, path, text, *, executable=False):
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if os.path.lexists(full):
            os.remove(full)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(full, 0o755 if executable else 0o644)
        self.git("add", path)

    def symlink(self, path, target):
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if os.path.lexists(full):
            os.remove(full)
        os.symlink(target, full)
        self.git("add", path)

    def gitlink(self, path):
        """A submodule entry naming a commit that EXISTS here, so the reader can read the object behind it."""
        full = os.path.join(self.root, path)
        if os.path.lexists(full):
            self.git("rm", "-q", "--cached", path)
            os.remove(full)
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.git("rev-parse", "HEAD") + "," + path)

    def commit(self, message):
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def entries(self, base, head):
        return dp.protected_diff(self.root, base, head, {PATH, "scripts/flight_deck/old.py"})[0]


class ScopedGrantJudge(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()
        self.world = World(self.policy)

    def verdict(self, entries=None, body=None, now=None, policy=None):
        policy = policy or self.policy
        now = epoch(120) if now is None else now
        evidence = self.world.evidence(body=body, now=now)
        return dp.machine_route(policy, evidence, None, REPO, entries or [entry()], now)

    # -- the positive ------------------------------------------------------------------------------
    def test_a_lawful_activation_admits_exactly_its_files_without_a_signature(self):
        self.assertIsNone(self.verdict())
        self.assertNotIn("unavailable", self.world.evidence()["scoped_grant"])

    # -- the three HOLD controls (5931392715), each distinct --------------------------------------
    def test_hold_control_1_an_operator_note_that_was_never_admitted_is_not_admission(self):
        label = self.policy.scoped_grant["admission_label"]
        self.world.served = served_node(self.world.operator, label, body="Exploratory note: NOT an admitted mission.",
                                        labels={"nodes": [], "pageInfo": {"hasNextPage": False}})
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_ADMISSION_UNPROVEN)

    def test_hold_control_2_an_activator_session_that_never_existed_is_not_ownership(self):
        self.world.record_body = render_record(self.policy, receipt__activated_by="never-existed/session-999")
        self.world.record["body"] = self.world.record_body
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_OWNER_UNPROVEN)

    def test_hold_control_3_an_activation_time_that_is_not_the_records_creation_refuses(self):
        for activated in (stamp(59), stamp(-1)):
            with self.subTest(activated=activated):
                self.world.record_body = render_record(self.policy, receipt__activated_at=activated)
                self.world.record["body"] = self.world.record_body
                self.assertEqual(self.verdict(), sg.SCOPED_GRANT_ACTIVATION_TIME_INVALID)

    def test_a_record_from_the_future_refuses(self):
        self.assertEqual(self.verdict(now=epoch(0) - 20), sg.SCOPED_GRANT_ACTIVATION_TIME_INVALID)

    # -- scope ---------------------------------------------------------------------------------------
    def test_a_path_outside_the_activation_refuses_even_inside_the_compiler_allowlist(self):
        self.assertEqual(self.verdict([entry(), entry("scripts/flight_deck/needs_you.py")]),
                         dp.MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE)
        self.assertEqual(self.verdict([entry(PATH, rename_from="scripts/flight_deck/old.py")]),
                         dp.MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE)

    def test_excluded_control_plane_and_root_paths_can_never_be_granted(self):
        root = sorted(self.policy.roots)[0]
        for path in ("scripts/agent_relay/pr_open.py", ".github/workflows/x.yml", "aeos/derivation_policy.py",
                     ".GITHUB/workflows/x.yml", root, "scripts/team_lead/runtime.py", "scripts/flight_deck/"):
            with self.subTest(path=path):
                self.world.record_body = render_record(self.policy, block__path_envelope=[path])
                self.world.record["body"] = self.world.record_body
                self.assertEqual(self.verdict([entry(path)]), sg.SCOPED_GRANT_ENVELOPE_INVALID)

    def test_a_wrong_repository_refuses(self):
        self.world.record_body = render_record(self.policy, block__repository="Other-Org/other")
        self.world.record["body"] = self.world.record_body
        self.assertEqual(self.verdict(), dp.MACHINE_ROUTE_REPOSITORY_MISMATCH)

    # -- lifecycle -----------------------------------------------------------------------------------
    def test_a_revoked_or_closed_grant_is_inactive(self):
        self.world.record_body = render_record(self.policy, block__state="REVOKED")
        self.world.record["body"] = self.world.record_body
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_INACTIVE)
        self.world.record_body = render_record(self.policy)
        self.world.record.update(body=self.world.record_body, state="CLOSED")
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_INACTIVE)

    def test_a_grant_beyond_seven_days_or_past_its_end_refuses(self):
        self.world.record_body = render_record(self.policy, block__not_after=stamp(7 * 24 * 60 + 1))
        self.world.record["body"] = self.world.record_body
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_TTL_INVALID)
        self.world.record_body = render_record(self.policy)
        self.world.record["body"] = self.world.record_body
        self.assertEqual(self.verdict(now=epoch(6 * 24 * 60)), sg.SCOPED_GRANT_EXPIRED)

    # -- authorship and replay ------------------------------------------------------------------------
    def test_a_record_authored_or_numbered_by_the_operator_is_impersonation(self):
        operator = {"login": self.world.operator, "__typename": "User"}
        self.world.record["author"] = dict(operator)
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_RECORD_NOT_MACHINE)
        self.world.record["author"] = dict(GQL_MACHINE)
        self.world.record["userContentEdits"]["nodes"][0]["editor"] = dict(operator)
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_RECORD_NOT_MACHINE)

    def test_a_replayed_or_duplicated_activation_refuses(self):
        # The same body copied onto another record names the wrong Issue in its own block.
        self.world.record["number"] = RECORD + 1
        self.assertEqual(self.verdict(body=self.world.pr_body(record_ref=f"{REPO}#{RECORD + 1}")),
                         sg.SCOPED_GRANT_RECORD_INVALID)
        self.world.record["number"] = RECORD
        # A second edit re-numbers or rewrites the record after activation.
        edits = self.world.record["userContentEdits"]
        edits["nodes"].append({"editedAt": stamp(30), "deletedAt": None, "editor": dict(GQL_MACHINE)})
        edits["totalCount"] = 2
        self.world.record["lastEditedAt"] = stamp(30)
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_RECORD_INVALID)
        edits["nodes"].pop()
        edits["totalCount"] = 1
        self.world.record["lastEditedAt"] = CREATED
        # Two machine edits at the same instant: still not "numbered in exactly one edit".
        edits["nodes"].append({"editedAt": CREATED, "deletedAt": None, "editor": dict(GQL_MACHINE)})
        edits["totalCount"] = 2
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_RECORD_INVALID)
        edits["nodes"].pop()
        edits["totalCount"] = 1
        # A pull request naming another version of the record body.
        self.assertEqual(self.verdict(body=self.world.pr_body(record_body=self.world.record_body + "x")),
                         sg.SCOPED_GRANT_RECORD_INVALID)
        # Two grant markers in one pull request.
        doubled = self.world.pr_body() + self.world.pr_body().split("\n", 3)[3]
        self.assertEqual(self.verdict(body=doubled), sg.SCOPED_GRANT_MARKER_INVALID)

    def test_an_edit_outside_the_activation_window_refuses(self):
        late = stamp(61)
        self.world.record["userContentEdits"]["nodes"][0]["editedAt"] = late
        self.world.record["lastEditedAt"] = late
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_RECORD_INVALID)

    def test_a_receipt_the_judge_would_refuse_is_an_invalid_record(self):
        cases = {
            "serves_the_programme": dict(
                receipt__serves=self.policy.scoped_grant["programme"],
                receipt__generation=self.policy.scoped_grant["programme"] + "@" + DIGEST,
                receipt__claim_ref=sg.claim_ref(self.policy.scoped_grant["programme"] + "@" + DIGEST)),
            "serves_another_repository": dict(receipt__serves="Other-Org/other#2894"),
            "generation_of_another_issue": dict(receipt__generation=REPO + "#1951@" + DIGEST,
                                                receipt__claim_ref=sg.claim_ref(REPO + "#1951@" + DIGEST)),
            "claim_ref_not_derived": dict(receipt__claim_ref="refs/aeos-claims/2894/000000000000"),
            "activator_is_the_operator": dict(receipt__activated_by=sorted(self.policy.operator_principals)[0]),
            "activator_is_the_machine": dict(receipt__activated_by=MACHINE),
            "another_directive": dict(receipt__directive_comment_id=1),
            "another_scope": dict(receipt__scope="deployment"),
            "another_programme": dict(receipt__programme=REPO + "#1951"),
            "claim_commit_not_a_sha": dict(receipt__claim_commit="HEAD"),
            "an_extra_key": dict(receipt__extra="x"),
        }
        for name, changes in cases.items():
            with self.subTest(case=name):
                self.world.record_body = render_record(self.policy, **changes)
                self.world.record["body"] = self.world.record_body
                self.assertEqual(self.verdict(), sg.SCOPED_GRANT_RECORD_INVALID)

    def test_a_record_that_moves_while_it_is_collected_is_unavailable(self):
        reads = []
        original = self.world.api

        def moving(path, *args):
            reply = original(path, *args)
            if path == "graphql" and any(a == f"i={RECORD}" for a in args):
                reads.append(1)
                if len(reads) > 1:
                    reply["data"]["repository"]["issue"]["body"] += "\nmoved"
            return reply
        self.world.api = moving
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_SOURCE_MOVED)

    def test_github_answering_with_another_issue_than_the_marker_names_refuses(self):
        # The marker names #6301 and the record body's own block says 6301, but the Issue GitHub returns
        # is numbered 6300: only the node-identity rule can refuse it.
        self.world.record_body = render_record(self.policy, block__issue=RECORD + 1)
        self.world.record["body"] = self.world.record_body
        original = self.world.api

        def aliased(path, *args):
            return original(path, *[("i=" + str(RECORD)) if a == f"i={RECORD + 1}" else a for a in args])
        self.world.api = aliased
        self.assertEqual(self.verdict(body=self.world.pr_body(record_ref=f"{REPO}#{RECORD + 1}")),
                         sg.SCOPED_GRANT_RECORD_INVALID)

    def test_a_record_in_another_repository_is_a_repository_mismatch(self):
        self.world.record["repository"] = {"nameWithOwner": "Other-Org/other"}
        self.assertEqual(self.verdict(body=self.world.pr_body(record_ref=f"Other-Org/other#{RECORD}")),
                         dp.MACHINE_ROUTE_REPOSITORY_MISMATCH)

    def test_facts_collected_for_another_grant_are_unavailable(self):
        evidence = self.world.evidence()
        other = self.world.pr_body(record_body=self.world.record_body + " ")
        evidence["pull_request"]["body"] = other
        self.assertEqual(dp.machine_route(self.policy, evidence, None, REPO, [entry()], epoch(120)),
                         sg.SCOPED_GRANT_UNAVAILABLE)

    def test_a_control_plane_path_stays_excluded_even_if_policy_ever_allowlisted_it(self):
        with open(os.path.join(HERE, dp.POLICY_FILE), "rb") as handle:
            document = json.loads(handle.read())
        document["machine_route"]["scoped_grant"].update(
            activation="enabled", directive_body_sha256=hashlib.sha256(DIRECTIVE.encode()).hexdigest())
        document["derivation_policy"]["allowlist_files"].append(".github/workflows/x.yml")
        policy = dp.parse_policy(json.dumps(document).encode())
        self.world = World(policy)
        self.world.record_body = render_record(policy, block__path_envelope=[".github/workflows/x.yml"])
        self.world.record["body"] = self.world.record_body
        self.assertEqual(self.verdict([entry(".github/workflows/x.yml")], policy=policy),
                         sg.SCOPED_GRANT_ENVELOPE_INVALID)

    def test_admission_follows_the_incumbent_canonized_root_rules(self):
        """Each served Issue below was labelled at -50 (before the activation), so only the canonized-root
        rule itself can refuse it."""
        label = self.policy.scoped_grant["admission_label"]
        operator = self.world.operator
        other = {"login": "someone", "__typename": "User"}
        bot = {"login": "aeos-autonomous-main", "__typename": "Bot"}

        def event(actor, minutes):
            return {"pageInfo": {"hasPreviousPage": False}, "nodes": [
                {"actor": actor, "label": {"id": "LA_1", "name": label}, "createdAt": stamp(minutes)}]}
        cases = {
            "closed": dict(state="CLOSED"),
            "machine_authored": dict(author=bot),
            "edited_by_another_user": dict(editor={"login": "someone"}, userContentEdits={
                "totalCount": 1, "pageInfo": {"hasNextPage": False},
                "nodes": [{"editedAt": stamp(-60), "deletedAt": None, "editor": other}]}),
            "deleted_edit_record": dict(userContentEdits={
                "totalCount": 1, "pageInfo": {"hasNextPage": False},
                "nodes": [{"editedAt": stamp(-60), "deletedAt": stamp(-55),
                           "editor": {"login": operator, "__typename": "User"}}]}),
            "labelled_by_the_machine": dict(timelineItems=event(bot, -50)),
            "labelled_by_another_user": dict(timelineItems=event(other, -50)),
            "labelled_before_the_last_edit": dict(timelineItems=event({"login": operator}, -70)),
            "carries_a_ceiling_block": dict(body="Mission\n```standing-authority\n{}\n```\n"),
            "sub_issue_child": dict(parent={"number": 12}),
            "label_removed_but_event_kept": dict(labels={"nodes": [], "pageInfo": {"hasNextPage": False}}),
        }
        for name, changes in cases.items():
            with self.subTest(case=name):
                self.world.served = served_node(operator, label, **changes)
                self.assertEqual(self.verdict(), sg.SCOPED_GRANT_ADMISSION_UNPROVEN)

    # -- directive -----------------------------------------------------------------------------------
    def test_a_stand_in_or_edited_directive_refuses(self):
        self.world.directive["body"] = "a stand-in"
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_DIRECTIVE_INVALID)
        self.world.directive["body"] = DIRECTIVE
        self.world.directive["lastEditedAt"] = stamp(-10)
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_DIRECTIVE_INVALID)
        self.world.directive["lastEditedAt"] = None
        for count in (1, False):  # an edit count, and a boolean that is never a count even where it equals 0
            with self.subTest(totalCount=count):
                self.world.directive["userContentEdits"] = {"totalCount": count}
                self.assertEqual(self.verdict(), sg.SCOPED_GRANT_DIRECTIVE_INVALID)
        self.world.directive["userContentEdits"] = {"totalCount": 0}
        self.world.directive["author"] = dict(GQL_MACHINE)
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_DIRECTIVE_INVALID)

    # -- ownership -----------------------------------------------------------------------------------
    def test_a_claim_that_moved_is_released_or_was_signed_by_another_is_not_ownership(self):
        cases = [
            ("moved", lambda w: setattr(w, "claim_sha", "e" * 40)),
            ("committer", lambda w: w.commit.update(committer={"login": "mallory", "type": "User"})),
            ("unverified", lambda w: w.commit["commit"].update(verification={"verified": False})),
            ("released", lambda w: w.commit["commit"].update(
                message=w.commit["commit"]["message"] + "state=RELEASED\n")),
            ("after", lambda w: w.commit["commit"].update(committer={"name": "GitHub", "date": stamp(1)})),
            ("author", lambda w: w.commit.update(author={"login": "someone", "type": "User"})),
            ("generation", lambda w: w.commit["commit"].update(message=w.commit["commit"]["message"].replace(
                GENERATION, SERVED + "@intent-v1:sha256:" + "e" * 64))),
        ]
        for name, mutate in cases:
            with self.subTest(case=name):
                self.world = World(self.policy)
                mutate(self.world)
                self.assertEqual(self.verdict(), sg.SCOPED_GRANT_OWNER_UNPROVEN)

    def test_admission_that_came_after_the_activation_refuses(self):
        label = self.policy.scoped_grant["admission_label"]
        node = served_node(self.world.operator, label)
        node["timelineItems"]["nodes"][0]["createdAt"] = stamp(5)
        self.world.served = node
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_ADMISSION_UNPROVEN)

    # -- independent review P1s (Codex HOLD) -----------------------------------------------------------
    def other_programme_evidence(self, *, body):
        """A PR that carries a grant marker but selects ANOTHER operator-authored ACTIVE programme whose own
        envelope covers the protected change (the reviewer's P1-a input)."""
        evidence = self.world.evidence(body=body)
        block = dict(schema="standing-authority/v2", state="ACTIVE", repository=REPO, issue=4818,
                     not_after=None, path_envelope=[PATH])
        evidence["programme"] = {"ref": REPO + "#4818", "state": "open", "author_login": self.world.operator,
                                 "author_type": "User", "body": "```standing-authority\n" + json.dumps(block)
                                 + "\n```\n", "updated_at": "t", "editors": []}
        return evidence

    def test_p1a_a_grant_marker_under_another_programme_is_never_judged_by_that_programme(self):
        body = self.world.pr_body().replace(self.policy.scoped_grant["programme"], REPO + "#4818")
        self.assertIn("aeos-programme: " + REPO + "#4818", body)
        evidence = self.other_programme_evidence(body=body)
        self.assertEqual(dp.machine_route(self.policy, evidence, None, REPO, [entry()], epoch(120)),
                         sg.SCOPED_GRANT_PROGRAMME_MISMATCH)

    def test_p1a_the_disabled_switch_refuses_a_grant_marker_under_any_programme(self):
        revoked = shipped_policy(activation="disabled")
        self.world = World(revoked)
        body = self.world.pr_body().replace(revoked.scoped_grant["programme"], REPO + "#4818")
        evidence = self.other_programme_evidence(body=body)
        self.assertEqual(dp.machine_route(revoked, evidence, None, REPO, [entry()], epoch(120)),
                         sg.SCOPED_GRANT_DISABLED)

    def test_p1a_no_marker_under_another_programme_is_unchanged(self):
        body = f"Fix.\n\n<!-- aeos-programme: {REPO}#4818 -->\n"
        evidence = self.other_programme_evidence(body=body)
        self.assertIsNone(dp.machine_route(self.policy, evidence, None, REPO, [entry()], epoch(120)))

    def test_p1b_a_held_claim_of_an_old_generation_cannot_authorize_a_changed_mission(self):
        # The served Issue was edited to a new mission and re-admitted (label re-applied after the edit);
        # the record still cites the old generation, whose claim is still HELD.
        label = self.policy.scoped_grant["admission_label"]
        self.world.served = served_node(self.world.operator, label, body="Mission, now something else")
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_GENERATION_UNBOUND)

    def test_p1b_the_generation_is_the_dispatchers_key_over_the_served_body(self):
        self.assertEqual(sg.current_generation(SERVED, SERVED_BODY, "intent-v1"), GENERATION)
        self.assertEqual(sg.current_generation(SERVED, SERVED_BODY, "v0"),
                         SERVED + "@sha256:" + hashlib.sha256(SERVED_BODY.encode()).hexdigest())
        # A body whose intent projection is not the identity is refused, never re-projected here.
        self.assertIsNone(sg.current_generation(SERVED, "x\n```yaml\ncommission_version: 1\n```\n", "intent-v1"))
        self.assertIsNone(sg.current_generation(SERVED, SERVED_BODY, "v9"))
        # Total over any str body, exactly as the dispatcher's digest (utf-8 with surrogatepass).
        odd = "a\ud800b"
        self.assertEqual(sg.current_generation(SERVED, odd, "v0"),
                         SERVED + "@sha256:" + hashlib.sha256(odd.encode("utf-8", "surrogatepass")).hexdigest())

    def test_p1b_a_v0_generation_bound_to_the_served_body_is_admitted(self):
        v0 = SERVED + "@sha256:" + hashlib.sha256(SERVED_BODY.encode()).hexdigest()
        self.world.record_body = render_record(self.policy, receipt__generation=v0,
                                               receipt__claim_ref=sg.claim_ref(v0))
        self.world.record["body"] = self.world.record_body
        self.world.commit["commit"]["message"] = self.world.commit["commit"]["message"].replace(GENERATION, v0)
        claim = sg.claim_ref(v0)
        original = self.world.api

        def api(path, *args):
            if path == f"repos/{REPO}/git/ref/{claim[len('refs/'):]}":
                return {"ref": claim, "object": {"sha": self.world.claim_sha, "type": "commit"}}
            return original(path, *args)
        self.world.api = api
        self.assertIsNone(self.verdict())

    # -- independent review P1 (revision 2): a granted path that is not a regular file --------------------
    def git_verdict(self, build):
        """Entries computed by the REAL derivation reader from real git objects, then judged."""
        with tempfile.TemporaryDirectory() as directory:
            repo = GitRepo(directory)
            repo.write(PATH, "VALUE = 1\n")
            base = repo.commit("base")
            build(repo)
            head = repo.commit("head")
            entries = repo.entries(base, head)
            self.assertTrue(entries, "the change must touch the granted path")
            return self.verdict(entries)

    def test_p1c_a_granted_file_replaced_by_a_symlink_to_ungranted_bytes_refuses(self):
        def exploit(repo):
            repo.write("scripts/flight_deck/payload", "import os\nos.system('id')\n")
            repo.symlink(PATH, "payload")
        self.assertEqual(self.git_verdict(exploit), sg.SCOPED_GRANT_NOT_REGULAR_FILE)

    def test_p1c_a_granted_file_replaced_by_a_gitlink_refuses(self):
        self.assertEqual(self.git_verdict(lambda repo: repo.gitlink(PATH)), sg.SCOPED_GRANT_NOT_REGULAR_FILE)

    def test_p1c_a_symlink_renamed_onto_or_added_at_a_granted_path_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = GitRepo(directory)
            repo.symlink("scripts/flight_deck/old.py", "elsewhere")
            base = repo.commit("base")
            repo.git("mv", "scripts/flight_deck/old.py", PATH)
            head = repo.commit("rename")
            entries = repo.entries(base, head)
            self.world.record_body = render_record(self.policy, block__path_envelope=[PATH, "scripts/flight_deck/old.py"])
            self.world.record["body"] = self.world.record_body
            self.assertEqual(self.verdict(entries), sg.SCOPED_GRANT_NOT_REGULAR_FILE)
        with tempfile.TemporaryDirectory() as directory:
            repo = GitRepo(directory)
            repo.write("README.md", "x\n")
            base = repo.commit("base")
            repo.symlink(PATH, "payload")
            head = repo.commit("added")
            self.assertEqual(self.verdict(repo.entries(base, head)), sg.SCOPED_GRANT_NOT_REGULAR_FILE)

    def test_p1c_a_symlink_at_the_base_turned_regular_still_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = GitRepo(directory)
            repo.symlink(PATH, "payload")
            base = repo.commit("base")
            repo.write(PATH, "VALUE = 2\n")
            head = repo.commit("head")
            self.assertEqual(self.verdict(repo.entries(base, head)), sg.SCOPED_GRANT_NOT_REGULAR_FILE)

    def test_p1c_regular_and_executable_file_changes_are_still_admitted(self):
        self.assertIsNone(self.git_verdict(lambda repo: repo.write(PATH, "VALUE = 2\n")))
        self.assertIsNone(self.git_verdict(lambda repo: repo.write(PATH, "VALUE = 2\n", executable=True)))

    def test_p1c_added_deleted_and_renamed_regular_files_are_admitted(self):
        self.world.record_body = render_record(self.policy, block__path_envelope=[PATH, "scripts/flight_deck/old.py"])
        self.world.record["body"] = self.world.record_body
        for name, (setup, change) in {
            "added": (lambda r: r.write("README.md", "x\n"), lambda r: r.write(PATH, "VALUE = 1\n")),
            "deleted": (lambda r: r.write(PATH, "VALUE = 1\n"), lambda r: r.git("rm", "-q", PATH)),
            "renamed": (lambda r: r.write("scripts/flight_deck/old.py", "VALUE = 1\n"),
                        lambda r: r.git("mv", "scripts/flight_deck/old.py", PATH)),
        }.items():
            with self.subTest(status=name), tempfile.TemporaryDirectory() as directory:
                repo = GitRepo(directory)
                setup(repo)
                base = repo.commit("base")
                change(repo)
                head = repo.commit("head")
                entries = repo.entries(base, head)
                self.assertEqual([e.status for e in entries], [name])
                self.assertIsNone(self.verdict(entries))

    def test_p1c_an_entry_without_git_modes_is_never_assumed_regular(self):
        bare = dp.Entry(PATH, "modified", "a" * 64, "b" * 64, None)
        self.assertEqual(self.verdict([bare]), sg.SCOPED_GRANT_NOT_REGULAR_FILE)
        # An absent side must carry the absent mode, never a link's.
        odd = dp.Entry(PATH, "added", dp.ABSENT, "b" * 64, None, pre_mode="120000", post_mode="100644")
        self.assertEqual(self.verdict([odd]), sg.SCOPED_GRANT_NOT_REGULAR_FILE)

    def test_p1c_a_new_unprotected_file_next_to_a_granted_change_is_not_judged_here(self):
        """Conclusion pinned (review question): a granted file whose NEW content loads a newly added,
        extensionless sibling gains nothing its granted content could not do inline, and the sibling's bytes
        are in the reviewed diff, so this judge does not refuse it. The residual is a pre-existing property of
        the derivation closure (AST imports only; symlinked and non-.py files are not followed) and applies
        to every route, not to grants."""
        def change(repo):
            repo.write("scripts/flight_deck/payload", "VALUE = 3\n")
            repo.write(PATH, "exec(open(__file__.rsplit('/', 1)[0] + '/payload').read())\n")
        self.assertIsNone(self.git_verdict(change))

    def test_p1c_modes_never_enter_the_signed_manifest_bytes(self):
        with_modes = dp.Entry(PATH, "modified", "a" * 64, "b" * 64, None, pre_mode="100644", post_mode="120000")
        without = dp.Entry(PATH, "modified", "a" * 64, "b" * 64, None)
        self.assertEqual(with_modes.as_dict(), without.as_dict())

    # -- independent review P1 (revision 3): sources that move during collection --------------------------
    def during_claim_commit_fetch(self, mutate):
        """Wrap the fake so ``mutate`` runs right after the claim commit is served: the reviewer's window."""
        original = self.world.api

        def api(path, *args):
            reply = original(path, *args)
            if "/commits/" in path:
                mutate(self.world)
            return reply
        self.world.api = api

    def test_p1d_a_served_issue_closed_during_collection_refuses(self):
        self.during_claim_commit_fetch(lambda w: w.served.update(state="CLOSED"))
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_SOURCE_MOVED)

    def test_p1d_an_admission_label_removed_during_collection_refuses(self):
        self.during_claim_commit_fetch(
            lambda w: w.served.update(labels={"nodes": [], "pageInfo": {"hasNextPage": False}}))
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_SOURCE_MOVED)

    def test_p1d_a_claim_ref_moved_during_collection_refuses(self):
        self.during_claim_commit_fetch(lambda w: setattr(w, "claim_sha", "e" * 40))
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_SOURCE_MOVED)

    def test_p1d_stale_or_future_evidence_refuses(self):
        evidence = self.world.evidence(now=epoch(120))
        self.assertIsNone(dp.machine_route(self.policy, evidence, None, REPO, [entry()], epoch(120)))
        # The bound is the comment operand's own, five minutes, pinned literally here.
        import comment_operand
        self.assertEqual(sg.MAX_EVIDENCE_AGE_SECONDS, comment_operand.MAX_AGE_SECONDS)
        self.assertIsNone(dp.machine_route(self.policy, evidence, None, REPO, [entry()], epoch(120) + 300))
        for now in (epoch(120) + 301, epoch(120) - 1):
            with self.subTest(now=now):
                self.assertEqual(dp.machine_route(self.policy, evidence, None, REPO, [entry()], now),
                                 sg.SCOPED_GRANT_EVIDENCE_NOT_CURRENT)
        for bad in (True, "1", None, float("nan"), float("inf")):
            with self.subTest(observed_at=bad):
                spoiled = copy.deepcopy(evidence)
                spoiled["scoped_grant"]["observed_at"] = bad
                self.assertEqual(dp.machine_route(self.policy, spoiled, None, REPO, [entry()], epoch(120)),
                                 sg.SCOPED_GRANT_EVIDENCE_NOT_CURRENT)
        # A boolean is never a time, even where its integer value would look current.
        spoiled = copy.deepcopy(evidence)
        spoiled["scoped_grant"]["observed_at"] = True
        self.assertEqual(sg.judge(self.policy.scoped_grant, self.policy, spoiled, REPO, [entry()], 2.0),
                         sg.SCOPED_GRANT_EVIDENCE_NOT_CURRENT)

    def test_p1d_an_absent_claim_that_appears_during_collection_refuses(self):
        claim = sg.claim_ref(GENERATION)
        original = self.world.api
        reads = []

        def api(path, *args):
            if path == f"repos/{REPO}/git/ref/{claim[len('refs/'):]}":
                reads.append(1)
                if len(reads) == 1:
                    return None
            return original(path, *args)
        self.world.api = api
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_SOURCE_MOVED)

    # -- independent review (revision 4): the WHOLE reading is compared; hostile shapes refuse typed ---------
    def after_first_reading(self, mutate):
        """Run ``mutate`` once, right after the FIRST reading's claim commit is served: inside collection."""
        original = self.world.api
        done = []

        def api(path, *args):
            reply = original(path, *args)
            if "/commits/" in path and not done:
                done.append(1)
                mutate(self.world)
            return reply
        self.world.api = api

    def test_p1e_a_record_edited_and_restored_within_one_second_during_collection_refuses(self):
        # The reviewer's exploit: body, lastEditedAt and state read as before; only the edit history grew 1 -> 3.
        def edit_and_restore(world):
            history = world.record["userContentEdits"]
            history["nodes"] += [dict(history["nodes"][0]), dict(history["nodes"][0])]
            history["totalCount"] = 3
        self.after_first_reading(edit_and_restore)
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_SOURCE_MOVED)

    def test_p1e_any_field_of_any_source_that_moves_during_collection_refuses(self):
        stranger = {"login": "someone-else", "__typename": "User"}
        cases = {
            "record created": lambda w: w.record.update(createdAt=stamp(1)),
            "record author": lambda w: w.record.update(author=dict(stranger)),
            "record edit editor": lambda w: w.record["userContentEdits"]["nodes"][0].update(editor=dict(stranger)),
            "record edit deleted": lambda w: w.record["userContentEdits"]["nodes"][0].update(deletedAt=stamp(1)),
            "directive edited and restored": lambda w: w.directive["userContentEdits"].update(totalCount=2),
            "directive edited": lambda w: w.directive.update(lastEditedAt=stamp(1)),
            "directive author": lambda w: w.directive.update(author=dict(stranger)),
            "directive rest address": lambda w: w.comment.update(node_id="IC_y"),
            "directive rest issue": lambda w: w.comment.update(issue_url="https://api.github.com/repos/o/r/issues/1"),
            "served edit history": lambda w: w.served["userContentEdits"].update(totalCount=2),
            "served parent": lambda w: w.served.update(parent={"number": 1}),
            "claim retargeted, same commit": lambda w: setattr(w, "claim_type", "tag"),
            "commit unverified": lambda w: w.commit["commit"]["verification"].update(verified=False),
            "commit message": lambda w: w.commit["commit"].update(message="state=RELEASED\n"),
            "commit author": lambda w: w.commit.update(author={"login": "someone-else", "type": "User"}),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                self.world = World(self.policy)
                self.after_first_reading(mutate)
                self.assertEqual(self.verdict(), sg.SCOPED_GRANT_SOURCE_MOVED)

    def test_p2_a_malformed_envelope_member_refuses_typed(self):
        for members in ([{}], [[]], [PATH, {}], [PATH, [PATH]], [None], [1], [True], [PATH, PATH]):
            with self.subTest(members=members):
                self.world.record_body = render_record(self.policy, block__path_envelope=members)
                self.world.record["body"] = self.world.record_body
                self.assertEqual(self.verdict(), sg.SCOPED_GRANT_ENVELOPE_INVALID)

    def test_p2_a_marker_number_beyond_any_issue_refuses_typed(self):
        for number in ("9" * 11, "9" * 5000):
            with self.subTest(digits=len(number)):
                body = self.world.pr_body(record_ref=f"{REPO}#{number}")
                self.assertEqual(sg.marker_state(body), sg.MARKER_MALFORMED)
                self.assertEqual(self.verdict(body=body), sg.SCOPED_GRANT_MARKER_INVALID)

    def test_p2_the_judge_never_raises_on_a_hostile_shape_anywhere_in_its_evidence(self):
        now = epoch(120)
        evidence = self.world.evidence(now=now)
        binding = self.policy.scoped_grant
        self.assertIsNone(sg.judge(binding, self.policy, evidence, REPO, [entry()], now))
        failures = []
        for address in addresses(evidence):
            if address[:1] not in ((), ("scoped_grant",), ("pull_request",)):
                continue
            for hostile in HOSTILE:
                spoiled = replaced(evidence, address, hostile)
                try:
                    got = sg.judge(binding, self.policy, spoiled, REPO, [entry()], now)
                except Exception as error:  # noqa: BLE001 - the property under test is "never raises"
                    failures.append((address, repr(hostile)[:20], repr(error)[:80]))
                    continue
                if got is not None and got not in VOCABULARY:
                    failures.append((address, repr(hostile)[:20], got))
        self.assertEqual(failures, [])

    def test_p2_a_hostile_block_or_receipt_member_refuses_typed_through_the_collector(self):
        fields = (["block__" + key for key in ("schema", "state", "repository", "issue", "not_after", "path_envelope")]
                  + ["receipt__" + key for key in sorted(sg.RECEIPT_KEYS)])
        failures = []
        for field in fields:
            for hostile in HOSTILE + tuple([value] for value in HOSTILE):
                self.world.record_body = render_record(self.policy, **{field: hostile})
                self.world.record["body"] = self.world.record_body
                try:
                    got = self.verdict()
                except Exception as error:  # noqa: BLE001 - the property under test is "never raises"
                    failures.append((field, repr(hostile)[:20], repr(error)[:80]))
                    continue
                if got not in VOCABULARY:
                    failures.append((field, repr(hostile)[:20], got))
        self.assertEqual(failures, [])

    # -- switches and failure ------------------------------------------------------------------------
    def test_the_shipped_binding_is_enabled_and_revocation_refuses_every_grant(self):
        with open(os.path.join(HERE, dp.POLICY_FILE), "rb") as handle:
            shipped = dp.parse_policy(handle.read())
        self.assertEqual(shipped.scoped_grant["activation"], "enabled")
        # Enabled, the shipped binding still pins the operator's REAL directive: a stand-in never matches.
        world = World(shipped)
        self.assertEqual(dp.machine_route(shipped, world.evidence(), None, REPO, [entry()], epoch(120)),
                         sg.SCOPED_GRANT_DIRECTIVE_INVALID)
        # Revocation is the one edit back to "disabled", and it refuses every grant.
        revoked = shipped_policy(activation="disabled")
        world = World(revoked)
        self.assertEqual(dp.machine_route(revoked, world.evidence(), None, REPO, [entry()], epoch(120)),
                         sg.SCOPED_GRANT_DISABLED)

    def test_the_judge_refuses_a_disabled_binding_on_its_own_whoever_calls_it(self):
        evidence = self.world.evidence()
        disabled = dict(self.policy.scoped_grant, activation="disabled")
        self.assertIsNone(sg.judge(self.policy.scoped_grant, self.policy, evidence, REPO, [entry()], epoch(120)))
        self.assertEqual(sg.judge(disabled, self.policy, evidence, REPO, [entry()], epoch(120)),
                         sg.SCOPED_GRANT_DISABLED)

    def test_a_marker_with_no_binding_never_passes_unnarrowed(self):
        policy = load_policy()
        policy.scoped_grant = None
        evidence = self.world.evidence()
        self.assertEqual(dp.machine_route(policy, evidence, None, REPO, [entry()], epoch(120)),
                         sg.SCOPED_GRANT_UNBOUND)

    def test_an_unreadable_record_or_directive_is_unavailable_never_empty(self):
        self.world.unreadable.add(RECORD)
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_UNAVAILABLE)
        self.world.unreadable.discard(RECORD)
        self.world.unreadable.add("directive")
        self.assertEqual(self.verdict(), sg.SCOPED_GRANT_UNAVAILABLE)

    def test_a_pull_request_without_a_grant_marker_keeps_todays_compiler_behaviour(self):
        body = f"Fix.\n\n<!-- aeos-programme: {self.policy.scoped_grant['programme']} -->\n"
        evidence = self.world.evidence(body=body)
        self.assertEqual(evidence["scoped_grant"], {"observed_at": epoch(120), "marker": None})
        self.assertIsNone(dp.machine_route(self.policy, evidence, None, REPO,
                                           [entry("scripts/flight_deck/needs_you.py")], epoch(120)))

    # -- contract details ----------------------------------------------------------------------------
    def test_claim_ref_matches_the_dispatcher_grammar(self):
        self.assertEqual(sg.claim_ref(GENERATION),
                         "refs/aeos-claims/2894/" + hashlib.sha256(DIGEST.encode()).hexdigest()[:12])
        self.assertEqual(sg.claim_ref(SERVED + "@sha256:" + "f" * 64), "refs/aeos-claims/2894/" + "f" * 12)
        for bad in ("x", SERVED + "@md5:abc", SERVED, "a#1@sha256:" + "f" * 64):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sg.claim_ref(bad)

    def test_the_binding_is_validated_against_the_class_bounds(self):
        for change in (dict(max_ttl_seconds=7 * 24 * 3600 + 1), dict(programme=REPO + "#1"),
                       dict(activation="on"), dict(excluded_paths=["scripts/"]),
                       dict(directive_body_sha256="nope")):
            with self.subTest(change=change), self.assertRaises(dp.PolicyError):
                load_policy(**change)


if __name__ == "__main__":
    unittest.main()
