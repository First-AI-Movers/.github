#!/usr/bin/env python3
"""The organization-wide surfaces of the scoped-grant consumer fail closed (agent-toolkit #3052 Class B).

Every policy load, for every repository the organization gate judges, imports ``scoped_grant`` and validates
``machine_route.scoped_grant``. These cases pin what happens when either goes wrong:

* any malformed binding, of any shape, is ``GATE_CONFIG_INVALID`` from ``parse_policy``, never another exception;
* the gate itself reports that code as its typed verdict, in a consumer repository as in the target one;
* the module imports only the standard library, so a runner can never fail to import it for a missing package.
"""
from __future__ import annotations

import ast
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import derivation_policy as dp  # noqa: E402
import merge_ready_gate as gate  # noqa: E402
import scoped_grant as sg  # noqa: E402

HOSTILE = ({}, [], [{}], [[]], {"": {}}, None, True, False, 0, -1, 10 ** 400, 1.5, float("nan"), "", "x", "\ud800")
GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_TERMINAL_PROMPT": "0"}


def shipped_document() -> dict:
    with open(os.path.join(HERE, dp.POLICY_FILE), "rb") as handle:
        return json.loads(handle.read())


LAWFUL = (("admission_label", "x"), ("admission_label", "\ud800"), ("directive_comment_id", 10 ** 400),
          ("excluded_paths", []), ("excluded_paths", ["x"]), ("excluded_paths", ["\ud800"]))
"""The ONLY generated values the binding contract allows: a non-empty label, a positive comment id, an exact-path
exclusion list. Every other generated value must refuse; a validator that starts accepting one fails here."""


def lawful(key, value) -> bool:
    # Matched on type too: ``True == 1`` and ``0 == False`` must never make a boolean look lawful.
    return any(key == k and type(value) is type(v) and value == v for k, v in LAWFUL)


def malformed_documents():
    """``(key, value, document)`` for every hostile value at every binding key, and for the binding as a whole."""
    base = shipped_document()
    for key in sorted(base["machine_route"]["scoped_grant"]):
        for value in HOSTILE + tuple([value] for value in HOSTILE):
            document = copy.deepcopy(base)
            document["machine_route"]["scoped_grant"][key] = value
            yield key, value, document
    for value in HOSTILE:
        document = copy.deepcopy(base)
        document["machine_route"]["scoped_grant"] = value
        yield "binding", value, document
    document = copy.deepcopy(base)
    del document["machine_route"]["authority_compiler"]
    yield "authority_compiler", None, document
    document = copy.deepcopy(base)
    document["machine_route"]["scoped_grant"]["extra"] = 1
    yield "extra", 1, document


class ScopedGrantSurfacesFailClosed(unittest.TestCase):
    def test_the_shipped_policy_parses(self):
        with open(os.path.join(HERE, dp.POLICY_FILE), "rb") as handle:
            self.assertIsNotNone(dp.parse_policy(handle.read()).scoped_grant)

    def test_every_malformed_binding_is_gate_config_invalid_and_nothing_else(self):
        failures, seen = [], set()
        for key, value, document in malformed_documents():
            expected = "parses" if lawful(key, value) else dp.GATE_CONFIG_INVALID
            if lawful(key, value):
                seen.add((key, repr(value)))
            try:
                dp.parse_policy(json.dumps(document).encode())
                got = "parses"
            except dp.PolicyError as error:
                got = error.code
            except Exception as error:  # noqa: BLE001 - the property under test is "never another exception"
                got = repr(error)[:80]
            if got != expected:
                failures.append((key, repr(value)[:24], got))
        # Every exemption is a value the generator really produces: none is stale, each is proven to parse.
        self.assertEqual(seen, {(k, repr(v)) for k, v in LAWFUL})
        self.assertEqual(failures, [])

    def test_the_gate_reports_a_malformed_binding_as_its_typed_verdict_in_every_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy_dir = os.path.join(tmp, "policy")
            shutil.copytree(HERE, policy_dir, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            document = shipped_document()
            document["machine_route"]["scoped_grant"]["excluded_paths"] = [{}]  # unhashable: a TypeError inside
            with open(os.path.join(policy_dir, dp.POLICY_FILE), "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            candidate = os.path.join(tmp, "candidate")
            os.makedirs(candidate)

            def git(*args):
                return subprocess.run(["git", "-C", candidate, *args], check=True, capture_output=True,
                                      env=GIT_ENV).stdout.decode().strip()
            git("init", "-q", "-b", "main")
            with open(os.path.join(candidate, "README.md"), "w", encoding="utf-8") as handle:
                handle.write("base\n")
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            base = git("rev-parse", "HEAD")
            with open(os.path.join(candidate, "README.md"), "w", encoding="utf-8") as handle:
                handle.write("head\n")
            git("commit", "-q", "-am", "head")
            head = git("rev-parse", "HEAD")
            for repository in ("First-AI-Movers/some-consumer", document["target_repository"]):
                with self.subTest(repository=repository):
                    report = gate.evaluate(candidate_dir=candidate, repository=repository, base_sha=base,
                                           head_sha=head, event_name="pull_request", policy_dir=policy_dir)
                    self.assertFalse(report.passed)
                    self.assertEqual(report.primary, gate.GATE_CONFIG_INVALID)

    def test_the_module_imports_only_the_standard_library(self):
        with open(sg.__file__, "rb") as handle:
            tree = ast.parse(handle.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertLessEqual(imported - {"__future__"}, set(sys.stdlib_module_names))
        self.assertLessEqual(imported, {"__future__", "datetime", "hashlib", "json", "re"})


class ServedRootBounds(unittest.TestCase):
    def setUp(self):
        from test_scoped_grant import World, load_policy, epoch
        self.policy = load_policy()
        self.world = World(self.policy)
        self.now = epoch(120)

    def admitted(self):
        from test_scoped_grant import SERVED
        return sg._admitted({"node": self.world.served,
                             "label": self.policy.scoped_grant["admission_label"]},
                            SERVED, self.policy, self.now)

    def test_parent_closed_refuses(self):
        self.world.served["parent"] = {"number": 12, "state": "CLOSED",
            "author": {"login": self.world.operator, "__typename": "User"}}
        self.assertFalse(self.admitted())

    def test_parent_bot_refuses(self):
        self.world.served["parent"] = {"number": 12, "state": "OPEN",
            "author": {"login": self.world.operator, "__typename": "Bot"}}
        self.assertFalse(self.admitted())

    def test_parent_unreadable_refuses(self):
        for parent in ({"number": 12}, {}, {"number": 12, "state": "OPEN", "author": None}):
            with self.subTest(parent=parent):
                self.world.served["parent"] = parent
                self.assertFalse(self.admitted())
        del self.world.served["parent"]
        self.assertFalse(self.admitted())

    def test_parent_nonoperator_refuses(self):
        self.world.served["parent"] = {"number": 12, "state": "OPEN",
            "author": {"login": "untrusted-user", "__typename": "User"}}
        self.assertFalse(self.admitted())

    def test_parent_graphql_error_refuses_collection(self):
        from test_scoped_grant import SERVED
        original = self.world.api

        def api(path, *args):
            if path == "graphql" and "i=" + SERVED.split("#")[1] in args:
                response = original(path, *args)
                response["data"]["repository"]["issue"]["parent"] = None
                response["errors"] = [{"message": "parent unavailable"}]
                return response
            return original(path, *args)
        self.world.api = api
        facts = self.world.evidence()["scoped_grant"]
        self.assertIsNone(facts["served"])
        self.assertFalse(sg._admitted(facts["served"], SERVED, self.policy, self.now))

    def ceiling(self, **changes):
        from test_scoped_grant import REPO, PATH, stamp
        block = dict(schema=sg.BLOCK_SCHEMA, state="ACTIVE", repository=REPO, issue=2894,
                     not_after=stamp(121), path_envelope=[PATH])
        block.update(changes)
        self.world.served["body"] = "Mission\n```standing-authority\n" + json.dumps(block) + "\n```\n"

    def test_fence_naming_another_issue_refuses(self):
        self.ceiling(issue=2895)
        self.assertFalse(self.admitted())
        self.ceiling(repository="First-AI-Movers/other")
        self.assertFalse(self.admitted())

    def test_fence_inactive_refuses(self):
        self.ceiling(state="INACTIVE")
        self.assertFalse(self.admitted())

    def test_fence_expired_refuses(self):
        from test_scoped_grant import stamp
        for minutes in (119, 120):
            with self.subTest(minutes=minutes):
                self.ceiling(not_after=stamp(minutes))
                self.assertFalse(self.admitted())

    def test_fence_malformed_refuses(self):
        for body in ("```standing-authority\n{}\n```\n",
                     "```standing-authority\ninvalid\n```\n",
                     "```standing-authority/v2\n{}\n```\n",
                     "```standing-authority\n{}", "```standing-authority"):
            with self.subTest(body=body):
                self.world.served["body"] = body
                self.assertFalse(self.admitted())
        self.ceiling(schema="standing-authority/v1")
        self.assertFalse(self.admitted())
        self.ceiling(not_after="unreadable")
        self.assertFalse(self.admitted())
        self.ceiling()
        self.world.served["body"] *= 2
        self.assertFalse(self.admitted())


if __name__ == "__main__":
    unittest.main()
