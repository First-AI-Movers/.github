#!/usr/bin/env python3
"""What in this policy repository is a protected decision, and what merges on the gate alone.

Agent-toolkit #3052, operator directive 2026-10-20: the operator's exact-head approval is for
genuine protected decisions only. Released: prose (a Markdown file directly in ``aeos/``, the root
docs) and a seat-ceilings edit that only removes whole seats. Still protected: the judge, its data,
the tests and their vectors, every workflow, the gate and smoke configuration, every
``.gitattributes`` and every test-collection hook or root test configuration.

Every fixture is a real git repository judged end to end by ``merge_ready_gate.evaluate`` with a
machine (bot) author and no operator approval. Plain ``unittest``.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import merge_ready_gate as gate  # noqa: E402
import test_merge_ready_gate as gate_tests  # noqa: E402  (fixture helpers only; no TestCase is imported)

POLICY = "First-AI-Movers/.github"
SAMPLE = "aeos/tests/test_sample.py"
VECTORS = "aeos/tests/vectors.json"
CEILINGS = "aeos/standing-seat-ceilings.json"
SEAT_REPOSITORY = "First-AI-Movers/agent-toolkit"

SAMPLE_SOURCE = textwrap.dedent('''\
    import unittest


    class SampleTests(unittest.TestCase):
        def test_one(self):
            self.assertTrue(True)
    ''')


def _entry(n: int, issue: int | None = None, repository: str = SEAT_REPOSITORY, **extra) -> dict:
    entry = {"schema": "standing-authority/v2", "repository": repository, "issue": 1000 + n if issue is None else issue,
             "programme_id": f"seat-{n}", "serial": 1, "path_envelope": [f"scripts/seat_{n}/"]}
    entry.update(extra)
    return entry


CEILINGS_DOCUMENT = {"schema": "aeos-standing-seat-ceilings/v1", "ceilings": [_entry(1), _entry(2), _entry(3)]}


class PolicyProtectedDecisions(unittest.TestCase):
    _machine_policy_dir = gate_tests.GateTestCase._machine_policy_dir
    _evidence_file = gate_tests.GateTestCase._evidence_file

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = gate_tests.Repo(self._tmp.name)
        self.repo.write("aeos/scoped_grant.py", "J = 1\n")
        self.repo.write("aeos/standing-governor-policy.json", '{"schema": "x"}\n')
        self.repo.write(SAMPLE, SAMPLE_SOURCE)
        self.repo.write(VECTORS, '{"vectors": [1, 2]}\n')
        self.write_ceilings(CEILINGS_DOCUMENT)
        self.repo.base = self.repo.commit("policy repository base")
        self.policy_dir = self._machine_policy_dir()
        self.machine = self._evidence_file("aeos-autonomous-main[bot]")

    # -- helpers -------------------------------------------------------------
    def write_ceilings(self, document) -> None:
        self.repo.write(CEILINGS, json.dumps(document, indent=2) + "\n")

    def rebase_ceilings(self, entries: list) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": entries})
        self.repo.base = self.repo.commit("ceilings on the base")

    def evaluate(self, head: str):
        return gate.evaluate(candidate_dir=self.repo.root, repository=POLICY, base_sha=self.repo.base,
                             head_sha=head, event_name="pull_request", policy_dir=self.policy_dir,
                             evidence_path=self.machine)

    def judge(self, message: str = "bot change"):
        return self.evaluate(self.repo.commit(message))

    def assertOrdinary(self, report) -> None:
        self.assertEqual(report.control_plane, [])
        self.assertNotIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, {f.code for f in report.findings})
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def assertOperator(self, report, path: str) -> None:
        self.assertIn(path, report.control_plane)
        self.assertIn(gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR, {f.code for f in report.findings})
        self.assertFalse(report.passed)

    def drop_object(self, sha: str) -> None:
        os.unlink(os.path.join(self.repo.root, ".git", "objects", sha[:2], sha[2:]))

    # -- not a protected decision: prose -------------------------------------
    def test_root_docs_and_aeos_prose_merge_without_the_operator(self) -> None:
        for path in ("README.md", "AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md",
                     "profile/README.md", "aeos/README.md", "aeos/main-smoke.md"):
            self.repo.write(path, "prose\n")
        self.assertOrdinary(self.judge("bot edits prose"))

    # -- the tests and their vectors stay protected ----------------------------
    def test_every_test_change_still_needs_the_operator(self) -> None:
        # Executable evidence: no AST floor can rule out a vacuous suite, so none of these is released.
        for path, content in (
                ("aeos/tests/test_extra.py", "def test_extra():\n    assert True\n"),
                ("aeos/tests/test_zz.py", "import unittest\nunittest.TestCase.run = lambda *a, **k: None\n"),
                (SAMPLE, SAMPLE_SOURCE + "\n\nglobals()['SampleTests'] = None\n"),
                (SAMPLE, SAMPLE_SOURCE.replace("assertTrue(True)", "assertTrue(1)")),
                ("aeos/tests/new-vectors.json", "{}\n"), (VECTORS, '{"vectors": [1]}\n'),
                ("aeos/tests/README.md", "prose\n")):
            self.repo.write(path, content)
            with self.subTest(path=path, content=content):
                self.assertOperator(self.judge(f"bot edits {path}"), path)
            gate_tests.git(self.repo.root, "checkout", "-q", self.repo.base, "--", ".")
            gate_tests.git(self.repo.root, "clean", "-q", "-fd")
            self.repo.base = self.repo.commit("restore")

    def test_a_judge_module_or_new_aeos_file_still_needs_the_operator(self) -> None:
        for path, content in (("aeos/scoped_grant.py", "J = 2\n"), ("aeos/foo.py", "X = 1\n"),
                              ("aeos/standing-governor-policy.json", '{"schema": "y"}\n')):
            self.repo.write(path, content)
            self.assertOperator(self.judge(f"bot edits {path}"), path)

    # -- import hooks and root test configuration (policy repository only) ----------
    def test_import_hooks_anywhere_are_control_plane(self) -> None:
        for path in ("conftest.py", "docs/conftest.py", "aeos/tests/sub/conftest.py", "sitecustomize.py",
                     "tools/usercustomize.py", "x.pth", "docs/deep/hook.PTH", "Hooks/ConfTest.PY"):
            self.repo.write(path, "X = 1\n")
            self.assertOperator(self.judge(f"bot adds {path}"), path)
            self.repo.remove(path)
            self.repo.base = self.repo.commit(f"drop {path}")

    def test_python_sources_anywhere_outside_aeos_are_control_plane(self) -> None:
        # `python3 -m pytest` / `-m unittest` from the root put the cwd first on sys.path, so any of these
        # would replace the runner or the standard library for whoever runs the suite.
        for path in ("pytest/__init__.py", "json.py", "unittest.py", "docs/x.py", "noxfile.py", "tools/a.pyc",
                     "b.pyw", "lib/c.so", "lib/d.PYD", "Unittest/__main__.PY"):
            self.repo.write(path, "X = 1\n")
            with self.subTest(path=path):
                self.assertOperator(self.judge(f"bot adds {path}"), path)
            self.repo.remove(path)
            self.repo.base = self.repo.commit(f"drop {path}")
        self.repo.write("README.md", "prose\n")
        self.assertOrdinary(self.judge("bot edits the README"))

    def test_root_test_configuration_is_control_plane(self) -> None:
        for path, content in (("pytest.ini", "[pytest]\n"), ("pyproject.toml", "[tool.pytest.ini_options]\n"),
                              ("setup.cfg", "[tool:pytest]\n"), ("tox.ini", "[pytest]\n"),
                              (".pytest.ini", "[pytest]\n"), ("pytest.toml", "[pytest]\n"),
                              (".pytest.toml", "[pytest]\n")):
            self.repo.write(path, content)
            self.assertOperator(self.judge(f"bot adds {path}"), path)
            self.repo.remove(path)
            self.repo.base = self.repo.commit(f"drop {path}")

    def test_test_configuration_names_below_the_root_are_ordinary(self) -> None:
        for path in ("docs/pyproject.toml", "docs/setup.cfg", "docs/pytest.toml", "docs/pytest.ini",
                     "docs/notes.pyi.md", "docs/py.txt"):
            self.repo.write(path, "[x]\n")
        self.assertOrdinary(self.judge())

    def test_deleting_an_import_hook_stays_control_plane(self) -> None:
        self.repo.write("conftest.py", "X = 1\n")
        self.repo.write("pytest.ini", "[pytest]\n")
        self.repo.write("json.py", "X = 1\n")
        self.repo.base = self.repo.commit("hooks on the base")
        for path in ("conftest.py", "pytest.ini", "json.py"):
            self.repo.remove(path)
        report = self.judge()
        self.assertOperator(report, "conftest.py")
        self.assertIn("pytest.ini", report.control_plane)
        self.assertIn("json.py", report.control_plane)

    def test_import_hooks_in_a_consumer_repository_are_ordinary(self) -> None:
        self.assertEqual(gate.control_plane_violations(
            ["conftest.py", "sitecustomize.py", "a.pth", "pytest.ini", "pyproject.toml", "json.py", "pytest/__init__.py",
             "pytest.toml"], "First-AI-Movers/example"), [])

    # -- the seat ceilings: a removal of whole seats is released ---------------
    def test_removing_one_seat_merges_without_the_operator(self) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1), _entry(3)]})
        self.assertOrdinary(self.judge())

    def test_removing_every_entry_of_a_seat_merges(self) -> None:
        self.rebase_ceilings([_entry(1), _entry(2, issue=7), _entry(3, issue=7, serial=2), _entry(4)])
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1), _entry(4)]})
        self.assertOrdinary(self.judge())

    def test_removing_a_seat_beside_a_prose_change_merges(self) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(2)]})
        self.repo.write("aeos/README.md", "prose\n")
        self.assertOrdinary(self.judge())

    def test_removing_one_entry_of_a_seat_that_keeps_another_needs_the_operator(self) -> None:
        # The kept entry would govern the seat alone: a removal must never promote another entry.
        self.rebase_ceilings([_entry(1, issue=7), _entry(2, issue=7, path_envelope=["scripts/"]), _entry(3)])
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(2, issue=7, path_envelope=["scripts/"]), _entry(3)]})
        self.assertOperator(self.judge(), CEILINGS)

    def test_the_seat_key_ignores_repository_case(self) -> None:
        self.rebase_ceilings([_entry(1, issue=7), _entry(2, issue=7, repository=SEAT_REPOSITORY.lower()), _entry(3)])
        self.write_ceilings({**CEILINGS_DOCUMENT,
                             "ceilings": [_entry(2, issue=7, repository=SEAT_REPOSITORY.lower()), _entry(3)]})
        self.assertOperator(self.judge(), CEILINGS)

    def test_an_entry_without_a_clean_seat_fails_closed(self) -> None:
        for broken in ({k: v for k, v in _entry(2).items() if k != "issue"},
                       {k: v for k, v in _entry(2).items() if k != "repository"},
                       _entry(2, issue=True), _entry(2, issue="1002"), _entry(2, repository="")):
            with self.subTest(broken=broken):
                self.rebase_ceilings([_entry(1), broken, _entry(3)])
                self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [broken, _entry(3)]})
                self.assertOperator(self.judge(), CEILINGS)

    # -- the seat ceilings: everything else is protected -----------------------
    def test_adding_a_ceiling_still_needs_the_operator(self) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1), _entry(2), _entry(3), _entry(4)]})
        self.assertOperator(self.judge(), CEILINGS)

    def test_replacing_a_removed_ceiling_with_a_new_one_still_needs_the_operator(self) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1), _entry(4)]})
        self.assertOperator(self.judge(), CEILINGS)

    def test_editing_a_ceiling_still_needs_the_operator(self) -> None:
        widened = {**_entry(2), "path_envelope": ["scripts/"]}
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1), widened]})
        self.assertOperator(self.judge(), CEILINGS)

    def test_duplicating_a_kept_ceiling_still_needs_the_operator(self) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1), _entry(1)]})
        self.assertOperator(self.judge(), CEILINGS)

    def test_reordering_ceilings_still_needs_the_operator(self) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(3), _entry(1)]})
        self.assertOperator(self.judge(), CEILINGS)

    def test_changing_another_ceilings_key_still_needs_the_operator(self) -> None:
        for document in ({"schema": "aeos-standing-seat-ceilings/v2", "ceilings": [_entry(1)]},
                         {**CEILINGS_DOCUMENT, "ceilings": [_entry(1)], "note": "added"}):
            with self.subTest(document=document):
                self.write_ceilings(document)
                self.assertOperator(self.judge(), CEILINGS)

    def test_rewriting_the_ceilings_without_removing_one_still_needs_the_operator(self) -> None:
        self.repo.write(CEILINGS, json.dumps(CEILINGS_DOCUMENT) + "\n")  # same document, new bytes
        self.assertOperator(self.judge(), CEILINGS)

    def test_ceilings_that_are_not_a_list_still_need_the_operator(self) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": {}})
        self.assertOperator(self.judge(), CEILINGS)

    def test_deleting_the_ceilings_still_needs_the_operator(self) -> None:
        self.repo.remove(CEILINGS)
        self.assertOperator(self.judge(), CEILINGS)

    def test_adding_the_ceilings_file_is_never_released(self) -> None:
        # Defence in depth: only a modification can be a removal, whatever bytes sit under the ids.
        base, head = json.dumps(CEILINGS_DOCUMENT).encode(), json.dumps({**CEILINGS_DOCUMENT, "ceilings": []}).encode()
        change = gate.Change("A", CEILINGS, "100644", "2" * 40, "100644", "1" * 40)
        self.assertFalse(gate._ceilings_removal_only(change, {"1" * 40: base, "2" * 40: head}))

    def test_a_symlinked_ceilings_file_is_never_released(self) -> None:
        # Defence in depth: link text is not the file, even when it spells a removal.
        base, head = json.dumps(CEILINGS_DOCUMENT).encode(), json.dumps({**CEILINGS_DOCUMENT, "ceilings": []}).encode()
        change = gate.Change("M", CEILINGS, "120000", "2" * 40, "100644", "1" * 40)
        self.assertFalse(gate._ceilings_removal_only(change, {"1" * 40: base, "2" * 40: head}))

    def test_unparseable_ceilings_still_need_the_operator(self) -> None:
        self.repo.write(CEILINGS, '{"schema": "aeos-standing-seat-ceilings/v1", "ceilings": [\n')
        self.assertOperator(self.judge(), CEILINGS)

    def test_an_unreadable_ceilings_base_fails_closed(self) -> None:
        base_blob = gate_tests.git(self.repo.root, "rev-parse", f"{self.repo.base}:{CEILINGS}")
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1)]})
        head = self.repo.commit("bot removes ceilings")
        self.drop_object(base_blob)
        self.assertOperator(self.evaluate(head), CEILINGS)

    def test_an_oversized_ceilings_file_is_not_released(self) -> None:
        padding = "x" * (gate.MAX_PARSE_BYTES + 1)
        self.rebase_ceilings([_entry(1, note=padding), _entry(2), _entry(3)])
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1, note=padding), _entry(3)]})
        self.assertIn(CEILINGS, self.judge().control_plane)

    def test_a_consumer_repository_is_untouched(self) -> None:
        self.write_ceilings({**CEILINGS_DOCUMENT, "ceilings": [_entry(1)]})
        head = self.repo.commit("a removal in a consumer")
        self.assertEqual(gate.policy_ordinary_paths(self.repo.root, gate.changed_records(
            self.repo.root, self.repo.base, head, "pull_request"), "First-AI-Movers/example"), frozenset())


if __name__ == "__main__":
    unittest.main()
