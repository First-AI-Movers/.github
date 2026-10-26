#!/usr/bin/env python3
"""Focused, deterministic tests for the AEOS post-merge smoke.

Plain ``unittest``; no third-party runner is required.

    python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main_smoke as smoke  # noqa: E402

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


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True,
                          env=GIT_ENV).stdout.decode().strip()


class Repo:
    def __init__(self, root: str) -> None:
        self.root = root
        git(root, "init", "-q", "-b", "main")

    def write(self, rel: str, content: str) -> None:
        path = os.path.join(self.root, rel)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def commit(self, message: str = "c") -> str:
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "--allow-empty", "-m", message)
        return git(self.root, "rev-parse", "HEAD")


class FakeTools:
    """Records invocations and replays scripted results."""

    def __init__(self, results=None, present=()):
        self.results = results or {}
        self.present = set(present)
        self.calls = []

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.present else None

    def run(self, argv, **kwargs):
        key = argv if isinstance(argv, str) else " ".join(argv)
        self.calls.append(key)
        for pattern, value in self.results.items():
            if pattern in key:
                if isinstance(value, Exception):
                    raise value
                rc, out, err = value
                return subprocess.CompletedProcess(argv, rc, out, err)
        return subprocess.CompletedProcess(argv, 0, "", "")


class SmokeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = Repo(self._tmp.name)

    def run_smoke(self, sha, tools=None):
        return smoke.run_smoke(self.repo.root, sha, tools=tools)

    # -- identity ----------------------------------------------------------
    def test_identity_mismatch_is_infrastructure_not_code(self) -> None:
        self.repo.write("a.py", "x = 1\n")
        self.repo.commit()
        other = "0" * 40
        result = self.run_smoke(other)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertEqual(result["checks"][0]["reason"], "IDENTITY_MISMATCH")
        self.assertIsNone(result["signature"])

    def test_malformed_sha_is_infrastructure(self) -> None:
        self.repo.commit()
        result = self.run_smoke("not-a-sha")
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertEqual(result["checks"][0]["reason"], "IDENTITY_MALFORMED")

    def test_nothing_runs_once_identity_is_unproven(self) -> None:
        self.repo.write(".github/aeos-smoke.json", json.dumps(
            {"schema_version": "1", "commands": [{"name": "boom", "run": "exit 1"}]}))
        self.repo.commit()
        result = self.run_smoke("1" * 40)
        self.assertEqual(len(result["checks"]), 1)

    # -- no smoke defined --------------------------------------------------
    def test_repository_with_nothing_to_run_passes_with_an_explicit_note(self) -> None:
        self.repo.write("README.md", "# docs only\n")
        result = self.run_smoke(self.repo.commit())
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual(result["checks"][-1]["reason"], "NO_SMOKE_DEFINED")
        self.assertIn("not evidence that the commit works", result["note"])
        self.assertEqual(result["source"], "none")

    def test_no_smoke_defined_is_stated_never_merely_an_empty_check_list(self) -> None:
        self.repo.write("README.md", "# docs\n")
        result = self.run_smoke(self.repo.commit())
        self.assertTrue(result["note"], "a green that measured nothing must say so")
        self.assertTrue(any(c["reason"] == "NO_SMOKE_DEFINED" for c in result["checks"]))

    # -- declared plan -----------------------------------------------------
    def declare(self, document) -> str:
        body = document if isinstance(document, str) else json.dumps(document)
        self.repo.write(".github/aeos-smoke.json", body)
        return self.repo.commit()

    def test_declared_commands_pass(self) -> None:
        sha = self.declare({"schema_version": "1",
                            "commands": [{"name": "ok", "run": "exit 0"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual(result["source"], "declared")

    def test_declared_command_failure_is_a_code_failure_with_a_signature(self) -> None:
        sha = self.declare({"schema_version": "1",
                            "commands": [{"name": "unit", "run": "exit 4"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "CODE_FAILURE")
        self.assertRegex(result["signature"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["checks"][-1]["reason"], "COMMAND_FAILURE:unit:exit4")

    def test_setup_failure_is_infrastructure_and_stops_before_the_checks(self) -> None:
        sha = self.declare({"schema_version": "1",
                            "setup": [{"name": "deps", "run": "exit 1"}],
                            "commands": [{"name": "unit", "run": "exit 1"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertEqual(result["checks"][-1]["reason"], "SETUP_FAILED:deps")
        self.assertNotIn("unit", [c["id"] for c in result["checks"]])

    def test_a_missing_tool_is_infrastructure_not_a_defect(self) -> None:
        sha = self.declare({"schema_version": "1",
                            "commands": [{"name": "unit", "run": "aeos-no-such-tool-xyz"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertTrue(result["checks"][-1]["reason"].startswith("TOOL_MISSING"))

    def test_outage_phrases_inside_test_ids_are_a_code_failure(self) -> None:
        """The 2026-10-14 incident: a pytest collection listing printed test ids
        containing outage phrases, and sixteen merges read as an outage."""
        listing = ("printf '%s\\n' "
                   "'tests/test_cycle.py::test_transport_error[Could not resolve host: github.com]' "
                   "'tests/test_cycle.py::test_transport_error[API rate limit exceeded]' "
                   "'ERROR tests/test_run_purpose.py'; exit 2")
        sha = self.declare({"schema_version": "1",
                            "commands": [{"name": "collectability", "run": listing}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "CODE_FAILURE")
        self.assertEqual(result["checks"][-1]["reason"], "COMMAND_FAILURE:collectability:exit2")
        self.assertRegex(result["signature"], r"^[0-9a-f]{64}$")

    def test_a_command_that_prints_an_outage_signature_is_still_a_code_failure(self) -> None:
        """The outage pattern is read on a failing setup step only. A command's
        output is repository-controlled, and here it hid a real failure."""
        sha = self.declare({"schema_version": "1", "commands": [
            {"name": "unit", "run": "echo 'Could not resolve host: pypi.org' >&2; exit 1"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "CODE_FAILURE")
        self.assertEqual(result["checks"][-1]["reason"], "COMMAND_FAILURE:unit:exit1")

    def test_a_setup_step_names_an_outage_signature_in_its_detail(self) -> None:
        for label, run, named in [
            ("outage", "echo 'Could not resolve host: pypi.org' >&2; exit 1", True),
            ("plain", "echo 'No matching distribution found for nosuchpkg' >&2; exit 1", False),
        ]:
            with self.subTest(label=label):
                sha = self.declare({"schema_version": "1",
                                    "setup": [{"name": "deps", "run": run}],
                                    "commands": [{"name": "unit", "run": "true"}]})
                check = self.run_smoke(sha)["checks"][-1]
                self.assertEqual(check["status"], "INFRA_UNAVAILABLE")
                # The reason is the same either way: a signature in the detail
                # never changes what the rail compares across runs.
                self.assertEqual(check["reason"], "SETUP_FAILED:deps")
                self.assertEqual("outage signature" in check["detail"], named, check["detail"])

    def test_timeout_makes_no_claim_about_the_code(self) -> None:
        sha = self.declare({"schema_version": "1", "timeout_seconds": 1,
                            "commands": [{"name": "hang", "run": "sleep 5"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertTrue(result["checks"][-1]["reason"].startswith("TIMEOUT"))

    def test_infrastructure_anywhere_outranks_a_code_failure(self) -> None:
        """A degraded measurement is not a confirmation."""
        sha = self.declare({"schema_version": "1", "commands": [
            {"name": "real", "run": "exit 2"},
            {"name": "missing", "run": "aeos-no-such-tool-xyz"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertTrue(any(c["status"] == "CODE_FAILURE" for c in result["checks"]))
        self.assertIsNone(result["signature"])

    # -- config validity ---------------------------------------------------
    def test_malformed_config_is_a_typed_code_failure(self) -> None:
        for label, document in [
            ("unparseable", "{not json"),
            ("not an object", "[1,2]"),
            ("missing version", '{"commands": []}'),
            ("wrong version", '{"schema_version": "9", "commands": []}'),
            ("boolean version", '{"schema_version": true, "commands": []}'),
            ("commands not a list", '{"schema_version": "1", "commands": "x"}'),
            ("entry not an object", '{"schema_version": "1", "commands": [1]}'),
            ("empty run", '{"schema_version": "1", "commands": [{"name": "a", "run": "  "}]}'),
            ("bad name", '{"schema_version": "1", "commands": [{"name": "a b", "run": "true"}]}'),
            ("no commands", '{"schema_version": "1", "setup": []}'),
            ("bad timeout", '{"schema_version": "1", "timeout_seconds": 0, '
                            '"commands": [{"name": "a", "run": "true"}]}'),
        ]:
            with self.subTest(label=label):
                self.setUp()
                result = self.run_smoke(self.declare(document))
                self.assertEqual(result["outcome"], "CODE_FAILURE")
                self.assertEqual(result["checks"][-1]["reason"], "SMOKE_CONFIG_INVALID")

    def test_duplicate_command_names_are_refused(self) -> None:
        """Two checks that cannot be told apart cannot be compared across runs."""
        result = self.run_smoke(self.declare({"schema_version": "1", "commands": [
            {"name": "a", "run": "true"}, {"name": "a", "run": "false"}]}))
        self.assertEqual(result["checks"][-1]["reason"], "SMOKE_CONFIG_INVALID")
        self.assertIn("duplicate", result["checks"][-1]["detail"])

    def test_integer_schema_version_is_accepted(self) -> None:
        result = self.run_smoke(self.declare({"schema_version": 1,
                                              "commands": [{"name": "a", "run": "true"}]}))
        self.assertEqual(result["outcome"], "PASS")

    def test_config_is_read_from_the_sha_not_from_the_working_tree(self) -> None:
        sha = self.declare({"schema_version": "1", "commands": [{"name": "ok", "run": "exit 0"}]})
        # Rewrite the working-tree copy with something that would fail. It is not
        # part of the committed SHA, so it must have no effect.
        self.repo.write(".github/aeos-smoke.json", json.dumps(
            {"schema_version": "1", "commands": [{"name": "boom", "run": "exit 9"}]}))
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual([c["id"] for c in result["checks"]][-1], "ok")

    def test_symlinked_config_is_refused(self) -> None:
        os.makedirs(os.path.join(self.repo.root, ".github"), exist_ok=True)
        os.symlink("../elsewhere.json", os.path.join(self.repo.root, ".github", "aeos-smoke.json"))
        result = self.run_smoke(self.repo.commit())
        self.assertEqual(result["checks"][-1]["reason"], "SMOKE_CONFIG_INVALID")
        self.assertIn("symlink", result["checks"][-1]["detail"])

    # -- derived defaults --------------------------------------------------
    def test_python_repository_derives_compile_and_ruff(self) -> None:
        self.repo.write("pkg/app.py", "x = 1\n")
        sha = self.repo.commit()
        plan = smoke.build_plan(self.repo.root, sha, smoke.Tools(), None)
        self.assertEqual([c["name"] for c in plan["commands"]], ["floor:compile", "floor:ruff"])
        self.assertEqual([s["name"] for s in plan["setup"]], ["install-ruff"])
        self.assertEqual(plan["source"], "floor:python")

    def test_vendored_trees_do_not_make_a_repository_python(self) -> None:
        """A syntax floor that fails on a checked-in dependency reports on
        somebody else's code, and here that would drive a revert."""
        self.repo.write("node_modules/dep/setup.py", "this is not python\n")
        self.repo.write("vendor/other/mod.py", "also not python(\n")
        sha = self.repo.commit()
        plan = smoke.build_plan(self.repo.root, sha, smoke.Tools(), None)
        self.assertEqual(plan["commands"], [])
        self.assertEqual(plan["source"], "none")

    def test_node_default_only_when_a_test_script_exists(self) -> None:
        self.repo.write("package.json", json.dumps({"name": "x", "scripts": {"build": "tsc"}}))
        sha = self.repo.commit()
        self.assertEqual(smoke.build_plan(self.repo.root, sha, smoke.Tools(), None)["commands"], [])

        self.repo.write("package.json", json.dumps({"name": "x", "scripts": {"test": "jest"}}))
        sha = self.repo.commit()
        plan = smoke.build_plan(self.repo.root, sha, smoke.Tools(), None)
        self.assertEqual(plan["source"], "derived:node")
        self.assertEqual([c["name"] for c in plan["commands"]], ["npm-test"])
        self.assertIn("npm install", plan["setup"][0]["run"])

    def test_node_lockfile_selects_npm_ci(self) -> None:
        self.repo.write("package.json", json.dumps({"scripts": {"test": "jest"}}))
        self.repo.write("package-lock.json", "{}")
        plan = smoke.build_plan(self.repo.root, self.repo.commit(), smoke.Tools(), None)
        self.assertIn("npm ci", plan["setup"][0]["run"])

    def test_compile_failure_names_the_files(self) -> None:
        self.repo.write("broken.py", "def f(:\n")
        sha = self.repo.commit()
        targets = smoke.build_plan(self.repo.root, sha, smoke.Tools(), None)["python_targets"]
        check = smoke.check_compile(self.repo.root, smoke.Tools(), 120, targets)
        self.assertEqual(check["status"], "CODE_FAILURE")
        self.assertEqual(check["reason"], "COMPILE_FAILURE")
        self.assertTrue(any("broken.py" in item for item in check["items"]), check["items"])

    def test_compile_ignores_vendored_trees(self) -> None:
        self.repo.write("node_modules/dep/broken.py", "def f(:\n")
        self.repo.write("ok.py", "x = 1\n")
        sha = self.repo.commit()
        targets = smoke.build_plan(self.repo.root, sha, smoke.Tools(), None)["python_targets"]
        self.assertEqual(targets, ["ok.py"])
        check = smoke.check_compile(self.repo.root, smoke.Tools(), 120, targets)
        self.assertEqual(check["status"], "PASS", check["items"])

    def test_untracked_and_generated_files_are_never_compiled(self) -> None:
        """A setup step can generate a dependency tree into the checkout; a
        syntax floor that fails on it reports on code the commit did not have."""
        self.repo.write("ok.py", "x = 1\n")
        sha = self.repo.commit()
        self.repo.write("generated_by_setup.py", "def f(:\n")   # untracked
        targets = smoke.build_plan(self.repo.root, sha, smoke.Tools(), None)["python_targets"]
        self.assertEqual(targets, ["ok.py"])
        check = smoke.check_compile(self.repo.root, smoke.Tools(), 120, targets)
        self.assertEqual(check["status"], "PASS", check["items"])

    def test_a_failed_ruff_install_does_not_suppress_the_syntax_floor(self) -> None:
        """compileall needs no installation, so a package-index outage must not
        stop it running -- and the run is still INFRA_UNAVAILABLE, on the basis
        of the check that actually could not run."""
        self.repo.write("app.py", "x = 1\n")
        sha = self.repo.commit()
        tools = FakeTools(present=set(), results={
            "pip install": (1, "", "Could not resolve host: pypi.org"),
            "compileall": (0, "", ""),
            "rev-parse": (0, sha + "\n", ""),
        })
        result = smoke.run_smoke(self.repo.root, sha, tools=tools)
        ids = [c["id"] for c in result["checks"]]
        self.assertIn(smoke.FLOOR_COMPILE_ID, ids, ids)
        self.assertEqual([c for c in result["checks"]
                          if c["id"] == smoke.FLOOR_COMPILE_ID][0]["status"], "PASS")
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertEqual([c for c in result["checks"]
                          if c["id"] == smoke.FLOOR_RUFF_ID][0]["reason"], "TOOL_MISSING:ruff")

    def test_a_declared_setup_failure_still_stops_everything(self) -> None:
        sha = self.declare({"schema_version": "1",
                            "setup": [{"name": "deps", "run": "exit 1"}],
                            "commands": [{"name": "unit", "run": "exit 0"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertNotIn("unit", [c["id"] for c in result["checks"]])

    def test_missing_ruff_is_infrastructure(self) -> None:
        check = smoke.check_ruff(self.repo.root, smoke.Tools(which=lambda n: None), 60, ["a.py"])
        self.assertEqual(check["status"], "INFRA_UNAVAILABLE")
        self.assertEqual(check["reason"], "TOOL_MISSING:ruff")

    def test_ruff_findings_are_stable_items(self) -> None:
        tools = FakeTools(present={"ruff"}, results={
            "ruff check": (1, "app.py:3:1: F821 undefined name `x`\nbad line\n", "")})
        check = smoke.check_ruff(self.repo.root, tools, 60, ["app.py"])
        self.assertEqual(check["reason"], "LINT_FAILURE")
        self.assertEqual(check["items"], ["app.py:3: F821"])

    def test_ruff_internal_error_is_infrastructure_not_a_defect(self) -> None:
        tools = FakeTools(present={"ruff"}, results={"ruff check": (2, "", "usage error")})
        check = smoke.check_ruff(self.repo.root, tools, 60, ["app.py"])
        self.assertEqual(check["status"], "INFRA_UNAVAILABLE")
        self.assertEqual(check["reason"], "RUFF_EXIT_2")

    # -- signature ---------------------------------------------------------
    def test_signature_is_identical_across_two_runs_of_the_same_commit(self) -> None:
        sha = self.declare({"schema_version": "1", "commands": [
            {"name": "unit", "run": "echo $RANDOM; date; exit 3"}]})
        first, second = self.run_smoke(sha), self.run_smoke(sha)
        self.assertEqual(first["outcome"], "CODE_FAILURE")
        self.assertEqual(first["signature"], second["signature"],
                         "process output must never contribute to the signature")

    def test_a_different_failure_produces_a_different_signature(self) -> None:
        a = self.run_smoke(self.declare({"schema_version": "1",
                                         "commands": [{"name": "unit", "run": "exit 3"}]}))
        self.setUp()
        b = self.run_smoke(self.declare({"schema_version": "1",
                                         "commands": [{"name": "unit", "run": "exit 4"}]}))
        self.assertNotEqual(a["signature"], b["signature"])

    def test_signature_ignores_infrastructure_checks(self) -> None:
        checks = [smoke._check("a", "CODE_FAILURE", "R", "d"),
                  smoke._check("b", "PASS", "PASS", "d")]
        with_infra = checks + [smoke._check("c", "INFRA_UNAVAILABLE", "TOOL_MISSING:x", "d")]
        self.assertEqual(smoke.signature(checks), smoke.signature(with_infra))

    def test_no_credential_reaches_a_repository_command(self) -> None:
        sha = self.declare({"schema_version": "1", "commands": [
            {"name": "peek", "run": "test -z \"${GH_TOKEN:-}${GITHUB_TOKEN:-}\""}]})
        os.environ["GH_TOKEN"] = "must-not-leak"
        os.environ["GITHUB_TOKEN"] = "must-not-leak"
        try:
            result = self.run_smoke(sha)
        finally:
            os.environ.pop("GH_TOKEN", None)
            os.environ.pop("GITHUB_TOKEN", None)
        self.assertEqual(result["outcome"], "PASS", [c for c in result["checks"]])

    def test_a_repository_command_cannot_forge_the_step_output(self) -> None:
        """Writing `outcome=PASS` into $GITHUB_OUTPUT would forge this rail's
        verdict, and write order is not a security property."""
        sha = self.declare({"schema_version": "1", "commands": [{
            "name": "evil",
            "run": 'echo outcome=PASS >> "${GITHUB_OUTPUT:-/dev/null}"; '
                   'echo INJECTED=1 >> "${GITHUB_ENV:-/dev/null}"; '
                   'echo /evil >> "${GITHUB_PATH:-/dev/null}"; exit 1',
        }]})
        out = os.path.join(self._tmp.name, "gh_output")
        env_file = os.path.join(self._tmp.name, "gh_env")
        path_file = os.path.join(self._tmp.name, "gh_path")
        for handle in (out, env_file, path_file):
            open(handle, "w").close()
        saved = {k: os.environ.get(k) for k in
                 ("GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STEP_SUMMARY")}
        os.environ.update({"GITHUB_OUTPUT": out, "GITHUB_ENV": env_file, "GITHUB_PATH": path_file})
        try:
            result = self.run_smoke(sha)
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(result["outcome"], "CODE_FAILURE")
        self.assertEqual(open(out).read(), "", "GITHUB_OUTPUT must not be reachable")
        self.assertEqual(open(env_file).read(), "", "GITHUB_ENV must not be reachable")
        self.assertEqual(open(path_file).read(), "", "GITHUB_PATH must not be reachable")

    def test_runner_credentials_are_withheld_from_repository_commands(self) -> None:
        for name in ("ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                     "GH_TOKEN", "GITHUB_TOKEN"):
            self.assertIn(name, smoke.WITHHELD_ENV)
        env = smoke.command_environment({"ACTIONS_RUNTIME_TOKEN": "x", "GITHUB_ENV": "y", "PATH": "/bin"})
        self.assertEqual(env, {"PATH": "/bin"})

    def test_a_backgrounded_writer_cannot_outlive_the_measurement(self) -> None:
        """`subprocess.run` waits for the direct child only, so a detached writer
        would still be running when the trusted reader reads the outcome."""
        marker = os.path.join(self._tmp.name, "written_after_the_fact")
        sha = self.declare({"schema_version": "1", "commands": [{
            "name": "detach",
            "run": f'(sleep 1; echo forged > {marker!r}) >/dev/null 2>&1 & exit 1',
        }]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "CODE_FAILURE")
        time.sleep(2.0)
        self.assertFalse(os.path.exists(marker),
                         "a backgrounded child survived the command it was started by")

    def test_a_timed_out_command_leaves_no_descendants(self) -> None:
        marker = os.path.join(self._tmp.name, "survived_the_timeout")
        sha = self.declare({"schema_version": "1", "timeout_seconds": 1, "commands": [{
            "name": "hang",
            "run": f'(sleep 3; echo forged > {marker!r}) & sleep 30',
        }]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        time.sleep(3.5)
        self.assertFalse(os.path.exists(marker),
                         "a descendant of a timed-out command kept running")

    # -- adoption defects -------------------------------------------------
    def _set_env(self, **values):
        saved = {k: os.environ.get(k) for k in values}
        os.environ.update({k: v for k, v in values.items() if v is not None})
        def restore():
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.addCleanup(restore)

    def test_a_repository_module_may_import_a_sibling_by_name(self) -> None:
        """The rail must not impose its own interpreter hardening on repository
        commands. A module run as a script importing a sibling is ordinary in the
        repository's own context, and PYTHONSAFEPATH turns it into a
        ModuleNotFoundError that has nothing to do with the code."""
        self.repo.write("pkg/split_integrity.py", "def check():\n    return 1\n")
        self.repo.write("pkg/tool.py", "import split_integrity\nassert split_integrity.check() == 1\n")
        sha = self.declare({"schema_version": "1",
                            "commands": [{"name": "unit", "run": "python3 pkg/tool.py"}]})
        # Exactly what the workflow sets job-wide today.
        self._set_env(PYTHONSAFEPATH="1", PYTHONDONTWRITEBYTECODE="1")
        # Assert on the declared command itself: the floor's ruff install needs a
        # package index, which this box does not have, so the run as a whole is
        # legitimately INFRA_UNAVAILABLE here. What defect 1 is about is whether
        # the repository's own command can run at all.
        report = self.run_smoke(sha)
        unit = [c for c in report["checks"] if c["id"] == "unit"]
        self.assertTrue(unit, [c["id"] for c in report["checks"]])
        self.assertEqual(unit[0]["status"], "PASS", unit[0])
        self.assertNotEqual(report["outcome"], "CODE_FAILURE")

    def test_the_policy_interpreter_keeps_its_own_hardening(self) -> None:
        """Dropping it from repository commands must not drop it from the
        interpreter it exists to protect."""
        self._set_env(PYTHONSAFEPATH="1", PYTHONDONTWRITEBYTECODE="1")
        self.assertEqual(os.environ.get("PYTHONSAFEPATH"), "1")
        leaked = sorted(set(smoke.command_environment()) & set(smoke.POLICY_INTERPRETER_ENV))
        self.assertEqual(leaked, [], f"policy hardening leaked into repository commands: {leaked}")

    def test_a_declaration_does_not_silently_remove_the_language_floor(self) -> None:
        """An adopter should have to work to remove the floor, not to keep it."""
        self.repo.write("app.py", "x = 1\n")
        sha = self.declare({"schema_version": "1",
                            "commands": [{"name": "unit", "run": "true"}]})
        tools = FakeTools(present={"ruff"}, results={"rev-parse": (0, sha + "\n", "")})
        report = smoke.run_smoke(self.repo.root, sha, tools=tools)
        ids = [c["id"] for c in report["checks"]]
        self.assertIn("floor:compile", ids, ids)
        self.assertIn("floor:ruff", ids, ids)
        self.assertIn("unit", ids, ids)

    def test_a_best_effort_setup_failure_does_not_decide_the_outcome(self) -> None:
        """The floor's ruff install is best effort. If it fails but ruff turns out
        to be present anyway, recording the install as an INFRA check would make
        the whole run INFRA_UNAVAILABLE on the strength of a step whose failure
        nothing depended on."""
        self.repo.write("app.py", "x = 1\n")
        sha = self.declare({"schema_version": "1", "commands": [{"name": "unit", "run": "true"}]})
        tools = FakeTools(present={"ruff"}, results={
            "pip install": (1, "", "Could not resolve host: pypi.org"),
            "rev-parse": (0, sha + "\n", ""),
        })
        report = smoke.run_smoke(self.repo.root, sha, tools=tools)
        self.assertEqual(report["outcome"], "PASS",
                         [(c["id"], c["status"]) for c in report["checks"]])
        self.assertNotIn("setup:install-ruff", [c["id"] for c in report["checks"]])
        self.assertIn("install-ruff", report["note"])
        self.assertIn("best effort", report["note"])

    def test_a_best_effort_failure_still_shows_through_the_dependent_check(self) -> None:
        """Not recording the install must not hide a floor that could not run."""
        self.repo.write("app.py", "x = 1\n")
        sha = self.declare({"schema_version": "1", "commands": [{"name": "unit", "run": "true"}]})
        tools = FakeTools(present=set(), results={
            "pip install": (1, "", "network down"),
            "rev-parse": (0, sha + "\n", ""),
        })
        report = smoke.run_smoke(self.repo.root, sha, tools=tools)
        self.assertEqual(report["outcome"], "INFRA_UNAVAILABLE")
        ruff = [c for c in report["checks"] if c["id"] == smoke.FLOOR_RUFF_ID][0]
        self.assertEqual(ruff["reason"], "TOOL_MISSING:ruff")

    def test_removing_the_floor_takes_an_explicit_opt_out(self) -> None:
        self.repo.write("app.py", "x = 1\n")
        sha = self.declare({"schema_version": "1", "language_floor": False,
                            "commands": [{"name": "unit", "run": "true"}]})
        tools = FakeTools(present={"ruff"}, results={"rev-parse": (0, sha + "\n", "")})
        report = smoke.run_smoke(self.repo.root, sha, tools=tools)
        ids = [c["id"] for c in report["checks"]]
        self.assertNotIn(smoke.FLOOR_COMPILE_ID, ids)
        self.assertNotIn(smoke.FLOOR_RUFF_ID, ids)
        self.assertEqual(report["source"], "declared")

    def test_a_non_boolean_language_floor_is_refused(self) -> None:
        for value in ('"false"', "0", "null"):
            with self.subTest(value=value):
                self.setUp()
                sha = self.declare('{"schema_version": "1", "language_floor": %s, '
                                   '"commands": [{"name": "a", "run": "true"}]}' % value)
                report = self.run_smoke(sha)
                self.assertEqual(report["outcome"], "CODE_FAILURE")
                self.assertEqual(report["checks"][-1]["reason"], "SMOKE_CONFIG_INVALID")

    def test_a_declared_name_can_never_collide_with_a_floor_id(self) -> None:
        """The floor ids carry a colon, which the declared-name grammar excludes,
        so the two namespaces cannot overlap however a repository names things."""
        for floor_id in (smoke.FLOOR_COMPILE_ID, smoke.FLOOR_RUFF_ID):
            self.assertIn(":", floor_id)
            with self.assertRaises(smoke.SmokeConfigError):
                smoke.parse_smoke_config(json.dumps({
                    "schema_version": "1",
                    "commands": [{"name": floor_id, "run": "true"}],
                }).encode())

    def test_the_source_names_both_halves_of_the_plan(self) -> None:
        self.repo.write("app.py", "x = 1\n")
        sha = self.declare({"schema_version": "1", "commands": [{"name": "unit", "run": "true"}]})
        tools = FakeTools(present={"ruff"}, results={"rev-parse": (0, sha + "\n", "")})
        self.assertEqual(smoke.run_smoke(self.repo.root, sha, tools=tools)["source"],
                         "floor:python+declared")

    def test_a_non_python_repository_that_declares_gets_only_what_it_declared(self) -> None:
        self.repo.write("main.go", "package main\n")
        sha = self.declare({"schema_version": "1", "commands": [{"name": "go-test", "run": "true"}]})
        report = self.run_smoke(sha)
        self.assertEqual(report["source"], "declared")
        self.assertEqual(report["outcome"], "PASS")

    def test_exit_codes_map_to_the_contract(self) -> None:
        self.assertEqual(smoke.EXIT, {"PASS": 0, "CODE_FAILURE": 1, "INFRA_UNAVAILABLE": 3})
        self.assertEqual(set(smoke.OUTCOMES), set(smoke.EXIT))

    def test_render_states_the_outcome_once(self) -> None:
        result = self.run_smoke(self.declare({"schema_version": "1",
                                              "commands": [{"name": "u", "run": "exit 1"}]}))
        text = smoke.render(result)
        self.assertIn("CODE_FAILURE", text)
        self.assertIn(result["signature"], text)


class DeclaredHistoryTestCase(unittest.TestCase):
    """A repository may declare that its checks need full history."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        os.makedirs(os.path.join(self._tmp.name, "origin"))
        self.repo = Repo(os.path.join(self._tmp.name, "origin"))
        self.repo.write("first.txt", "recorded\n")
        self.first = self.repo.commit("first")
        self.marker = os.path.join(self._tmp.name, "ran")

    def declare(self, history) -> str:
        document = {"schema_version": "1",
                    "commands": [{"name": "replay",
                                  "run": f"git cat-file -e {self.first} && touch {self.marker}"}]}
        if history is not None:
            document["history"] = history
        self.repo.write(".github/aeos-smoke.json", json.dumps(document))
        return self.repo.commit("declare")

    def shallow_clone(self, sha) -> str:
        clone = os.path.join(self._tmp.name, "shallow")
        git(self._tmp.name, "clone", "-q", "--depth", "1", f"file://{self.repo.root}", clone)
        self.assertEqual(git(clone, "rev-parse", "HEAD"), sha)
        self.assertEqual(git(clone, "rev-parse", "--is-shallow-repository"), "true")
        return clone

    def test_history_defaults_to_shallow_and_is_never_checked_then(self) -> None:
        sha = self.declare(None)
        self.assertEqual(smoke.declared_history(self.repo.root, sha), "shallow")
        result = smoke.run_smoke(self.repo.root, sha)
        self.assertNotIn("history", [c["id"] for c in result["checks"]])
        self.assertEqual(result["outcome"], "PASS")

    def test_full_history_present_runs_the_checks_that_read_it(self) -> None:
        sha = self.declare("full")
        self.assertEqual(smoke.declared_history(self.repo.root, sha), "full")
        result = smoke.run_smoke(self.repo.root, sha)
        self.assertEqual(result["outcome"], "PASS")
        history = [c for c in result["checks"] if c["id"] == "history"]
        self.assertEqual([c["status"] for c in history], ["PASS"])
        self.assertTrue(os.path.exists(self.marker))

    def test_full_history_missing_is_infrastructure_and_nothing_runs(self) -> None:
        """Without the guard the replay command fails, and that reads as the code's fault."""
        sha = self.declare("full")
        result = smoke.run_smoke(self.shallow_clone(sha), sha)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertEqual(result["checks"][-1]["reason"], "HISTORY_UNAVAILABLE")
        self.assertIsNone(result["signature"])
        self.assertFalse(os.path.exists(self.marker), "no command may run without the history")

    def test_a_shallow_declaration_runs_shallow(self) -> None:
        sha = self.declare("shallow")
        result = smoke.run_smoke(self.shallow_clone(sha), sha)
        self.assertEqual(result["outcome"], "CODE_FAILURE")
        self.assertEqual(result["checks"][-1]["reason"], "COMMAND_FAILURE:replay:exit1")

    def test_a_credential_left_by_the_fetch_stops_everything(self) -> None:
        sha = self.declare("full")
        for key in ("http.https://github.com/.extraheader", "includeIf.gitdir:/.path"):
            with self.subTest(key=key):
                git(self.repo.root, "config", "--local", key, "AUTHORIZATION: basic eA==")
                result = smoke.run_smoke(self.repo.root, sha)
                git(self.repo.root, "config", "--local", "--unset", key)
                self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
                self.assertEqual(result["checks"][-1]["reason"], "CHECKOUT_CREDENTIAL_KEPT")
                self.assertFalse(os.path.exists(self.marker))
        self.assertEqual(smoke.run_smoke(self.repo.root, sha)["outcome"], "PASS")

    def test_a_history_value_must_be_exact(self) -> None:
        for bad in ("FULL", "deep", "", True, 1, None, ["full"]):
            with self.subTest(history=bad):
                sha = self.declare(bad) if bad is not None else None
                if sha is None:
                    self.repo.write(".github/aeos-smoke.json", json.dumps(
                        {"schema_version": "1", "history": None,
                         "commands": [{"name": "replay", "run": "true"}]}))
                    sha = self.repo.commit("null")
                result = smoke.run_smoke(self.repo.root, sha)
                self.assertEqual(result["checks"][-1]["reason"], "SMOKE_CONFIG_INVALID")
                self.assertEqual(smoke.declared_history(self.repo.root, sha), "shallow")

    def test_an_unreadable_declaration_answers_shallow_and_the_smoke_reports_it(self) -> None:
        self.repo.write(".github/aeos-smoke.json", "{not json")
        sha = self.repo.commit("broken")
        self.assertEqual(smoke.declared_history(self.repo.root, sha), "shallow")
        self.assertEqual(smoke.run_smoke(self.repo.root, sha)["checks"][-1]["reason"],
                         "SMOKE_CONFIG_INVALID")

    def test_the_cli_prints_only_the_answer_and_runs_nothing(self) -> None:
        sha = self.declare("full")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = smoke.main(["--repo-root", self.repo.root, "--expected-sha", sha, "--declared-history"])
        self.assertEqual((rc, out.getvalue()), (0, "history=full\nbudget_minutes=20\n"))
        self.assertFalse(os.path.exists(self.marker))


class BudgetTestCase(unittest.TestCase):
    """A declared budget bounds the whole smoke, and the outcome is always written."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        os.makedirs(os.path.join(self._tmp.name, "repo"))
        self.repo = Repo(os.path.join(self._tmp.name, "repo"))

    def declare(self, **extra) -> str:
        document = {"schema_version": "1", "language_floor": False,
                    "commands": [{"name": "first", "run": "echo first"}, {"name": "second", "run": "echo second"},
                                 {"name": "third", "run": "echo third"}]}
        document.update(extra)
        self.repo.write(".github/aeos-smoke.json", json.dumps(document))
        return self.repo.commit()

    class Clock:
        def __init__(self):
            self.now, self.deadline = 1000.0, None

        def __call__(self):
            return self.now

    class Recording(FakeTools):
        """Records each timeout; running ``first`` moves the clock on by ``jump``."""

        def __init__(self, sha, results=None, jump=0.0):
            super().__init__(results={"rev-parse HEAD": (0, sha + "\n", ""), **(results or {})})
            self.clock, self.timeouts, self.jump = BudgetTestCase.Clock(), [], jump

        def run(self, argv, **kwargs):
            self.timeouts.append(kwargs.get("timeout"))
            if isinstance(argv, str) and "first" in argv:
                self.clock.now += self.jump
            return super().run(argv, **kwargs)

    def test_the_budget_is_a_declared_exact_integer(self) -> None:
        self.assertEqual(smoke.parse_smoke_config(json.dumps(
            {"schema_version": "1", "commands": [{"name": "u", "run": "true"}]}).encode())["budget_minutes"], 20)
        for good in (10, 90, 280):
            with self.subTest(budget=good):
                plan = smoke.parse_smoke_config(json.dumps({"schema_version": "1", "budget_minutes": good,
                                                            "commands": [{"name": "u", "run": "true"}]}).encode())
                self.assertEqual(plan["budget_minutes"], good)
        for bad in (9, 2, 281, 0, True, "90", 90.0, None):
            with self.subTest(budget=bad):
                with self.assertRaises(smoke.SmokeConfigError):
                    smoke.parse_smoke_config(json.dumps({"schema_version": "1", "budget_minutes": bad,
                                                         "commands": [{"name": "u", "run": "true"}]}).encode())

    def test_one_command_may_use_the_largest_budget(self) -> None:
        self.assertEqual(smoke.MAX_TIMEOUT_SECONDS, smoke.MAX_BUDGET_MINUTES * 60)
        plan = smoke.parse_smoke_config(json.dumps({"schema_version": "1", "timeout_seconds": 9000,
                                                    "commands": [{"name": "u", "run": "true"}]}).encode())
        self.assertEqual(plan["timeout_seconds"], 9000)

    def test_the_query_prints_the_declared_budget_or_the_default(self) -> None:
        for extra, expected in (({"budget_minutes": 150}, "150"), ({}, "20")):
            with self.subTest(extra=extra):
                sha = self.declare(**extra)
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    smoke.main(["--repo-root", self.repo.root, "--expected-sha", sha, "--declared-history"])
                self.assertIn(f"budget_minutes={expected}\n", out.getvalue())

    def test_a_spent_budget_stops_the_run_typed_and_runs_nothing_more(self) -> None:
        sha = self.declare(budget_minutes=10)
        tools = self.Recording(sha, jump=600)
        result = smoke.run_smoke(self.repo.root, sha, tools=tools)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertIsNone(result["signature"])
        self.assertEqual([c["id"] for c in result["checks"]][-2:], ["first", "second"])
        self.assertEqual(result["checks"][-1]["reason"], "SMOKE_BUDGET_EXHAUSTED")
        self.assertFalse(any("second" in call or "third" in call for call in tools.calls),
                         "nothing runs after the budget")
        self.assertIn("budget ran out", result["note"])

    def test_a_command_is_given_no_more_than_the_budget_left(self) -> None:
        sha = self.declare(budget_minutes=10, timeout_seconds=600)
        tools = self.Recording(sha)
        smoke.run_smoke(self.repo.root, sha, tools=tools)
        command_timeouts = tools.timeouts[-3:]
        self.assertTrue(all(t <= 10 * 60 - smoke.BUDGET_MARGIN_SECONDS for t in command_timeouts), command_timeouts)

    def test_a_command_cut_by_the_budget_is_typed_as_the_budget(self) -> None:
        sha = self.declare(budget_minutes=10, timeout_seconds=600)
        tools = self.Recording(sha, results={"echo first": subprocess.TimeoutExpired("echo first", 1)})
        result = smoke.run_smoke(self.repo.root, sha, tools=tools)
        self.assertEqual(result["checks"][-1]["id"], "first")
        self.assertEqual(result["checks"][-1]["reason"], "SMOKE_BUDGET_EXHAUSTED")

    def test_a_command_cut_by_its_own_timeout_keeps_its_reason(self) -> None:
        """The near miss: a timeout shorter than the budget left is the command's own."""
        sha = self.declare(budget_minutes=60, timeout_seconds=30)
        tools = self.Recording(sha, results={"echo first": subprocess.TimeoutExpired("echo first", 30)})
        result = smoke.run_smoke(self.repo.root, sha, tools=tools)
        first = next(c for c in result["checks"] if c["id"] == "first")
        self.assertEqual(first["reason"], "TIMEOUT:echo first")
        self.assertEqual(result["checks"][-1]["id"], "third", "an own timeout does not end the run")

    def test_every_floor_chunk_asks_the_budget_again(self) -> None:
        """A floor check runs one process per 400 files; each one is bounded by what is left."""
        clock = self.Clock()

        class Chunks(FakeTools):
            def __init__(self):
                super().__init__(present=("ruff",))
                self.clock, self.timeouts = clock, []

            def run(self, argv, **kwargs):
                allowed = kwargs["timeout"]
                self.timeouts.append((allowed, clock.deadline - clock.now))
                if allowed < 500:
                    clock.now += allowed
                    raise subprocess.TimeoutExpired(argv, allowed)
                clock.now += 500
                return subprocess.CompletedProcess(argv, 0, "", "")

        targets = [f"f{i}.py" for i in range(801)]
        for check in (smoke.check_compile, smoke.check_ruff):
            with self.subTest(check=check.__name__):
                clock.now, clock.deadline = 0.0, 1100.0
                tools = Chunks()
                result = check(self.repo.root, tools, smoke.Budget(clock.deadline, 600, clock), targets)
                self.assertEqual(result["reason"], "SMOKE_BUDGET_EXHAUSTED")
                self.assertEqual(len(tools.timeouts), 3)
                self.assertTrue(all(allowed <= left for allowed, left in tools.timeouts), tools.timeouts)
                self.assertLessEqual(clock.now, clock.deadline)

    def test_a_spent_budget_still_writes_the_outcome_and_exits_infra(self) -> None:
        sha = self.declare(budget_minutes=10)
        tools = self.Recording(sha, jump=600)
        out = os.path.join(self._tmp.name, "smoke.json")
        with mock.patch.object(smoke, "Tools", lambda: tools), contextlib.redirect_stdout(io.StringIO()):
            rc = smoke.main(["--repo-root", self.repo.root, "--expected-sha", sha, "--out", out])
        self.assertEqual(rc, 3)
        document = json.loads(pathlib.Path(out).read_text(encoding="utf-8"))
        self.assertEqual((document["outcome"], document["checks"][-1]["reason"]),
                         ("INFRA_UNAVAILABLE", "SMOKE_BUDGET_EXHAUSTED"))

    def test_the_smallest_budget_covers_the_reads_made_before_it_can_be_asked(self) -> None:
        """Identity, the declaration, the tree and the history checks run before
        the budget exists. Count them on a real full-history run, and prove the
        smallest budget's deadline leaves room for all of them at their bound."""
        sha = self.declare(budget_minutes=10, history="full")
        real_git, gitobject_calls = smoke.gitobject.run_git, []

        def counting(*args, **kwargs):
            gitobject_calls.append(args[1][0] if len(args) > 1 else kwargs)
            return real_git(*args, **kwargs)

        tools = self.Recording(sha, results={"is-shallow-repository": (0, "false\n", ""),
                                             "--get-regexp": (1, "", "")})
        with mock.patch.object(smoke.gitobject, "run_git", counting):
            smoke.run_smoke(self.repo.root, sha, tools=tools)
        before_commands = [c for c in tools.calls if not c.startswith("echo ")]
        self.assertEqual(len(gitobject_calls) + len(before_commands), smoke.PREFLIGHT_GIT_CALLS,
                         (gitobject_calls, before_commands))
        per_call = max(smoke.gitobject.GIT_TIMEOUT_SECONDS, 60)
        self.assertGreaterEqual(smoke.MIN_BUDGET_MINUTES * 60 - smoke.BUDGET_MARGIN_SECONDS,
                                smoke.PREFLIGHT_GIT_CALLS * per_call)

    def test_an_undeclared_budget_is_the_bound_every_smoke_had(self) -> None:
        sha = self.declare()
        limit = 20 * 60 - smoke.BUDGET_MARGIN_SECONDS
        for jump, outcome in ((limit - 5, "PASS"), (limit + 5, "INFRA_UNAVAILABLE")):
            with self.subTest(jump=jump):
                result = smoke.run_smoke(self.repo.root, sha, tools=self.Recording(sha, jump=jump))
                self.assertEqual(result["outcome"], outcome)


class FailureOutputTestCase(unittest.TestCase):
    """A failing command's output is kept beside the outcome, never inside it."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        os.makedirs(os.path.join(self._tmp.name, "repo"))
        self.repo = Repo(os.path.join(self._tmp.name, "repo"))

    def declare(self, document) -> str:
        self.repo.write(".github/aeos-smoke.json", json.dumps(document))
        return self.repo.commit()

    def test_output_is_kept_and_never_reaches_the_signature(self) -> None:
        sha = self.declare({"schema_version": "1", "commands": [
            {"name": "unit", "run": "date +%s%N; echo collection error >&2; exit 2"}]})
        first, second = [], []
        a = smoke.run_smoke(self.repo.root, sha, failure_output=first)
        b = smoke.run_smoke(self.repo.root, sha, failure_output=second)
        self.assertEqual(a["signature"], b["signature"])
        self.assertNotEqual(first[0]["stdout"], second[0]["stdout"])
        self.assertEqual((first[0]["check"], first[0]["exit"]), ("unit", 2))
        self.assertIn("collection error", first[0]["stderr"])
        self.assertNotIn("collection error", json.dumps(a))

    def test_a_failing_setup_step_keeps_its_output_and_a_passing_command_none(self) -> None:
        sha = self.declare({"schema_version": "1",
                            "setup": [{"name": "deps", "run": "echo no index >&2; exit 1"}],
                            "commands": [{"name": "unit", "run": "true"}]})
        kept = []
        smoke.run_smoke(self.repo.root, sha, failure_output=kept)
        self.assertEqual([(k["check"], k["stderr"]) for k in kept], [("setup:deps", "no index\n")])
        passing = []
        smoke.run_smoke(self.repo.root, self.declare(
            {"schema_version": "1", "commands": [{"name": "unit", "run": "echo fine"}]}),
            failure_output=passing)
        self.assertEqual(passing, [])

    def test_output_is_bounded_and_keeps_both_ends(self) -> None:
        head, tail = smoke.FAILURE_OUTPUT_HEAD_CHARS, smoke.FAILURE_OUTPUT_TAIL_CHARS
        text = "H" * head + "m" * 50000 + "T" * tail
        kept = smoke.bounded_output(text)
        self.assertTrue(kept.startswith("H" * head) and kept.endswith("T" * tail))
        self.assertIn("[... 50000 characters omitted ...]", kept)
        self.assertNotIn("m", kept.replace("omitted", ""))
        self.assertEqual(smoke.bounded_output("short"), "short")

    def test_credential_shapes_are_redacted_before_the_cut(self) -> None:
        token = "ghp_" + "A1b2" * 10
        self.assertEqual(smoke.bounded_output(f"x {token} y"), "x [REDACTED:github_token] y")
        head = smoke.FAILURE_OUTPUT_HEAD_CHARS
        straddling = "p" * (head - 10) + " " + token + " " + "q" * 60000
        kept = smoke.bounded_output(straddling)
        self.assertFalse("A1b2" in kept, "a cut through a token must not keep its prefix")

    def test_a_whole_private_key_block_is_redacted_terminated_or_not(self) -> None:
        begin, end = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
        body = "\n".join(["MIIEpAIBAAKCAQEA" + "x" * 48] * 20)
        whole = f"before\n{begin}\n{body}\n{end}\nafter"
        self.assertEqual(smoke.bounded_output(whole), "before\n[REDACTED:private_key_block]\nafter")
        self.assertEqual(smoke.bounded_output(f"x {begin}\n{body}"), "x [REDACTED:private_key_block]")
        head = smoke.FAILURE_OUTPUT_HEAD_CHARS
        straddling = "p" * (head - 40) + f"\n{begin}\n{body * 40}\n{end}\n" + "q" * 60000
        kept = smoke.bounded_output(straddling)
        self.assertNotIn("MIIEpAIBAAKCAQEA", kept)
        self.assertNotIn(end, kept)

    def test_the_credential_shapes_are_the_gates(self) -> None:
        import merge_ready_gate
        self.assertEqual([(n, p.pattern, p.flags) for n, p in smoke.CREDENTIAL_SHAPES],
                         [(n, p.pattern, p.flags) for n, p in merge_ready_gate.SECRET_SHAPES])

    def test_the_outcome_file_keeps_it_beside_the_decided_fields(self) -> None:
        sha = self.declare({"schema_version": "1",
                            "commands": [{"name": "unit", "run": "echo traceback line; exit 2"}]})
        out = os.path.join(self._tmp.name, "smoke.json")
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            rc = smoke.main(["--repo-root", self.repo.root, "--expected-sha", sha, "--out", out])
        self.assertEqual(rc, 1)
        document = json.loads(pathlib.Path(out).read_text(encoding="utf-8"))
        kept = document.pop("failure_output")
        self.assertEqual(kept, [{"check": "unit", "exit": 2, "stdout": "traceback line\n", "stderr": ""}])
        decided = smoke.run_smoke(self.repo.root, sha)
        for key in ("outcome", "signature", "source", "checks", "note"):
            self.assertEqual(document[key], decided[key], key)
        self.assertNotIn("traceback line", json.dumps(document))
        self.assertNotIn("traceback line", printed.getvalue(), "the job log never carries it")

    def test_a_passing_outcome_file_is_unchanged(self) -> None:
        sha = self.declare({"schema_version": "1", "commands": [{"name": "unit", "run": "echo fine"}]})
        out = os.path.join(self._tmp.name, "smoke.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(smoke.main(["--repo-root", self.repo.root, "--expected-sha", sha, "--out", out]), 0)
        document = json.loads(pathlib.Path(out).read_text(encoding="utf-8"))
        self.assertNotIn("failure_output", document)

    def test_a_passing_run_with_a_failed_best_effort_step_is_unchanged(self) -> None:
        """The floor's ruff install is best effort: it can fail inside a PASS."""
        sha = self.declare({"schema_version": "1", "commands": [{"name": "unit", "run": "true"}]})
        real = smoke.run_smoke

        def passing_with_a_kept_failure(*args, failure_output=None, **kwargs):
            result = real(*args, failure_output=failure_output, **kwargs)
            failure_output.append({"check": "setup:install-ruff", "exit": 1, "stdout": "", "stderr": "offline"})
            return result

        out = os.path.join(self._tmp.name, "smoke.json")
        with mock.patch.object(smoke, "run_smoke", passing_with_a_kept_failure), \
                contextlib.redirect_stdout(io.StringIO()) as printed:
            rc = smoke.main(["--repo-root", self.repo.root, "--expected-sha", sha, "--out", out])
        self.assertEqual(rc, 0)
        self.assertNotIn("failure_output", json.loads(pathlib.Path(out).read_text(encoding="utf-8")))
        self.assertNotIn("failure_output", printed.getvalue())

    def test_the_breaker_decides_the_same_with_or_without_it(self) -> None:
        import revert_controller
        sha = self.declare({"schema_version": "1", "commands": [{"name": "unit", "run": "echo x; exit 2"}]})
        kept = []
        result = smoke.run_smoke(self.repo.root, sha, failure_output=kept)
        with_output = {**result, "failure_output": kept}
        before = "0" * 40
        plain = revert_controller.decide(result, result, result, sha, before, self.repo.root)
        carried = revert_controller.decide(with_output, with_output, with_output, sha, before, self.repo.root)
        self.assertEqual(plain, carried)
        self.assertNotIn("failure_output", json.dumps(carried))

    def test_the_cut_never_exposes_a_shape_it_made(self) -> None:
        token = "ghp_" + "A1b2" * 11
        tail = smoke.FAILURE_OUTPUT_TAIL_CHARS
        joined = "H" * smoke.FAILURE_OUTPUT_HEAD_CHARS + "m" * 999 + "z" + token + " " + "t" * (tail - len(token) - 1)
        self.assertIn("z" + token, joined, "before the cut no word boundary precedes the token")
        self.assertNotIn(token, smoke.bounded_output(joined))


def _outcome(sha, checks, source="floor:python+declared"):
    """An outcome document shaped exactly as `run_smoke` writes one."""
    result = smoke.classify(checks)
    return {"schema_version": smoke.SCHEMA_VERSION, "check_context": smoke.CHECK_CONTEXT,
            "sha": sha, "outcome": result, "source": source, "note": "",
            "signature": smoke.signature(checks) if result == "CODE_FAILURE" else None,
            "checks": checks, "duration_seconds": 1.0}


#: What pytest 9.1.1 prints for ``--collect-only -q`` over a tree with a
#: module-name collision and an import error (checkout path neutralised).
PYTEST_COLLECTION_OUTPUT = """\
tests/a/test_cycle.py::test_ok
tests/test_fail.py::test_f

==================================== ERRORS ====================================
____________________ ERROR collecting tests/b/test_cycle.py ____________________
import file mismatch:
imported module 'test_cycle' has this __file__ attribute:
  /work/tests/a/test_cycle.py
which is not the same as the test file we want to collect:
  /work/tests/b/test_cycle.py
HINT: remove __pycache__ / .pyc files and/or use a unique basename for your test file modules
____________________ ERROR collecting tests/test_broken.py _____________________
E   ModuleNotFoundError: No module named 'nonexistent_mod'
=========================== short test summary info ============================
ERROR tests/b/test_cycle.py
ERROR tests/test_broken.py
!!!!!!!!!!!!!!!!!!! Interrupted: 2 errors during collection !!!!!!!!!!!!!!!!!!!!
2 tests collected, 2 errors in 0.03s
"""

#: What it prints for ``-q`` with ``CI`` set: a message's later lines follow its
#: item, unindented as often as not, and a parameter id may hold `` - ``.
PYTEST_RUN_OUTPUT = """\
FFF                                                                      [100%]
=================================== FAILURES ===================================
____________________________________ test_f ____________________________________
----------------------------- Captured stdout call -----------------------------
FAILED tests/captured.py::not_a_finding
=========================== short test summary info ============================
FAILED tests/test_fail.py::test_f - AssertionError: ERROR fake.py line
  FAILED x.py::y
assert 0
FAILED tests/test_fail.py::test_p[a b] - AssertionError: assert 'a b' == 'z'
FAILED tests/test_fail.py::test_p[c - d] - AssertionError: assert 'c - d' == 'z'
FAILED tests/test_fail.py::test_q[e] - assert [1] == [2]
4 failed in 0.01s
"""


class PytestItemsTestCase(unittest.TestCase):
    """The findings a failing declared command names, read from pytest's summary."""

    def test_collection_errors_are_named_by_path_and_typed_as_a_collection(self) -> None:
        items, kind = smoke.pytest_items(PYTEST_COLLECTION_OUTPUT, "")
        self.assertEqual(items, ["ERROR tests/b/test_cycle.py", "ERROR tests/test_broken.py"])
        self.assertEqual(kind, smoke.PYTEST_COLLECTION_ITEMS)

    def test_a_finished_session_names_each_failing_node_id_once(self) -> None:
        items, kind = smoke.pytest_items(PYTEST_RUN_OUTPUT)
        self.assertEqual(items, ["FAILED tests/test_fail.py::test_f",
                                 "FAILED tests/test_fail.py::test_p[a b]",
                                 "FAILED tests/test_fail.py::test_p[c - d]",
                                 "FAILED tests/test_fail.py::test_q[e]"])
        self.assertEqual(kind, smoke.PYTEST_ITEMS)

    def test_the_findings_are_read_from_either_stream_and_in_any_order(self) -> None:
        lines = PYTEST_RUN_OUTPUT.splitlines()
        start = lines.index("=========================== short test summary info ============================")
        shuffled = "\n".join(lines[:start + 1] + list(reversed(lines[start + 1:-1])) + lines[-1:])
        self.assertEqual(smoke.pytest_items("", shuffled), smoke.pytest_items(PYTEST_RUN_OUTPUT, ""))

    def test_only_the_summary_section_is_read(self) -> None:
        wrapped = (PYTEST_COLLECTION_OUTPUT + "collectability: collect exited 2\n"
                   "ERROR tests/after_the_session.py\n")
        self.assertEqual(smoke.pytest_items(wrapped), smoke.pytest_items(PYTEST_COLLECTION_OUTPUT))
        stats_only = PYTEST_RUN_OUTPUT + "FAILED tests/after_the_stats.py::t\n"
        stopped = PYTEST_COLLECTION_OUTPUT.replace(
            "!!!!\n2 tests collected", "!!!!\nERROR tests/after_the_stop.py\n2 tests collected")
        self.assertEqual(smoke.pytest_items(stopped), smoke.pytest_items(PYTEST_COLLECTION_OUTPUT))
        self.assertEqual(smoke.pytest_items(stats_only), smoke.pytest_items(PYTEST_RUN_OUTPUT))
        banner = PYTEST_RUN_OUTPUT.replace("4 failed in 0.01s", "==== warnings summary ====\n"
                                           "FAILED tests/a_warning.py::t\n4 failed in 0.01s")
        self.assertEqual(smoke.pytest_items(banner), smoke.pytest_items(PYTEST_RUN_OUTPUT))

    def test_output_with_no_summary_names_nothing(self) -> None:
        for text in ("", "Traceback (most recent call last):\nFAILED tests/x.py::t\n",
                     "ERROR: file or directory not found: tests/gone.py\n"):
            with self.subTest(text=text):
                self.assertEqual(smoke.pytest_items(text), ([], None))

    def test_a_session_stopped_early_for_another_reason_is_not_comparable(self) -> None:
        for stop in ("stopping after 1 failures", "KeyboardInterrupt",
                     "Interrupted: Test failed, continuing from this test next run."):
            with self.subTest(stop=stop):
                text = PYTEST_RUN_OUTPUT.replace("4 failed in 0.01s", f"!!!!! {stop} !!!!!\n4 failed in 0.01s")
                items, kind = smoke.pytest_items(text)
                self.assertTrue(items)
                self.assertIsNone(kind)

    def test_a_collection_stop_beside_another_stop_is_not_comparable(self) -> None:
        items, kind = smoke.pytest_items(PYTEST_COLLECTION_OUTPUT + "!!!!! KeyboardInterrupt !!!!!\n")
        self.assertEqual(len(items), 2)
        self.assertIsNone(kind)

    def test_two_sessions_are_not_comparable(self) -> None:
        items, kind = smoke.pytest_items(PYTEST_RUN_OUTPUT + PYTEST_COLLECTION_OUTPUT)
        self.assertEqual(len(items), 6)
        self.assertIsNone(kind)

    def test_more_findings_than_the_outcome_keeps_are_not_comparable(self) -> None:
        summary = "\n".join(f"FAILED tests/test_n.py::test_{n:04d}" for n in range(smoke.MAX_ITEMS + 1))
        items, kind = smoke.pytest_items(f"==== short test summary info ====\n{summary}\n")
        self.assertEqual(len(items), smoke.MAX_ITEMS + 1)
        self.assertIsNone(kind)
        _, kind = smoke.pytest_items("==== short test summary info ====\n"
                                     + "\n".join(summary.splitlines()[:smoke.MAX_ITEMS]) + "\n")
        self.assertEqual(kind, smoke.PYTEST_ITEMS)

    def test_a_finding_is_redacted_and_bounded(self) -> None:
        token = "ghp_" + "A1b2" * 10
        begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
        text = ("==== short test summary info ====\n"
                f"FAILED tests/test_s.py::test_seed[{token}]\n"
                f"FAILED tests/test_s.py::test_seed[{begin}x] - ValueError\n"
                f"FAILED tests/test_s.py::test_long[{'x' * 2000}]\n")
        items, _ = smoke.pytest_items(text)
        self.assertIn("FAILED tests/test_s.py::test_seed[[REDACTED:github_token]]", items)
        self.assertIn("FAILED tests/test_s.py::test_seed[[REDACTED:private_key_block]", items)
        self.assertNotIn("A1b2", json.dumps(items))
        self.assertTrue(all(len(i) <= smoke.MAX_ITEM_CHARS for i in items))

    def test_a_failing_command_carries_its_findings_into_the_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repo(tmp)
            repo.write("collect.txt", PYTEST_COLLECTION_OUTPUT)
            repo.write(".github/aeos-smoke.json", json.dumps({
                "schema_version": "1", "language_floor": False,
                "commands": [{"name": "collectability", "run": "date +%s%N; cat collect.txt >&2; exit 2"},
                             {"name": "plain", "run": "echo no summary here; exit 1"}]}))
            sha = repo.commit()
            first, second = smoke.run_smoke(tmp, sha), smoke.run_smoke(tmp, sha)
        self.assertEqual(first["signature"], second["signature"])
        collect, plain = first["checks"][-2], first["checks"][-1]
        self.assertEqual(collect["items"], ["ERROR tests/b/test_cycle.py", "ERROR tests/test_broken.py"])
        self.assertEqual(collect["item_kind"], smoke.PYTEST_COLLECTION_ITEMS)
        self.assertEqual(collect["reason"], "COMMAND_FAILURE:collectability:exit2")
        # Output pytest did not summarise still fails, exactly as before.
        self.assertEqual((plain["status"], plain["items"]), ("CODE_FAILURE", []))
        self.assertNotIn("item_kind", plain)
        self.assertEqual(first["outcome"], "CODE_FAILURE")

    def test_a_passing_command_names_nothing_whatever_it_prints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repo(tmp)
            repo.write("collect.txt", PYTEST_COLLECTION_OUTPUT)
            repo.write(".github/aeos-smoke.json", json.dumps({
                "schema_version": "1", "language_floor": False,
                "commands": [{"name": "unit", "run": "cat collect.txt"}]}))
            result = smoke.run_smoke(tmp, repo.commit())
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual(result["checks"][-1]["items"], [])
        self.assertNotIn("item_kind", result["checks"][-1])


class RepeatedInfraTestCase(unittest.TestCase):
    """The same INFRA reason on two consecutive commits is not an outage."""

    SHA = "1" * 40
    PARENT = "2" * 40
    IDENTITY = smoke._check("identity", "PASS", "PASS", "HEAD matches")
    HANG = smoke._check("collectability", "INFRA_UNAVAILABLE",
                        "TIMEOUT:python3 scripts/ci/smoke_collectability.py", "timed out")
    UNIT = smoke._check("unit", "PASS", "PASS", "exited 0")

    def test_the_same_infra_reason_on_consecutive_shas_is_promoted(self) -> None:
        current = _outcome(self.SHA, [self.IDENTITY, self.HANG, self.UNIT])
        before = json.dumps(current, sort_keys=True)
        promoted = smoke.promote_repeated_infra(
            current, _outcome(self.PARENT, [self.IDENTITY, self.HANG, self.UNIT]))
        self.assertEqual(promoted["outcome"], "CODE_FAILURE")
        hang = [c for c in promoted["checks"] if c["id"] == "collectability"][0]
        self.assertEqual(hang["status"], "CODE_FAILURE")
        self.assertEqual(hang["reason"],
                         "REPEATED_INFRA:TIMEOUT:python3 scripts/ci/smoke_collectability.py")
        self.assertEqual(promoted["signature"], smoke.signature(promoted["checks"]))
        self.assertRegex(promoted["signature"], r"^[0-9a-f]{64}$")
        self.assertEqual(promoted["promoted_from"], "INFRA_UNAVAILABLE")
        self.assertEqual(json.dumps(current, sort_keys=True), before, "the input is not mutated")

    def test_anything_short_of_the_same_reason_on_the_previous_commit_stays_an_outage(self) -> None:
        current = _outcome(self.SHA, [self.IDENTITY, self.HANG])
        other = smoke._check("collectability", "INFRA_UNAVAILABLE", "TOOL_MISSING:pytest", "")
        extra = smoke._check("unit", "INFRA_UNAVAILABLE", "TIMEOUT:unit", "")
        unproven = smoke._check("identity", "INFRA_UNAVAILABLE", "IDENTITY_MISMATCH", "")
        for label, this, previous in [
            ("a different reason", current, _outcome(self.PARENT, [self.IDENTITY, other])),
            ("a reason only the parent had", current,
             _outcome(self.PARENT, [self.IDENTITY, self.HANG, extra])),
            ("a reason only this commit has", _outcome(self.SHA, [self.IDENTITY, self.HANG, extra]),
             _outcome(self.PARENT, [self.IDENTITY, self.HANG])),
            ("a passing parent", current, _outcome(self.PARENT, [self.IDENTITY, self.UNIT])),
            ("the same commit again", current, _outcome(self.SHA, [self.IDENTITY, self.HANG])),
            ("a parent that ran a different plan", current,
             _outcome(self.PARENT, [self.IDENTITY, self.HANG], source="declared")),
            ("a parent whose identity is unproven", current, _outcome(self.PARENT, [unproven])),
            ("no parent at all", current, None),
            ("a parent whose outcome is not an outage", current,
             {**_outcome(self.PARENT, [self.IDENTITY, self.HANG]), "outcome": "CODE_FAILURE"}),
            ("no INFRA reason to repeat",
             {**_outcome(self.SHA, [self.IDENTITY]), "outcome": "INFRA_UNAVAILABLE"},
             {**_outcome(self.PARENT, [self.IDENTITY]), "outcome": "INFRA_UNAVAILABLE"}),
            ("a finding that is not text",
             _outcome(self.SHA, [self.IDENTITY, self.HANG,
                                 smoke._check("dup", "CODE_FAILURE", "X", "", items=["x"]),
                                 {**smoke._check("dup", "CODE_FAILURE", "X", ""), "items": [1]}]),
             _outcome(self.PARENT, [self.IDENTITY, self.HANG])),
            ("a check not shaped as the smoke writes one",
             _outcome(self.SHA, [self.IDENTITY,
                                 {k: v for k, v in self.HANG.items() if k != "items"}]),
             _outcome(self.PARENT, [self.IDENTITY, self.HANG])),
        ]:
            with self.subTest(label=label):
                self.assertIs(smoke.promote_repeated_infra(this, previous), this)

    def test_an_unproven_identity_is_never_promoted(self) -> None:
        """A run that could not prove which commit it measured is not "on a sha"."""
        unproven = smoke._check("identity", "INFRA_UNAVAILABLE", "IDENTITY_MISMATCH", "")
        current = _outcome(self.SHA, [unproven])
        self.assertIs(smoke.promote_repeated_infra(current, _outcome(self.PARENT, [unproven])),
                      current)


class AdoptionContractTestCase(unittest.TestCase):
    """The documented caller and the reusable workflow are one contract.

    A caller may only pass a secret the reusable declares in
    `on.workflow_call.secrets`, and that mismatch fails at run time in the
    adopting repository rather than here -- which is exactly the kind of break
    nobody sees until a revert is needed.
    """

    ROOT = pathlib.Path(__file__).resolve().parents[2]

    def setUp(self) -> None:
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest("PyYAML is unavailable")
        self.yaml = yaml
        self.workflow = yaml.safe_load(
            (self.ROOT / ".github/workflows/aeos-main-smoke.yml").read_text(encoding="utf-8"))
        doc = (self.ROOT / "aeos/main-smoke.md").read_text(encoding="utf-8")
        self.snippet = doc.split("```yaml", 1)[1].split("```", 1)[0]
        self.caller = yaml.safe_load(self.snippet)
        self.doc = doc

    def _on(self):
        return self.workflow[True] if True in self.workflow else self.workflow["on"]

    def _declared_secrets(self) -> dict:
        call = self._on().get("workflow_call") or {}
        return call.get("secrets") or {}

    def test_the_documented_caller_passes_only_declared_secrets(self) -> None:
        declared = set(self._declared_secrets())
        passed = set(self.caller["jobs"]["smoke"].get("secrets") or {})
        self.assertTrue(passed, "the caller should name the secret it needs")
        self.assertLessEqual(passed, declared,
                             "a caller may only pass a secret the reusable declares")

    def test_the_documented_caller_does_not_inherit_every_secret(self) -> None:
        # The snippet, not the prose around it, which explains why.
        self.assertNotIn("inherit", self.snippet)

    def test_the_revert_secret_is_optional_so_the_smoke_still_runs_without_it(self) -> None:
        declared = self._declared_secrets()
        self.assertIn("AEOS_REVERT_APP_PRIVATE_KEY", declared)
        self.assertFalse(declared["AEOS_REVERT_APP_PRIVATE_KEY"].get("required", False))

    def test_the_documented_caller_targets_this_reusable_workflow(self) -> None:
        uses = self.caller["jobs"]["smoke"]["uses"]
        self.assertTrue(uses.endswith(".github/workflows/aeos-main-smoke.yml@main"), uses)

    def test_the_reusable_is_callable_and_holds_the_decisions(self) -> None:
        self.assertEqual(list(self._on()), ["workflow_call"])
        # Concurrency must live here, not in the caller: that is what keeps the
        # caller small and the attribution rule in one place.
        self.assertEqual(self.workflow["concurrency"]["cancel-in-progress"], False)
        self.assertNotIn("concurrency", self.caller)

    def test_interpreter_hardening_is_never_set_job_wide(self) -> None:
        """Anything in a workflow- or job-level `env:` is inherited by every
        repository-declared command. Interpreter hardening set there is an
        adoption trap: it breaks ordinary repositories for a reason that has
        nothing to do with their code."""
        self.assertNotIn("env", self.workflow, "no workflow-level env")
        for name, job in self.workflow["jobs"].items():
            for key in (job.get("env") or {}):
                self.assertFalse(key.startswith("PYTHON"),
                                 f"{name} sets {key} job-wide")

    def test_the_policy_steps_do_set_their_own_hardening(self) -> None:
        """Dropping it job-wide must not drop it from the interpreter it protects."""
        guarded = 0
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                run = step.get("run") or ""
                if "policy/aeos/" in run:
                    env = step.get("env") or {}
                    self.assertEqual(env.get("PYTHONSAFEPATH"), "1", step.get("name"))
                    self.assertEqual(env.get("PYTHONDONTWRITEBYTECODE"), "1", step.get("name"))
                    guarded += 1
        self.assertGreaterEqual(guarded, 5, "every policy invocation must be guarded")

    def test_the_trusted_checkout_is_made_unwritable_where_repo_code_runs(self) -> None:
        for name, job in self.workflow["jobs"].items():
            runs_repo_code = any("main_smoke.py" in (s.get("run") or "") for s in job["steps"])
            if not runs_repo_code:
                continue
            self.assertTrue(
                any("chmod -R a-w policy" in (s.get("run") or "") for s in job["steps"]),
                f"{name} runs repository commands without locking the trusted rail")

    def test_the_breaker_also_runs_on_an_outage_so_a_repeat_can_be_seen(self) -> None:
        """The breaker promotes the same INFRA reason on a commit and its parent,
        so the rerun, the parent smoke and the decision must run on an outage too."""
        jobs = self.workflow["jobs"]
        for name in ("confirm", "parent-smoke", "auto-revert"):
            with self.subTest(job=name):
                self.assertIn("'CODE_FAILURE'", jobs[name]["if"])
                self.assertIn("'INFRA_UNAVAILABLE'", jobs[name]["if"])

    def test_only_the_revert_job_references_a_secret(self) -> None:
        for name, job in self.workflow["jobs"].items():
            if "secrets." in self.yaml.dump(job):
                self.assertEqual(name, "auto-revert")

    SMOKE_JOBS = ("main-smoke", "confirm", "parent-smoke")

    def test_each_smoke_job_fetches_declared_history_and_keeps_no_credential(self) -> None:
        for name in self.SMOKE_JOBS:
            with self.subTest(job=name):
                steps = self.workflow["jobs"][name]["steps"]
                names = [s.get("name") for s in steps]
                lock = next(i for i, s in enumerate(steps) if "chmod -R a-w policy" in (s.get("run") or ""))
                read = next(i for i, s in enumerate(steps) if s.get("id") == "history")
                fetch = read + 1
                smoke_at = next(i for i, s in enumerate(steps)
                                if "main_smoke.py" in (s.get("run") or "") and "--declared-history"
                                not in s["run"])
                self.assertLess(lock, read, names)
                self.assertLess(fetch, smoke_at, names)
                self.assertIn("--declared-history", steps[read]["run"])
                deepen = steps[fetch]
                # The shallow checkout of the commit under test is the first checkout, after the
                # runner-label refusal, which checks nothing out.
                first = next(s for s in steps if (s.get("uses") or "").startswith("actions/checkout@"))
                self.assertIs(first, steps[1], names)
                self.assertEqual(deepen["if"], "steps.history.outputs.history == 'full'")
                self.assertTrue(deepen["uses"].startswith("actions/checkout@"))
                self.assertEqual(deepen["uses"], first["uses"])
                self.assertEqual(deepen["with"]["fetch-depth"], 0)
                self.assertIs(deepen["with"]["persist-credentials"], False)
                self.assertEqual(deepen["with"]["path"], "repo")
                self.assertEqual(deepen["with"]["ref"], first["with"]["ref"],
                                 "the history must be the history of the commit under test")
                self.assertEqual(first["with"]["fetch-depth"], 1, "shallow stays the default")

    def test_a_failed_fetch_still_reaches_the_typed_smoke(self) -> None:
        for name in self.SMOKE_JOBS:
            with self.subTest(job=name):
                steps = self.workflow["jobs"][name]["steps"]
                read = next(i for i, s in enumerate(steps) if s.get("id") == "history")
                self.assertIs(steps[read + 1].get("continue-on-error"), True)

    def test_every_smoke_step_has_its_own_bound_and_the_job_is_only_a_backstop(self) -> None:
        bounded = "${{ fromJSON(steps.history.outputs.budget_minutes || '20') }}"
        for name in self.SMOKE_JOBS:
            with self.subTest(job=name):
                job = self.workflow["jobs"][name]
                self.assertEqual(job["timeout-minutes"], 360)
                limits = [s.get("timeout-minutes") for s in job["steps"]]
                self.assertNotIn(None, limits, "an unbounded step would inherit the 360-minute ceiling")
                runs_smoke = [s for s in job["steps"] if "main_smoke.py" in (s.get("run") or "")
                              and "--declared-history" not in s["run"]]
                self.assertEqual([s["timeout-minutes"] for s in runs_smoke], [bounded])
                deepen = [s["timeout-minutes"] for s in job["steps"]
                          if s.get("if") == "steps.history.outputs.history == 'full'"]
                others = [s["timeout-minutes"] for s in job["steps"] if s not in runs_smoke
                          and s.get("if") != "steps.history.outputs.history == 'full'"]
                self.assertEqual(sum(others) + 20, 58, "an undeclared smoke's worst case, as documented")
                # The largest budget with full history still leaves the job room to start and finish.
                self.assertLessEqual(sum(others) + sum(deepen) + smoke.MAX_BUDGET_MINUTES, 360 - 5)

    def test_no_new_artifact_or_step_output_carries_command_output(self) -> None:
        dumped = self.yaml.dump(self.workflow)
        self.assertNotIn("failure-output", dumped)
        self.assertNotIn("failure_output", dumped)


if __name__ == "__main__":
    unittest.main(verbosity=2)
