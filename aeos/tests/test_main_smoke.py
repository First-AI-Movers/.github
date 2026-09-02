#!/usr/bin/env python3
"""Focused, deterministic tests for the AEOS post-merge smoke.

Plain ``unittest``; no third-party runner is required.

    python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

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

    def test_outage_shaped_output_reclassifies_a_failure_as_infrastructure(self) -> None:
        sha = self.declare({"schema_version": "1", "commands": [
            {"name": "unit", "run": "echo 'Could not resolve host: pypi.org' >&2; exit 1"}]})
        result = self.run_smoke(sha)
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertEqual(result["checks"][-1]["reason"], "INFRA_OUTPUT:unit")

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
        plan = smoke.derive_plan(self.repo.root, sha, smoke.Tools())
        self.assertEqual([c["name"] for c in plan["commands"]], ["compile", "ruff"])
        self.assertEqual([s["name"] for s in plan["setup"]], ["install-ruff"])
        self.assertEqual(plan["languages"], ["python"])

    def test_vendored_trees_do_not_make_a_repository_python(self) -> None:
        """A syntax floor that fails on a checked-in dependency reports on
        somebody else's code, and here that would drive a revert."""
        self.repo.write("node_modules/dep/setup.py", "this is not python\n")
        self.repo.write("vendor/other/mod.py", "also not python(\n")
        sha = self.repo.commit()
        plan = smoke.derive_plan(self.repo.root, sha, smoke.Tools())
        self.assertEqual(plan["languages"], [])

    def test_node_default_only_when_a_test_script_exists(self) -> None:
        self.repo.write("package.json", json.dumps({"name": "x", "scripts": {"build": "tsc"}}))
        sha = self.repo.commit()
        self.assertEqual(smoke.derive_plan(self.repo.root, sha, smoke.Tools())["languages"], [])

        self.repo.write("package.json", json.dumps({"name": "x", "scripts": {"test": "jest"}}))
        sha = self.repo.commit()
        plan = smoke.derive_plan(self.repo.root, sha, smoke.Tools())
        self.assertEqual(plan["languages"], ["node"])
        self.assertEqual([c["name"] for c in plan["commands"]], ["npm-test"])
        self.assertIn("npm install", plan["setup"][0]["run"])

    def test_node_lockfile_selects_npm_ci(self) -> None:
        self.repo.write("package.json", json.dumps({"scripts": {"test": "jest"}}))
        self.repo.write("package-lock.json", "{}")
        plan = smoke.derive_plan(self.repo.root, self.repo.commit(), smoke.Tools())
        self.assertIn("npm ci", plan["setup"][0]["run"])

    def test_compile_failure_names_the_files(self) -> None:
        self.repo.write("broken.py", "def f(:\n")
        sha = self.repo.commit()
        targets = smoke.derive_plan(self.repo.root, sha, smoke.Tools())["python_targets"]
        check = smoke.check_compile(self.repo.root, smoke.Tools(), 120, targets)
        self.assertEqual(check["status"], "CODE_FAILURE")
        self.assertEqual(check["reason"], "COMPILE_FAILURE")
        self.assertTrue(any("broken.py" in item for item in check["items"]), check["items"])

    def test_compile_ignores_vendored_trees(self) -> None:
        self.repo.write("node_modules/dep/broken.py", "def f(:\n")
        self.repo.write("ok.py", "x = 1\n")
        sha = self.repo.commit()
        targets = smoke.derive_plan(self.repo.root, sha, smoke.Tools())["python_targets"]
        self.assertEqual(targets, ["ok.py"])
        check = smoke.check_compile(self.repo.root, smoke.Tools(), 120, targets)
        self.assertEqual(check["status"], "PASS", check["items"])

    def test_untracked_and_generated_files_are_never_compiled(self) -> None:
        """A setup step can generate a dependency tree into the checkout; a
        syntax floor that fails on it reports on code the commit did not have."""
        self.repo.write("ok.py", "x = 1\n")
        sha = self.repo.commit()
        self.repo.write("generated_by_setup.py", "def f(:\n")   # untracked
        targets = smoke.derive_plan(self.repo.root, sha, smoke.Tools())["python_targets"]
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
        self.assertIn("compile", ids, ids)
        self.assertEqual([c for c in result["checks"] if c["id"] == "compile"][0]["status"], "PASS")
        self.assertEqual(result["outcome"], "INFRA_UNAVAILABLE")
        self.assertEqual([c for c in result["checks"] if c["id"] == "ruff"][0]["reason"],
                         "TOOL_MISSING:ruff")

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

    def test_exit_codes_map_to_the_contract(self) -> None:
        self.assertEqual(smoke.EXIT, {"PASS": 0, "CODE_FAILURE": 1, "INFRA_UNAVAILABLE": 3})
        self.assertEqual(set(smoke.OUTCOMES), set(smoke.EXIT))

    def test_render_states_the_outcome_once(self) -> None:
        result = self.run_smoke(self.declare({"schema_version": "1",
                                              "commands": [{"name": "u", "run": "exit 1"}]}))
        text = smoke.render(result)
        self.assertIn("CODE_FAILURE", text)
        self.assertIn(result["signature"], text)


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

    def test_only_the_revert_job_references_a_secret(self) -> None:
        for name, job in self.workflow["jobs"].items():
            if "secrets." in self.yaml.dump(job):
                self.assertEqual(name, "auto-revert")


if __name__ == "__main__":
    unittest.main(verbosity=2)
