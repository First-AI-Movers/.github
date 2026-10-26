#!/usr/bin/env python3
"""Where the organization rails run: GitHub-hosted by default, an AEOS Development Cell on request.

The reusable smoke takes ``inputs.runner_labels``; the Required Workflow gate, which receives no caller
inputs, reads ``vars.AEOS_MERGE_READY_RUNNER_LABELS``. Each guard has a violation that must be refused and
a near-miss that must stay admitted:

* ``runs-on`` maps only the exact Cell value to the Cell literal and everything else to ``ubuntu-latest``,
  so no value can name a runner itself;
* a fork's pull request never reaches a Cell;
* the first step of every routed job fails any value outside the two-entry allowlist, typed;
* the job that holds the revert App key is never routed.

    python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import merge_ready_gate as gate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
HOSTED = '["ubuntu-latest"]'
CELL = '["self-hosted","linux","x64","aeos-cell"]'
REFUSE_STEP = "Refuse a runner label set outside the allowlist"
SMOKE_SOURCE = "inputs.runner_labels"
GATE_SOURCE = "vars.AEOS_MERGE_READY_RUNNER_LABELS"
ROUTED_SMOKE_JOBS = ("main-smoke", "confirm", "parent-smoke")
UNROUTED_SMOKE_JOBS = ("auto-revert",)


def route(source: str) -> str:
    return (f"${{{{ fromJSON({source} == '{CELL}' && (!github.event.pull_request "
            f"|| github.event.pull_request.head.repo.full_name == github.repository) "
            f"&& '{CELL}' || '{HOSTED}') }}}}")


# Values that must be refused, each a near-miss of an allowed one.
REFUSED = (
    "",
    "ubuntu-latest",
    '"ubuntu-latest"',
    '["ubuntu-latest" ]',
    '["ubuntu-latest"]\n',
    '["ubuntu-22.04"]',
    '["self-hosted", "linux", "x64", "aeos-cell"]',
    '["SELF-HOSTED","LINUX","X64","AEOS-CELL"]',
    '["self-hosted","linux","x64"]',
    '["self-hosted","linux","x64","aeos-cell","gpu"]',
    '["linux","self-hosted","x64","aeos-cell"]',
    '["self-hosted","linux","x64","attacker"]',
    '["self-hosted"]',
    "$(touch pwned)",
)


class _CaseInsensitive(str):
    """GitHub expression ``==`` compares strings ignoring case."""

    def __eq__(self, other):  # noqa: D401
        return isinstance(other, str) and self.lower() == other.lower()

    __hash__ = str.__hash__


def evaluate_route(expression: str, context: dict) -> list:
    """A model of GitHub's evaluation of exactly this routing expression ([INFERRED] faithful to the platform).

    It translates ``!``, ``&&``, ``||`` and context paths into Python, which shares the short-circuit
    value semantics the expression relies on; ``!`` here never precedes a comparison, so Python's lower
    ``not`` precedence does not change the result.
    """
    inner = expression.strip()
    assert inner.startswith("${{ fromJSON(") and inner.endswith(") }}"), inner
    inner = inner[len("${{ fromJSON("):-len(") }}")]

    def lookup(path: str):
        value = context
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        return _CaseInsensitive(value) if isinstance(value, str) else value

    pieces = inner.split("'")
    for index in range(0, len(pieces), 2):   # outside string literals only
        code = pieces[index].replace("&&", " and ").replace("||", " or ").replace("!", " not ")
        pieces[index] = re.sub(r"\b((?:inputs|vars|github)(?:\.[A-Za-z0-9_]+)+)", r"_lookup('\1')", code)
    result = eval("'".join(pieces), {"__builtins__": {}}, {"_lookup": lookup})  # noqa: S307 - our own bytes
    return json.loads(result)


def _load(name: str) -> dict:
    try:
        import yaml
    except ImportError:  # pragma: no cover
        raise unittest.SkipTest("PyYAML is unavailable")
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _on(document: dict) -> dict:
    return document[True] if True in document else document["on"]


class RoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.smoke = _load("aeos-main-smoke.yml")
        self.gate = _load("aeos-merge-ready.yml")

    def test_the_smoke_declares_an_optional_input_whose_default_is_today(self) -> None:
        declared = _on(self.smoke)["workflow_call"]["inputs"]["runner_labels"]
        self.assertEqual(declared["type"], "string")
        self.assertIs(declared.get("required", False), False)
        self.assertEqual(declared["default"], HOSTED)

    def test_every_smoke_job_is_either_routed_or_deliberately_hosted(self) -> None:
        # A new job forces a decision here rather than inheriting one silently.
        self.assertEqual(set(self.smoke["jobs"]), set(ROUTED_SMOKE_JOBS) | set(UNROUTED_SMOKE_JOBS))
        for name in ROUTED_SMOKE_JOBS:
            with self.subTest(job=name):
                self.assertEqual(self.smoke["jobs"][name]["runs-on"], route(SMOKE_SOURCE))
        for name in UNROUTED_SMOKE_JOBS:
            with self.subTest(job=name):
                # the job that holds the revert App key never leaves a fresh GitHub-hosted VM
                self.assertEqual(self.smoke["jobs"][name]["runs-on"], "ubuntu-latest")

    def test_the_gate_is_routed_by_its_variable_only(self) -> None:
        self.assertEqual(list(self.gate["jobs"]), ["aeos-merge-ready"])
        self.assertEqual(self.gate["jobs"]["aeos-merge-ready"]["runs-on"], route(GATE_SOURCE))
        self.assertNotIn("workflow_call", _on(self.gate), "a Required Workflow takes no caller inputs")

    def test_the_expression_selects_only_the_two_literals(self) -> None:
        push = {"event_name": "push", "repository": "First-AI-Movers/x", "event": {}}
        same_repo_pr = {"event_name": "pull_request", "repository": "First-AI-Movers/x",
                        "event": {"pull_request": {"head": {"repo": {"full_name": "First-AI-Movers/x"}}}}}
        fork_pr = {"event_name": "pull_request", "repository": "First-AI-Movers/x",
                   "event": {"pull_request": {"head": {"repo": {"full_name": "someone/x"}}}}}
        deleted_fork_pr = {"event_name": "pull_request", "repository": "First-AI-Movers/x",
                           "event": {"pull_request": {"head": {"repo": None}}}}
        merge_group = {"event_name": "merge_group", "repository": "First-AI-Movers/x",
                       "event": {"merge_group": {"head_sha": "a" * 40}}}
        # The deployed bytes are evaluated, not this file's copy of them.
        deployed = [(f"aeos-main-smoke/{name}", self.smoke["jobs"][name]["runs-on"], "inputs", "runner_labels")
                    for name in ROUTED_SMOKE_JOBS]
        deployed.append(("aeos-merge-ready", self.gate["jobs"]["aeos-merge-ready"]["runs-on"], "vars",
                         "AEOS_MERGE_READY_RUNNER_LABELS"))
        for where, expression, holder, key in deployed:

            def run_on(value, github):
                context = {"github": github, holder: {} if value is None else {key: value}}
                return evaluate_route(expression, context)

            with self.subTest(where=where):
                self.assertEqual(run_on(None, push), ["ubuntu-latest"])
                self.assertEqual(run_on(HOSTED, push), ["ubuntu-latest"])
                self.assertEqual(run_on(CELL, push), json.loads(CELL))
                self.assertEqual(run_on(CELL, same_repo_pr), json.loads(CELL))
                self.assertEqual(run_on(CELL, merge_group), json.loads(CELL))
                # a fork's pull request never reaches a Cell, whatever the knob says
                self.assertEqual(run_on(CELL, fork_pr), ["ubuntu-latest"])
                self.assertEqual(run_on(CELL, deleted_fork_pr), ["ubuntu-latest"])
                for value in REFUSED:
                    # never a runner the value names itself: only one of the two literals
                    self.assertIn(run_on(value, push), (["ubuntu-latest"], json.loads(CELL)), value)
                    if value.lower() != CELL.lower():
                        self.assertEqual(run_on(value, push), ["ubuntu-latest"], value)


class RefusalStepTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("bash") is None:  # pragma: no cover
            self.skipTest("bash is unavailable")
        self.smoke = _load("aeos-main-smoke.yml")
        self.gate = _load("aeos-merge-ready.yml")

    def routed(self):
        for name in ROUTED_SMOKE_JOBS:
            yield f"aeos-main-smoke/{name}", self.smoke["jobs"][name], SMOKE_SOURCE, "AEOS_MAIN_SMOKE: RUNNER_LABELS_REFUSED"
        yield ("aeos-merge-ready", self.gate["jobs"]["aeos-merge-ready"], GATE_SOURCE,
               "AEOS_MERGE_READY_RESULT: FAIL GATE_CONFIG_INVALID")

    @staticmethod
    def run_step(step: dict, value: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as temp:
            summary = pathlib.Path(temp) / "summary.md"
            summary.write_text("")
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "AEOS_RUNNER_LABELS": value,
                   "GITHUB_STEP_SUMMARY": str(summary)}
            # GitHub's default for an unspecified Linux shell is `bash -e {0}`.
            proc = subprocess.run(["bash", "-e", "-c", step["run"]], env=env, cwd=temp,
                                  capture_output=True, text=True, timeout=30)
            return proc.returncode, proc.stdout, summary.read_text()

    def test_the_refusal_is_the_first_step_and_reads_the_routing_source(self) -> None:
        for where, job, source, _line in self.routed():
            with self.subTest(where=where):
                first = job["steps"][0]
                self.assertEqual(first["name"], REFUSE_STEP)
                self.assertNotIn("uses", first)
                bound = first["env"]["AEOS_RUNNER_LABELS"]
                self.assertIn(source, bound)
                # the value reaches the shell as data, never interpolated into the script
                self.assertNotIn("${{", first["run"])

    def test_the_gate_reads_an_unset_variable_as_the_hosted_default(self) -> None:
        bound = self.gate["jobs"]["aeos-merge-ready"]["steps"][0]["env"]["AEOS_RUNNER_LABELS"]
        self.assertEqual(bound, f"${{{{ {GATE_SOURCE} || '{HOSTED}' }}}}")

    def test_both_allowed_values_pass_and_every_near_miss_is_refused_typed(self) -> None:
        for where, job, _source, line in self.routed():
            step = job["steps"][0]
            for value in (HOSTED, CELL):
                with self.subTest(where=where, value=value):
                    self.assertEqual(self.run_step(step, value), (0, "", ""))
            for value in REFUSED:
                with self.subTest(where=where, value=value):
                    code, out, summary = self.run_step(step, value)
                    self.assertEqual(code, 1)
                    self.assertEqual(out.splitlines()[0], line)
                    self.assertIn(line, summary)

    def test_the_gate_refusal_is_in_the_closed_vocabulary(self) -> None:
        self.assertIn(gate.GATE_CONFIG_INVALID, gate.REASON_CODES)


class ContractDocTests(unittest.TestCase):
    def test_the_documented_cell_caller_passes_only_declared_inputs(self) -> None:
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest("PyYAML is unavailable")
        doc = (ROOT / "aeos" / "main-smoke.md").read_text(encoding="utf-8")
        blocks = [b.split("```", 1)[0] for b in doc.split("```yaml")[1:]]
        cell_callers = [yaml.safe_load(b) for b in blocks if "runner_labels" in b]
        self.assertEqual(len(cell_callers), 1)
        caller = cell_callers[0]["jobs"]["smoke"]
        declared = _on(_load("aeos-main-smoke.yml"))["workflow_call"]["inputs"]
        self.assertLessEqual(set(caller["with"]), set(declared))
        self.assertEqual(caller["with"]["runner_labels"], CELL)
        self.assertTrue(caller["uses"].endswith(".github/workflows/aeos-main-smoke.yml@main"))

    def test_the_gate_contract_names_the_variable_and_the_cell_value(self) -> None:
        readme = (ROOT / "aeos" / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"AEOS_MERGE_READY_RUNNER_LABELS = {CELL}", readme)


if __name__ == "__main__":
    unittest.main()
