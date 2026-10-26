"""The shared gate and smoke workflows run on GitHub's hosted default and carry no runner-selection step.

Policy PR 53 (2026-10-26) added an Actions-variable runner selection and a new executable step to
aeos-merge-ready.yml. The organization's merge judge App re-derives its verdict from that workflow and accepts
exactly its four known steps, so every repository's verdict became UNKNOWN (POLICY_SHAPE_UNKNOWN) until the
selection was removed. This pins the removal: a new executable step in the gate workflow is a judge-contract change,
not a runner preference.
"""
import os
import unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GATE = os.path.join(ROOT, ".github", "workflows", "aeos-merge-ready.yml")
SMOKE = os.path.join(ROOT, ".github", "workflows", "aeos-main-smoke.yml")
#: The executable steps the merge judge App accepts, in order (agent-toolkit scripts/admission_shadow/core.py STEPS).
JUDGE_STEPS = (
    "Collect authenticated evidence (trusted; machine route)",
    "Gate",
    "Recheck an accepted protected change before this verdict publishes",
    "Recheck the operator's approval before this verdict publishes",
)


def _load(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class RunnerSelectionRemoved(unittest.TestCase):
    def test_the_gate_keeps_exactly_the_steps_the_judge_accepts(self):
        jobs = _load(GATE)["jobs"]
        (job,) = [j for j in jobs.values() if any(s.get("name") == JUDGE_STEPS[0] for s in j.get("steps", []))]
        executable = [s.get("name") for s in job["steps"] if "run" in s]
        self.assertEqual(executable, list(JUDGE_STEPS))

    def test_no_workflow_reads_a_runner_label_variable(self):
        for path in (GATE, SMOKE):
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            self.assertNotIn("RUNNER_LABELS", text, path)
            self.assertNotIn("aeos-cell", text, path)

    def test_every_job_runs_on_the_hosted_default(self):
        for path in (GATE, SMOKE):
            for name, job in _load(path)["jobs"].items():
                if "runs-on" in job:
                    self.assertEqual(job["runs-on"], "ubuntu-latest", f"{path}:{name}")


if __name__ == "__main__":
    unittest.main()
