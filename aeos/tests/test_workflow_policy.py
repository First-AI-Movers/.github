#!/usr/bin/env python3
"""Tests for the deterministic control-plane proof that replaced a human verdict.

Two obligations run through every case here.

**Two-sided.** Each rule gets a violation that must fire AND a near-miss that must
stay silent. A policy that only ever says "no" is not a floor, it is a wall, and a
policy that only ever says "yes" is decoration. The negative controls are chosen
to be the shapes the organization's real workflows actually use.

**Non-vacuous.** ``test_every_rule_fires`` walks the rule inventory itself, so a
rule added without a probe fails the suite rather than being silently untested.
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import control_plane_proof as cpp  # noqa: E402
import workflow_policy as wp  # noqa: E402

PIN = "a" * 40
WF = ".github/workflows/ci.yml"


def _wf(**overrides) -> dict:
    """A minimal compliant workflow -- the shape every negative control starts from."""
    doc = {
        "on": "push",
        "permissions": {"contents": "read"},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"uses": f"actions/checkout@{PIN}"}],
            }
        },
    }
    doc.update(overrides)
    return doc


class WorkflowPolicyTests(unittest.TestCase):
    # -- the baseline is genuinely clean --------------------------------
    def test_a_compliant_workflow_produces_no_findings(self) -> None:
        self.assertEqual(wp.evaluate_workflow(WF, _wf()), [])

    # -- rule 1: privileged trigger -------------------------------------
    def test_pull_request_target_fires_in_every_yaml_spelling(self) -> None:
        for on in (
            "pull_request_target",
            ["pull_request_target"],
            {"pull_request_target": None},
            {"push": None, "pull_request_target": {"types": ["opened"]}},
        ):
            with self.subTest(on=on):
                self.assertTrue(wp.evaluate_workflow(WF, _wf(on=on)))

    def test_the_on_key_is_read_through_the_yaml_boolean_alias(self) -> None:
        """`on` is YAML 1.1 true, so a safe loader keys it as True. Reading only
        the string "on" would make every trigger rule silently vacuous."""
        doc = _wf()
        doc[True] = doc.pop("on")
        doc[True] = {"pull_request_target": None}
        self.assertTrue(wp.evaluate_workflow(WF, doc))

    def test_ordinary_triggers_are_silent(self) -> None:
        for on in ("push", "pull_request", ["push", "merge_group"], {"schedule": []}):
            with self.subTest(on=on):
                self.assertEqual(wp.evaluate_workflow(WF, _wf(on=on)), [])

    # -- rule 2: declared, bounded permissions --------------------------
    def test_write_all_fires_as_a_string_and_as_a_scope(self) -> None:
        self.assertTrue(wp.evaluate_workflow(WF, _wf(permissions="write-all")))
        self.assertTrue(wp.evaluate_workflow(WF, _wf(permissions={"contents": "write-all"})))

    def test_undeclared_permissions_fire_only_when_neither_level_declares(self) -> None:
        doc = _wf()
        del doc["permissions"]
        self.assertTrue(wp.evaluate_workflow(WF, doc))
        doc["jobs"]["build"]["permissions"] = {"contents": "read"}
        self.assertEqual(wp.evaluate_workflow(WF, doc), [])

    def test_an_empty_permissions_map_is_the_strictest_grant_not_an_omission(self) -> None:
        self.assertEqual(wp.evaluate_workflow(WF, _wf(permissions={})), [])

    def test_named_write_scopes_are_permitted(self) -> None:
        doc = _wf(permissions={"contents": "read", "actions": "write"})
        self.assertEqual(wp.evaluate_workflow(WF, doc), [])

    # -- rule 3: action pinning -----------------------------------------
    def test_unpinned_third_party_uses_fires(self) -> None:
        for ref in ("some/action@v4", "some/action@main", "some/action", "a/b@1.2.3"):
            with self.subTest(ref=ref):
                doc = _wf()
                doc["jobs"]["build"]["steps"] = [{"uses": ref}]
                self.assertTrue(wp.evaluate_workflow(WF, doc))

    def test_pinned_local_docker_and_org_reusable_refs_are_silent(self) -> None:
        doc = _wf()
        doc["jobs"]["build"]["steps"] = [
            {"uses": f"actions/checkout@{PIN}"},
            {"uses": "./.github/actions/thing"},
            {"uses": "docker://alpine:3"},
        ]
        doc["jobs"]["reuse"] = {
            "uses": "First-AI-Movers/agent-toolkit/.github/workflows/x.yml@main"
        }
        self.assertEqual(wp.evaluate_workflow(WF, doc), [])

    def test_a_reusable_workflow_at_the_job_level_is_checked_too(self) -> None:
        doc = _wf()
        doc["jobs"]["reuse"] = {"uses": "outside/org/.github/workflows/x.yml@main"}
        self.assertTrue(wp.evaluate_workflow(WF, doc))

    # -- rule 4: script injection ---------------------------------------
    INJECTIONS = (
        "${{ github.head_ref }}",
        "${{ github.event.pull_request.title }}",
        "${{ github.event.pull_request.body }}",
        "${{ github.event.issue.title }}",
        "${{ github.event.comment.body }}",
        "${{ github.event.review.body }}",
        "${{ github.event.pull_request.head.ref }}",
        "${{ github.event.pull_request.head.label }}",
        "${{ github.event.head_commit.message }}",
        "${{ github.event.pull_request.user.login }}",
    )

    SAFE_CONTEXTS = (
        "${{ github.event.pull_request.head.sha }}",
        "${{ github.event.pull_request.number }}",
        "${{ github.event.pull_request.base.sha || 'main' }}",
        "${{ github.event_name }}",
        "${{ github.sha }}",
        "${{ github.event.before }}",
        "${{ github.event.pull_request.head.repo.full_name }}",
        "${{ github.ref_name }}",
        "${{ github.event.pull_request.base.ref }}",
    )

    def test_author_controlled_text_in_run_fires(self) -> None:
        for expr in self.INJECTIONS:
            with self.subTest(expr=expr):
                doc = _wf()
                doc["jobs"]["build"]["steps"] = [{"run": f"echo {expr}"}]
                self.assertTrue(wp.evaluate_workflow(WF, doc), expr)

    def test_constrained_contexts_in_run_are_silent(self) -> None:
        """These are the shapes the organization's real workflows use. Firing on
        them would reject the entire existing population for no safety gain."""
        for expr in self.SAFE_CONTEXTS:
            with self.subTest(expr=expr):
                doc = _wf()
                doc["jobs"]["build"]["steps"] = [{"run": f"echo {expr}"}]
                self.assertEqual(wp.evaluate_workflow(WF, doc), [], expr)

    def test_author_controlled_text_bound_to_env_is_silent(self) -> None:
        """The documented fix must actually be accepted, or the rule is unusable."""
        doc = _wf()
        doc["jobs"]["build"]["steps"] = [
            {"run": 'echo "$TITLE"', "env": {"TITLE": "${{ github.event.pull_request.title }}"}}
        ]
        self.assertEqual(wp.evaluate_workflow(WF, doc), [])

    # -- rule 5: secrets in run -----------------------------------------
    def test_a_secret_interpolated_into_run_fires_and_env_bound_does_not(self) -> None:
        doc = _wf()
        doc["jobs"]["build"]["steps"] = [{"run": "curl -H ${{ secrets.TOKEN }} x"}]
        self.assertTrue(wp.evaluate_workflow(WF, doc))
        doc["jobs"]["build"]["steps"] = [
            {"run": 'curl -H "$T" x', "env": {"T": "${{ secrets.TOKEN }}"}}
        ]
        self.assertEqual(wp.evaluate_workflow(WF, doc), [])

    # -- rule 6: reserved identity --------------------------------------
    def test_a_consumer_may_not_take_the_org_gate_path_or_check_name(self) -> None:
        doc = _wf(on="pull_request")
        self.assertTrue(
            wp.evaluate_workflow(wp.ORG_GATE_WORKFLOW_PATH, doc, "First-AI-Movers/agent-toolkit")
        )
        named = _wf()
        named["jobs"] = {"aeos-merge-ready": {"runs-on": "ubuntu-latest", "steps": []}}
        self.assertTrue(wp.evaluate_workflow(WF, named, "First-AI-Movers/agent-toolkit"))
        declared = _wf()
        declared["jobs"]["build"]["name"] = "aeos-merge-ready"
        self.assertTrue(wp.evaluate_workflow(WF, declared, "First-AI-Movers/agent-toolkit"))

    def test_the_policy_repository_owns_that_identity(self) -> None:
        doc = _wf(on="pull_request")
        self.assertEqual(
            wp.evaluate_workflow(wp.ORG_GATE_WORKFLOW_PATH, doc, "First-AI-Movers/.github"), []
        )

    def test_a_similarly_named_job_is_not_over_matched(self) -> None:
        doc = _wf()
        doc["jobs"] = {"aeos-merge-ready-repo": {"runs-on": "ubuntu-latest", "steps": []}}
        self.assertEqual(wp.evaluate_workflow(WF, doc, "First-AI-Movers/agent-toolkit"), [])

    # -- robustness ------------------------------------------------------
    def test_malformed_documents_never_raise(self) -> None:
        """Candidate bytes are adversarial. A parse the safe loader accepted can
        still be any shape at all, and a crash here is a gate outage."""
        for doc in (None, [], "text", 7, {"jobs": "not a map"}, {"jobs": {"a": None}},
                    {"jobs": {"a": {"steps": "no"}}}, {"jobs": {"a": {"steps": [None, 3]}}},
                    {"on": 5, "jobs": {}}, {"permissions": [1, 2], "jobs": {}}):
            with self.subTest(doc=doc):
                self.assertIsInstance(wp.evaluate_workflow(WF, doc), list)

    def test_path_classification(self) -> None:
        for path in (".github/workflows/a.yml", ".github/workflows/a.yaml",
                     ".github/actions/x/action.yml"):
            self.assertTrue(wp.is_workflow_path(path), path)
        for path in (".github/CODEOWNERS", ".github/dependabot.yml",
                     "workflows/a.yml", ".github/workflows/README.md"):
            self.assertFalse(wp.is_workflow_path(path), path)

    # -- the inventory itself is covered --------------------------------
    def test_every_rule_fires(self) -> None:
        """One probe per declared rule. A rule added without a probe fails here
        rather than shipping untested."""
        probes = {
            "FORBIDDEN_TRIGGERS": _wf(on={"pull_request_target": None}),
            "BROAD_PERMISSION_TOKENS": _wf(permissions="write-all"),
            "SHA_PIN_RE": {**_wf(), "jobs": {"b": {"steps": [{"uses": "x/y@v1"}]}},
                           "permissions": {"contents": "read"}},
            "INJECTION_CONTEXT_RE": {**_wf(), "jobs": {
                "b": {"steps": [{"run": "echo ${{ github.head_ref }}"}]}}},
            "SECRET_IN_RUN_RE": {**_wf(), "jobs": {
                "b": {"steps": [{"run": "echo ${{ secrets.X }}"}]}}},
            "RESERVED_CHECK_JOB_NAMES": {**_wf(), "jobs": {
                "aeos-merge-ready": {"steps": []}}},
        }
        declared = {
            name
            for name in vars(wp)
            if name.isupper() and name.endswith(("_TRIGGERS", "_TOKENS", "_RE", "_NAMES"))
            and name not in {"SHA_PIN_RE", "LOCAL_USES_RE", "DOCKER_USES_RE", "YAML_SUFFIXES"}
        } | {"SHA_PIN_RE"}
        self.assertEqual(declared - set(probes), set(), "a declared rule has no probe")
        for name, doc in probes.items():
            with self.subTest(rule=name):
                self.assertTrue(
                    wp.evaluate_workflow(WF, doc, "First-AI-Movers/agent-toolkit"),
                    f"{name} did not fire",
                )


class ControlPlaneProofTests(unittest.TestCase):
    # -- gate config ----------------------------------------------------
    def test_blanket_allowlist_entries_fire(self) -> None:
        for pattern in ("*", "**", "**/*", "*.*", "./*", "/*", "", "  "):
            with self.subTest(pattern=pattern):
                data = json.dumps(
                    {"schema_version": "1", "secret_shape_allowlist": [pattern]}
                ).encode()
                self.assertTrue(cpp.evaluate_gate_config(cpp.GATE_CONFIG_PATH, data))

    def test_a_narrow_allowlist_is_silent(self) -> None:
        data = json.dumps(
            {"schema_version": "1", "secret_shape_allowlist": ["tests/fixtures/**", "docs/*.md"]}
        ).encode()
        self.assertEqual(cpp.evaluate_gate_config(cpp.GATE_CONFIG_PATH, data), [])

    def test_gate_config_shape_errors_fire(self) -> None:
        for data in (b"{not json", b"[]", b'{"schema_version": "9"}',
                     b'{"schema_version": "1", "secret_shape_allowlist": "**"}'):
            with self.subTest(data=data):
                self.assertTrue(cpp.evaluate_gate_config(cpp.GATE_CONFIG_PATH, data))

    # -- smoke config ---------------------------------------------------
    def test_emptied_rail_declarations_fire(self) -> None:
        for payload in ({"schema_version": "1", "smoke_suites": []},
                        {"schema_version": "1", "compile_roots": []},
                        {"schema_version": "1", "smoke_suites": ["", "  "]},
                        {"schema_version": "1", "smoke_suites": "tests/"}):
            with self.subTest(payload=payload):
                self.assertTrue(
                    cpp.evaluate_smoke_config(cpp.SMOKE_CONFIG_PATH, json.dumps(payload).encode())
                )

    def test_a_populated_or_absent_rail_declaration_is_silent(self) -> None:
        populated = {"schema_version": "1", "smoke_suites": ["tests/"], "compile_roots": ["."]}
        self.assertEqual(
            cpp.evaluate_smoke_config(cpp.SMOKE_CONFIG_PATH, json.dumps(populated).encode()), []
        )
        # Absent keys mean "keep the built-in default", which is stricter, not weaker.
        self.assertEqual(
            cpp.evaluate_smoke_config(cpp.SMOKE_CONFIG_PATH, b'{"schema_version": "1"}'), []
        )

    # -- gate-source integrity ------------------------------------------
    def test_a_gutted_gate_source_fires_for_every_missing_declaration(self) -> None:
        findings = cpp.evaluate_policy_source("aeos/merge_ready_gate.py", b"x = 1\n")
        self.assertEqual(len(findings), len(cpp.REQUIRED_GATE_CONSTANTS))
        for name in cpp.REQUIRED_GATE_CONSTANTS:
            self.assertTrue(any(name in f for f in findings), name)

    def test_the_real_gate_source_satisfies_its_own_floor(self) -> None:
        """The floor must pass the file it protects, or it is unshippable."""
        source = (pathlib.Path(__file__).resolve().parents[1] / "merge_ready_gate.py").read_bytes()
        self.assertEqual(cpp.evaluate_policy_source("aeos/merge_ready_gate.py", source), [])

    def test_the_floor_reads_the_candidate_without_executing_it(self) -> None:
        """ast.parse builds a tree and runs nothing: a candidate whose import-time
        body would raise is still measurable."""
        source = (
            b"import nonexistent_module_" + b"x" * 20 + b"\n"
            b"raise SystemExit('detonate')\n"
            b"CONTROL_PLANE_PREFIXES = ()\nCONTROL_PLANE_PATHS = ()\n"
            b"SECRET_SHAPES = ()\nREASON_CODES = ()\n"
        )
        self.assertEqual(cpp.evaluate_policy_source("aeos/merge_ready_gate.py", source), [])

    def test_unparseable_gate_source_fires(self) -> None:
        self.assertTrue(cpp.evaluate_policy_source("aeos/merge_ready_gate.py", b"def (\n"))

    def test_other_policy_files_only_need_to_parse(self) -> None:
        self.assertEqual(cpp.evaluate_policy_source("aeos/helper.py", b"x = 1\n"), [])
        self.assertEqual(cpp.evaluate_policy_source("aeos/README.md", b"not python ("), [])

    # -- deletion --------------------------------------------------------
    def test_deletion_is_operator_governed_only_in_the_policy_repository(self) -> None:
        self.assertTrue(
            cpp.evaluate_control_plane_deletion(
                "aeos/merge_ready_gate.py", "First-AI-Movers/.github"
            )
        )
        self.assertEqual(
            cpp.evaluate_control_plane_deletion(
                ".github/workflows/ci.yml", "First-AI-Movers/agent-toolkit"
            ),
            [],
        )

    # -- dispatch --------------------------------------------------------
    def test_the_lane_routes_each_surface_to_its_own_floor(self) -> None:
        repo = "First-AI-Movers/agent-toolkit"
        wf = cpp.evaluate_control_plane_file(
            WF, b"on: push\npermissions: write-all\njobs: {}\n", repo
        )
        self.assertEqual({c for c, _ in wf}, {wp.WORKFLOW_POLICY_VIOLATION})

        cfg = cpp.evaluate_control_plane_file(
            cpp.GATE_CONFIG_PATH,
            b'{"schema_version": "1", "secret_shape_allowlist": ["**"]}',
            repo,
        )
        self.assertEqual({c for c, _ in cfg}, {cpp.CONTROL_PLANE_PROOF_FAILED})

        smoke = cpp.evaluate_control_plane_file(
            cpp.SMOKE_CONFIG_PATH, b'{"schema_version": "1", "smoke_suites": []}', repo
        )
        self.assertEqual({c for c, _ in smoke}, {cpp.CONTROL_PLANE_PROOF_FAILED})

        # The gate source is policy only in the policy repository.
        self.assertEqual(
            cpp.evaluate_control_plane_file("aeos/merge_ready_gate.py", b"x = 1\n", repo), []
        )
        self.assertTrue(
            cpp.evaluate_control_plane_file(
                "aeos/merge_ready_gate.py", b"x = 1\n", "First-AI-Movers/.github"
            )
        )

    def test_unreadable_workflow_yaml_fails_closed(self) -> None:
        out = cpp.evaluate_control_plane_file(WF, b"a: b\n  c: d\n :: bad\n", "r")
        self.assertEqual({c for c, _ in out}, {cpp.CONTROL_PLANE_PROOF_FAILED})


if __name__ == "__main__":
    unittest.main(verbosity=2)
