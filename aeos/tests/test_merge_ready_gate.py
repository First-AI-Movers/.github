#!/usr/bin/env python3
"""Focused, deterministic tests for the AEOS organization merge-ready gate.

Plain ``unittest``; no third-party test runner is required.

    python3 -m unittest discover -s aeos/tests -v

Secret-shape fixtures are assembled from fragments at runtime so that no literal
credential-shaped string is ever committed to this public repository (and so the
gate does not flag its own test suite).
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import merge_ready_gate as gate  # noqa: E402

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
    proc = subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        check=True,
        env=GIT_ENV,
    )
    return proc.stdout.decode().strip()


class Repo:
    """A throwaway git working tree standing in for the candidate checkout."""

    def __init__(self, root: str) -> None:
        self.root = root
        git(root, "init", "-q", "-b", "main")
        self.write("README.md", "# fixture\n")
        self.base = self.commit("base")

    def write(self, rel: str, content: str) -> None:
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(rel) else None
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def write_bytes(self, rel: str, content: bytes) -> None:
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(rel) else None
        with open(path, "wb") as handle:
            handle.write(content)

    def remove(self, rel: str) -> None:
        os.unlink(os.path.join(self.root, rel))

    def commit(self, message: str) -> str:
        git(self.root, "add", "-A")
        return self.commit_index(message)

    def commit_index(self, message: str) -> str:
        """Commit whatever is already staged, without `git add -A` -- which would
        drop a gitlink whose directory does not exist on disk."""
        git(self.root, "commit", "-q", "--allow-empty", "-m", message)
        return git(self.root, "rev-parse", "HEAD")


class GateTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = Repo(self._tmp.name)

    def run_gate(self, head: str, repository: str = "First-AI-Movers/example", **kwargs):
        return gate.evaluate(
            candidate_dir=self.repo.root,
            repository=repository,
            base_sha=self.repo.base,
            head_sha=head,
            event_name=kwargs.pop("event_name", "pull_request"),
            **kwargs,
        )

    def seed_gate_config(self, document) -> None:
        """Commit a gate configuration onto the BASE commit."""
        body = document if isinstance(document, str) else json.dumps(document)
        self.repo.write(".github/aeos-gate.json", body)
        self.repo.base = self.repo.commit("seed gate config")

    def assertFailsWith(self, report, code: str) -> None:
        self.assertFalse(report.passed, f"expected FAIL {code}, got PASS")
        self.assertEqual(report.primary, code)
        self.assertIn(code, gate.REASON_CODES)

    # -- clean / empty -----------------------------------------------------
    def test_clean_changed_set_passes(self) -> None:
        self.repo.write("src/app.py", "def add(a, b):\n    return a + b\n")
        self.repo.write("conf/settings.json", '{"enabled": true}\n')
        self.repo.write("conf/settings.yaml", "enabled: true\nitems:\n  - one\n")
        self.repo.write("docs/notes.md", "Just prose.\n")
        report = self.run_gate(self.repo.commit("clean change"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.scanned, 4)

    def test_event_without_a_commit_range_fails_closed(self) -> None:
        """A dispatched run has no range; inventing one would be a green that
        measured nothing, published under the required context name."""
        for event in ("workflow_dispatch", "push", "", "schedule"):
            with self.subTest(event=event):
                report = self.run_gate(self.repo.commit("x"), event_name=event)
                self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)

    def test_brand_new_repository_with_no_target_files_passes(self) -> None:
        """No control plane, no .python-version, no scripts/: absence is normal."""
        self.repo.write("hello.txt", "hello\n")
        report = self.run_gate(self.repo.commit("first change"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_empty_commit_passes(self) -> None:
        report = self.run_gate(self.repo.commit("empty"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.scanned, 0)

    # -- control plane -----------------------------------------------------
    def test_compliant_workflow_change_is_measured_and_merges(self) -> None:
        """The behaviour this plane replaces: a workflow edit used to be deferred
        to a person by path alone. It is now judged, and a compliant one passes."""
        self.repo.write(
            ".github/workflows/ci.yml",
            "on: push\n"
            "permissions:\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n",
        )
        report = self.run_gate(self.repo.commit("add compliant workflow"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.control_plane, [".github/workflows/ci.yml"])

    def test_privileged_trigger_fails_the_workflow_policy(self) -> None:
        self.repo.write(
            ".github/workflows/ci.yml",
            "on:\n  pull_request_target:\n"
            "permissions:\n  contents: read\njobs: {}\n",
        )
        report = self.run_gate(self.repo.commit("privileged trigger"))
        self.assertFailsWith(report, gate.WORKFLOW_POLICY_VIOLATION)

    def test_unpinned_third_party_action_fails_the_workflow_policy(self) -> None:
        self.repo.write(
            ".github/workflows/ci.yml",
            "on: push\npermissions:\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: some/action@v4\n",
        )
        report = self.run_gate(self.repo.commit("floating tag"))
        self.assertFailsWith(report, gate.WORKFLOW_POLICY_VIOLATION)

    def test_script_injection_fails_the_workflow_policy(self) -> None:
        self.repo.write(
            ".github/workflows/ci.yml",
            "on: push\npermissions:\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n",
        )
        report = self.run_gate(self.repo.commit("injection"))
        self.assertFailsWith(report, gate.WORKFLOW_POLICY_VIOLATION)

    def test_undeclared_permissions_fail_the_workflow_policy(self) -> None:
        self.repo.write(
            ".github/workflows/ci.yml",
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
        )
        report = self.run_gate(self.repo.commit("no permissions"))
        self.assertFailsWith(report, gate.WORKFLOW_POLICY_VIOLATION)

    def test_a_consumer_may_not_publish_the_reserved_check_name(self) -> None:
        """The twin-check hazard measured on agent-toolkit PR #3227."""
        self.repo.write(
            ".github/workflows/aeos-merge-ready.yml",
            "on: pull_request\npermissions:\n  contents: read\n"
            "jobs:\n  aeos-merge-ready:\n    runs-on: ubuntu-latest\n    steps: []\n",
        )
        report = self.run_gate(self.repo.commit("impersonate the org gate"))
        self.assertFailsWith(report, gate.WORKFLOW_POLICY_VIOLATION)
        details = " ".join(f.detail for f in report.findings)
        self.assertIn("organization gate", details)
        self.assertIn("reserved for the", details)

    def test_the_policy_repository_itself_may_use_its_own_identity(self) -> None:
        self.repo.write(
            ".github/workflows/aeos-merge-ready.yml",
            "on: pull_request\npermissions:\n  contents: read\n"
            "jobs:\n  aeos-merge-ready:\n    runs-on: ubuntu-latest\n    steps: []\n",
        )
        report = self.run_gate(
            self.repo.commit("the org gate itself"), repository="First-AI-Movers/.github"
        )
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_compliant_composite_action_change_merges(self) -> None:
        self.repo.write(".github/actions/thing/action.yml", "runs:\n  using: node20\n")
        report = self.run_gate(self.repo.commit("add action"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_workflow_deletion_merges_in_a_consumer_repository(self) -> None:
        """A deleted path has no bytes to judge. In a consumer repository the
        deletion cannot reach the required verdict -- that is injected by the
        organization ruleset from a repository this branch cannot touch."""
        self.repo.write(".github/workflows/ci.yml", "on: push\njobs: {}\n")
        self.repo.base = self.repo.commit("seed workflow")
        self.repo.remove(".github/workflows/ci.yml")
        report = self.run_gate(self.repo.commit("delete workflow"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_deleting_the_organizations_gate_source_stays_operator_governed(self) -> None:
        """The one residual human gate: deleting the gate that judges all eight
        repositories cannot be proven safe from candidate content there is none of."""
        self.repo.write("aeos/merge_ready_gate.py", "CONTROL_PLANE_PREFIXES = ()\n")
        self.repo.base = self.repo.commit("seed the gate source")
        self.repo.remove("aeos/merge_ready_gate.py")
        report = self.run_gate(
            self.repo.commit("delete the gate"), repository="First-AI-Movers/.github"
        )
        self.assertFailsWith(report, gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR)

    def test_other_dot_github_files_are_not_control_plane(self) -> None:
        self.repo.write(".github/CODEOWNERS", "* @First-AI-Movers/maintainers\n")
        self.repo.write(".github/dependabot.yml", "version: 2\nupdates: []\n")
        report = self.run_gate(self.repo.commit("community health"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_control_plane_content_is_read_not_short_circuited(self) -> None:
        """The inverse of the old behaviour, asserted deliberately: candidate
        control-plane bytes ARE read now, and the ordinary floors still apply to
        them. Unparseable workflow YAML is a finding, not a deferral."""
        self.repo.write(".github/workflows/ci.yml", "this: is: not: valid: yaml:\n")
        self.repo.write("broken.json", "{not json")
        report = self.run_gate(self.repo.commit("mixed"))
        self.assertFalse(report.passed)
        self.assertEqual(report.scanned, 2)
        self.assertEqual(report.control_plane, [".github/workflows/ci.yml"])
        codes = {f.code for f in report.findings}
        # The lane's own "not readable YAML" verdict outranks the general
        # structured floor in REASON_CODES, so it is the primary...
        self.assertEqual(report.primary, gate.CONTROL_PLANE_PROOF_FAILED)
        # ...but the ordinary floors still ran over BOTH files, which is the
        # property that was unreachable while the control plane short-circuited.
        self.assertIn(gate.STRUCTURED_DATA_UNPARSEABLE, codes)
        self.assertEqual(
            {f.path for f in report.findings if f.code == gate.STRUCTURED_DATA_UNPARSEABLE},
            {".github/workflows/ci.yml", "broken.json"},
        )

    def test_policy_repository_gate_source_keeps_its_load_bearing_declarations(self) -> None:
        """The anti-ratchet floor. A gate edit that deletes a load-bearing
        declaration cannot merge itself through; one that keeps them all can.

        The judge is always the predecessor: this verdict comes from the copy of
        the gate already on `main`, never from the candidate's."""
        self.repo.write("aeos/merge_ready_gate.py", "x = 1\n")
        gutted = self.repo.commit("gut the gate")
        report = self.run_gate(gutted, repository="First-AI-Movers/.github")
        self.assertFailsWith(report, gate.CONTROL_PLANE_PROOF_FAILED)
        details = " ".join(f.detail for f in report.findings)
        for name in ("CONTROL_PLANE_PREFIXES", "SECRET_SHAPES", "REASON_CODES"):
            self.assertIn(name, details)

        # The same path in any other repository is ordinary source.
        self.assertTrue(self.run_gate(gutted, repository="First-AI-Movers/other").passed)

    def test_policy_repository_gate_source_edit_that_keeps_them_merges(self) -> None:
        self.repo.write(
            "aeos/merge_ready_gate.py",
            "CONTROL_PLANE_PREFIXES = ()\n"
            "CONTROL_PLANE_PATHS = ()\n"
            "SECRET_SHAPES = ()\n"
            "REASON_CODES = ()\n"
            "# an ordinary edit to the gate\n",
        )
        report = self.run_gate(
            self.repo.commit("ordinary gate edit"), repository="First-AI-Movers/.github"
        )
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    # -- secret shapes -----------------------------------------------------
    def test_github_token_shape_is_caught(self) -> None:
        token = "gh" + "p_" + ("A1b2C3d4E5" * 4)[:36]
        self.repo.write("deploy.sh", f"#!/bin/sh\nexport TOKEN={token}\n")
        report = self.run_gate(self.repo.commit("leak"))
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        self.assertEqual(report.findings[0].path, "deploy.sh")
        self.assertIn("line 2", report.findings[0].detail)
        self.assertIn("github_token", report.findings[0].detail)

    def test_secret_value_is_never_echoed(self) -> None:
        token = "AKIA" + "ABCDEFGHIJKLMNOP"
        self.repo.write("infra/creds.tf", f'key = "{token}"\n')
        report = self.run_gate(self.repo.commit("leak"))
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        rendered = gate.render(report, "r", "pull_request", self.repo.base, "head")
        self.assertNotIn(token, rendered)
        self.assertIn("aws_access_key_id", rendered)

    def test_each_shape_family_is_detected(self) -> None:
        cases = {
            "github_token": "gh" + "s_" + "Z" * 36,
            "github_pat": "github" + "_pat_" + "A" * 22 + "_" + "B" * 55,
            "aws_access_key_id": "AKIA" + "QRSTUVWXYZ012345",
            "private_key_block": "-----BEGIN" + " RSA" + " PRIVATE KEY-----",
            "slack_token": "xox" + "b-" + "1234567890-abcdef",
            "anthropic_api_key": "sk-" + "ant-" + "a" * 30,
            "provider_api_key": "sk-" + "proj-" + "c" * 40,
            "google_api_key": "AIza" + "0" * 35,
        }
        for shape, value in cases.items():
            with self.subTest(shape=shape):
                findings, skipped = gate.scan_secret_shapes(
                    "f.txt", f"v = {value}\n".encode()
                )
                self.assertIsNone(skipped)
                self.assertTrue(findings, f"{shape} not detected")
                self.assertIn(shape, findings[0].detail)

    def test_ordinary_prose_and_code_do_not_false_positive(self) -> None:
        benign = textwrap.dedent(
            """
            # Set GITHUB_TOKEN in the environment before running.
            token = os.environ["GITHUB_TOKEN"]
            aws_profile = "AKIA-style ids are 20 characters long"
            key = "sk-short"
            url = "https://example.invalid/AIzaShort"
            slack = "xoxb-"
            pem = "-----BEGIN CERTIFICATE-----"
            sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
            """
        )
        self.assertEqual(gate.scan_secret_shapes("a.py", benign.encode()), ([], None))

    def test_binary_and_undecodable_skips_are_disclosed_not_silent(self) -> None:
        """A skip that is not reported is an absence producing a green."""
        token = ("gh" + "p_" + "D" * 36).encode()
        self.repo.write_bytes("blob.bin", b"\x00\x01\x02" + token)
        self.repo.write_bytes("latin.txt", b"caf\xe9 " + token)
        report = self.run_gate(self.repo.commit("unscannable"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.scanned, 2)
        self.assertTrue(any("binary content" in n for n in report.skipped), report.skipped)
        self.assertTrue(any("not valid UTF-8" in n for n in report.skipped), report.skipped)

    def test_oversize_file_is_skipped_and_reported(self) -> None:
        self.repo.write_bytes("big.txt", b"x" * (gate.MAX_SCAN_BYTES + 10))
        report = self.run_gate(self.repo.commit("big"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertTrue(any("big.txt" in note for note in report.skipped))

    def test_symlink_is_recognised_by_mode_and_not_followed(self) -> None:
        """A symlink's blob is its target path, not the target's content, and the
        gate never touches the filesystem to resolve it."""
        os.symlink("/etc/passwd", os.path.join(self.repo.root, "escape.json"))
        os.symlink("README.md", os.path.join(self.repo.root, "inside.json"))
        report = self.run_gate(self.repo.commit("symlinks"))
        # Note both are named .json: if the link text were parsed as content they
        # would fail as unparseable JSON.
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.scanned, 0)
        self.assertEqual(
            sum("symlink, target not followed" in note for note in report.skipped), 2
        )

    # -- structured data ---------------------------------------------------
    def test_unparseable_json_is_caught(self) -> None:
        self.repo.write("data/config.json", '{"a": 1,,}\n')
        report = self.run_gate(self.repo.commit("bad json"))
        self.assertFailsWith(report, gate.STRUCTURED_DATA_UNPARSEABLE)
        self.assertEqual(report.findings[0].path, "data/config.json")

    def test_unparseable_yaml_is_caught(self) -> None:
        self.repo.write("data/config.yaml", "a: 1\n  b: 2\n :\n- broken\n")
        report = self.run_gate(self.repo.commit("bad yaml"))
        self.assertFailsWith(report, gate.STRUCTURED_DATA_UNPARSEABLE)

    def test_multi_document_yaml_parses(self) -> None:
        self.repo.write("k8s/manifest.yml", "kind: A\n---\nkind: B\n")
        report = self.run_gate(self.repo.commit("multidoc"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_yaml_uses_safe_loader_only(self) -> None:
        """A tag that only an unsafe loader would construct must not be honoured."""
        payload = b"!!python/object/apply:os.system ['echo pwned']\n"
        findings = gate.parse_structured("evil.yaml", payload)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, gate.STRUCTURED_DATA_UNPARSEABLE)

    # -- python syntax -----------------------------------------------------
    def test_python_syntax_error_is_caught(self) -> None:
        self.repo.write("src/broken.py", "def f(:\n    pass\n")
        report = self.run_gate(self.repo.commit("bad python"))
        self.assertFailsWith(report, gate.SYNTAX_ERROR)
        self.assertEqual(report.findings[0].path, "src/broken.py")

    def test_python_is_parsed_never_executed(self) -> None:
        marker = os.path.join(self._tmp.name, "SHOULD_NOT_EXIST")
        self.repo.write(
            "src/sideeffect.py",
            f"import pathlib\npathlib.Path({marker!r}).write_text('executed')\n",
        )
        report = self.run_gate(self.repo.commit("side effect"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertFalse(os.path.exists(marker), "candidate code was executed")

    # -- deletions ---------------------------------------------------------
    def test_deleted_file_is_skipped_not_read(self) -> None:
        token = "gh" + "u_" + "E" * 36
        self.repo.write("old.py", f"TOKEN = '{token}'\ndef f(:\n")
        self.repo.base = self.repo.commit("seed a file that would fail if read")
        self.repo.remove("old.py")
        report = self.run_gate(self.repo.commit("delete it"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.deleted, 1)
        self.assertEqual(report.scanned, 0)

    # -- fail closed -------------------------------------------------------
    def test_missing_base_commit_fails_closed(self) -> None:
        report = gate.evaluate(
            candidate_dir=self.repo.root,
            repository="r",
            base_sha="0" * 40,
            head_sha=self.repo.commit("head"),
            event_name="pull_request",
        )
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)

    def test_malformed_sha_fails_closed(self) -> None:
        report = gate.evaluate(
            candidate_dir=self.repo.root,
            repository="r",
            base_sha="not-a-sha",
            head_sha=self.repo.base,
            event_name="pull_request",
        )
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)

    def test_non_git_candidate_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            report = gate.evaluate(
                candidate_dir=empty,
                repository="r",
                base_sha="a" * 40,
                head_sha="b" * 40,
                event_name="pull_request",
            )
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)

    def test_identical_endpoints_fail_closed_on_pull_request(self) -> None:
        """An unresolved event payload must not present as 'nothing changed'."""
        report = self.run_gate(self.repo.base, event_name="pull_request")
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)
        report = self.run_gate(self.repo.base, event_name="merge_group")
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)

    def test_content_comes_from_head_sha_not_the_working_tree(self) -> None:
        """The verdict is published against head_sha, so the bytes judged must be
        the bytes at head_sha. Reading a working tree instead would let a tree
        that merely happens to be checked out decide the verdict."""
        token = "gh" + "p_" + "K3m9Q" * 7 + "zR"
        self.repo.write("app.py", f"TOKEN = '{token}'\n")
        head = self.repo.commit("committed leak")
        # Scrub the working tree. The blob at head_sha still holds the leak.
        self.repo.write("app.py", "TOKEN = None\n")
        report = self.run_gate(head)
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)

        # And the converse: a dirty working tree over a clean head does not fail.
        self.setUp()
        self.repo.write("app.py", "TOKEN = None\n")
        head = self.repo.commit("clean head")
        self.repo.write("app.py", f"TOKEN = '{token}'\n")
        self.assertTrue(self.run_gate(head).passed)

    def test_deleted_head_blob_is_never_requested(self) -> None:
        self.repo.write("ghost.txt", "here\n")
        head = self.repo.commit("add ghost")
        os.unlink(os.path.join(self.repo.root, "ghost.txt"))
        # The file is gone from disk but its blob is in the object store, so the
        # gate reads it regardless of the working tree.
        self.assertTrue(self.run_gate(head).passed)

    # -- budget ------------------------------------------------------------
    def test_budget_exceeded_is_typed_and_fails(self) -> None:
        ticks = iter([0.0] + [1000.0] * 64)
        self.repo.write("a.txt", "one\n")
        report = gate.evaluate(
            candidate_dir=self.repo.root,
            repository="r",
            base_sha=self.repo.base,
            head_sha=self.repo.commit("slow"),
            event_name="pull_request",
            hard_budget=1.0,
            clock=lambda: next(ticks),
        )
        self.assertFailsWith(report, gate.BUDGET_EXCEEDED)

    def test_pass_is_only_returned_after_self_measurement(self) -> None:
        self.repo.write("a.txt", "one\n")
        report = self.run_gate(self.repo.commit("fine"))
        self.assertTrue(report.passed)
        self.assertGreater(report.elapsed, 0.0)

    # -- reporting ---------------------------------------------------------
    def test_render_names_offending_paths_and_emits_one_result_line(self) -> None:
        self.repo.write("bad.json", "{")
        report = self.run_gate(self.repo.commit("bad"))
        text = gate.render(report, "org/repo", "pull_request", self.repo.base, "deadbeef")
        self.assertEqual(text.count(gate.RESULT_PREFIX), 1)
        self.assertIn(f"{gate.RESULT_PREFIX} FAIL {gate.STRUCTURED_DATA_UNPARSEABLE}", text)
        self.assertIn("bad.json", text)
        self.assertIn("org/repo", text)

    def test_cli_exit_codes_and_summary(self) -> None:
        self.repo.write("bad.json", "{")
        head = self.repo.commit("bad")
        summary = os.path.join(self._tmp.name, "summary.md")
        env_backup = os.environ.get("GITHUB_STEP_SUMMARY")
        os.environ["GITHUB_STEP_SUMMARY"] = summary
        try:
            rc = gate.main([
                "--candidate-dir", self.repo.root,
                "--repository", "org/repo",
                "--event-name", "pull_request",
                "--base-sha", self.repo.base,
                "--head-sha", head,
            ])
        finally:
            if env_backup is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = env_backup
        self.assertEqual(rc, 1)
        with open(summary, encoding="utf-8") as handle:
            written = handle.read()
        self.assertIn(gate.STRUCTURED_DATA_UNPARSEABLE, written)

    # -- hardening ---------------------------------------------------------
    def test_deeply_nested_json_is_refused_without_recursing(self) -> None:
        findings = gate.parse_structured("deep.json", b"[" * 200000 + b"]" * 200000)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, gate.STRUCTURED_DATA_UNPARSEABLE)
        self.assertIn("nesting depth", findings[0].detail)

    def test_deeply_nested_yaml_is_refused_without_reaching_the_parser(self) -> None:
        """libyaml overruns its C stack on deep flow nesting; never hand it the bytes."""
        findings = gate.parse_structured("deep.yaml", b"[" * 100000 + b"]" * 100000)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, gate.STRUCTURED_DATA_UNPARSEABLE)
        self.assertIn("nesting depth", findings[0].detail)

    def test_ordinary_nesting_and_brackets_in_strings_still_parse(self) -> None:
        self.assertEqual(gate.parse_structured("ok.yaml", b"a:\n  - [1, 2, [3, 4]]\n"), [])
        payload = ('{"s": "' + "[" * (gate.MAX_STRUCTURE_DEPTH - 1) + '"}').encode()
        self.assertEqual(gate.parse_structured("ok.json", payload), [])
        self.assertEqual(gate.flow_nesting_depth("[]" * 10000), 1)

    def test_nesting_depth_is_not_diluted_by_intervening_content(self) -> None:
        """Whitespace and scalars between the brackets must not reset the count."""
        spaced = "[ " * 100000 + "] " * 100000
        self.assertGreater(gate.flow_nesting_depth(spaced), gate.MAX_STRUCTURE_DEPTH)
        keyed = "{a: {b: " * 50000
        self.assertGreater(gate.flow_nesting_depth(keyed), gate.MAX_STRUCTURE_DEPTH)
        findings = gate.parse_structured("spaced.yaml", spaced.encode())
        self.assertEqual([f.code for f in findings], [gate.STRUCTURED_DATA_UNPARSEABLE])
        self.assertIn("nesting depth", findings[0].detail)
        # A wide-but-shallow document is measured as shallow.
        wide = ",".join("[%d]" % i for i in range(100000))
        self.assertLessEqual(gate.flow_nesting_depth(wide), 1)

    def test_control_plane_match_is_case_insensitive(self) -> None:
        self.assertEqual(
            gate.control_plane_violations([".GitHub/Workflows/ci.yml"], "org/repo"),
            [".GitHub/Workflows/ci.yml"],
        )

    def test_unexpected_exception_becomes_a_typed_verdict(self) -> None:
        self.repo.write("a.txt", "hello\n")
        head = self.repo.commit("boom")
        original = gate.scan_secret_shapes
        gate.scan_secret_shapes = lambda *a, **k: (_ for _ in ()).throw(RecursionError("boom"))  # noqa: E501
        try:
            report = self.run_gate(head)
        finally:
            gate.scan_secret_shapes = original
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)
        self.assertIn("RecursionError", report.findings[0].detail)

    def test_guarded_entry_point_never_raises(self) -> None:
        report = gate._evaluate_guarded(
            candidate_dir=None,  # type: ignore[arg-type]
            repository="r",
            base_sha="a" * 40,
            head_sha="b" * 40,
            event_name="pull_request",
        )
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)

    # -- the range, not just its endpoints ---------------------------------
    # A branch that commits a credential and scrubs it before opening the pull
    # request leaves the object on `refs/pull/<n>/head` forever. The endpoint
    # diff cannot see it -- the content is at neither endpoint -- and under the
    # squash-only merge policy this gate is deployed behind it never reaches the
    # default branch either, so no post-merge history scan sees it. These tests
    # pin the only place in the lifecycle that looks.
    SUPERSEDED = "gh" + "p_" + "Z9y8X7w6V5" * 3 + "Z9y8X7"  # 36 chars after the prefix

    def test_secret_committed_then_removed_before_head_is_caught(self) -> None:
        self.repo.write("deploy.sh", f"#!/bin/sh\nexport TOKEN={self.SUPERSEDED}\n")
        self.repo.commit("oops, a credential")
        self.repo.write("deploy.sh", "#!/bin/sh\nexport TOKEN=$FROM_ENV\n")
        head = self.repo.commit("scrub it before anyone looks")

        # The head tree is clean: only the range scan can produce this verdict,
        # so deleting that conjunct turns this test red rather than leaving it
        # satisfied by the head-side scan.
        self.assertNotIn(self.SUPERSEDED, open(os.path.join(self.repo.root, "deploy.sh")).read())
        report = self.run_gate(head)
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        self.assertEqual(report.findings[0].path, "deploy.sh")
        self.assertIn("superseded commit", report.findings[0].detail)
        self.assertEqual(report.history_scanned, 1)

    def test_a_superseded_secret_value_is_never_echoed(self) -> None:
        self.repo.write("infra/creds.tf", f'key = "{self.SUPERSEDED}"\n')
        self.repo.commit("leak")
        self.repo.write("infra/creds.tf", 'key = var.token\n')
        head = self.repo.commit("scrub")
        report = self.run_gate(head)
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        rendered = gate.render(report, "r", "pull_request", self.repo.base, head)
        self.assertNotIn(self.SUPERSEDED, rendered)
        self.assertIn("github_token", rendered)

    def test_a_file_added_and_deleted_within_the_range_is_caught(self) -> None:
        """The deletion route reads nothing at head; the object still exists."""
        self.repo.write("tmp/scratch.env", f"TOKEN={self.SUPERSEDED}\n")
        self.repo.commit("scratch file")
        self.repo.remove("tmp/scratch.env")
        head = self.repo.commit("remove the scratch file")
        report = self.run_gate(head)
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        self.assertEqual(report.findings[0].path, "tmp/scratch.env")

    def test_a_clean_multi_commit_range_still_passes(self) -> None:
        self.repo.write("src/app.py", "VALUE = 1\n")
        self.repo.commit("first")
        self.repo.write("src/app.py", "VALUE = 2\n")
        self.repo.commit("second")
        self.repo.write("src/app.py", "VALUE = 3\n")
        head = self.repo.commit("third")
        report = self.run_gate(head)
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        # Two superseded revisions of app.py; the head revision is the changed set.
        self.assertEqual(report.scanned, 1)
        self.assertEqual(report.history_scanned, 2)

    def test_the_head_revision_is_not_scanned_twice(self) -> None:
        self.repo.write("src/app.py", "VALUE = 1\n")
        head = self.repo.commit("single commit")
        report = self.run_gate(head)
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.scanned, 1)
        self.assertEqual(report.history_scanned, 0)

    def test_an_allowlisted_path_exempts_its_superseded_revisions_too(self) -> None:
        self.seed_gate_config(
            {"schema_version": "1", "secret_shape_allowlist": ["Engine/scripts/tests/**"]}
        )
        self.repo.write("Engine/scripts/tests/test_supply.py", f"TOKEN = '{self.SUPERSEDED}'\n")
        self.repo.commit("verified canary")
        self.repo.write("Engine/scripts/tests/test_supply.py", "TOKEN = None\n")
        head = self.repo.commit("retire the canary")
        report = self.run_gate(head)
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(len(report.exempted), 1)
        self.assertIn("superseded revision", report.exempted[0])

    def test_a_control_plane_change_still_reads_no_content_at_all(self) -> None:
        """The path-only short circuit must stay ahead of both scans."""
        self.repo.write(".github/workflows/ci.yml", f"# {self.SUPERSEDED}\n")
        self.repo.commit("workflow with a secret in it")
        self.repo.write(".github/workflows/ci.yml", "on: push\njobs: {}\n")
        head = self.repo.commit("scrub the workflow")
        report = self.run_gate(head)
        self.assertFailsWith(report, gate.CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR)
        self.assertEqual(report.scanned, 0)
        self.assertEqual(report.history_scanned, 0)

    def test_a_shallow_clone_fails_closed(self) -> None:
        """rev-list stops at the graft boundary and reports a truncated range as
        a complete one; a green from that measured less than it claims."""
        self.repo.write("src/app.py", "VALUE = 1\n")
        self.repo.commit("first")
        self.repo.write("src/app.py", "VALUE = 2\n")
        head = self.repo.commit("second")
        # Graft at the base: the endpoint diff still resolves, so this reaches
        # the range scan rather than failing earlier for a different reason.
        with open(os.path.join(self.repo.root, ".git", "shallow"), "w", encoding="utf-8") as fh:
            fh.write(self.repo.base + "\n")
        report = self.run_gate(head)
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)
        self.assertIn("shallow", report.findings[0].detail)
        with self.assertRaises(gate.GateError):
            gate.history_objects(self.repo.root, self.repo.base, head)

    def test_binary_superseded_content_does_not_break_the_scan(self) -> None:
        self.repo.write_bytes("assets/blob.bin", b"\x00\x01\x02" * 64)
        self.repo.commit("binary")
        self.repo.write_bytes("assets/blob.bin", b"\x00\x09" * 64)
        head = self.repo.commit("different binary")
        report = self.run_gate(head)
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.history_scanned, 1)

    # -- operator allowlist (.github/aeos-gate.json) -----------------------
    LEAK = "gh" + "p_" + "B7q2X" * 7 + "cA"  # 36 chars after the prefix

    def test_absent_gate_config_is_normal_and_changes_nothing(self) -> None:
        self.repo.write("tests/fixture.py", f"TOKEN = '{self.LEAK}'\n")
        report = self.run_gate(self.repo.commit("canary, no config"))
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        self.assertFalse(report.config.present)

    def test_allowlisted_path_with_a_secret_shape_passes(self) -> None:
        self.seed_gate_config(
            {"schema_version": "1", "secret_shape_allowlist": ["Engine/scripts/tests/**"]}
        )
        self.repo.write("Engine/scripts/tests/test_supply.py", f"TOKEN = '{self.LEAK}'\n")
        report = self.run_gate(self.repo.commit("verified canary"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertTrue(report.config.present)
        self.assertEqual(len(report.exempted), 1)
        self.assertIn("github_token", report.exempted[0])

    def test_non_allowlisted_path_with_the_same_shape_still_fails(self) -> None:
        self.seed_gate_config(
            {"schema_version": "1", "secret_shape_allowlist": ["Engine/scripts/tests/**"]}
        )
        self.repo.write("Engine/scripts/deploy.py", f"TOKEN = '{self.LEAK}'\n")
        report = self.run_gate(self.repo.commit("real leak"))
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        self.assertEqual(report.exempted, [])

    def test_a_valid_gate_config_edit_merges(self) -> None:
        self.repo.write(
            ".github/aeos-gate.json",
            '{"schema_version": "1", "secret_shape_allowlist": ["tests/fixtures/**"]}\n',
        )
        report = self.run_gate(self.repo.commit("narrow, reasoned exemption"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_a_blanket_allowlist_entry_fails_the_proof(self) -> None:
        """The self-serve bypass this file exists to prevent: a wildcard entry
        turns off secret detection for every file, permanently."""
        for blanket in ("**", "*", "**/*", ""):
            with self.subTest(pattern=blanket):
                self.setUp()
                self.repo.write(
                    ".github/aeos-gate.json",
                    '{"schema_version": "1", "secret_shape_allowlist": ["' + blanket + '"]}\n',
                )
                report = self.run_gate(self.repo.commit("blanket exemption"))
                self.assertFailsWith(report, gate.CONTROL_PLANE_PROOF_FAILED)

    def test_an_unparseable_gate_config_fails_the_proof(self) -> None:
        self.repo.write(".github/aeos-gate.json", "{not json")
        report = self.run_gate(self.repo.commit("broken config"))
        self.assertFalse(report.passed)

    def test_a_valid_smoke_config_edit_merges(self) -> None:
        self.repo.write(
            ".github/aeos-smoke.json",
            '{"schema_version": "1", "smoke_suites": ["tests/"], "compile_roots": ["."]}\n',
        )
        report = self.run_gate(self.repo.commit("declare the rail"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_emptying_the_smoke_declaration_fails_the_proof(self) -> None:
        """Rewritten to run nothing, the rail still reports green and now measures
        nothing -- worse than a red one, because nobody looks at it again."""
        for payload in (
            '{"schema_version": "1", "smoke_suites": []}',
            '{"schema_version": "1", "compile_roots": []}',
            '{"schema_version": "1", "smoke_suites": ["", "  "]}',
        ):
            with self.subTest(payload=payload):
                self.setUp()
                self.repo.write(".github/aeos-smoke.json", payload + "\n")
                report = self.run_gate(self.repo.commit("disarm the rail"))
                self.assertFailsWith(report, gate.CONTROL_PLANE_PROOF_FAILED)

    def test_deleting_the_smoke_config_restores_the_defaults_and_merges(self) -> None:
        """Absence means the rail uses its built-in defaults -- a stricter posture,
        not a weaker one -- so the deletion needs no human."""
        self.repo.write(
            ".github/aeos-smoke.json",
            '{"schema_version": "1", "smoke_suites": ["tests/"]}\n',
        )
        self.repo.base = self.repo.commit("seed a real smoke")
        self.repo.remove(".github/aeos-smoke.json")
        report = self.run_gate(self.repo.commit("delete it"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_config_is_read_from_the_base_not_from_the_working_tree(self) -> None:
        """The load-bearing conjunct: a branch cannot supply its own exemptions."""
        self.seed_gate_config({"schema_version": "1", "secret_shape_allowlist": ["safe/**"]})
        self.repo.write("app/secrets.py", f"TOKEN = '{self.LEAK}'\n")
        head = self.repo.commit("leak outside the allowlist")
        # Rewrite the configuration in the working tree only. It is not in the
        # changed set, so it does not trip the control-plane check -- and it must
        # have no effect, because the gate reads the blob at base_sha.
        self.repo.write(".github/aeos-gate.json",
                        json.dumps({"schema_version": "1", "secret_shape_allowlist": ["**"]}))
        report = self.run_gate(head)
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        self.assertEqual(report.config.secret_shape_allowlist, ("safe/**",))

    def test_malformed_gate_config_fails_closed(self) -> None:
        for label, document in [
            ("unparseable", "{not json"),
            ("not an object", "[1, 2, 3]"),
            ("missing schema_version", '{"secret_shape_allowlist": []}'),
            ("wrong schema_version", '{"schema_version": "9"}'),
            ("allowlist not a list", '{"schema_version": "1", "secret_shape_allowlist": "docs/**"}'),
            ("allowlist entry not a string", '{"schema_version": "1", "secret_shape_allowlist": [7]}'),
        ]:
            with self.subTest(label=label):
                self.setUp()
                self.seed_gate_config(document)
                self.repo.write("ordinary.txt", "nothing wrong here\n")
                report = self.run_gate(self.repo.commit("ordinary change"))
                self.assertFailsWith(report, gate.GATE_CONFIG_INVALID)

    def test_integer_schema_version_is_accepted(self) -> None:
        self.seed_gate_config({"schema_version": 1, "secret_shape_allowlist": []})
        self.repo.write("ordinary.txt", "fine\n")
        self.assertTrue(self.run_gate(self.repo.commit("ordinary")).passed)

    def test_unknown_config_keys_are_ignored(self) -> None:
        self.seed_gate_config({"schema_version": "1", "future_option": {"a": 1}})
        self.repo.write("ordinary.txt", "fine\n")
        self.assertTrue(self.run_gate(self.repo.commit("ordinary")).passed)

    def test_allowlist_does_not_exempt_the_other_floors(self) -> None:
        self.seed_gate_config({"schema_version": "1", "secret_shape_allowlist": ["**"]})
        self.repo.write("tests/broken.py", f"TOKEN = '{self.LEAK}'\ndef f(:\n")
        self.assertFailsWith(self.run_gate(self.repo.commit("syntax")), gate.SYNTAX_ERROR)

        self.setUp()
        self.seed_gate_config({"schema_version": "1", "secret_shape_allowlist": ["**"]})
        self.repo.write("tests/fixture.json", '{"token": "' + self.LEAK + '",,}')
        self.assertFailsWith(
            self.run_gate(self.repo.commit("json")), gate.STRUCTURED_DATA_UNPARSEABLE
        )

    def test_allowlist_never_exempts_the_control_plane(self) -> None:
        """The property survives the move to the strict lane, and is now checked
        where it actually bites: a real credential shape inside a workflow, with
        an allowlist that covers it, is still a finding. Under the old
        short-circuit this was never exercised -- no workflow byte was read."""
        self.seed_gate_config({"schema_version": "1", "secret_shape_allowlist": ["**"]})
        self.repo.write(
            ".github/workflows/ci.yml",
            "on: push\npermissions:\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo " + self.LEAK + "\n",
        )
        report = self.run_gate(self.repo.commit("workflow"))
        self.assertFailsWith(report, gate.SECRET_SHAPE_DETECTED)
        self.assertEqual(report.exempted, [])

        # Negative control: the SAME allowlist DOES exempt an ordinary path, so
        # the assertion above is about the control plane, not a broken allowlist.
        self.setUp()
        self.seed_gate_config({"schema_version": "1", "secret_shape_allowlist": ["**"]})
        self.repo.write("app/fixture.py", "TOKEN = '" + self.LEAK + "'\n")
        ordinary = self.run_gate(self.repo.commit("ordinary path"))
        self.assertTrue(ordinary.passed, [f.render() for f in ordinary.findings])
        self.assertTrue(ordinary.exempted)

    def test_glob_semantics_are_fnmatch_plus_the_documented_extension(self) -> None:
        match = gate.path_matches_glob
        # fnmatch: `*` is not separator-aware, so a trailing `**` covers any depth.
        self.assertTrue(match("Engine/scripts/tests/a/b/c.py", "Engine/scripts/tests/**"))
        self.assertTrue(match("Engine/scripts/tests/t.py", "Engine/scripts/tests/**"))
        self.assertFalse(match("Engine/scripts/deploy.py", "Engine/scripts/tests/**"))
        # The documented `/**/` extension also matches a single separator.
        self.assertTrue(match("docs/guide/a.md", "docs/**/*.md"))
        self.assertTrue(match("docs/a.md", "docs/**/*.md"))
        self.assertFalse(match("docs/a.txt", "docs/**/*.md"))
        self.assertFalse(match("other/a.md", "docs/**/*.md"))
        # Exact paths work as themselves.
        self.assertTrue(match("tests/test_alert_privacy.py", "tests/test_alert_privacy.py"))
        self.assertFalse(match("tests/test_alert_privacy.pyc", "tests/test_alert_privacy.py"))

    def test_oversized_and_overlong_allowlists_fail_closed(self) -> None:
        with self.assertRaises(gate.GateError) as caught:
            gate.parse_gate_config(
                json.dumps(
                    {
                        "schema_version": "1",
                        "secret_shape_allowlist": ["p%d" % i
                                                   for i in range(gate.MAX_ALLOWLIST_PATTERNS + 1)],
                    }
                ).encode()
            )
        self.assertEqual(caught.exception.code, gate.GATE_CONFIG_INVALID)

    # -- published examples and placeholders --------------------------------
    def test_vendor_examples_and_placeholders_do_not_block(self) -> None:
        """A false positive blocks every repository in the organization, and the
        only override is an operator-merged control-plane change."""
        cases = [
            "AKIA" + "IOSFODNN7EXAMPLE",
            "gh" + "p_16C7e42F292c6912E7710c838347Ae178B4a",
            "OPENAI_API_KEY=sk-" + "X" * 40,
            "sk-" + "yourkeyhereyourkeyhereyourkeyhere",
            "SLACK_BOT_TOKEN=xox" + "b-your-bot-token-here",
            "ANTHROPIC_API_KEY=sk-" + "ant-api03-REPLACE-ME-" + "a" * 24,
            "AIza" + "SyEXAMPLE" + "0" * 26,
        ]
        for value in cases:
            with self.subTest(value=value[:24]):
                findings, skipped = gate.scan_secret_shapes("README.md", value.encode())
                self.assertIsNone(skipped)
                self.assertEqual(findings, [], f"false positive on {value[:24]!r}")

    def test_a_real_looking_credential_still_blocks(self) -> None:
        """The placeholder allowance must not swallow the actual check."""
        for value in [
            "gh" + "p_" + "K3m9Q" * 7 + "zR",
            "AKIA" + "3Z7QW4NB2XKD9RTV",
            "sk-" + "ant-" + "api03-" + "Rk39ZmQ7" * 4,
            "xox" + "b-3948573094-38457-QmZk39dLwPq",
        ]:
            with self.subTest(value=value[:16]):
                findings, _ = gate.scan_secret_shapes("app.py", value.encode())
                self.assertTrue(findings, f"missed {value[:16]!r}")

    # -- modes ---------------------------------------------------------------
    def test_submodule_gitlink_is_skipped_by_mode(self) -> None:
        git(self.repo.root, "update-index", "--add", "--cacheinfo",
            f"160000,{self.repo.base},vendor")
        report = self.run_gate(self.repo.commit_index("add submodule pointer"))
        self.assertTrue(report.passed, [f.render() for f in report.findings])
        self.assertEqual(report.scanned, 0)
        self.assertTrue(any("submodule reference" in n for n in report.skipped),
                        report.skipped)

    # -- identity ------------------------------------------------------------
    def test_abbreviated_sha_is_refused(self) -> None:
        """An abbreviated prefix resolves, which would make the commit evaluated
        a function of what else is in the object store."""
        head = self.repo.commit("change")
        report = gate.evaluate(
            candidate_dir=self.repo.root,
            repository="r",
            base_sha=self.repo.base[:7],
            head_sha=head,
            event_name="pull_request",
        )
        self.assertFailsWith(report, gate.EVIDENCE_UNREADABLE)
        self.assertIn("full object id", report.findings[0].detail)

    # -- vocabulary fail-closed ---------------------------------------------
    def test_unregistered_reason_code_does_not_render_as_pass(self) -> None:
        report = gate.Report()
        report.findings.append(gate.Finding("SOME_FUTURE_CODE", "a.py", "detail"))
        report.resolve_primary()
        self.assertFalse(report.passed)
        self.assertEqual(report.primary, "SOME_FUTURE_CODE")

    def test_schema_version_type_confusion_is_rejected(self) -> None:
        for value in ["true", "1.0"]:
            with self.subTest(value=value):
                with self.assertRaises(gate.GateError) as caught:
                    gate.parse_gate_config(
                        ('{"schema_version": %s}' % value).encode()
                    )
                self.assertEqual(caught.exception.code, gate.GATE_CONFIG_INVALID)

    def test_symlinked_gate_config_is_invalid(self) -> None:
        os.symlink("../elsewhere.json", os.path.join(self.repo.root, "aeos-gate.json"))
        os.makedirs(os.path.join(self.repo.root, ".github"), exist_ok=True)
        os.symlink("../elsewhere.json",
                   os.path.join(self.repo.root, ".github", "aeos-gate.json"))
        self.repo.base = self.repo.commit("symlinked config")
        self.repo.write("ordinary.txt", "fine\n")
        report = self.run_gate(self.repo.commit("ordinary"))
        self.assertFailsWith(report, gate.GATE_CONFIG_INVALID)
        self.assertIn("symlink", report.findings[0].detail)

    def test_the_documented_control_plane_set_matches_the_enforced_one(self) -> None:
        """A README that lists a different set from the code is how the two
        halves of this rule drift apart."""
        readme = pathlib.Path(__file__).resolve().parents[1] / "README.md"
        text = readme.read_text(encoding="utf-8")
        section = text.split("## The control-plane set", 1)[1].split("\n\n", 3)[2]
        documented = set(re.findall(r"^- `([^`]+)`$", section, flags=re.MULTILINE))
        enforced = {p + "**" for p in gate.CONTROL_PLANE_PREFIXES} | set(gate.CONTROL_PLANE_PATHS)
        self.assertEqual(documented, enforced)

    def test_reason_codes_are_a_closed_vocabulary(self) -> None:
        self.assertEqual(len(set(gate.REASON_CODES)), len(gate.REASON_CODES))
        for code in gate.REASON_CODES:
            self.assertRegex(code, r"^[A-Z_]+$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
