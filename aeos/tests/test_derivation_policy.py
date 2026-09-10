#!/usr/bin/env python3
"""Focused, deterministic tests for the standing-governor derivation-policy conjunct.

Plain ``unittest``. Every fixture is a throwaway git repository and a throwaway
ed25519 key generated here; no literal credential or real key material is
committed. ``ssh-keygen`` is the one tool beyond ``git`` these tests need, which
is exactly the tool the gate needs.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import derivation_policy as dp  # noqa: E402
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

TARGET = "First-AI-Movers/agent-toolkit"
LABEL = "aeos-standing-governor"
FAR_FUTURE = "2999-01-01T00:00:00Z"
PAST = "2000-01-01T00:00:00Z"


def git(repo: str, *args: str) -> str:
    proc = subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True, env=GIT_ENV)
    return proc.stdout.decode().strip()


def keygen(directory: str, name: str) -> tuple[str, str, str]:
    """A throwaway ed25519 key: (private path, public key line, fingerprint)."""
    private = os.path.join(directory, name)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", private],
        check=True, capture_output=True,
    )
    with open(private + ".pub", encoding="utf-8") as handle:
        parts = handle.read().split()
    public = f"{parts[0]} {parts[1]}"
    fingerprint = subprocess.run(
        ["ssh-keygen", "-lf", private + ".pub"], check=True, capture_output=True, text=True
    ).stdout.split()[1]
    return private, public, fingerprint


def sign(private: str, manifest: bytes, namespace: str = dp.SIGNATURE_NAMESPACE) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "manifest.json")
        with open(path, "wb") as handle:
            handle.write(manifest)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", private, "-n", namespace, path],
            check=True, capture_output=True,
        )
        with open(path + ".sig", "rb") as handle:
            return handle.read()


class Repo:
    """A candidate repository with a tiny first-party module graph under scripts/."""

    ROOT = "scripts/agent_relay/standing_authority.py"

    def __init__(self, root: str) -> None:
        self.root = root
        git(root, "init", "-q", "-b", "main")
        # The graph: the root imports a sibling absolutely, a package by relative
        # import inside a function (lazy), a from-import that names a submodule,
        # and a non-allowlisted helper. Package inits execute on import.
        self.write("scripts/agent_relay/__init__.py", "")
        self.write(
            self.ROOT,
            "import agent_relay.models\n"
            "from commission_train import authority\n"
            "def lazy():\n"
            "    from .validate import check  # noqa\n"
            "    import helpers.util\n",
        )
        self.write("scripts/agent_relay/models.py", "X = 1\n")
        self.write("scripts/agent_relay/validate.py", "def check():\n    return True\n")
        self.write("scripts/agent_relay/unrelated.py", "Y = 2\n")
        self.write("scripts/commission_train/__init__.py", "")
        self.write("scripts/commission_train/authority.py", "def check_chain(s):\n    return s\n")
        self.write("scripts/helpers/__init__.py", "")
        self.write("scripts/helpers/util.py", "Z = 3\n")
        self.write("docs/notes.md", "prose\n")
        self.base = self.commit("base")

    def write(self, rel: str, content: str) -> None:
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def write_bytes(self, rel: str, content: bytes) -> None:
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content)

    def remove(self, rel: str) -> None:
        os.unlink(os.path.join(self.root, rel))

    def move(self, src: str, dst: str) -> None:
        path = os.path.join(self.root, dst)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.rename(os.path.join(self.root, src), path)

    def commit(self, message: str) -> str:
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "--allow-empty", "-m", message)
        return git(self.root, "rev-parse", "HEAD")


EXPECTED_FULL = {
    "scripts/agent_relay/standing_authority.py",
    "scripts/agent_relay/__init__.py",
    "scripts/agent_relay/models.py",
    "scripts/agent_relay/validate.py",
    "scripts/commission_train/__init__.py",
    "scripts/commission_train/authority.py",
    "scripts/helpers/__init__.py",
    "scripts/helpers/util.py",
}
EXPECTED_BOUNDED = {p for p in EXPECTED_FULL if not p.startswith("scripts/helpers/")}


class DerivationPolicyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        os.makedirs(os.path.join(self._tmp.name, "candidate"), exist_ok=True)
        self.repo = Repo(os.path.join(self._tmp.name, "candidate"))
        self.keys = os.path.join(self._tmp.name, "keys")
        os.makedirs(self.keys)
        self.private, self.public, self.fingerprint = keygen(self.keys, "operator")
        self.policy_dir = os.path.join(self._tmp.name, "policy")
        os.makedirs(self.policy_dir)
        self.write_policy(not_after=FAR_FUTURE)

    # -- fixture helpers ----------------------------------------------------
    def policy_document(self, *, not_after, members=None, public=None, fingerprint=None) -> dict:
        return {
            "schema": dp.POLICY_SCHEMA,
            "target_repository": TARGET,
            "accepted_signers": [
                {
                    "label": LABEL,
                    "fingerprint": fingerprint or self.fingerprint,
                    "public_key": public or self.public,
                    "not_after": not_after,
                }
            ],
            "derivation_policy": {
                "roots": [Repo.ROOT],
                "allowlist_prefixes": ["scripts/agent_relay/", "scripts/commission_train/"],
                "allowlist_files": [],
                "members": sorted(EXPECTED_BOUNDED if members is None else members),
            },
        }

    def write_policy(self, **kwargs) -> None:
        with open(os.path.join(self.policy_dir, dp.POLICY_FILE), "w", encoding="utf-8") as handle:
            json.dump(self.policy_document(**kwargs), handle)

    def policy(self) -> dp.Policy:
        return dp.load_policy(self.policy_dir)

    def evaluate(self, head: str, repository: str = TARGET, now=None):
        kwargs = {}
        if now is not None:
            kwargs["now"] = now
        return dp.evaluate_derivation_policy(
            self.repo.root, repository, self.repo.base, head, self.policy_dir, **kwargs
        )

    def manifest_for(self, head: str, private: str | None = None, sign_it: bool = True) -> bytes:
        """Compute the canonical manifest for the working tree's protected changes
        relative to the base and commit it (and its signature) onto the head."""
        manifest = dp.expected_manifest(self.repo.root, TARGET, self.repo.base, head, self.policy())
        self.repo.write_bytes(dp.MANIFEST_PATH, manifest)
        if sign_it:
            self.repo.write_bytes(dp.SIGNATURE_PATH, sign(private or self.private, manifest))
        return manifest

    def codes(self, findings) -> list[str]:
        return [code for code, _path, _detail in findings]

    # -- closure regeneration --------------------------------------------------
    def test_closure_follows_absolute_relative_lazy_and_submodule_imports_with_package_inits(self) -> None:
        full, bounded = dp.regenerate_closure(self.repo.root, self.repo.base, self.policy())
        self.assertEqual(full, EXPECTED_FULL)
        self.assertEqual(bounded, EXPECTED_BOUNDED)
        self.assertNotIn("scripts/agent_relay/unrelated.py", full)

    def test_missing_root_is_drift_not_silence(self) -> None:
        self.write_policy(not_after=FAR_FUTURE)
        with open(os.path.join(self.policy_dir, dp.POLICY_FILE), encoding="utf-8") as handle:
            document = json.load(handle)
        document["derivation_policy"]["roots"] = ["scripts/agent_relay/absent.py"]
        with open(os.path.join(self.policy_dir, dp.POLICY_FILE), "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        with self.assertRaises(dp.PolicyError) as ctx:
            dp.regenerate_closure(self.repo.root, self.repo.base, self.policy())
        self.assertEqual(ctx.exception.code, dp.DERIVATION_POLICY_DRIFT)

    # -- inert cases ----------------------------------------------------------
    def test_other_repository_is_inert(self) -> None:
        self.repo.write(Repo.ROOT, "WIDENED = True\n")
        head = self.repo.commit("touch protected in another repo")
        self.assertEqual(self.evaluate(head, repository="First-AI-Movers/other"), [])

    def test_unprotected_change_is_inert(self) -> None:
        self.repo.write("docs/notes.md", "more prose\n")
        self.repo.write("scripts/helpers/util.py", "Z = 4\n")  # in the closure, outside the allowlist
        head = self.repo.commit("unprotected")
        self.assertEqual(self.evaluate(head), [])

    def test_allowlisted_but_unprotected_change_needs_no_signature(self) -> None:
        self.repo.write("scripts/agent_relay/unrelated.py", "Y = 3\n")
        head = self.repo.commit("allowlisted non-member")
        self.assertEqual(self.evaluate(head), [])

    def test_no_policy_file_means_no_conjunct(self) -> None:
        os.unlink(os.path.join(self.policy_dir, dp.POLICY_FILE))
        self.repo.write(Repo.ROOT, "WIDENED = True\n")
        head = self.repo.commit("touch protected")
        self.assertEqual(self.evaluate(head), [])

    # -- the signed matrix ------------------------------------------------------
    def test_signed_modification_passes(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        manifest = self.manifest_for(head)
        head = self.repo.commit("sign")
        self.assertEqual(self.evaluate(head), [])
        document = json.loads(manifest)
        self.assertEqual([e["status"] for e in document["entries"]], ["modified"])
        self.assertNotIn(head, manifest.decode())
        self.assertNotIn("head", document)

    def test_signed_addition_deletion_and_rename_pass(self) -> None:
        self.repo.write("scripts/commission_train/derivation.py", "def derive_child():\n    return None\n")
        self.repo.write(Repo.ROOT, self.repo_root_source_importing("commission_train.derivation"))
        self.repo.remove("scripts/agent_relay/validate.py")
        self.repo.move("scripts/agent_relay/models.py", "scripts/agent_relay/models_v2.py")
        head = self.repo.commit("add, delete, rename")
        # The policy's member list must match the closure at the merge base, which
        # is unchanged by the head, so the committed list is still current.
        manifest = self.manifest_for(head)
        head = self.repo.commit("sign")
        self.assertEqual(self.evaluate(head), [])
        statuses = {e["path"]: e["status"] for e in json.loads(manifest)["entries"]}
        self.assertEqual(statuses["scripts/agent_relay/validate.py"], "deleted")
        self.assertEqual(statuses["scripts/agent_relay/models_v2.py"], "renamed")
        self.assertEqual(statuses[Repo.ROOT], "modified")
        rename = [e for e in json.loads(manifest)["entries"] if e["status"] == "renamed"][0]
        self.assertEqual(rename["rename_from"], "scripts/agent_relay/models.py")
        self.assertNotEqual(rename["pre_sha256"], dp.ABSENT)
        deleted = [e for e in json.loads(manifest)["entries"] if e["status"] == "deleted"][0]
        self.assertEqual(deleted["post_sha256"], dp.ABSENT)

    def repo_root_source_importing(self, extra: str) -> str:
        return (
            "import agent_relay.models\n"
            "from commission_train import authority\n"
            f"import {extra}\n"
            "def lazy():\n"
            "    from .validate import check  # noqa\n"
            "    import helpers.util\n"
        )

    # -- negatives ----------------------------------------------------------------
    def test_unsigned_protected_modification_is_refused(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected, no manifest")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
        self.assertIn("no signed manifest", findings[0][2])

    def test_manifest_that_omits_a_deletion_is_incomplete(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        self.repo.remove("scripts/agent_relay/validate.py")
        head = self.repo.commit("modify and delete")
        base = dp.merge_base(self.repo.root, self.repo.base, head)
        entries, _ = dp.protected_diff(self.repo.root, base, head, self.policy())
        partial = [e for e in entries if e.status != "deleted"]
        manifest = dp.canonical_manifest(TARGET, base, partial)
        self.repo.write_bytes(dp.MANIFEST_PATH, manifest)
        self.repo.write_bytes(dp.SIGNATURE_PATH, sign(self.private, manifest))
        head = self.repo.commit("sign a manifest without the deletion")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_MANIFEST_INCOMPLETE])
        self.assertIn("deleted:scripts/agent_relay/validate.py", findings[0][2])

    def test_rename_to_an_unlisted_path_cannot_escape(self) -> None:
        self.repo.move("scripts/agent_relay/models.py", "scripts/agent_relay/renamed_models.py")
        head = self.repo.commit("rename protected away")
        base = dp.merge_base(self.repo.root, self.repo.base, head)
        manifest = dp.canonical_manifest(TARGET, base, [])  # claims nothing protected changed
        self.repo.write_bytes(dp.MANIFEST_PATH, manifest)
        self.repo.write_bytes(dp.SIGNATURE_PATH, sign(self.private, manifest))
        head = self.repo.commit("sign an empty manifest")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_MANIFEST_INCOMPLETE])
        self.assertIn("renamed:scripts/agent_relay/renamed_models.py", findings[0][2])

    def test_signature_by_an_unpinned_key_is_refused(self) -> None:
        other, _pub, _fp = keygen(self.keys, "impostor")
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        self.manifest_for(head, private=other)
        head = self.repo.commit("sign with an unpinned key")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
        self.assertIn("does not verify", findings[0][2])

    def test_signature_in_the_wrong_namespace_is_refused(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        manifest = dp.expected_manifest(self.repo.root, TARGET, self.repo.base, head, self.policy())
        self.repo.write_bytes(dp.MANIFEST_PATH, manifest)
        self.repo.write_bytes(dp.SIGNATURE_PATH, sign(self.private, manifest, namespace="at-standing-ceiling"))
        head = self.repo.commit("sign in another namespace")
        self.assertEqual(self.codes(self.evaluate(head)), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])

    def test_expired_signer_is_stale(self) -> None:
        self.write_policy(not_after=PAST)
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        self.manifest_for(head)
        head = self.repo.commit("sign")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
        self.assertIn("expired", findings[0][2])

    def test_inactive_signer_entry_fails_closed(self) -> None:
        self.write_policy(not_after=None)
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        self.manifest_for(head)
        head = self.repo.commit("sign")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
        self.assertIn("not active", findings[0][2])

    def test_expiry_is_decided_at_evaluation_time(self) -> None:
        self.write_policy(not_after="2030-01-01T00:00:00Z")
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        self.manifest_for(head)
        head = self.repo.commit("sign")
        self.assertEqual(self.evaluate(head, now=lambda: 1.0e9), [])
        self.assertEqual(self.codes(self.evaluate(head, now=lambda: 4.0e9)), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])

    def test_stale_member_list_is_drift(self) -> None:
        self.write_policy(not_after=FAR_FUTURE, members=EXPECTED_BOUNDED - {"scripts/agent_relay/validate.py"})
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected under a stale list")
        self.manifest_for(head)
        head = self.repo.commit("sign")
        findings = self.evaluate(head)
        self.assertIn(dp.DERIVATION_POLICY_DRIFT, self.codes(findings))
        self.assertIn("scripts/agent_relay/validate.py", findings[0][2])

    def test_candidate_cannot_redefine_its_own_judge(self) -> None:
        """A candidate that ships its own policy file and pins its own key gets
        judged by the trusted policy directory, never by its own bytes."""
        impostor, pub, fp = keygen(self.keys, "impostor")
        self.repo.write(
            "aeos/standing-governor-policy.json",
            json.dumps(self.policy_document(not_after=FAR_FUTURE, public=pub, fingerprint=fp)),
        )
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("ship a forged policy")
        self.manifest_for(head, private=impostor)
        head = self.repo.commit("sign with the impostor key")
        self.assertEqual(self.codes(self.evaluate(head)), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])

    def test_manifest_and_signature_are_not_protected_paths(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        manifest = self.manifest_for(head)
        entries = json.loads(manifest)["entries"]
        self.assertEqual([e["path"] for e in entries], ["scripts/agent_relay/models.py"])
        head = self.repo.commit("sign")
        # Re-signing on a later head changes only the manifest files: still clean.
        manifest2 = self.manifest_for(head)
        self.assertEqual(manifest, manifest2)

    # -- policy document validation ----------------------------------------------
    def test_invalid_policy_is_gate_config_invalid(self) -> None:
        with open(os.path.join(self.policy_dir, dp.POLICY_FILE), "w", encoding="utf-8") as handle:
            handle.write('{"schema": "wrong"}')
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify")
        with self.assertRaises(dp.PolicyError) as ctx:
            self.evaluate(head)
        self.assertEqual(ctx.exception.code, dp.GATE_CONFIG_INVALID)

    def test_policy_rejects_unsorted_members_and_bad_fingerprint(self) -> None:
        document = self.policy_document(not_after=FAR_FUTURE)
        document["derivation_policy"]["members"] = list(reversed(document["derivation_policy"]["members"]))
        with self.assertRaises(dp.PolicyError):
            dp.parse_policy(json.dumps(document).encode())
        document = self.policy_document(not_after=FAR_FUTURE, fingerprint="SHA256:short")
        with self.assertRaises(dp.PolicyError):
            dp.parse_policy(json.dumps(document).encode())

    # -- signer identity: the pinned fingerprint is bound to the trusted key ------
    def test_fingerprint_of_matches_ssh_keygen_for_every_accepted_key_type(self) -> None:
        # Positive control: the pure-Python fingerprint is the value ssh-keygen prints.
        self.assertEqual(dp.fingerprint_of(self.public), self.fingerprint)
        for key_type, extra in (("ecdsa", ["-b", "256"]), ("rsa", ["-b", "2048"])):
            private = os.path.join(self.keys, key_type)
            subprocess.run(
                ["ssh-keygen", "-q", "-t", key_type, *extra, "-N", "", "-f", private],
                check=True, capture_output=True,
            )
            with open(private + ".pub", encoding="utf-8") as handle:
                parts = handle.read().split()
            expected = subprocess.run(
                ["ssh-keygen", "-lf", private + ".pub"], check=True, capture_output=True, text=True
            ).stdout.split()[1]
            self.assertEqual(dp.fingerprint_of(f"{parts[0]} {parts[1]}"), expected)

    def test_signer_whose_fingerprint_is_not_its_public_keys_is_refused(self) -> None:
        # RC0 finding 1: fingerprint of key A, public key B, signed by B was accepted.
        other_private, other_public, _other_fingerprint = keygen(self.keys, "other")
        self.write_policy(not_after=FAR_FUTURE, public=other_public, fingerprint=self.fingerprint)
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        with self.assertRaises(dp.PolicyError) as ctx:
            dp.load_policy(self.policy_dir)
        self.assertEqual(ctx.exception.code, dp.GATE_CONFIG_INVALID)
        self.assertIn("is not the fingerprint of public_key", ctx.exception.detail)
        # A manifest signed by the key that IS in public_key is still refused, and the
        # gate reports the typed policy defect rather than a PASS.
        manifest = dp.canonical_manifest(TARGET, self.repo.base, [])
        self.repo.write_bytes(dp.MANIFEST_PATH, manifest)
        self.repo.write_bytes(dp.SIGNATURE_PATH, sign(other_private, manifest))
        head = self.repo.commit("sign with the unbound key")
        report = gate.evaluate(
            candidate_dir=self.repo.root, repository=TARGET, base_sha=self.repo.base,
            head_sha=head, event_name="pull_request", policy_dir=self.policy_dir,
        )
        self.assertFalse(report.passed)
        self.assertIn(gate.GATE_CONFIG_INVALID, {f.code for f in report.findings})

    def test_public_key_blob_that_does_not_name_its_type_is_refused(self) -> None:
        import base64

        forged = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x07ssh-rsa" + b"\x01" * 32).decode()
        with self.assertRaises(ValueError):
            dp.fingerprint_of(forged)
        document = self.policy_document(not_after=FAR_FUTURE, public=forged)
        with self.assertRaises(dp.PolicyError) as ctx:
            dp.parse_policy(json.dumps(document).encode())
        self.assertIn("malformed", ctx.exception.detail)

    # -- the protected set follows the candidate's own closure ---------------------
    def test_newly_imported_allowlisted_helper_must_be_in_the_manifest(self) -> None:
        # RC0 finding 2: a root-only manifest was accepted for a change that also
        # added scripts/agent_relay/new_validator.py and imported it from the root.
        self.repo.write("scripts/agent_relay/new_validator.py", "def widen():\n    return True\n")
        self.repo.write(Repo.ROOT, self.repo_root_source_importing("agent_relay.new_validator"))
        head = self.repo.commit("add a helper and import it from a root")
        base = dp.merge_base(self.repo.root, self.repo.base, head)
        # The committed members alone (the pre-repair protected set) miss the helper.
        root_only, _ = dp.protected_diff(self.repo.root, base, head, self.policy())
        self.assertEqual([e.path for e in root_only], [Repo.ROOT])
        partial = dp.canonical_manifest(TARGET, base, root_only)
        self.repo.write_bytes(dp.MANIFEST_PATH, partial)
        self.repo.write_bytes(dp.SIGNATURE_PATH, sign(self.private, partial))
        head = self.repo.commit("sign the root-only manifest")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_MANIFEST_INCOMPLETE])
        self.assertIn("added:scripts/agent_relay/new_validator.py", findings[0][2])
        # The complete manifest covers the helper with its post-image digest and passes.
        manifest = self.manifest_for(head)
        head = self.repo.commit("sign the complete manifest")
        self.assertEqual(self.evaluate(head), [])
        entries = {e["path"]: e for e in json.loads(manifest)["entries"]}
        self.assertEqual(set(entries), {Repo.ROOT, "scripts/agent_relay/new_validator.py"})
        helper = entries["scripts/agent_relay/new_validator.py"]
        self.assertEqual(helper["status"], "added")
        self.assertEqual(helper["pre_sha256"], dp.ABSENT)
        self.assertEqual(helper["post_sha256"], hashlib.sha256(b"def widen():\n    return True\n").hexdigest())

    def test_newly_imported_helper_outside_the_allowlist_stays_ordinary_code(self) -> None:
        # Contrast control for the previous test: the same shape outside the allowlist
        # is the ADR's accepted residual, so only the root edit needs the signature.
        self.repo.write("scripts/helpers/extra.py", "W = 4\n")
        self.repo.write(Repo.ROOT, self.repo_root_source_importing("helpers.extra"))
        head = self.repo.commit("import a non-allowlisted helper")
        manifest = self.manifest_for(head)
        head = self.repo.commit("sign")
        self.assertEqual(self.evaluate(head), [])
        self.assertEqual([e["path"] for e in json.loads(manifest)["entries"]], [Repo.ROOT])

    def test_added_allowlisted_file_that_no_root_imports_is_not_protected(self) -> None:
        # Being under the allowlist is not being in the closure: an orphan needs no signature.
        self.repo.write("scripts/agent_relay/orphan.py", "ORPHAN = True\n")
        head = self.repo.commit("add an orphan under the allowlist")
        self.assertEqual(self.evaluate(head), [])

    def test_deleting_a_declared_root_is_drift_at_the_head(self) -> None:
        self.repo.remove(Repo.ROOT)
        head = self.repo.commit("delete a root")
        report = gate.evaluate(
            candidate_dir=self.repo.root, repository=TARGET, base_sha=self.repo.base,
            head_sha=head, event_name="pull_request", policy_dir=self.policy_dir,
        )
        self.assertFalse(report.passed)
        self.assertIn(gate.DERIVATION_POLICY_DRIFT, {f.code for f in report.findings})

    # -- the manifest representation is the ADR's: SHA-256 images and a diff digest --
    def test_manifest_carries_sha256_images_and_the_protected_diff_digest(self) -> None:
        # RC0 finding 3: the manifest recorded git object ids, not SHA-256 image digests.
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        manifest = self.manifest_for(head)
        document = json.loads(manifest)
        [entry] = document["entries"]
        self.assertEqual(entry["pre_sha256"], hashlib.sha256(b"X = 1\n").hexdigest())
        self.assertEqual(entry["post_sha256"], hashlib.sha256(b"X = 2\n").hexdigest())
        self.assertNotIn("pre_blob", entry)
        blob_id = git(self.repo.root, "rev-parse", f"{head}:scripts/agent_relay/models.py")
        self.assertNotIn(blob_id, manifest.decode())
        canonical_entries = json.dumps(document["entries"], sort_keys=True, separators=(",", ":"))
        self.assertEqual(
            document["protected_diff_sha256"], hashlib.sha256(canonical_entries.encode()).hexdigest()
        )
        head = self.repo.commit("sign")
        self.assertEqual(self.evaluate(head), [])

    def test_manifest_with_git_object_ids_or_a_wrong_digest_is_incomplete(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        expected = json.loads(self.manifest_for(head))
        # (a) the pre-repair representation: git object ids under the old field names
        legacy = dict(expected)
        legacy["entries"] = [
            {
                "path": e["path"], "status": e["status"],
                "pre_blob": git(self.repo.root, "rev-parse", f"{self.repo.base}:{e['path']}"),
                "post_blob": git(self.repo.root, "rev-parse", f"{head}:{e['path']}"),
            }
            for e in expected["entries"]
        ]
        legacy.pop("protected_diff_sha256")
        # (b) the right entries with a tampered digest
        tampered = dict(expected)
        tampered["protected_diff_sha256"] = "0" * 64
        for variant in (legacy, tampered):
            raw = (json.dumps(variant, sort_keys=True, separators=(",", ":")) + "\n").encode()
            self.repo.write_bytes(dp.MANIFEST_PATH, raw)
            self.repo.write_bytes(dp.SIGNATURE_PATH, sign(self.private, raw))
            head = self.repo.commit("sign a non-canonical manifest")
            self.assertEqual(self.codes(self.evaluate(head)), [dp.DERIVATION_POLICY_MANIFEST_INCOMPLETE])

    # -- review-thread repairs (PR #11 threads 3968966086 / 3968966100 / 3968977928) --
    def test_added_root_package_initializer_is_protected_at_the_head(self) -> None:
        # Codex P1: a root imported by dotted name executes its package __init__ first.
        # The root here imports nothing from its own package, so the initializer is
        # reachable only through seeding; adding one that did not exist at the base
        # must land in the signed set instead of passing as an unreachable allowlisted file.
        root = "scripts/commission_train/authority.py"
        self.repo.remove("scripts/commission_train/__init__.py")
        self.repo.base = self.repo.commit("base without the package initializer")
        document = self.policy_document(not_after=FAR_FUTURE, members={root})
        document["derivation_policy"]["roots"] = [root]
        with open(os.path.join(self.policy_dir, dp.POLICY_FILE), "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        self.repo.write("scripts/commission_train/__init__.py", "import os\nos.environ['WIDENED'] = '1'\n")
        head = self.repo.commit("add an executable package initializer, touch no root")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
        manifest = self.manifest_for(head)
        head = self.repo.commit("sign")
        self.assertEqual(self.evaluate(head), [])
        [entry] = json.loads(manifest)["entries"]
        self.assertEqual((entry["path"], entry["status"]), ("scripts/commission_train/__init__.py", "added"))

    def test_duplicate_signer_labels_are_refused(self) -> None:
        # Codex P2: ssh-keygen -I <label> accepts any allowed-signers line sharing the
        # label, so a rotated key under a reused label would let the expired key verify.
        _p, other_public, other_fingerprint = keygen(self.keys, "rotated")
        document = self.policy_document(not_after=PAST)
        document["accepted_signers"].append(
            {"label": LABEL, "fingerprint": other_fingerprint, "public_key": other_public, "not_after": FAR_FUTURE}
        )
        with self.assertRaises(dp.PolicyError) as ctx:
            dp.parse_policy(json.dumps(document).encode())
        self.assertEqual(ctx.exception.code, dp.GATE_CONFIG_INVALID)
        self.assertIn("labels must be unique", ctx.exception.detail)

    def test_verification_file_names_only_the_signer_under_test(self) -> None:
        # Defence in depth for the same finding: the allowed-signers bytes handed to
        # ssh-keygen carry exactly one key, and an expired key next to an active one
        # under a distinct label is still refused.
        old_private = self.private
        new_private, new_public, new_fingerprint = keygen(self.keys, "rotated")
        document = self.policy_document(not_after=PAST)
        document["accepted_signers"].append(
            {"label": "aeos-standing-governor-2", "fingerprint": new_fingerprint,
             "public_key": new_public, "not_after": FAR_FUTURE}
        )
        with open(os.path.join(self.policy_dir, dp.POLICY_FILE), "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        policy = self.policy()
        self.assertEqual(len(policy.signers), 2)
        for signer in policy.signers:
            allowed = dp._allowed_signers(signer).decode()
            self.assertEqual(allowed.count("\n"), 1)
            self.assertIn(signer.public_key, allowed)
            self.assertNotIn([s for s in policy.signers if s is not signer][0].public_key, allowed)
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        self.manifest_for(head, private=old_private)
        head = self.repo.commit("sign with the expired key")
        findings = self.evaluate(head)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
        self.assertIn("expired", findings[0][2])
        self.manifest_for(head, private=new_private)
        head = self.repo.commit("sign with the active key")
        self.assertEqual(self.evaluate(head), [])

    def test_changed_path_with_a_backslash_is_ordinary_and_typed(self) -> None:
        # CodeRabbit: a backslash is a legal file name; an unrelated one is inert, and
        # a path this conjunct cannot accept is a typed EVIDENCE_UNREADABLE, not a
        # bare ValueError.
        self.repo.write("docs/odd\\name.md", "prose\n")
        head = self.repo.commit("odd file name")
        self.assertEqual(self.evaluate(head), [])
        # git cannot emit a traversing path, so the typed conversion is exercised by
        # substituting the plumbing for one record.
        record = b":100644 100644 " + b"a" * 40 + b" " + b"b" * 40 + b" M\0../escape.py\0"
        original = dp._git
        dp._git = lambda *_args, **_kwargs: record
        try:
            with self.assertRaises(dp.PolicyError) as ctx:
                dp.raw_diff(self.repo.root, self.repo.base, head)
        finally:
            dp._git = original
        self.assertEqual(ctx.exception.code, dp.EVIDENCE_UNREADABLE)

    # -- the machine route (#3752 Slice A) -------------------------------------------
    MACHINE = "aeos-autonomous-main[bot]"
    OPERATOR = "hpcosta"
    PROGRAMME_REF = "First-AI-Movers/agent-toolkit#3732"

    def machine_policy(self, **kwargs) -> dict:
        document = self.policy_document(not_after=kwargs.pop("not_after", None))
        document["machine_route"] = {
            "machine_principals": [{"login": self.MACHINE, "type": "Bot"}],
            "operator_principals": [self.OPERATOR],
        }
        document["machine_route"].update(kwargs)
        return document

    def write_machine_policy(self, **kwargs) -> None:
        with open(os.path.join(self.policy_dir, dp.POLICY_FILE), "w", encoding="utf-8") as handle:
            json.dump(self.machine_policy(**kwargs), handle)

    @staticmethod
    def days_ahead(days: float) -> str:
        import datetime as _dt
        stamp = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=days)
        return stamp.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def programme_body(self, *, state="ACTIVE", not_after=None, envelope=None,
                       repository=TARGET, issue=3732) -> str:
        not_after = not_after or self.days_ahead(7)
        block = {"schema": "standing-authority/v2", "state": state, "repository": repository, "issue": issue,
                 "programme_id": "at-1951-standing", "serial": 3, "not_after": not_after,
                 "path_envelope": envelope or ["scripts/agent_relay/", "tests/agent_relay/"], "signature": ""}
        return "## Quiet child\n```standing-authority\n" + json.dumps(block, sort_keys=True) + "\n```\n"

    def evidence(self, *, author=None, author_type="Bot", programme=None, event="pull_request",
                 repository=TARGET, pr_body=None, head_commit=None, **programme_overrides) -> dict:
        doc = {"schema": dp.EVIDENCE_SCHEMA, "event": event, "repository": repository, "actor": author or self.MACHINE}
        if event == "pull_request":
            doc["pull_request"] = {"number": 3760, "author_login": author or self.MACHINE, "author_type": author_type,
                                   "head_sha": "0" * 40, "head_commit_author_login": head_commit or author or self.MACHINE,
                                   "body": pr_body if pr_body is not None else f"<!-- aeos-programme: {self.PROGRAMME_REF} -->"}
            if programme is not False:
                doc["programme"] = {"ref": self.PROGRAMME_REF, "state": "open", "author_login": self.OPERATOR,
                                    "author_type": "User", "body": self.programme_body(), "updated_at": "t",
                                    "editors": [self.OPERATOR]}
                doc["programme"].update(programme or {})
                doc["programme"].update(programme_overrides)
        return doc

    def write_evidence(self, doc) -> str:
        path = os.path.join(self.policy_dir, "evidence.json")
        with open(path, "w", encoding="utf-8") as handle:
            if isinstance(doc, (bytes, bytearray)):
                handle.write(doc.decode("utf-8", "replace"))
            else:
                json.dump(doc, handle)
        return path

    def protected_head(self) -> str:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        return self.repo.commit("machine-authored protected change, no manifest")

    def route(self, head, evidence_doc, **kwargs):
        path = self.write_evidence(evidence_doc) if evidence_doc is not None else None
        return dp.evaluate_derivation_policy(self.repo.root, kwargs.pop("repository", TARGET), self.repo.base, head,
                                             self.policy_dir, evidence_path=path, **kwargs)

    def test_a_machine_authored_protected_change_inside_a_current_operator_programme_needs_no_signature(self) -> None:
        self.write_machine_policy()
        head = self.protected_head()
        self.assertEqual(self.route(head, self.evidence()), [])
        # the same change with no evidence at all falls back to the SSH route and is refused
        findings = self.route(head, None)
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
        self.assertIn(dp.MACHINE_ROUTE_EVIDENCE_ABSENT, findings[0][2])

    def test_the_machine_route_is_off_unless_the_policy_pins_both_principal_sets(self) -> None:
        # the signer-only policy (no machine_route) never admits an unsigned protected diff
        head = self.protected_head()
        findings = self.route(head, self.evidence())
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED])
        self.assertIn(dp.MACHINE_ROUTE_DISABLED, findings[0][2])

    def test_every_machine_route_negative_refuses_with_its_own_reason(self) -> None:
        self.write_machine_policy()
        head = self.protected_head()
        cases = {
            dp.MACHINE_ROUTE_ACTOR_IS_OPERATOR: self.evidence(author=self.OPERATOR, author_type="User"),
            dp.MACHINE_ROUTE_ACTOR_NOT_MACHINE: self.evidence(author="someone-else[bot]"),
            dp.MACHINE_ROUTE_ACTOR_NOT_MACHINE + "-human-pretending": self.evidence(author=self.MACHINE, author_type="User"),
            dp.MACHINE_ROUTE_PROGRAMME_ABSENT: self.evidence(pr_body="no marker here"),
            dp.MACHINE_ROUTE_PROGRAMME_ABSENT + "-two-markers": self.evidence(
                pr_body=f"<!-- aeos-programme: {self.PROGRAMME_REF} --> <!-- aeos-programme: {TARGET}#1 -->"),
            dp.MACHINE_ROUTE_PROGRAMME_UNAVAILABLE: self.evidence(programme=False),
            dp.MACHINE_ROUTE_PROGRAMME_UNAVAILABLE + "-read-failed": self.evidence(unavailable="could not read"),
            dp.MACHINE_ROUTE_PROGRAMME_UNAVAILABLE + "-other-ref": self.evidence(ref=f"{TARGET}#99"),
            dp.MACHINE_ROUTE_PROGRAMME_NOT_OPEN: self.evidence(state="closed"),
            dp.MACHINE_ROUTE_AUTHORITY_NOT_OPERATOR: self.evidence(author_login=self.MACHINE, programme={"author_type": "Bot"}),
            dp.MACHINE_ROUTE_AUTHORITY_NOT_OPERATOR + "-operator-login-bot-type": self.evidence(programme={"author_type": "Bot"}),
            dp.MACHINE_ROUTE_TRIGGER_NOT_MACHINE: dict(self.evidence(), actor=self.OPERATOR),
            dp.MACHINE_ROUTE_TRIGGER_NOT_MACHINE + "-contributor-push": dict(self.evidence(), actor="contributor"),
            dp.MACHINE_ROUTE_HEAD_COMMIT_NOT_MACHINE: self.evidence(head_commit="contributor"),
            dp.MACHINE_ROUTE_AUTHORITY_EDITED_BY_NON_OPERATOR: self.evidence(editors=[self.OPERATOR, "contributor"]),
            dp.MACHINE_ROUTE_AUTHORITY_EDITED_BY_NON_OPERATOR + "-bot-edit": self.evidence(editors=[self.MACHINE]),
            dp.MACHINE_ROUTE_PROGRAMME_UNAVAILABLE + "-edit-history-unreadable": self.evidence(editors=None),
            dp.MACHINE_ROUTE_AUTHORITY_NOT_OPERATOR + "-other-human": self.evidence(author_login="contributor"),
            dp.MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID: self.evidence(body="no block"),
            dp.MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID + "-v1": self.evidence(
                body="```standing-authority\n" + json.dumps({"schema": "standing-authority/v1", "state": "ACTIVE"}) + "\n```\n"),
            dp.MACHINE_ROUTE_AUTHORITY_REF_MISMATCH: self.evidence(body=self.programme_body(issue=1951)),
            dp.MACHINE_ROUTE_REPOSITORY_MISMATCH: self.evidence(repository="First-AI-Movers/other"),
            dp.MACHINE_ROUTE_AUTHORITY_REF_MISMATCH + "-other-repo-block": self.evidence(
                body=self.programme_body(repository="First-AI-Movers/other")),
            dp.MACHINE_ROUTE_AUTHORITY_NOT_ACTIVE: self.evidence(body=self.programme_body(state="PAUSED")),
            dp.MACHINE_ROUTE_AUTHORITY_EXPIRED: self.evidence(body=self.programme_body(not_after="2000-01-01T00:00:00Z")),
            dp.MACHINE_ROUTE_AUTHORITY_TTL_EXCEEDED: self.evidence(body=self.programme_body(not_after=self.days_ahead(15))),
            dp.MACHINE_ROUTE_AUTHORITY_TTL_EXCEEDED + "-forever": self.evidence(body=self.programme_body(not_after="9999-12-31T23:59:59Z")),
            dp.MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID + "-traversal-after-a-match": self.evidence(
                body=self.programme_body(envelope=["scripts/agent_relay/", "../"])),
            dp.MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID + "-absolute-entry": self.evidence(
                body=self.programme_body(envelope=["/scripts/agent_relay/"])),
            dp.MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE: self.evidence(body=self.programme_body(envelope=["docs/"])),
            dp.MACHINE_ROUTE_EVENT_UNPROVABLE: self.evidence(event="merge_group"),
            dp.MACHINE_ROUTE_EVENT_UNPROVABLE + "-push-event-with-pr-block": dict(self.evidence(), event="push"),
            dp.MACHINE_ROUTE_EVIDENCE_MALFORMED: b"{not json",
            dp.MACHINE_ROUTE_EVIDENCE_MALFORMED + "-schema": {"schema": "other"},
        }
        for label, doc in cases.items():
            token = next(t for t in (
                dp.MACHINE_ROUTE_ACTOR_IS_OPERATOR, dp.MACHINE_ROUTE_ACTOR_NOT_MACHINE, dp.MACHINE_ROUTE_PROGRAMME_ABSENT,
                dp.MACHINE_ROUTE_PROGRAMME_UNAVAILABLE, dp.MACHINE_ROUTE_PROGRAMME_NOT_OPEN,
                dp.MACHINE_ROUTE_AUTHORITY_NOT_OPERATOR, dp.MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID,
                dp.MACHINE_ROUTE_AUTHORITY_REF_MISMATCH, dp.MACHINE_ROUTE_REPOSITORY_MISMATCH,
                dp.MACHINE_ROUTE_AUTHORITY_NOT_ACTIVE, dp.MACHINE_ROUTE_AUTHORITY_EXPIRED,
                dp.MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE, dp.MACHINE_ROUTE_EVENT_UNPROVABLE,
                dp.MACHINE_ROUTE_EVIDENCE_MALFORMED, dp.MACHINE_ROUTE_TRIGGER_NOT_MACHINE,
                dp.MACHINE_ROUTE_AUTHORITY_TTL_EXCEEDED, dp.MACHINE_ROUTE_ROOT_NEEDS_EXACT_ENVELOPE,
                dp.MACHINE_ROUTE_HEAD_COMMIT_NOT_MACHINE,
                dp.MACHINE_ROUTE_AUTHORITY_EDITED_BY_NON_OPERATOR) if label.startswith(t))
            findings = self.route(head, doc)
            self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_DIFF_UNSIGNED], label)
            self.assertIn(token, findings[0][2], label)

    def test_a_queued_merge_group_run_is_provable_when_the_workflow_resolved_the_queued_pr(self) -> None:
        self.write_machine_policy()
        head = self.protected_head()
        self.assertEqual(self.route(head, dict(self.evidence(), event="merge_group")), [])
        findings = self.route(head, {**self.evidence(programme=False), "event": "merge_group", "pull_request": None})
        self.assertIn(dp.MACHINE_ROUTE_EVENT_UNPROVABLE, findings[0][2])

    def test_a_declared_root_is_admitted_only_by_an_exact_envelope_entry(self) -> None:
        # Review F3: a directory prefix must never silently authorise rewriting the ceiling parser.
        self.write_machine_policy()
        self.repo.write(Repo.ROOT, "def check(x):\n    return True\n")
        head = self.repo.commit("rewrite the derivation root")
        findings = self.route(head, self.evidence(body=self.programme_body(envelope=["scripts/agent_relay/"])))
        self.assertIn(dp.MACHINE_ROUTE_ROOT_NEEDS_EXACT_ENVELOPE, findings[0][2])
        findings = self.route(head, self.evidence(body=self.programme_body(envelope=["scripts/"])))
        self.assertIn(dp.MACHINE_ROUTE_ROOT_NEEDS_EXACT_ENVELOPE, findings[0][2])
        self.assertEqual(self.route(head, self.evidence(body=self.programme_body(envelope=[Repo.ROOT]))), [])
        # a non-root member is still admitted by the prefix
        self.repo.write("scripts/agent_relay/models.py", "X = 5\n")
        head = self.repo.commit("also touch a non-root member")
        findings = self.route(head, self.evidence(body=self.programme_body(envelope=["scripts/agent_relay/"])))
        self.assertIn(dp.MACHINE_ROUTE_ROOT_NEEDS_EXACT_ENVELOPE, findings[0][2])
        self.assertEqual(self.route(head, self.evidence(body=self.programme_body(envelope=["scripts/agent_relay/", Repo.ROOT]))), [])

    def test_evidence_inside_the_candidate_tree_is_refused(self) -> None:
        # Review F8: evidence is the workflow's, never the candidate's.
        self.write_machine_policy()
        head = self.protected_head()
        inside = os.path.join(self.repo.root, "evidence.json")
        with open(inside, "w", encoding="utf-8") as handle:
            json.dump(self.evidence(), handle)
        findings = dp.evaluate_derivation_policy(self.repo.root, TARGET, self.repo.base, head, self.policy_dir,
                                                 evidence_path=inside)
        self.assertIn(dp.MACHINE_ROUTE_EVIDENCE_MALFORMED, findings[0][2])
        link = os.path.join(self.policy_dir, "evidence-link.json")
        os.symlink(inside, link)
        findings = dp.evaluate_derivation_policy(self.repo.root, TARGET, self.repo.base, head, self.policy_dir,
                                                 evidence_path=link)
        self.assertIn(dp.MACHINE_ROUTE_EVIDENCE_MALFORMED, findings[0][2])

    def test_the_workflow_marker_regex_matches_the_policy_regex(self) -> None:
        # Review F6: the evidence step carries a second copy of the marker pattern; keep them equal.
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        with open(os.path.join(root, ".github", "workflows", "aeos-merge-ready.yml"), encoding="utf-8") as handle:
            workflow = handle.read()
        import re as _re
        embedded = _re.search(r're\.findall\(r"(.*?)", body\)', workflow)
        self.assertIsNotNone(embedded)
        self.assertEqual(embedded.group(1), dp._PROGRAMME_MARKER_RE.pattern)
        self.assertIn("--evidence-file", workflow)

    def test_the_machine_route_covers_renames_and_deletions_by_both_paths(self) -> None:
        self.write_machine_policy()
        self.repo.move("scripts/agent_relay/models.py", "scripts/agent_relay/models_v2.py")
        head = self.repo.commit("rename inside the envelope")
        self.assertEqual(self.route(head, self.evidence()), [])
        # an envelope that covers only the new path does not cover the old one
        findings = self.route(head, self.evidence(body=self.programme_body(envelope=["scripts/agent_relay/models_v2.py"])))
        self.assertIn(dp.MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE, findings[0][2])

    def test_the_ssh_route_still_admits_when_the_machine_route_refuses(self) -> None:
        self.write_machine_policy(not_after=FAR_FUTURE)
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        self.manifest_for(head)
        head = self.repo.commit("sign")
        self.assertEqual(self.route(head, self.evidence(author=self.OPERATOR, author_type="User")), [])
        # and both refusals are reported together when neither route admits
        self.repo.write("scripts/agent_relay/models.py", "X = 3\n")
        head = self.repo.commit("modify again without re-signing")
        findings = self.route(head, self.evidence(author=self.OPERATOR, author_type="User"))
        self.assertEqual(self.codes(findings), [dp.DERIVATION_POLICY_MANIFEST_INCOMPLETE])

    def test_a_policy_that_blurs_machine_and_operator_principals_is_invalid(self) -> None:
        for bad in ({"operator_principals": [self.MACHINE]}, {"machine_principals": [{"login": self.OPERATOR, "type": "Bot"}]},
                    {"machine_principals": [{"login": self.MACHINE, "type": "User"}]},
                    {"machine_principals": []}, {"operator_principals": []}, {"extra": 1},
                    {"operator_principals": [self.OPERATOR, self.OPERATOR]},
                    {"machine_principals": [{"login": self.MACHINE, "type": "Bot"}, {"login": self.MACHINE, "type": "Bot"}]}):
            with self.assertRaises(dp.PolicyError, msg=str(bad)):
                dp.parse_policy(json.dumps(self.machine_policy(**bad)).encode())

    def test_the_shipped_policy_pins_the_proven_principals(self) -> None:
        shipped = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        policy = dp.load_policy(shipped)
        self.assertTrue(policy.machine_route_enabled)
        self.assertEqual(policy.machine_principals, (("aeos-autonomous-main[bot]", "Bot"),))
        self.assertEqual(policy.operator_principals, frozenset({"hpcosta"}))

    # -- composition into the gate -------------------------------------------------
    def test_gate_reports_the_typed_reason_and_keeps_every_other_floor(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        self.repo.write("broken.json", "{not json")
        head = self.repo.commit("unsigned protected change plus a broken config")
        report = gate.evaluate(
            candidate_dir=self.repo.root, repository=TARGET, base_sha=self.repo.base,
            head_sha=head, event_name="pull_request", policy_dir=self.policy_dir,
        )
        self.assertFalse(report.passed)
        codes = {f.code for f in report.findings}
        self.assertIn(gate.DERIVATION_POLICY_DIFF_UNSIGNED, codes)
        self.assertIn(gate.STRUCTURED_DATA_UNPARSEABLE, codes)
        self.assertIn(gate.DERIVATION_POLICY_DIFF_UNSIGNED, gate.REASON_CODES)
        rendered = gate.render(report, TARGET, "pull_request", self.repo.base, head)
        self.assertIn("DERIVATION_POLICY_DIFF_UNSIGNED", rendered)

    def test_gate_passes_a_signed_protected_change(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify protected")
        self.manifest_for(head)
        head = self.repo.commit("sign")
        report = gate.evaluate(
            candidate_dir=self.repo.root, repository=TARGET, base_sha=self.repo.base,
            head_sha=head, event_name="pull_request", policy_dir=self.policy_dir,
        )
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_gate_without_a_policy_directory_entry_is_unchanged_for_other_repositories(self) -> None:
        self.repo.write("scripts/agent_relay/models.py", "X = 2\n")
        head = self.repo.commit("modify")
        report = gate.evaluate(
            candidate_dir=self.repo.root, repository="First-AI-Movers/other", base_sha=self.repo.base,
            head_sha=head, event_name="pull_request", policy_dir=self.policy_dir,
        )
        self.assertTrue(report.passed, [f.render() for f in report.findings])

    def test_shipped_policy_file_is_valid_and_targets_the_toolkit(self) -> None:
        shipped = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        policy = dp.load_policy(shipped)
        self.assertIsNotNone(policy)
        self.assertEqual(policy.target_repository, TARGET.lower())
        self.assertEqual([s.label for s in policy.signers], [LABEL])
        self.assertTrue(policy.members)
        self.assertTrue(all(policy.in_allowlist(m) for m in policy.members))
        self.assertTrue(set(policy.roots) <= policy.members)
        [signer] = policy.signers
        self.assertEqual(dp.fingerprint_of(signer.public_key), signer.fingerprint)
        # The operator's value (#1951 comment 5601714921), taken verbatim: not inferred here.
        self.assertEqual(signer.not_after, dp._parse_not_after("2026-12-08T00:00:00Z", LABEL))
        self.assertLess(signer.not_after, dp._parse_not_after("2026-12-08T00:00:01Z", LABEL))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
