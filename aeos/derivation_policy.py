#!/usr/bin/env python3
"""derivation_policy.py -- the standing-governor derivation-policy conjunct.

Decided by ``ADR:standing-governor-continuity-authority`` (agent-toolkit, Accepted
2026-09-09) §D2 and §D15 Tier 1 item 1, and authorized by #1951 operator decision
5600051094 item 2. This module is TRUSTED POLICY: it is checked out from the
organization's ``.github`` repository and reads candidate bytes as data only.

What it decides
---------------
A pull request in the target repository whose base-to-head diff touches a
*protected* path -- one of the modules that implement the standing-governor
ceiling parser, narrowing chain, deriver, admission and replay enforcers, launcher
and naming validator -- earns no ``aeos-merge-ready`` verdict unless the head
carries an operator-signed manifest over the whole protected diff. Without that,
a process holding the shared node credential could widen the validators that read
its own authority through an ordinary auto-squashed pull request.

The protected set is a **generated, bounded member list** committed here: the
first-party import closure of the named roots under ``scripts/`` (whole AST, so a
lazy in-function import counts; package ``__init__.py`` modules count because
they execute on import), intersected with an explicit allowlist. The gate
regenerates that set from the *base* commit on every evaluation and refuses when
the committed list has drifted, so the list is never stale and never hand-kept.

The signed manifest binds the trusted base SHA and one entry per protected path
whose identity differs between base and head: status ``added`` / ``modified`` /
``deleted`` / ``renamed``, the pre-image blob id (or ``absent``), the post-image
blob id (or ``absent``), and both paths for a rename. It never binds the head
SHA, which would depend on the manifest itself. The manifest and its signature are
excluded from the diff they describe.

Trust model, restated for this conjunct
---------------------------------------
* Policy (signer, namespace, roots, allowlist, member list) is read from THIS
  checkout, never from the candidate.
* Candidate Python is parsed with :mod:`ast`; nothing in it runs.
* ``ssh-keygen -Y verify`` is the one subprocess beyond ``git`` this repository
  permits, invoked with argv only, over a manifest the gate already read and a
  signature blob the gate already read, against an allowed-signers file the gate
  writes from trusted policy into a private temporary directory. The candidate
  supplies bytes to a system tool; it never supplies a command.
* Every route out reports a code from the gate's closed vocabulary.
"""

from __future__ import annotations

import ast
import datetime as _dt
import json
import os
import re
import subprocess
import tempfile
import time

DERIVATION_POLICY_DIFF_UNSIGNED = "DERIVATION_POLICY_DIFF_UNSIGNED"
DERIVATION_POLICY_MANIFEST_INCOMPLETE = "DERIVATION_POLICY_MANIFEST_INCOMPLETE"
DERIVATION_POLICY_DRIFT = "DERIVATION_POLICY_DRIFT"
GATE_CONFIG_INVALID = "GATE_CONFIG_INVALID"
EVIDENCE_UNREADABLE = "EVIDENCE_UNREADABLE"

POLICY_FILE = "standing-governor-policy.json"
POLICY_SCHEMA = "aeos-standing-governor-policy/v1"
MANIFEST_SCHEMA = "derivation-policy-manifest/v1"
SIGNATURE_NAMESPACE = "at-derivation-policy"

MANIFEST_PATH = "aeos/derivation-policy-manifest.json"
SIGNATURE_PATH = "aeos/derivation-policy-manifest.sig"
"""Where the candidate carries the manifest and its detached SSH signature.
Both live outside every protected path, and both are excluded from the diff the
manifest describes."""

SCRIPTS_ROOT = "scripts/"
PYTHON_SUFFIX = ".py"
MAX_POLICY_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_MODULE_BYTES = 4 << 20
MAX_CLOSURE_MODULES = 5000
GIT_TIMEOUT_SECONDS = 30
SSH_KEYGEN_TIMEOUT_SECONDS = 15
ABSENT = "absent"
STATUSES = ("added", "modified", "deleted", "renamed")

_HEX40 = re.compile(r"[0-9a-f]{40}")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_LABEL_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_PUBKEY_RE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]+$")


class PolicyError(Exception):
    """A typed refusal from this conjunct; the gate maps it onto its vocabulary."""

    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(f"{code} {path}: {detail}")
        self.code = code
        self.path = path
        self.detail = detail


# --------------------------------------------------------------------------
# Policy (trusted data, read from this checkout)
# --------------------------------------------------------------------------
class Signer:
    __slots__ = ("label", "fingerprint", "public_key", "not_after")

    def __init__(self, label: str, fingerprint: str, public_key: str, not_after) -> None:
        self.label = label
        self.fingerprint = fingerprint
        self.public_key = public_key
        self.not_after = not_after  # ``None`` means the entry is not yet active.


class Policy:
    __slots__ = (
        "target_repository",
        "signers",
        "roots",
        "allowlist_prefixes",
        "allowlist_files",
        "members",
        "manifest_path",
        "signature_path",
    )

    def __init__(self, document: dict) -> None:
        self.target_repository = document["target_repository"].strip().lower()
        self.signers = [
            Signer(s["label"], s["fingerprint"], s["public_key"], s.get("not_after"))
            for s in document["accepted_signers"]
        ]
        policy = document["derivation_policy"]
        self.roots = tuple(policy["roots"])
        self.allowlist_prefixes = tuple(policy["allowlist_prefixes"])
        self.allowlist_files = frozenset(policy["allowlist_files"])
        self.members = frozenset(policy["members"])
        self.manifest_path = document.get("manifest_path", MANIFEST_PATH)
        self.signature_path = document.get("signature_path", SIGNATURE_PATH)

    def protects(self, path: str) -> bool:
        return path in self.members

    def in_allowlist(self, path: str) -> bool:
        return path in self.allowlist_files or any(
            path.startswith(prefix) for prefix in self.allowlist_prefixes
        )


def _parse_not_after(value, label: str):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"signer {label}: not_after must be a string or null")
    try:
        stamp = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"signer {label}: not_after is not ISO-8601: {exc}") from exc
    if stamp.tzinfo is None:
        raise ValueError(f"signer {label}: not_after must carry a UTC offset")
    return stamp.timestamp()


def parse_policy(raw: bytes) -> Policy:
    """Validate the trusted policy document. Every defect is ``GATE_CONFIG_INVALID``."""
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(GATE_CONFIG_INVALID, POLICY_FILE, "policy file exceeds the size cap")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PolicyError(GATE_CONFIG_INVALID, POLICY_FILE, f"policy is not readable JSON: {exc}")
    try:
        if not isinstance(document, dict) or document.get("schema") != POLICY_SCHEMA:
            raise ValueError(f"schema must be {POLICY_SCHEMA!r}")
        if not isinstance(document.get("target_repository"), str) or "/" not in document["target_repository"]:
            raise ValueError("target_repository must be 'owner/name'")
        signers = document.get("accepted_signers")
        if not isinstance(signers, list) or not signers:
            raise ValueError("accepted_signers must be a non-empty list")
        for signer in signers:
            if not isinstance(signer, dict):
                raise ValueError("each accepted signer must be an object")
            label = signer.get("label")
            if not isinstance(label, str) or not _LABEL_RE.match(label):
                raise ValueError("signer label must be a lowercase kebab token")
            if not isinstance(signer.get("fingerprint"), str) or not _FINGERPRINT_RE.match(
                signer["fingerprint"]
            ):
                raise ValueError(f"signer {label}: fingerprint must be SHA256:<43 base64 chars>")
            if not isinstance(signer.get("public_key"), str) or not _PUBKEY_RE.match(
                signer["public_key"]
            ):
                raise ValueError(f"signer {label}: public_key must be '<type> <base64>'")
            signer["not_after"] = _parse_not_after(signer.get("not_after"), label)
        policy = document.get("derivation_policy")
        if not isinstance(policy, dict):
            raise ValueError("derivation_policy must be an object")
        for key in ("roots", "allowlist_prefixes", "allowlist_files", "members"):
            value = policy.get(key)
            if not isinstance(value, list) or any(not isinstance(p, str) or not p for p in value):
                raise ValueError(f"derivation_policy.{key} must be a list of paths")
            for p in value:
                _safe_relpath(p.rstrip("/") if key == "allowlist_prefixes" else p, key)
        if not policy["roots"]:
            raise ValueError("derivation_policy.roots must not be empty")
        for root in policy["roots"]:
            if not root.startswith(SCRIPTS_ROOT) or not root.endswith(PYTHON_SUFFIX):
                raise ValueError(f"root {root!r} must be a Python module under {SCRIPTS_ROOT}")
        for prefix in policy["allowlist_prefixes"]:
            if not prefix.startswith(SCRIPTS_ROOT) or not prefix.endswith("/"):
                raise ValueError(f"allowlist prefix {prefix!r} must be a directory under {SCRIPTS_ROOT}")
        members = policy["members"]
        if len(members) != len(set(members)) or members != sorted(members):
            raise ValueError("derivation_policy.members must be sorted and unique")
        for key in ("manifest_path", "signature_path"):
            if key in document:
                _safe_relpath(document[key], key)
        return Policy(document)
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyError(GATE_CONFIG_INVALID, POLICY_FILE, f"policy is invalid: {exc}")


def _safe_relpath(path: str, role: str) -> str:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        raise ValueError(f"{role}: {path!r} is not a repository-relative path")
    parts = path.split("/")
    if ".." in parts or "." in parts or "" in parts:
        raise ValueError(f"{role}: {path!r} traverses or has an empty segment")
    return path


def load_policy(policy_dir: str) -> Policy | None:
    """The trusted policy beside this module, or ``None`` when the organization has
    not declared one (the conjunct is then absent, never silently green)."""
    path = os.path.join(policy_dir, POLICY_FILE)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        return parse_policy(handle.read())


# --------------------------------------------------------------------------
# git plumbing (argv only; every interpolated value is validated hex or a constant)
# --------------------------------------------------------------------------
def _git(candidate_dir: str, args: list[str], stdin: bytes | None = None) -> bytes:
    cmd = ["git", "-C", candidate_dir, "--no-pager"] + args
    try:
        proc = subprocess.run(
            cmd, input=stdin, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, check=False
        )
    except FileNotFoundError as exc:  # pragma: no cover
        raise PolicyError(EVIDENCE_UNREADABLE, "-", f"git is unavailable: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PolicyError(EVIDENCE_UNREADABLE, "-", f"git timed out: {' '.join(args)}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "git failed"
        raise PolicyError(EVIDENCE_UNREADABLE, "-", f"git {args[0]} failed: {detail}")
    return proc.stdout


def _hex(sha: str, role: str) -> str:
    sha = (sha or "").lower()
    if not _HEX40.fullmatch(sha):
        raise PolicyError(EVIDENCE_UNREADABLE, "-", f"{role} is not a full object id: {sha!r}")
    return sha


def merge_base(candidate_dir: str, base_sha: str, head_sha: str) -> str:
    out = _git(candidate_dir, ["merge-base", _hex(base_sha, "base"), _hex(head_sha, "head")])
    return _hex(out.decode("utf-8", "replace").strip(), "merge base")


def tree_paths(candidate_dir: str, commit: str, prefix: str) -> dict[str, str]:
    """``path -> blob id`` for every regular file under ``prefix`` at ``commit``."""
    out = _git(candidate_dir, ["ls-tree", "-r", "-z", "--full-tree", _hex(commit, "commit"), "--", prefix])
    result: dict[str, str] = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        parts = meta.decode("utf-8", "replace").split()
        if len(parts) != 3 or parts[1] != "blob" or parts[0] not in ("100644", "100755"):
            continue
        result[os.fsdecode(path)] = parts[2]
    return result


def read_blobs(candidate_dir: str, shas: list[str]) -> dict[str, bytes]:
    if not shas:
        return {}
    out = _git(candidate_dir, ["cat-file", "--batch"], stdin=("\n".join(shas) + "\n").encode())
    blobs: dict[str, bytes] = {}
    pos = 0
    while pos < len(out):
        end = out.find(b"\n", pos)
        if end < 0:
            raise PolicyError(EVIDENCE_UNREADABLE, "-", "git cat-file emitted a truncated header")
        header = out[pos:end].decode("utf-8", "replace").split()
        if len(header) == 2:
            raise PolicyError(EVIDENCE_UNREADABLE, "-", f"object {header[0]} is {header[1]}")
        if len(header) != 3:
            raise PolicyError(EVIDENCE_UNREADABLE, "-", f"git cat-file emitted a malformed header: {header!r}")
        sha, _kind, raw_size = header
        size = int(raw_size)
        start = end + 1
        blobs[sha] = out[start : start + size]
        pos = start + size + 1
    return blobs


# --------------------------------------------------------------------------
# Closure regeneration (trusted code walks candidate Python as data)
# --------------------------------------------------------------------------
def _module_id(path: str) -> str | None:
    """``scripts/a/b.py`` -> ``a.b``; ``scripts/a/__init__.py`` -> ``a``."""
    if not path.startswith(SCRIPTS_ROOT) or not path.endswith(PYTHON_SUFFIX):
        return None
    rel = path[len(SCRIPTS_ROOT) : -len(PYTHON_SUFFIX)]
    if rel.endswith("/__init__"):
        rel = rel[: -len("/__init__")]
    return rel.replace("/", ".")


def _resolve(module_id: str, files: dict[str, str]) -> str | None:
    """A dotted module id to its file under ``scripts/``, or ``None`` for a
    standard-library, third-party or absent module."""
    if not module_id:
        return None
    base = SCRIPTS_ROOT + module_id.replace(".", "/")
    if base + PYTHON_SUFFIX in files:
        return base + PYTHON_SUFFIX
    if base + "/__init__.py" in files:
        return base + "/__init__.py"
    return None


def _imports_of(tree: ast.AST, module_id: str, is_package: bool) -> set[str]:
    """Every dotted module id the tree imports, absolute or relative, at any depth."""
    out: set[str] = set()
    package_parts = module_id.split(".") if is_package else module_id.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                parts = name.split(".")
                for depth in range(1, len(parts) + 1):
                    out.add(".".join(parts[:depth]))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level - 1 > len(package_parts):
                    continue
                anchor = package_parts[: len(package_parts) - (node.level - 1)]
                base = ".".join(anchor + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            if base:
                parts = base.split(".")
                for depth in range(1, len(parts) + 1):
                    out.add(".".join(parts[:depth]))
            for alias in node.names:
                if alias.name != "*" and base:
                    out.add(base + "." + alias.name)
                elif alias.name != "*" and not base:
                    out.add(alias.name)
    return out


def regenerate_closure(candidate_dir: str, commit: str, policy: Policy) -> tuple[set[str], set[str]]:
    """``(full closure, bounded members)`` at ``commit``, from blobs read as data."""
    files = tree_paths(candidate_dir, commit, SCRIPTS_ROOT)
    pending: list[str] = []
    for root in policy.roots:
        if root not in files:
            raise PolicyError(
                DERIVATION_POLICY_DRIFT, root, f"declared derivation root is absent at {commit[:12]}"
            )
        pending.append(root)
    seen: set[str] = set()
    while pending:
        if len(seen) > MAX_CLOSURE_MODULES:
            raise PolicyError(EVIDENCE_UNREADABLE, "-", "import closure exceeds the module cap")
        batch = [p for p in pending if p not in seen]
        pending = []
        if not batch:
            break
        seen.update(batch)
        blobs = read_blobs(candidate_dir, sorted({files[p] for p in batch}))
        for path in batch:
            data = blobs.get(files[path])
            if data is None or len(data) > MAX_MODULE_BYTES:
                raise PolicyError(EVIDENCE_UNREADABLE, path, "module content unreadable or over the cap")
            try:
                tree = ast.parse(data.decode("utf-8"), filename=path)
            except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
                raise PolicyError(
                    DERIVATION_POLICY_DRIFT, path, f"protected module does not parse at {commit[:12]}: {type(exc).__name__}"
                )
            module_id = _module_id(path) or ""
            for imported in _imports_of(tree, module_id, path.endswith("/__init__.py")):
                target = _resolve(imported, files)
                if target and target not in seen:
                    pending.append(target)
    bounded = {p for p in seen if policy.in_allowlist(p)}
    return seen, bounded


# --------------------------------------------------------------------------
# Protected diff from the merge base, rename-aware
# --------------------------------------------------------------------------
class Entry:
    __slots__ = ("path", "status", "pre_blob", "post_blob", "rename_from")

    def __init__(self, path: str, status: str, pre_blob: str, post_blob: str, rename_from: str | None) -> None:
        self.path = path
        self.status = status
        self.pre_blob = pre_blob
        self.post_blob = post_blob
        self.rename_from = rename_from

    def as_dict(self) -> dict:
        record = {
            "path": self.path,
            "status": self.status,
            "pre_blob": self.pre_blob,
            "post_blob": self.post_blob,
        }
        if self.rename_from is not None:
            record["rename_from"] = self.rename_from
        return record


def protected_diff(candidate_dir: str, base: str, head: str, policy: Policy) -> tuple[list[Entry], list[str]]:
    """Every change between ``base`` and ``head`` that touches a protected path,
    with pre- and post-image blob ids and rename detection. Returns the entries and
    the list of all changed paths (for the inert pre-check)."""
    out = _git(
        candidate_dir,
        ["diff", "--no-ext-diff", "--no-textconv", "-M", "--raw", "--abbrev=40", "-z", _hex(base, "base"), _hex(head, "head")],
    )
    fields = out.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    entries: list[Entry] = []
    touched: list[str] = []
    index = 0
    while index < len(fields):
        meta = fields[index].decode("utf-8", "replace")
        if not meta.startswith(":"):
            raise PolicyError(EVIDENCE_UNREADABLE, "-", f"git diff emitted an unrecognised record: {meta!r}")
        parts = meta[1:].split()
        if len(parts) != 5:
            raise PolicyError(EVIDENCE_UNREADABLE, "-", f"git diff emitted a malformed record: {meta!r}")
        src_mode, dst_mode, src_sha, dst_sha, status = parts
        code = status[0]
        if code in ("R", "C"):
            if index + 2 >= len(fields):
                raise PolicyError(EVIDENCE_UNREADABLE, "-", "git diff emitted a rename with no destination")
            old = os.fsdecode(fields[index + 1])
            new = os.fsdecode(fields[index + 2])
            index += 3
        else:
            if index + 1 >= len(fields):
                raise PolicyError(EVIDENCE_UNREADABLE, "-", "git diff emitted a record with no path")
            old = new = os.fsdecode(fields[index + 1])
            index += 2
        for p in {old, new}:
            _safe_relpath(p, "changed path")
        touched.extend({old, new})
        pre = src_sha if src_sha.strip("0") else ABSENT
        post = dst_sha if dst_sha.strip("0") else ABSENT
        if code == "A":
            if policy.protects(new):
                entries.append(Entry(new, "added", ABSENT, post, None))
        elif code == "D":
            if policy.protects(old):
                entries.append(Entry(old, "deleted", pre, ABSENT, None))
        elif code == "M" or code == "T":
            if policy.protects(new):
                entries.append(Entry(new, "modified", pre, post, None))
        elif code == "R":
            if policy.protects(old) or policy.protects(new):
                entries.append(Entry(new, "renamed", pre, post, old))
        elif code == "C":
            if policy.protects(new):
                entries.append(Entry(new, "added", ABSENT, post, None))
        else:
            raise PolicyError(EVIDENCE_UNREADABLE, new, f"git diff emitted an unknown status {status!r}")
    entries.sort(key=lambda e: e.path)
    return entries, touched


def canonical_manifest(repository: str, base: str, entries: list[Entry]) -> bytes:
    """The exact bytes the operator signs and the gate recomputes. The head SHA is
    deliberately absent: it would depend on the manifest committed on that head."""
    document = {
        "schema": MANIFEST_SCHEMA,
        "repository": repository.strip().lower(),
        "base_sha": base,
        "namespace": SIGNATURE_NAMESPACE,
        "entries": [e.as_dict() for e in entries],
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# Signature verification (argv only; bytes the gate already read)
# --------------------------------------------------------------------------
def _allowed_signers(policy: Policy) -> bytes:
    lines = [f'{s.label} namespaces="{SIGNATURE_NAMESPACE}" {s.public_key}\n' for s in policy.signers]
    return "".join(lines).encode("utf-8")


def verify_signature(policy: Policy, signer: Signer, manifest: bytes, signature: bytes) -> str | None:
    """``None`` when ``signature`` is a valid signature by ``signer`` over
    ``manifest`` in the policy namespace; otherwise a one-line reason."""
    if len(signature) > MAX_SIGNATURE_BYTES:
        return "signature exceeds the size cap"
    if b"-----BEGIN SSH SIGNATURE-----" not in signature:
        return "signature is not an SSH signature block"
    with tempfile.TemporaryDirectory(prefix="aeos-derivation-policy-") as tmp:
        allowed = os.path.join(tmp, "allowed_signers")
        sig_path = os.path.join(tmp, "manifest.sig")
        with open(allowed, "wb") as handle:
            handle.write(_allowed_signers(policy))
        with open(sig_path, "wb") as handle:
            handle.write(signature)
        cmd = [
            "ssh-keygen", "-Y", "verify", "-f", allowed, "-I", signer.label,
            "-n", SIGNATURE_NAMESPACE, "-s", sig_path,
        ]
        try:
            proc = subprocess.run(
                cmd, input=manifest, capture_output=True, timeout=SSH_KEYGEN_TIMEOUT_SECONDS, check=False
            )
        except FileNotFoundError:
            return "ssh-keygen is unavailable on this runner"
        except subprocess.TimeoutExpired:
            return "ssh-keygen timed out"
    if proc.returncode != 0:
        return "signature does not verify against the pinned signer"
    return None


# --------------------------------------------------------------------------
# The conjunct
# --------------------------------------------------------------------------
def evaluate_derivation_policy(
    candidate_dir: str,
    repository: str,
    base_sha: str,
    head_sha: str,
    policy_dir: str,
    now=time.time,
) -> list[tuple[str, str, str]]:
    """``(code, path, detail)`` findings for the derivation-policy conjunct.

    Inert (returns ``[]``) when no policy is declared, when the repository is not
    the policy's target, or when the change touches no protected or allowlisted
    path. Every refusal is typed; nothing here can produce a PASS by accident.
    """
    policy = load_policy(policy_dir)
    if policy is None or (repository or "").strip().lower() != policy.target_repository:
        return []

    base = merge_base(candidate_dir, base_sha, head_sha)
    entries, touched = protected_diff(candidate_dir, base, head_sha, policy)
    interesting = [p for p in touched if policy.protects(p) or policy.in_allowlist(p)]
    if not interesting and not entries:
        return []  # inert: the candidate touches nothing near the protected set

    findings: list[tuple[str, str, str]] = []

    # Drift: the committed member list must equal the closure regenerated at the
    # merge base. A stale list would protect the wrong files.
    _full, regenerated = regenerate_closure(candidate_dir, base, policy)
    if regenerated != policy.members:
        missing = sorted(regenerated - policy.members)[:6]
        extra = sorted(policy.members - regenerated)[:6]
        findings.append(
            (
                DERIVATION_POLICY_DRIFT,
                POLICY_FILE,
                "committed member list differs from the closure regenerated at "
                f"{base[:12]} (not committed: {missing}; no longer in closure: {extra})",
            )
        )
    if not entries:
        return findings  # allowlisted-but-unprotected change: no signature needed

    # A protected diff needs the operator's signature over its canonical bytes.
    head_tree = tree_paths(candidate_dir, head_sha, "aeos/")
    manifest_sha = head_tree.get(policy.manifest_path)
    signature_sha = head_tree.get(policy.signature_path)
    expected = canonical_manifest(repository, base, entries)
    if manifest_sha is None or signature_sha is None:
        findings.append(
            (
                DERIVATION_POLICY_DIFF_UNSIGNED,
                policy.manifest_path,
                f"{len(entries)} protected path(s) changed and the head carries no "
                f"signed manifest ({policy.manifest_path} + {policy.signature_path})",
            )
        )
        return findings
    blobs = read_blobs(candidate_dir, sorted({manifest_sha, signature_sha}))
    manifest = blobs.get(manifest_sha, b"")
    signature = blobs.get(signature_sha, b"")
    if len(manifest) > MAX_MANIFEST_BYTES:
        findings.append((DERIVATION_POLICY_MANIFEST_INCOMPLETE, policy.manifest_path, "manifest exceeds the size cap"))
        return findings
    if manifest != expected:
        findings.append(
            (
                DERIVATION_POLICY_MANIFEST_INCOMPLETE,
                policy.manifest_path,
                "manifest bytes are not the canonical representation of the protected "
                f"diff from {base[:12]}: expected entries "
                + ", ".join(f"{e.status}:{e.path}" for e in entries),
            )
        )
        return findings

    stamp = now()
    reasons: list[str] = []
    for signer in policy.signers:
        if signer.not_after is None:
            reasons.append(f"{signer.label}: signer entry is not active (not_after unset)")
            continue
        if stamp >= signer.not_after:
            reasons.append(f"{signer.label}: signer entry expired")
            continue
        problem = verify_signature(policy, signer, manifest, signature)
        if problem is None:
            return findings
        reasons.append(f"{signer.label}: {problem}")
    findings.append(
        (
            DERIVATION_POLICY_DIFF_UNSIGNED,
            policy.signature_path,
            "protected diff is not signed by a current pinned signer (" + "; ".join(reasons) + ")",
        )
    )
    return findings
