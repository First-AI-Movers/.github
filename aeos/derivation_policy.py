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
modules the named roots under ``scripts/`` reach through first-party imports
(whole AST, so a lazy in-function import counts; package ``__init__.py`` modules
count because they execute on import) along chains made only of allowlisted
modules. A module reached only through an unprotected module is not a member: the
validators live on the protected chains, and the unprotected module in front of it is
already ordinary code (agent-toolkit #3052). A module that enters the set at the
candidate head without changing is an ``entered`` entry, so its existing bytes are
answered for too. The gate
regenerates that set from the *base* commit on every evaluation and refuses when
the committed list has drifted, so the list is never stale and never hand-kept.
The gate regenerates the same closure at the *candidate head* as well, and the
set a candidate must sign is the union: a helper the candidate adds under the
allowlist and imports from a root enters the protected set in the same change,
so the operator's signature covers the whole effective validator change, not
only the files that were protected before the candidate existed.

The signed manifest binds the trusted base SHA, one entry per protected path
whose identity differs between base and head -- status ``added`` / ``modified`` /
``deleted`` / ``renamed``, the SHA-256 of the pre-image bytes at the base (or
``absent``), the SHA-256 of the post-image bytes at the head (or ``absent``), and
both paths for a rename -- and the canonical protected-diff digest, the SHA-256
of those entries' canonical serialization. It never binds the head SHA, which
would depend on the manifest itself, and it never uses git object ids, which are
a statement about where bytes sit rather than what they are. The manifest and
its signature are excluded from the diff they describe.

Trust model, restated for this conjunct
---------------------------------------
* Policy (signer, namespace, roots, allowlist, member list) is read from THIS
  checkout, never from the candidate. A signer entry is accepted only when its
  pinned ``fingerprint`` is the SHA-256 fingerprint of its ``public_key``: the
  human-reviewed fingerprint is the boundary, and a public key that does not
  produce it invalidates the policy rather than silently replacing the signer.
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
import base64
import binascii
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time

import accepted_change
import comment_operand
import operator_approval
import scoped_grant

DERIVATION_POLICY_DIFF_UNSIGNED = "DERIVATION_POLICY_DIFF_UNSIGNED"
DERIVATION_POLICY_MANIFEST_INCOMPLETE = "DERIVATION_POLICY_MANIFEST_INCOMPLETE"
DERIVATION_POLICY_DRIFT = "DERIVATION_POLICY_DRIFT"
GATE_CONFIG_INVALID = "GATE_CONFIG_INVALID"
EVIDENCE_UNREADABLE = "EVIDENCE_UNREADABLE"

POLICY_FILE = "standing-governor-policy.json"
POLICY_SCHEMA = "aeos-standing-governor-policy/v1"
MANIFEST_SCHEMA = "derivation-policy-manifest/v1"
SIGNATURE_NAMESPACE = "at-derivation-policy"

EVIDENCE_SCHEMA = "aeos-actor-evidence/v1"
PROGRAMME_MARKER = "aeos-programme:"
PROGRAMME_BLOCK_SCHEMA = "standing-authority/v2"
AUTHORITY_COMPILER_SCHEMA = "aeos-programme-authority-compiler/v1"
MAX_EVIDENCE_BYTES = 512 * 1024
MAX_PROGRAMME_EDITS = 100
"""The gate's own bound on the edit history it will judge (the workflow records at most this many;
a longer history is unavailable, not "operator-only by assumption")."""
# A programme block is REVOCATION-bounded, not calendar-bounded (operator decision
# agent-toolkit#3752 5925947456): `not_after: null` is standing intent that holds until the
# operator closes the Issue, moves `state` off ACTIVE, or supersedes the block. Elapsed time alone
# revokes nothing. The operator decided on 2026-10-04 that standing seats are not renewed by hand
# (agent-toolkit#6364 5977590767), and on 2026-10-26 that a routine admitted change must never wait
# on his approval because an authority's date passed ("I should not be needed to approve this type
# of things … this is something that needs to be fixed in the system itself", agent-toolkit#3052
# 6425439595; agent-toolkit AGENTS.md "Age alone never removes working capacity"). So on ANY block
# judged against its own path envelope, a date that has passed refuses nothing; it is still parsed
# and must be well-formed. Only the compiler programme, judged against the policy allowlist rather
# than an envelope, keeps its date.
# Short-lived CREDENTIALS (signers above, App tokens) keep their own expiry.
"""The machine route (#3752 Slice A). The trusted workflow — never the candidate — writes one
``aeos-actor-evidence/v1`` file: the GitHub-authenticated pull-request author (login, type),
the workflow actor, and the programme Issue the candidate's body names with
``<!-- aeos-programme: owner/repo#N -->`` (its state, author login/type and body, read with the
workflow's own token). The networkless gate then admits a protected diff WITHOUT an operator
SSH signature when, and only when, every one of these holds: the author is a pinned machine
principal and not a pinned operator principal; the programme Issue is OPEN, authored by a
pinned operator principal, and carries a ``standing-authority/v2`` block naming this
repository and that Issue, ``state: ACTIVE`` and a well-formed ``not_after`` (a date ends nothing on a block judged against
its own envelope; only the compiler programme keeps its date); every protected
changed path lies inside that block's ``path_envelope``. Anything missing, stale or ambiguous
fails closed to the SSH route, which stays as the break-glass/transition path. Credential
reachability alone grants nothing: the App token can open the PR, but only the operator's
authorship of the Issue authorizes its scope."""

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
_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})(?:\[bot\])?$")
_PROGRAMME_REF_RE = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)$")
_PROGRAMME_MARKER_RE = re.compile(r"<!--\s*aeos-programme:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*)\s*-->")
_PROGRAMME_ID_RE = re.compile(r"^\*\*Policy / Programme ID:\*\* `([A-Z][A-Z0-9-]{2,127})`\s*$", re.M)
_BLOCK_RE = re.compile(r"^```standing-authority[ \t]*\n(.*?)\n```[ \t]*(?:\n|$)", re.M | re.S)
_PUBKEY_RE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]+$")


def fingerprint_of(public_key: str) -> str:
    """The OpenSSH SHA-256 fingerprint of an ``<type> <base64>`` public key line --
    the same value ``ssh-keygen -lf`` prints -- computed here so that the pinned
    fingerprint can be bound to the key the verifier trusts without trusting the
    candidate or a second tool. Raises ``ValueError`` when the key blob is not
    well-formed base64 whose leading length-prefixed string names the key type."""
    parts = public_key.split()
    if len(parts) != 2:
        raise ValueError("public key must be '<type> <base64>'")
    key_type, encoded = parts
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"public key blob is not base64: {exc}") from exc
    if len(blob) < 4:
        raise ValueError("public key blob is truncated")
    length = int.from_bytes(blob[:4], "big")
    if blob[4 : 4 + length] != key_type.encode("ascii"):
        raise ValueError("public key blob does not name its declared key type")
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + digest


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
        "machine_principals",
        "operator_principals",
        "comment_operand",
        "authority_compiler",
        "scoped_grant",
        "operator_approval",
        "accepted_changes",
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
        route = document.get("machine_route") or {}
        self.machine_principals = tuple(
            (m["login"], m["type"]) for m in route.get("machine_principals", ())
        )
        self.operator_principals = frozenset(route.get("operator_principals", ()))
        self.comment_operand = route.get("comment_operand")
        self.authority_compiler = route.get("authority_compiler")
        # #3052 Class B: the scoped-machine-grant consumer's binding (``scoped_grant.validate_binding``).
        self.scoped_grant = route.get("scoped_grant")
        # #3052 paperwork removal: the operator's approval of an exact machine-authored head
        # (``operator_approval.validate_binding``); absent means the route does not exist.
        self.operator_approval = route.get("operator_approval")
        # #3052: exact protected changes the operator accepted in trusted policy (``accepted_change.validate``).
        self.accepted_changes = route.get("accepted_changes") or []

    @property
    def machine_route_enabled(self) -> bool:
        return bool(self.machine_principals) and bool(self.operator_principals)

    def protects(self, path: str) -> bool:
        return path in self.members

    def in_allowlist(self, path: str) -> bool:
        # An exact allowlisted module's same-named package directory is allowlisted too: CPython imports
        # ``x/__init__.py`` in place of ``x.py`` once it exists (agent-toolkit #3052).
        return (path in self.allowlist_files
                or any(path.startswith(prefix) for prefix in self.allowlist_prefixes)
                or any(path.startswith(_package_dir(f)) for f in self.allowlist_files if f.endswith(PYTHON_SUFFIX)))

    def root_or_shadow(self, path: str) -> bool:
        """A declared root, or a path inside the package directory that would replace it."""
        return path in self.roots or any(path.startswith(_package_dir(r)) for r in self.roots)


def _package_dir(module_path: str) -> str:
    """``scripts/a/b.py`` -> ``scripts/a/b/``: the directory whose ``__init__`` CPython imports in its place."""
    return module_path[: -len(PYTHON_SUFFIX)] + "/"


def _parse_not_after(value, label: str):
    """``label`` names the holder in messages (``signer <label>`` or ``programme``)."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label}: not_after must be a string or null")
    try:
        stamp = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label}: not_after is not ISO-8601: {exc}") from exc
    if stamp.tzinfo is None:
        raise ValueError(f"{label}: not_after must carry a UTC offset")
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
        labels = [s.get("label") for s in signers if isinstance(s, dict)]
        if len(labels) != len(set(labels)):
            # ssh-keygen -I <principal> accepts any allowed-signers line sharing the
            # label, so a rotated (expired) key under a reused label would still
            # verify; one label, one key.
            raise ValueError("accepted_signers labels must be unique")
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
            try:
                computed = fingerprint_of(signer["public_key"])
            except ValueError as exc:
                raise ValueError(f"signer {label}: public_key is malformed: {exc}") from exc
            if computed != signer["fingerprint"]:
                # The pinned fingerprint is the reviewed boundary; a key that does
                # not produce it must not become the trusted verifier key.
                raise ValueError(
                    f"signer {label}: fingerprint {signer['fingerprint']} is not the "
                    f"fingerprint of public_key ({computed})"
                )
            signer["not_after"] = _parse_not_after(signer.get("not_after"), f"signer {label}")
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
        route = document.get("machine_route")
        if route is not None:
            if (not isinstance(route, dict)
                    or set(route) - {"machine_principals", "operator_principals", "decision", "comment_operand",
                                     "authority_compiler", "scoped_grant", "operator_approval",
                                     "accepted_changes"}):
                raise ValueError("machine_route has unknown keys")
            machines = route.get("machine_principals")
            operators = route.get("operator_principals")
            if (not isinstance(machines, list) or not machines or not isinstance(operators, list) or not operators):
                raise ValueError("machine_route needs non-empty machine_principals and operator_principals")
            logins = []
            for entry in machines:
                if (not isinstance(entry, dict) or set(entry) != {"login", "type"}
                        or not isinstance(entry["login"], str) or not _LOGIN_RE.match(entry["login"])
                        or entry["type"] != "Bot"):
                    raise ValueError("each machine principal is {login: '<app>[bot]', type: 'Bot'}")
                if not entry["login"].endswith("[bot]"):
                    raise ValueError("a machine principal login must end with [bot]")
                logins.append(entry["login"])
            for login in operators:
                if not isinstance(login, str) or not _LOGIN_RE.match(login) or login.endswith("[bot]"):
                    raise ValueError("each operator principal is a human GitHub login")
            if set(logins) & set(operators) or len(set(logins)) != len(logins) or len(set(operators)) != len(operators):
                # Identity separation is the whole point: one login can never be both.
                raise ValueError("machine and operator principals must be disjoint and unique")
            if "comment_operand" in route:
                comment_operand.validate(route["comment_operand"], programme_block)
            if "authority_compiler" in route:
                compiler = route["authority_compiler"]
                if (not isinstance(compiler, dict)
                        or set(compiler) != {"schema", "programme", "programme_id"}
                        or compiler.get("schema") != AUTHORITY_COMPILER_SCHEMA
                        or not isinstance(compiler.get("programme"), str)
                        or not _PROGRAMME_REF_RE.fullmatch(compiler["programme"])
                        or not isinstance(compiler.get("programme_id"), str)
                        or not re.fullmatch(r"[A-Z][A-Z0-9-]{2,127}", compiler["programme_id"])):
                    raise ValueError("authority_compiler must bind one programme ref and programme ID")
            if "scoped_grant" in route:
                # #3052 Class B: a grant only narrows the compiler programme, so it binds nothing without one.
                scoped_grant.validate_binding(route["scoped_grant"], compiler=route.get("authority_compiler"))
            if "operator_approval" in route:
                operator_approval.validate_binding(route["operator_approval"])
            if "accepted_changes" in route:
                prefixes, files = tuple(policy["allowlist_prefixes"]), frozenset(policy["allowlist_files"])
                accepted_change.validate(
                    route["accepted_changes"], target_repository=document["target_repository"].strip().lower(),
                    in_allowlist=lambda path: path in files or path.startswith(prefixes))
        return Policy(document)
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyError(GATE_CONFIG_INVALID, POLICY_FILE, f"policy is invalid: {exc}")


def _safe_relpath(path: str, role: str) -> str:
    if not isinstance(path, str) or not path or path.startswith("/"):
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


def _package_inits_of(path: str, files: dict[str, str]) -> list[str]:
    """Every ``__init__.py`` on the package chain above ``path`` (under
    ``scripts/``) that exists in ``files``, outermost first."""
    inits: list[str] = []
    parts = path[len(SCRIPTS_ROOT) :].split("/")[:-1]
    for depth in range(1, len(parts) + 1):
        init = SCRIPTS_ROOT + "/".join(parts[:depth]) + "/__init__.py"
        if init in files:
            inits.append(init)
    return inits


def _resolve(module_id: str, files: dict[str, str]) -> str | None:
    """A dotted module id to its file under ``scripts/``, or ``None`` for a
    standard-library, third-party or absent module. A package wins over a
    same-named module file, as in CPython's path finder: otherwise a new
    ``x/__init__.py`` beside a protected ``x.py`` would be what Python runs while
    the walk kept reading ``x.py`` (agent-toolkit #3052)."""
    if not module_id:
        return None
    base = SCRIPTS_ROOT + module_id.replace(".", "/")
    if base + "/__init__.py" in files:
        return base + "/__init__.py"
    if base + PYTHON_SUFFIX in files:
        return base + PYTHON_SUFFIX
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
    """``(expanded, bounded members)`` at ``commit``, from blobs read as data.

    ``expanded`` is every module parsed: the allowlisted roots and what they reach through allowlisted modules,
    so the rest of the first-party import closure is never read (agent-toolkit #8963). ``bounded`` is the part of it a root reaches
    along an import chain made ONLY of allowlisted modules (agent-toolkit #3052, 2026-10-19). A module reached only
    through an unprotected module is not bounded: the validator classes this conjunct exists for live on the
    protected chains, and the unprotected module in front of it is already ordinary code, so its protection
    reviewed no validator. A root outside the allowlist is itself unprotected, so nothing is bounded behind it."""
    files = tree_paths(candidate_dir, commit, SCRIPTS_ROOT)
    pending: list[str] = []
    for root in policy.roots:
        if root not in files:
            raise PolicyError(
                DERIVATION_POLICY_DRIFT, root, f"declared derivation root is absent at {commit[:12]}"
            )
        pending.append(root)
        # A root inside a package is imported by dotted name, so Python executes
        # every ancestor package initializer first: seed those that exist at this
        # commit, so that adding one at the head lands in the protected set.
        pending.extend(_package_inits_of(root, files))
    seeds = list(pending)
    # Only allowlisted modules are expanded: ``bounded`` follows allowlisted edges alone, so parsing the
    # unprotected rest of the closure decides nothing and cost most of the gate's budget (agent-toolkit #8963).
    pending = [p for p in pending if policy.in_allowlist(p)]
    edges: dict[str, set[str]] = {}
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
            targets = edges.setdefault(path, set())
            for imported in _imports_of(tree, module_id, path.endswith("/__init__.py")):
                target = _resolve(imported, files)
                if target:
                    targets.add(target)
                    if target not in seen and policy.in_allowlist(target):
                        pending.append(target)
    bounded: set[str] = set()
    chain = [p for p in seeds if policy.in_allowlist(p)]
    while chain:
        path = chain.pop()
        if path not in bounded:
            bounded.add(path)
            chain.extend(t for t in edges.get(path, ()) if t not in bounded and policy.in_allowlist(t))
    return seen, bounded


# --------------------------------------------------------------------------
# Protected diff from the merge base, rename-aware
# --------------------------------------------------------------------------
class Entry:
    """One protected path whose identity differs between base and head. The image
    fields are SHA-256 hex digests of the file bytes (never git object ids) or
    ``absent``."""

    __slots__ = ("path", "status", "pre_sha256", "post_sha256", "rename_from", "pre_mode", "post_mode", "unseen")

    def __init__(
        self, path: str, status: str, pre_sha256: str, post_sha256: str, rename_from: str | None,
        pre_mode: str | None = None, post_mode: str | None = None,
    ) -> None:
        self.path = path
        self.status = status
        self.pre_sha256 = pre_sha256
        self.post_sha256 = post_sha256
        self.rename_from = rename_from
        # The git modes of the two sides (``100644``, ``120000``, ``000000`` ...), carried for the scoped-grant
        # judge (agent-toolkit #3052 Class B) and deliberately NOT part of ``as_dict``: the signed manifest
        # bytes are unchanged.
        self.pre_mode = pre_mode
        self.post_mode = post_mode
        # True when this path enters the protected set at the head with bytes a diff of the change does not show
        # (agent-toolkit #3052): set by ``candidate_entries``, read by the approval route, and like the modes NOT
        # part of ``as_dict``.
        self.unseen = False

    def as_dict(self) -> dict:
        record = {
            "path": self.path,
            "status": self.status,
            "pre_sha256": self.pre_sha256,
            "post_sha256": self.post_sha256,
        }
        if self.rename_from is not None:
            record["rename_from"] = self.rename_from
        return record


class _Change:
    """One raw ``git diff`` record: status letter, old and new path, and the
    pre/post git object ids (used only to read the bytes that are then hashed)."""

    __slots__ = ("code", "old", "new", "pre_blob", "post_blob", "src_mode", "dst_mode")

    def __init__(self, code: str, old: str, new: str, pre_blob: str, post_blob: str,
                 src_mode: str | None = None, dst_mode: str | None = None) -> None:
        self.code = code
        self.old = old
        self.new = new
        self.pre_blob = pre_blob
        self.post_blob = post_blob
        self.src_mode = src_mode
        self.dst_mode = dst_mode


def raw_diff(candidate_dir: str, base: str, head: str) -> list[_Change]:
    """Every change between ``base`` and ``head``, rename-aware, as data."""
    out = _git(
        candidate_dir,
        ["diff", "--no-ext-diff", "--no-textconv", "-M", "--raw", "--abbrev=40", "-z", _hex(base, "base"), _hex(head, "head")],
    )
    fields = out.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    changes: list[_Change] = []
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
            try:
                _safe_relpath(p, "changed path")
            except ValueError as exc:
                raise PolicyError(EVIDENCE_UNREADABLE, "-", str(exc)) from exc
        if code not in ("A", "D", "M", "T", "R", "C"):
            raise PolicyError(EVIDENCE_UNREADABLE, new, f"git diff emitted an unknown status {status!r}")
        pre = src_sha if src_sha.strip("0") else ABSENT
        post = dst_sha if dst_sha.strip("0") else ABSENT
        changes.append(_Change(code, old, new, pre, post, src_mode, dst_mode))
    return changes


def touched_paths(changes: list[_Change]) -> list[str]:
    seen: list[str] = []
    for change in changes:
        for p in (change.old, change.new):
            if p not in seen:
                seen.append(p)
    return seen


def _select(changes: list[_Change], protects) -> list[tuple[_Change, Entry]]:
    selected: list[tuple[_Change, Entry]] = []
    for c in changes:
        if c.code == "A" or c.code == "C":
            if protects(c.new):
                selected.append((c, Entry(c.new, "added", ABSENT, "", None, c.src_mode, c.dst_mode)))
        elif c.code == "D":
            if protects(c.old):
                selected.append((c, Entry(c.old, "deleted", "", ABSENT, None, c.src_mode, c.dst_mode)))
        elif c.code == "M" or c.code == "T":
            if protects(c.new):
                selected.append((c, Entry(c.new, "modified", "", "", None, c.src_mode, c.dst_mode)))
        elif c.code == "R":
            if protects(c.old) or protects(c.new):
                selected.append((c, Entry(c.new, "renamed", "", "", c.old, c.src_mode, c.dst_mode)))
    return selected


def _hash_images(candidate_dir: str, selected: list[tuple[_Change, Entry]]) -> list[Entry]:
    """Fill every non-absent image with the SHA-256 of the exact file bytes."""
    wanted = sorted(
        {c.pre_blob for c, e in selected if e.pre_sha256 != ABSENT}
        | {c.post_blob for c, e in selected if e.post_sha256 != ABSENT}
    )
    blobs = read_blobs(candidate_dir, wanted)
    entries: list[Entry] = []
    for change, entry in selected:
        for attr, blob in (("pre_sha256", change.pre_blob), ("post_sha256", change.post_blob)):
            if getattr(entry, attr) == ABSENT:
                continue
            data = blobs.get(blob)
            if data is None:
                raise PolicyError(EVIDENCE_UNREADABLE, entry.path, f"image {blob[:12]} could not be read")
            setattr(entry, attr, hashlib.sha256(data).hexdigest())
        entries.append(entry)
    entries.sort(key=lambda e: e.path)
    return entries


def protected_diff(
    candidate_dir: str, base: str, head: str, protected, changes: list[_Change] | None = None
) -> tuple[list[Entry], list[str]]:
    """Every change between ``base`` and ``head`` that touches a protected path,
    with SHA-256 pre- and post-image digests and rename detection. ``protected`` is
    a :class:`Policy` (its committed members) or an explicit collection of paths.
    Returns the entries and the list of all changed paths."""
    if changes is None:
        changes = raw_diff(candidate_dir, base, head)
    protects = protected.protects if isinstance(protected, Policy) else (lambda p: p in protected)
    entries = _hash_images(candidate_dir, _select(changes, protects))
    return entries, touched_paths(changes)


def protected_diff_digest(entries: list[Entry]) -> str:
    """The canonical protected-diff digest: SHA-256 over the entries' canonical
    serialization (sorted by path, sorted keys, no whitespace)."""
    canonical = json.dumps([e.as_dict() for e in entries], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_manifest(repository: str, base: str, entries: list[Entry]) -> bytes:
    """The exact bytes the operator signs and the gate recomputes: the trusted base
    SHA, the entries, and the canonical protected-diff digest. The head SHA is
    deliberately absent: it would depend on the manifest committed on that head."""
    document = {
        "schema": MANIFEST_SCHEMA,
        "repository": repository.strip().lower(),
        "base_sha": base,
        "namespace": SIGNATURE_NAMESPACE,
        "entries": [e.as_dict() for e in entries],
        "protected_diff_sha256": protected_diff_digest(entries),
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def candidate_protected_set(
    candidate_dir: str, base: str, head: str, policy: Policy
) -> tuple[frozenset[str], tuple[str, str, str] | None]:
    """``(protected, drift_finding)`` of :func:`candidate_protected_sets`, for callers that need only the union."""
    protected, _entering, drift = candidate_protected_sets(candidate_dir, base, head, policy)
    return protected, drift


def candidate_protected_sets(
    candidate_dir: str, base: str, head: str, policy: Policy
) -> tuple[frozenset[str], frozenset[str], tuple[str, str, str] | None]:
    """The set of paths a candidate must sign: the committed members, the closure
    regenerated at the merge base, and the closure regenerated at the head (so a
    helper the candidate adds and imports is protected in the same change).
    Returns ``(protected, drift_finding)``. Growth is not drift: a member the base
    closure gained after ``members`` was committed is already in the union, so
    refusing it would add no protection and would strand every candidate until the
    list is refreshed. The drift finding is set only when a committed member is no
    longer in the base closure, which is also what refuses a candidate whose merge
    base predates members the list has since committed.

    Returns ``(protected, entering, drift_finding)``. ``entering`` is what the head
    protects and the base did not: a module a candidate starts importing along a
    protected chain. Its bytes were written while it was ordinary code, so the
    candidate answers for them even where it does not change them (#3052)."""
    _full, at_base = regenerate_closure(candidate_dir, base, policy)
    drift = None
    departed = policy.members - at_base
    if departed:
        drift = (
            DERIVATION_POLICY_DRIFT,
            POLICY_FILE,
            "committed member(s) no longer in the closure regenerated at "
            f"{base[:12]}: {sorted(departed)[:6]}",
        )
    _full, at_head = regenerate_closure(candidate_dir, head, policy)
    return frozenset(policy.members | at_base | at_head), frozenset(at_head - at_base - policy.members), drift


def candidate_entries(
    candidate_dir: str, base: str, head: str, protected, entering, changes: list[_Change] | None = None
) -> list[Entry]:
    """The protected diff, plus one ``entered`` entry for each path that enters the
    protected set at the head without changing: both images are the bytes it
    already had, so a signature, an envelope or a grant must name it like any
    changed member."""
    if changes is None:
        changes = raw_diff(candidate_dir, base, head)
    # A package directory beside a protected module file replaces it at import, so whatever changes inside it
    # is protected too, whether or not anything imports the module by name (a root launched with ``-m``).
    shadowed = tuple(_package_dir(p) for p in protected if p.endswith(PYTHON_SUFFIX) and not p.endswith("/__init__.py"))
    entries = _hash_images(candidate_dir, _select(changes, lambda p: p in protected or p.startswith(shadowed)))
    changed = {p for c in changes for p in (c.old, c.new)}
    unchanged = sorted(p for p in entering if p not in changed)
    if not unchanged:
        return _mark_unseen(entries, protected, entering)
    modes = {}
    out = _git(candidate_dir, ["ls-tree", "-z", "--full-tree", _hex(head, "head"), "--", *unchanged])
    for record in out.split(b"\0"):
        meta, _, path = record.partition(b"\t")
        parts = meta.decode("utf-8", "replace").split()
        if len(parts) == 3 and parts[1] == "blob":
            modes[os.fsdecode(path)] = (parts[0], parts[2])
    blobs = read_blobs(candidate_dir, sorted({blob for _mode, blob in modes.values()}))
    for path in unchanged:
        if path not in modes or blobs.get(modes[path][1]) is None:
            raise PolicyError(EVIDENCE_UNREADABLE, path, "an entering protected path could not be read at the head")
        mode, blob = modes[path]
        digest = hashlib.sha256(blobs[blob]).hexdigest()
        entries.append(Entry(path, "entered", digest, digest, None, mode, mode))
    entries.sort(key=lambda e: e.path)
    return _mark_unseen(entries, protected, entering)


def _mark_unseen(entries: list[Entry], protected, entering) -> list[Entry]:
    """Mark each entry whose bytes a reviewer of the diff does not see: a path entering the protected set that the
    change does not add whole. A small edit, a type change or a rename from a path that was not protected leaves the
    rest of the bytes, written while it was ordinary code, out of the diff; a rename of a path that was already
    protected does not, because those bytes were already answered for."""
    before = frozenset(protected) - frozenset(entering)
    for entry in entries:
        if entry.path in entering and not (
                entry.status == "added" or (entry.status == "renamed" and entry.rename_from in before)):
            entry.unseen = True
    return entries


def expected_manifest(candidate_dir: str, repository: str, base_sha: str, head_sha: str, policy: Policy) -> bytes:
    """The manifest bytes the gate will require for this candidate -- what an
    implementation lane prints for the operator to sign off-node."""
    base = merge_base(candidate_dir, base_sha, head_sha)
    protected, entering, _drift = candidate_protected_sets(candidate_dir, base, head_sha, policy)
    entries = candidate_entries(candidate_dir, base, head_sha, protected, entering)
    return canonical_manifest(repository, base, entries)


# --------------------------------------------------------------------------
# Signature verification (argv only; bytes the gate already read)
# --------------------------------------------------------------------------
def _allowed_signers(signer: Signer) -> bytes:
    """An allowed-signers file naming exactly the one signer under test, so that
    expiry and activity decided on this ``Signer`` govern exactly the key that
    ``ssh-keygen`` is allowed to accept."""
    return f'{signer.label} namespaces="{SIGNATURE_NAMESPACE}" {signer.public_key}\n'.encode("utf-8")


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
            handle.write(_allowed_signers(signer))
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
# --------------------------------------------------------------------------
# The machine route (#3752 Slice A): authenticated actor + operator programme authority
# --------------------------------------------------------------------------
MACHINE_ROUTE_DISABLED = "MACHINE_ROUTE_DISABLED"
MACHINE_ROUTE_EVIDENCE_ABSENT = "MACHINE_ROUTE_EVIDENCE_ABSENT"
MACHINE_ROUTE_EVIDENCE_MALFORMED = "MACHINE_ROUTE_EVIDENCE_MALFORMED"
MACHINE_ROUTE_EVENT_UNPROVABLE = "MACHINE_ROUTE_EVENT_UNPROVABLE"
MACHINE_ROUTE_ACTOR_NOT_MACHINE = "MACHINE_ROUTE_ACTOR_NOT_MACHINE"
MACHINE_ROUTE_ACTOR_IS_OPERATOR = "MACHINE_ROUTE_ACTOR_IS_OPERATOR"
MACHINE_ROUTE_TRIGGER_NOT_MACHINE = "MACHINE_ROUTE_TRIGGER_NOT_MACHINE"
MACHINE_ROUTE_HEAD_COMMIT_NOT_MACHINE = "MACHINE_ROUTE_HEAD_COMMIT_NOT_MACHINE"
MACHINE_ROUTE_AUTHORITY_EDITED_BY_NON_OPERATOR = "MACHINE_ROUTE_AUTHORITY_EDITED_BY_NON_OPERATOR"
MACHINE_ROUTE_PROGRAMME_ABSENT = "MACHINE_ROUTE_PROGRAMME_ABSENT"
MACHINE_ROUTE_PROGRAMME_UNAVAILABLE = "MACHINE_ROUTE_PROGRAMME_UNAVAILABLE"
MACHINE_ROUTE_PROGRAMME_NOT_OPEN = "MACHINE_ROUTE_PROGRAMME_NOT_OPEN"
MACHINE_ROUTE_AUTHORITY_NOT_OPERATOR = "MACHINE_ROUTE_AUTHORITY_NOT_OPERATOR"
MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID = "MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID"
MACHINE_ROUTE_AUTHORITY_REF_MISMATCH = "MACHINE_ROUTE_AUTHORITY_REF_MISMATCH"
MACHINE_ROUTE_AUTHORITY_NOT_ACTIVE = "MACHINE_ROUTE_AUTHORITY_NOT_ACTIVE"
MACHINE_ROUTE_AUTHORITY_EXPIRED = "MACHINE_ROUTE_AUTHORITY_EXPIRED"
MACHINE_ROUTE_REPOSITORY_MISMATCH = "MACHINE_ROUTE_REPOSITORY_MISMATCH"
MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE = "MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE"
MACHINE_ROUTE_ROOT_NEEDS_EXACT_ENVELOPE = "MACHINE_ROUTE_ROOT_NEEDS_EXACT_ENVELOPE"
MACHINE_ROUTE_AUTHORITY_COMPILATION_INVALID = "MACHINE_ROUTE_AUTHORITY_COMPILATION_INVALID"
MACHINE_ROUTE_APPROVAL_ENTERED_NOT_IN_DIFF = "MACHINE_ROUTE_APPROVAL_ENTERED_NOT_IN_DIFF"
"""An exact-head approval was given on a diff that does not show all the bytes of a module entering the protected
set: it enters unchanged, edited, retyped or renamed from an unprotected path (agent-toolkit #3052). Carry the module so
its whole content is in the diff (add it under a new path), or by a route that names it: a programme envelope, a
scoped grant or the signed manifest."""


def load_evidence(path: str | None, *, candidate_dir: str | None = None) -> tuple[dict | None, str | None]:
    """``(evidence, reason)``: the trusted workflow's evidence document, or a typed reason why
    the machine route cannot be evaluated. Never raises; absence is a reason, not a pass. A path
    that resolves inside the candidate tree is refused: evidence is the workflow's, never the
    candidate's, even when no candidate code runs."""
    if not path:
        return None, MACHINE_ROUTE_EVIDENCE_ABSENT
    if candidate_dir:
        real = os.path.realpath(path)
        root = os.path.realpath(candidate_dir)
        if real == root or real.startswith(root.rstrip(os.sep) + os.sep):
            return None, MACHINE_ROUTE_EVIDENCE_MALFORMED
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_EVIDENCE_BYTES + 1)
    except OSError:
        return None, MACHINE_ROUTE_EVIDENCE_ABSENT
    if len(raw) > MAX_EVIDENCE_BYTES:
        return None, MACHINE_ROUTE_EVIDENCE_MALFORMED
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, MACHINE_ROUTE_EVIDENCE_MALFORMED
    if not isinstance(document, dict) or document.get("schema") != EVIDENCE_SCHEMA:
        return None, MACHINE_ROUTE_EVIDENCE_MALFORMED
    return document, None


def programme_ref_from_body(body: str) -> str | None:
    """The single ``<!-- aeos-programme: owner/repo#N -->`` marker in a PR body, or ``None``
    when there is not exactly one. The marker SELECTS a source; it grants nothing."""
    if not isinstance(body, str):
        return None
    refs = _PROGRAMME_MARKER_RE.findall(body)
    return refs[0] if len(refs) == 1 else None


def programme_block(body: str) -> dict | None:
    """The ``standing-authority/v2`` block on the programme Issue, read as data with only the
    keys the machine route needs; ``None`` when absent or malformed."""
    if not isinstance(body, str):
        return None
    matches = list(_BLOCK_RE.finditer(body))
    if len(matches) != 1:
        return None
    try:
        block = json.loads(matches[0][1])
    except ValueError:
        return None
    if not isinstance(block, dict) or block.get("schema") != PROGRAMME_BLOCK_SCHEMA:
        return None
    for key in ("state", "repository", "issue", "not_after", "path_envelope"):
        if key not in block:
            return None
    if (not isinstance(block["repository"], str) or type(block["issue"]) is not int
            or not isinstance(block["state"], str)
            or not (block["not_after"] is None or isinstance(block["not_after"], str))
            or not isinstance(block["path_envelope"], list) or not block["path_envelope"]
            or any(not isinstance(p, str) or not p for p in block["path_envelope"])):
        return None
    # The WHOLE envelope is validated here, once, so a malformed entry anywhere in the list
    # invalidates the block regardless of where a matching entry sits.
    for prefix in block["path_envelope"]:
        try:
            _safe_relpath(prefix.rstrip("/") or "/", "path_envelope")
        except ValueError:
            return None  # absolute, traversing and empty-segment entries land here; a backslash
            # entry is accepted by the path rule and can never match a git path, so it is inert
    return block


def programme_id_from_body(body: str) -> str | None:
    """The stable operator-authored programme identity, or ``None`` unless the
    Issue body carries exactly one canonical identity line. This identifies an
    existing intent source; it is never a candidate grant or a path list."""
    if not isinstance(body, str):
        return None
    identities = _PROGRAMME_ID_RE.findall(body)
    return identities[0] if len(identities) == 1 else None


def _within_envelope(path: str, envelope: list[str], *, exact_only: bool = False) -> bool:
    """Prefix entries end with ``/``; every other entry is an exact file. A declared derivation
    ROOT (``exact_only``) is admitted only by an exact entry: a directory prefix such as
    ``scripts/agent_relay/`` must never silently authorise rewriting the ceiling parser itself."""
    for prefix in envelope:
        if prefix.endswith("/"):
            if not exact_only and path.startswith(prefix):
                return True
        elif path == prefix:
            return True
    return False


# -- the full resident ceiling: the one programme block that has no calendar end -------------
# A standing seat's ceiling is the COMPLETE ``standing-authority/v2`` block: the closed key set
# below, every axis well-typed, and the resident posture. agent-toolkit reads it with
# ``scripts/agent_relay/standing_ceiling.py`` (``_check_v2_structure`` + ``is_full_ceiling``) and has
# treated it as having no calendar end since agent-toolkit#6478. The gate cannot import that
# code, so the definition is restated here, operation for operation; the names and the order
# follow the original so the two can be read side by side, and
# ``tests/full-resident-ceiling-vectors.json`` records the original's patterns, bounds and key sets
# and the verdict it gave for each case.
# Two deliberate differences, both keeping the date when the two hosts run the same interpreter
# settings: for a ``not_after`` UTC cannot express the original raises instead of answering, and
# this restatement answers "not full"; and a reference's number is bounded here by a written
# constant in addition to the interpreter's integer-string limit, which is all the original has
# (``MAX_CEILING_REF_DIGITS`` says when the two hosts can still differ).
# A block that merely names a posture, a programme and a serial is NOT this class, and neither
# is the six-field form: each is a bounded authority and keeps the end it states.
RESIDENT_POSTURE = "standing-governor-resident"
MAX_CEILING_PATH_ENVELOPE = 64
MAX_CEILING_SERIAL = 1_000_000
MAX_CEILING_SIGNATURE_CHARS = 16 * 1024
MAX_CEILING_ACTIVE = 8
MAX_CEILING_DISJOINT = 16
MAX_CEILING_SCOPE_TOKENS = 100
MAX_CEILING_RELPATH_CHARS = 200
MAX_CEILING_REF_DIGITS = 4300
"""The longest number a reference may carry. The original converts the number with ``int`` and so
stops at the interpreter's integer-string limit, 4300 digits by default. This judge converts it
too and also refuses any run longer than this written bound, so its own limit is the SMALLER of
the two: a runner whose interpreter limit is lifted admits nothing beyond the bound, and a runner
whose limit is lower refuses sooner. The bound cannot follow another host. Where agent-toolkit
runs with a lower interpreter limit than this gate's runner, a number longer than that limit and
within this bound is a reference here and not there. No Issue number is longer than ten digits."""
_CEILING_REQUIRED_KEYS = frozenset({
    "schema", "state", "source_body_sha256", "authority", "scope", "parent",
    "repository", "issue", "programme_id", "serial", "not_after", "posture",
    "path_envelope", "max_active_writers", "max_active_child_prs",
    "granted_completion_class", "execution_mode", "signature",
})
_CEILING_OPTIONAL_KEYS = frozenset({"comments", "disjoint_with"})
_CEILING_AUTHORITY_KEYS = frozenset({
    "repository_read", "repository_write", "create_isolated_worktree", "create_branch",
    "create_pull_request", "same_scope_self_heal", "reply_with_evidence",
    "resolve_review_threads", "merge", "deployment", "infrastructure", "migrations", "secrets",
    "identity_or_billing", "consuming_repositories", "create_github_issue_same_repo",
})
"""The closed grant vocabulary of a ceiling's ``authority`` map. A block that uses a grant this
set does not name is not a full ceiling HERE and keeps its date: the gate fails closed until
the vocabulary is added in a reviewed change to this file."""
_CEILING_COMPLETION_CLASSES = (None, "L1", "L2", "L3")
_CEILING_EXECUTION_MODES = ("verify", "modify")
_CEILING_REF_RE = re.compile(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)\Z")
_CEILING_PROGRAMME_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_CEILING_LABEL_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_CEILING_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_CEILING_TOKEN_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}")


def _ceiling_ref(value) -> None:
    """agent-toolkit ``split_ref``: the pattern, then the conversion of the number. The conversion is
    part of the original and is kept: a digit run Python refuses to convert is not a reference there,
    so it is not one here."""
    match = _CEILING_REF_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or len(match[2]) > MAX_CEILING_REF_DIGITS:
        raise ValueError("ceiling ref")
    int(match[2])


def _ceiling_instant(value) -> None:
    """A string ``datetime.fromisoformat`` reads (``Z`` accepted) that carries an offset and is
    expressible in UTC."""
    if not isinstance(value, str):
        raise ValueError("ceiling instant")
    stamp = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("ceiling instant")
    stamp.astimezone(_dt.timezone.utc)  # an instant UTC cannot express raises OverflowError


def _ceiling_relpath(path) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        return False
    parts = path.rstrip("/").split("/") if path != "/" else [""]
    return all(part not in ("", ".", "..") for part in parts) and len(path) <= MAX_CEILING_RELPATH_CHARS


def _check_full_ceiling_structure(ceiling) -> None:
    """The closed, well-typed ``standing-authority/v2`` document a standing seat verifies at its
    first step. Raises on the first defect; returns nothing. It reads structure only: ``state``,
    the Issue binding, the envelope and the principals are the machine route's own conjuncts."""
    if not isinstance(ceiling, dict):
        raise ValueError
    keys = set(ceiling)
    if keys - (_CEILING_REQUIRED_KEYS | _CEILING_OPTIONAL_KEYS) or not _CEILING_REQUIRED_KEYS <= keys:
        raise ValueError
    if ceiling["schema"] != PROGRAMME_BLOCK_SCHEMA:
        raise ValueError
    if ceiling["parent"] is not None:
        _ceiling_ref(ceiling["parent"])
    if not isinstance(ceiling["repository"], str) or type(ceiling["issue"]) is not int:
        raise ValueError
    _ceiling_ref(f"{ceiling['repository']}#{ceiling['issue']}")
    if not isinstance(ceiling["programme_id"], str) or not _CEILING_PROGRAMME_RE.match(ceiling["programme_id"]):
        raise ValueError
    if type(ceiling["serial"]) is not int or not 1 <= ceiling["serial"] <= MAX_CEILING_SERIAL:
        raise ValueError
    if ceiling["not_after"] is not None:  # null: standing until revoked
        _ceiling_instant(ceiling["not_after"])
    if not isinstance(ceiling["posture"], str) or not _CEILING_LABEL_RE.match(ceiling["posture"]):
        raise ValueError
    if (not isinstance(ceiling["source_body_sha256"], str)
            or not _CEILING_HEX64_RE.match(ceiling["source_body_sha256"])):
        raise ValueError
    envelope = ceiling["path_envelope"]
    if (not isinstance(envelope, list) or not 1 <= len(envelope) <= MAX_CEILING_PATH_ENVELOPE
            or any(not _ceiling_relpath(p) for p in envelope)
            or len(set(envelope)) != len(envelope)):
        raise ValueError
    for key in ("max_active_writers", "max_active_child_prs"):
        if type(ceiling[key]) is not int or not 0 <= ceiling[key] <= MAX_CEILING_ACTIVE:
            raise ValueError
    if ceiling["granted_completion_class"] not in _CEILING_COMPLETION_CLASSES:
        raise ValueError
    if ceiling["execution_mode"] not in _CEILING_EXECUTION_MODES:
        raise ValueError
    if not isinstance(ceiling["signature"], str) or len(ceiling["signature"]) > MAX_CEILING_SIGNATURE_CHARS:
        raise ValueError
    if "disjoint_with" in ceiling:
        split = ceiling["disjoint_with"]
        if (not isinstance(split, list) or len(split) > MAX_CEILING_DISJOINT or len(set(split)) != len(split)
                or any(not isinstance(p, str) or not _CEILING_PROGRAMME_RE.match(p) for p in split)
                or ceiling["programme_id"] in split):
            raise ValueError
    grants, scope = ceiling["authority"], ceiling["scope"]
    if (not isinstance(grants, dict) or set(grants) - _CEILING_AUTHORITY_KEYS
            or any(type(v) is not bool for v in grants.values())
            or not isinstance(scope, dict) or set(scope) != {"allowed", "forbidden"}):
        raise ValueError
    for tokens in scope.values():
        if (not isinstance(tokens, list) or len(tokens) > MAX_CEILING_SCOPE_TOKENS
                or any(not isinstance(t, str) or not _CEILING_TOKEN_RE.fullmatch(t) for t in tokens)):
            raise ValueError


def is_full_resident_ceiling(block) -> bool:
    """True only for a structurally valid full ``standing-authority/v2`` ceiling that carries the
    resident posture. Never raises: anything it cannot read as that class is ``False``, and a
    block that is not this class keeps its date."""
    try:
        _check_full_ceiling_structure(block)
    except (ValueError, TypeError, KeyError, OverflowError):
        return False
    return block["posture"] == RESIDENT_POSTURE


def _resident_scope_classes(tokens):
    """The ceiling reader's bounded plural and identity/billing aliases, for scope contradictions."""
    classes = set()
    for token in tokens:
        if token.endswith("ies") and len(token) > 3:
            token = token[:-3] + "y"
        elif token.endswith("s") and not token.endswith("ss"):
            token = token[:-1]
        classes.update({"identity", "billing", "identity_or_billing"}
                       if token in {"identity", "billing", "identity_or_billing"} else {token})
    return classes


def served_resident_admits(body, ref, paths) -> bool:
    """Narrow a grant to a served full resident's existing write authority and OWN envelope.

    Reuses the strict resident class, not the six-field activation parser. Its historical date
    does not end this class; the activation record's TTL and expiry are still judged separately.
    Source-prose binding and scope contradictions follow standing_ceiling.parse_v2. Nothing here
    proves GitHub admission, edit provenance, current generation or claim ownership: the caller does.
    """
    block = scoped_grant._fence(body, "standing-authority")
    if not is_full_resident_ceiling(block):
        return False
    if block["state"] != "ACTIVE" or f"{block['repository']}#{block['issue']}" != ref:
        return False
    match = _BLOCK_RE.search(body)
    prose = body[:match.start()] + body[match.end():]
    if hashlib.sha256(prose.encode()).hexdigest() != block["source_body_sha256"]:
        return False
    grants = block["authority"]
    allowed = _resident_scope_classes(block["scope"]["allowed"])
    forbidden = _resident_scope_classes(block["scope"]["forbidden"])
    granted = _resident_scope_classes(k for k, value in grants.items() if value)
    protected = _resident_scope_classes(("deployment", "infrastructure", "migrations", "secrets",
                                        "identity_or_billing", "merge", "public_release",
                                        "external_communication", "legal_commitment"))
    if (allowed & forbidden or granted & forbidden or not protected <= forbidden):
        return False
    if grants.get("repository_write") is not True or "repository_write" not in allowed:
        return False
    if (block["execution_mode"] != "modify" or block["max_active_writers"] < 1
            or block["max_active_child_prs"] < 1):
        return False
    return all(_within_envelope(path, block["path_envelope"]) for path in paths)


def machine_route(policy: Policy, evidence: dict | None, evidence_reason: str | None,
                  repository: str, entries: list[Entry], now: float, head_sha: str | None = None,
                  admission: dict | None = None) -> str | None:
    """``None`` when the machine route admits this protected diff; otherwise the ONE typed
    reason it does not. Every conjunct is checked; the first failure names the reason."""
    if not policy.machine_route_enabled:
        return MACHINE_ROUTE_DISABLED
    if evidence is None:
        return evidence_reason or MACHINE_ROUTE_EVIDENCE_ABSENT
    # A merge-group run is provable only when the workflow resolved the queued PR itself
    # (from the queue's head ref) and recorded it as authenticated pull-request evidence.
    if (evidence.get("event") not in ("pull_request", "merge_group")
            or not isinstance(evidence.get("pull_request"), dict)):
        return MACHINE_ROUTE_EVENT_UNPROVABLE
    pr = evidence["pull_request"]
    login, kind = pr.get("author_login"), pr.get("author_type")
    if not isinstance(login, str) or not isinstance(kind, str):
        return MACHINE_ROUTE_EVIDENCE_MALFORMED
    if login in policy.operator_principals:
        return MACHINE_ROUTE_ACTOR_IS_OPERATOR
    if (login, kind) not in policy.machine_principals:
        return MACHINE_ROUTE_ACTOR_NOT_MACHINE
    machine_logins = {m for m, _ in policy.machine_principals}
    # The PR author is not enough: a collaborator can push to a bot-authored PR, and the PR
    # keeps its bot author. The workflow actor (who triggered this run) and the author of the
    # head commit must both be the machine as well.
    if evidence.get("actor") not in machine_logins:
        return MACHINE_ROUTE_TRIGGER_NOT_MACHINE
    if pr.get("head_commit_author_login") not in machine_logins:
        return MACHINE_ROUTE_HEAD_COMMIT_NOT_MACHINE
    if (evidence.get("repository") or "").strip().lower() != repository.strip().lower():
        return MACHINE_ROUTE_REPOSITORY_MISMATCH
    # #3052 Class B: grant-marker presence is decided BEFORE any programme-specific routing. A pull request
    # that names a scoped machine grant is judged only by the scoped-grant judge, under the one compiler
    # programme its binding names; with no binding, or a disabled one, it refuses whatever programme it
    # selects. A pull request without a marker takes exactly the route below, unchanged.
    grant_state = scoped_grant.marker_state(pr.get("body", ""))
    if grant_state != scoped_grant.MARKER_ABSENT:
        if policy.scoped_grant is None:
            return scoped_grant.SCOPED_GRANT_UNBOUND
        if policy.scoped_grant.get("activation") != "enabled":
            return scoped_grant.SCOPED_GRANT_DISABLED
        if programme_ref_from_body(pr.get("body", "")) != policy.scoped_grant["programme"]:
            return scoped_grant.SCOPED_GRANT_PROGRAMME_MISMATCH
        # No grant reaches a root (``scoped_grant``'s envelope rule); a package that would replace one is a root.
        if any(path is not None and policy.root_or_shadow(path)
               for entry in entries for path in (entry.path, entry.rename_from)):
            return scoped_grant.SCOPED_GRANT_ENVELOPE_INVALID
    # #3052 paperwork removal: the operator's approval of exactly this machine-authored head stands in for a
    # programme envelope. It binds one commit, so it is never wider than an envelope. A grant-marked pull
    # request is still judged only by the scoped-grant judge, never by an approval.
    approval = None
    if grant_state == scoped_grant.MARKER_ABSENT and policy.operator_approval is not None:
        approval = operator_approval.refusal(policy, evidence, repository, head_sha or "")
        if approval is None and any(getattr(entry, "unseen", False) for entry in entries):
            approval = MACHINE_ROUTE_APPROVAL_ENTERED_NOT_IN_DIFF
        if approval is None:
            if admission is not None:
                # The pass rests on the approval: the gate job re-reads it before publishing.
                admission["operator_approval"] = True
            return None
    # #3052: an exact protected change the operator accepted in trusted policy. It is matched by the canonical
    # protected-diff digest, so no description selects it, and a grant-marked pull request is never judged here.
    if grant_state == scoped_grant.MARKER_ABSENT and policy.accepted_changes:
        digest = protected_diff_digest(entries)
        accepted = accepted_change.entry_for(policy.accepted_changes, repository, digest)
        if accepted is not None:
            reason = accepted_change.refusal(accepted, evidence, entries=entries, now=now)
            if reason is None and admission is not None:
                # The pass rests on the acceptance: the gate job re-reads it from current policy before publishing.
                admission["accepted_change"] = {"repository": accepted["repository"], "protected_diff_sha256": digest}
            return reason
    ref = programme_ref_from_body(pr.get("body", ""))
    if ref is None:
        return approval or MACHINE_ROUTE_PROGRAMME_ABSENT
    programme = evidence.get("programme")
    if not isinstance(programme, dict) or programme.get("ref") != ref:
        return MACHINE_ROUTE_PROGRAMME_UNAVAILABLE
    if programme.get("unavailable"):
        return MACHINE_ROUTE_PROGRAMME_UNAVAILABLE
    if programme.get("state") != "open":
        return MACHINE_ROUTE_PROGRAMME_NOT_OPEN
    if (programme.get("author_login") not in policy.operator_principals
            or programme.get("author_type") != "User"):
        return MACHINE_ROUTE_AUTHORITY_NOT_OPERATOR
    # GitHub keeps the creator in `user` after any edit. The body is authoritative only when
    # every recorded edit was made by an operator principal: the workflow records the Issue's
    # content-edit history (GraphQL userContentEdits) and an unreadable history is not "none".
    editors = programme.get("editors")
    if (not isinstance(editors, list) or any(not isinstance(e, str) for e in editors)
            or len(editors) > MAX_PROGRAMME_EDITS):
        return MACHINE_ROUTE_PROGRAMME_UNAVAILABLE
    if any(e not in policy.operator_principals for e in editors):
        return MACHINE_ROUTE_AUTHORITY_EDITED_BY_NON_OPERATOR
    body = programme.get("body", "")
    operand = policy.comment_operand
    if operand is not None and operand.get("programme") == ref:
        body = comment_operand.resolve(operand, evidence, programme, policy, programme_block, now)
    block = programme_block(body)
    if block is None:
        return MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID
    if f"{block['repository']}#{block['issue']}" != ref:
        return MACHINE_ROUTE_AUTHORITY_REF_MISMATCH
    if block["repository"].strip().lower() != repository.strip().lower():
        return MACHINE_ROUTE_REPOSITORY_MISMATCH
    if block["state"] != "ACTIVE":
        return MACHINE_ROUTE_AUTHORITY_NOT_ACTIVE
    try:
        not_after = _parse_not_after(block["not_after"], "programme")
    except ValueError:
        return MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID
    compiler = policy.authority_compiler
    compiled = compiler is not None and compiler["programme"] == ref
    # A block judged against its OWN path envelope has no calendar end: it stands until the
    # operator closes the Issue, moves `state` off ACTIVE or supersedes the block, all checked
    # above. The compiler programme is judged against the policy allowlist instead of an
    # envelope, so its date is honoured whatever shape its block has.
    if not_after is not None and now >= not_after and compiled:
        return MACHINE_ROUTE_AUTHORITY_EXPIRED
    # M5 authority compilation is deliberately a policy-selected interpretation
    # of an *existing* operator programme, not another authority document. It
    # produces exactly this candidate's already-computed protected paths and
    # stores no paths, signatures, callbacks, or candidate bytes in policy. The
    # trusted workflow supplies the Issue body; the PR marker only selects it.
    if compiled:
        if programme_id_from_body(body) != compiler["programme_id"]:
            return MACHINE_ROUTE_AUTHORITY_COMPILATION_INVALID
        # #3052 Class B: a grant-marked pull request (already bound to this programme above) is judged ONLY
        # against that grant's exact files. It never falls back to the compiler's whole allowlist.
        if grant_state != scoped_grant.MARKER_ABSENT:
            return scoped_grant.judge(policy.scoped_grant, policy, evidence, repository, entries, now,
                                      resident_admits=served_resident_admits)
        for entry in entries:
            for path in (entry.path, entry.rename_from):
                if path is not None and not policy.in_allowlist(path):
                    return MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE
        return None
    for entry in entries:
        for path in (entry.path, entry.rename_from):
            if path is None:
                continue
            if policy.root_or_shadow(path):
                if not _within_envelope(path, block["path_envelope"], exact_only=True):
                    return MACHINE_ROUTE_ROOT_NEEDS_EXACT_ENVELOPE
            elif not _within_envelope(path, block["path_envelope"]):
                return MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE
    return None


def evaluate_derivation_policy(
    candidate_dir: str,
    repository: str,
    base_sha: str,
    head_sha: str,
    policy_dir: str,
    now=time.time,
    evidence_path: str | None = None,
    admission: dict | None = None,
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
    changes = raw_diff(candidate_dir, base, head_sha)
    touched = touched_paths(changes)
    interesting = [p for p in touched if policy.protects(p) or policy.in_allowlist(p)]
    if not interesting:
        return []  # inert: the candidate touches nothing near the protected set

    findings: list[tuple[str, str, str]] = []

    # The protected set for THIS candidate: committed members (drift-checked
    # against the closure at the merge base) plus the closure at the head, so a
    # newly added, newly imported allowlisted helper is signed in the same change.
    protected, entering, drift = candidate_protected_sets(candidate_dir, base, head_sha, policy)
    if drift is not None:
        findings.append(drift)
    entries = candidate_entries(candidate_dir, base, head_sha, protected, entering, changes)
    if not entries:
        return findings  # allowlisted-but-unprotected change: no signature needed

    # Route 1 — the machine route: an admitted machine principal executing inside a current
    # operator-authored programme authority needs no operator signature (#3752).
    stamp = now()
    evidence, evidence_reason = load_evidence(evidence_path, candidate_dir=candidate_dir)
    route_reason = machine_route(policy, evidence, evidence_reason, repository, entries, stamp, head_sha=head_sha,
                                 admission=admission)
    if route_reason is None:
        return findings

    # Route 2 — break-glass / transition: the operator's signature over the canonical bytes.
    head_tree = tree_paths(candidate_dir, head_sha, "aeos/")
    manifest_sha = head_tree.get(policy.manifest_path)
    signature_sha = head_tree.get(policy.signature_path)
    expected = canonical_manifest(repository, base, entries)
    if manifest_sha is None or signature_sha is None:
        findings.append(
            (
                DERIVATION_POLICY_DIFF_UNSIGNED,
                policy.manifest_path,
                f"{len(entries)} protected path(s) changed; machine route: {route_reason}; "
                f"the head carries no signed manifest ({policy.manifest_path} + {policy.signature_path})",
            )
        )
        return findings
    blobs = read_blobs(candidate_dir, sorted({manifest_sha, signature_sha}))
    manifest = blobs.get(manifest_sha, b"")
    signature = blobs.get(signature_sha, b"")
    if len(manifest) > MAX_MANIFEST_BYTES:
        findings.append((DERIVATION_POLICY_MANIFEST_INCOMPLETE, policy.manifest_path,
                         f"machine route: {route_reason}; manifest exceeds the size cap"))
        return findings
    if manifest != expected:
        findings.append(
            (
                DERIVATION_POLICY_MANIFEST_INCOMPLETE,
                policy.manifest_path,
                f"machine route: {route_reason}; manifest bytes are not the canonical representation of the "
                f"protected diff from {base[:12]}: expected entries "
                + ", ".join(f"{e.status}:{e.path}" for e in entries),
            )
        )
        return findings

    reasons: list[str] = [f"machine route: {route_reason}"]
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
