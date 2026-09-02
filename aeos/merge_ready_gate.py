#!/usr/bin/env python3
"""AEOS organization merge-ready gate.

This module is TRUSTED POLICY. It is checked out from the organization's public
``.github`` repository and is the only code the ``aeos-merge-ready`` check
executes.

Trust model
-----------
The candidate (the bytes proposed by a pull request) is DATA. This module reads
candidate files as bytes and parses them. It never imports, executes, sources,
or shells out to anything the candidate supplies. It runs no candidate test
command, reads no candidate configuration, and makes no network calls.

Repository-agnostic
-------------------
The gate depends on no file existing in the target repository. A brand-new
repository with an empty changed set passes. Absence of target-repository files
is normal, not an error.

The gate is a deterministic hygiene floor, not a review. It carries no model,
no provider, no reviewer or thread input, and no pull-request-body semantics.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time

try:  # PyYAML is preinstalled on GitHub-hosted ubuntu runners.
    import yaml as _yaml
except Exception:  # pragma: no cover - exercised only on a runner without PyYAML
    _yaml = None
    _YAML_SAFE_LOADER = None
else:
    # Both loaders are the SAFE loader: neither resolves a Python-object tag or
    # constructs an arbitrary object. CSafeLoader is the libyaml binding and is
    # roughly twenty times faster, which is the difference between a gate that
    # fits its budget on a large changed set and one that does not.
    _YAML_SAFE_LOADER = getattr(_yaml, "CSafeLoader", None) or _yaml.SafeLoader

# --------------------------------------------------------------------------
# Closed reason-code vocabulary. Nothing outside this tuple is ever emitted.
# --------------------------------------------------------------------------
CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR = "CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR"
SECRET_SHAPE_DETECTED = "SECRET_SHAPE_DETECTED"
STRUCTURED_DATA_UNPARSEABLE = "STRUCTURED_DATA_UNPARSEABLE"
SYNTAX_ERROR = "SYNTAX_ERROR"
EVIDENCE_UNREADABLE = "EVIDENCE_UNREADABLE"
BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
GATE_CONFIG_INVALID = "GATE_CONFIG_INVALID"

REASON_CODES = (
    EVIDENCE_UNREADABLE,
    GATE_CONFIG_INVALID,
    CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR,
    BUDGET_EXCEEDED,
    SECRET_SHAPE_DETECTED,
    STRUCTURED_DATA_UNPARSEABLE,
    SYNTAX_ERROR,
)
"""Ordered most-authoritative first; the primary code reported is the earliest
member of this tuple that has at least one finding."""

RESULT_PREFIX = "AEOS_MERGE_READY_RESULT:"

# --------------------------------------------------------------------------
# Control plane
# --------------------------------------------------------------------------
CONTROL_PLANE_PREFIXES = (".github/workflows/", ".github/actions/")
"""Changing what runs on merge is an operator-governed act in every repository."""

GATE_CONFIG_PATH = ".github/aeos-gate.json"
SMOKE_CONFIG_PATH = ".github/aeos-smoke.json"

CONTROL_PLANE_PATHS = (GATE_CONFIG_PATH, SMOKE_CONFIG_PATH)
"""Exact paths that are control plane in their own right.

Each of these files decides how a check behaves, so a branch able to edit its own
copy would be deciding what it is judged by. Making them operator-governed is the
conjunct that turns a configuration file from a hole into a decision somebody
accountable made.

- `aeos-gate.json` carries the secret-shape exemptions, so editing it is a
  self-serve bypass of the one check that stops a credential reaching a public
  branch.
- `aeos-smoke.json` declares what the post-main rail runs against the merged
  commit. Rewriting it to a command that always succeeds silently disarms that
  rail for the repository -- no operator involved, and no signal that the check
  still reporting green now measures nothing. A gate that protects its own
  allowlist but not the smoke definition protects the wrong half.

Both literals are defined once, above, because the enforced set and the
documented set drift apart the moment either is spelled out twice."""

GATE_CONFIG_SCHEMA_VERSIONS = ("1", 1)
MAX_GATE_CONFIG_BYTES = 256 * 1024
MAX_ALLOWLIST_PATTERNS = 5000

POLICY_REPOSITORY = "first-ai-movers/.github"
POLICY_SELF_PREFIXES = ("aeos/",)
"""In the policy repository itself the gate's own source is control plane too:
without this, a pull request could rewrite the code that governs every other
repository and be waved through by the very gate it is rewriting."""

# --------------------------------------------------------------------------
# Budgets and caps
# --------------------------------------------------------------------------
DEFAULT_HARD_BUDGET_SECONDS = 45.0
"""Deliberately below the workflow's external 60s ceiling. Set equal to it, the
external timer -- which starts first, at interpreter launch -- would always win
and the gate's own measurement would be decoration."""

DEFAULT_SOFT_BUDGET_SECONDS = 10.0
MAX_SCAN_BYTES = 1 << 20          # 1 MiB: secret-shape scan cap
MAX_PARSE_BYTES = 4 << 20         # 4 MiB: structured-data / syntax parse cap
SNIFF_BYTES = 8192
BATCH_BYTES = 32 << 20            # 32 MiB: bound on blob content held at once

MODE_DELETED = "000000"
MODE_SYMLINK = "120000"
MODE_GITLINK = "160000"
REGULAR_MODES = ("100644", "100755")
MAX_FINDINGS_PER_FILE = 5
MAX_FINDINGS_REPORTED = 100
GIT_TIMEOUT_SECONDS = 30

MAX_STRUCTURE_DEPTH = 200
"""Maximum flow-style nesting depth accepted in changed JSON/YAML.

Both parsers descend recursively on flow nesting: CPython's json raises
RecursionError at roughly a thousand levels, and PyYAML's libyaml binding
overruns the C stack and dies of SIGSEGV between twenty and fifty thousand.
Real configuration does not nest past about twenty levels, so this bound is two
orders of magnitude clear of anything legitimate and keeps candidate bytes away
from a recursive parser's stack entirely."""

STRUCTURED_JSON_SUFFIXES = (".json",)
STRUCTURED_YAML_SUFFIXES = (".yml", ".yaml")
PYTHON_SUFFIXES = (".py", ".pyi")

# --------------------------------------------------------------------------
# Secret shapes. Precision over recall: a false positive blocks every repository
# in the organization, and the gate is a hygiene floor, not a forensic scanner.
# Patterns are built so that this file and its tests do not match themselves.
# --------------------------------------------------------------------------
PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "redacted",
    "changeme",
    "change-me",
    "replaceme",
    "replace-me",
    "your-",
    "your_",
    "yourkey",
    "xxxx",
    "dummy",
    "notreal",
    "fakekey",
    "sample",
)
"""Substrings that mark a match as a published example or a documentation
placeholder rather than a credential.

Vendors publish credential-shaped constants in their own documentation --
``AKIAIOSFODNN7EXAMPLE`` is AWS's canonical access key id, and setup guides are
full of ``sk-XXXX...`` and ``xoxb-your-bot-token-here``. Firing on those makes
an ordinary README unmergeable across the whole organization, and the only
override is an operator-merged control-plane change. Precision is worth more
than recall here: anyone deliberately exfiltrating a secret past a regex floor
has easier options than adding the word "example" to it, so this trades nothing
real away."""

PUBLISHED_EXAMPLE_DIGESTS = frozenset(
    {
        # The access-token value used throughout GitHub's own REST documentation.
        # Stored as a SHA-256 digest so that this public repository never carries
        # a credential-shaped literal -- which would also make the gate flag its
        # own source. Verify with: printf %s '<value from the docs>' | sha256sum
        "3543c50b0cb9cea8e55eb1f529b79f043cb250d485fde7b66cabbb5183add7da",
    }
)
"""Exact values a vendor publishes in its own documentation. They match a real
shape and carry no placeholder word, so only an exact-value check can clear
them."""


SECRET_SHAPES = (
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9]{22,}_[A-Za-z0-9]{50,}\b")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN[A-Z ]{0,20} PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b")),
    ("provider_api_key", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9]{32,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)


class GateError(Exception):
    """A failure that stops evaluation immediately with a typed reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class Finding:
    __slots__ = ("code", "path", "detail")

    def __init__(self, code: str, path: str, detail: str) -> None:
        self.code = code
        self.path = path
        self.detail = detail

    def render(self) -> str:
        return f"{self.code} {self.path}: {self.detail}"


# --------------------------------------------------------------------------
# Changed-set resolution
# --------------------------------------------------------------------------
def _run_git(
    candidate_dir: str, args: list[str], stdin: str | None = None
) -> subprocess.CompletedProcess:
    # argv only: never a shell, and every interpolated value is either a module
    # constant or an object id already validated as hex.
    cmd = ["git", "-C", candidate_dir, "--no-pager"] + args
    try:
        return subprocess.run(
            cmd,
            input=stdin.encode() if stdin is not None else None,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:  # pragma: no cover - git absent on runner
        raise GateError(EVIDENCE_UNREADABLE, f"git is unavailable: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GateError(EVIDENCE_UNREADABLE, f"git timed out: {' '.join(args)}") from exc


def _verify_commit(candidate_dir: str, sha: str, role: str) -> None:
    # A full object id only. An abbreviated prefix resolves, which would make the
    # commit the gate evaluates a function of what else happens to be in the
    # object store rather than of what the event named.
    if not sha or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha.lower()):
        raise GateError(
            EVIDENCE_UNREADABLE,
            f"{role} sha is missing or is not a full object id: {sha!r}",
        )
    proc = _run_git(candidate_dir, ["rev-parse", "--verify", "--quiet", sha + "^{commit}"])
    if proc.returncode != 0:
        raise GateError(
            EVIDENCE_UNREADABLE,
            f"{role} commit {sha} is not present in the candidate checkout "
            f"(a full-depth checkout is required)",
        )


def _safe_relpath(path: str) -> str:
    if not path:
        raise GateError(EVIDENCE_UNREADABLE, "git reported an empty path")
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise GateError(EVIDENCE_UNREADABLE, f"git reported an absolute path: {path!r}")
    parts = path.split("/")
    if ".." in parts or "" in parts[:-1]:
        raise GateError(EVIDENCE_UNREADABLE, f"git reported a traversing path: {path!r}")
    return path


DIFFING_EVENTS = ("pull_request", "merge_group")


class Change:
    """One entry in the changed set, addressed by content rather than by file.

    ``blob_sha`` is the object id of this path's content *at the head commit*.
    Reading it is what binds the verdict to the commit the check is reported
    against: a working tree is a place bytes happen to be sitting, while a blob
    id is a cryptographic statement about which bytes they are.
    """

    __slots__ = ("status", "path", "mode", "blob_sha")

    def __init__(self, status: str, path: str, mode: str, blob_sha: str) -> None:
        self.status = status
        self.path = path
        self.mode = mode
        self.blob_sha = blob_sha

    @property
    def deleted(self) -> bool:
        return self.status.startswith("D") or self.mode == MODE_DELETED


def changed_records(
    candidate_dir: str, base_sha: str, head_sha: str, event_name: str
) -> list[Change]:
    """Return the changed set for ``base...head``, with head-side modes and blobs.

    Fails closed: any git error, any missing commit, any malformed record, and
    any event this gate does not know how to bound is ``EVIDENCE_UNREADABLE``.
    An unreadable changed set is never treated as an empty changed set.
    """
    if not os.path.isdir(os.path.join(candidate_dir, ".git")):
        raise GateError(
            EVIDENCE_UNREADABLE,
            f"candidate checkout {candidate_dir!r} is not a git working tree",
        )
    if event_name not in DIFFING_EVENTS:
        # Only events that carry a real two-endpoint range are evaluable. Any
        # other trigger would have to invent a range, and an invented range
        # produces a green that measured nothing -- on the very check context
        # that rulesets and auto-merge read.
        raise GateError(
            EVIDENCE_UNREADABLE,
            f"event {event_name!r} does not carry a comparable commit range; "
            f"this gate evaluates {' and '.join(DIFFING_EVENTS)} only",
        )
    _verify_commit(candidate_dir, base_sha, "base")
    _verify_commit(candidate_dir, head_sha, "head")

    if base_sha.lower() == head_sha.lower():
        # A pull request or a merge group always spans at least one commit.
        # Identical endpoints mean the event payload did not resolve, and an
        # unresolved payload must not present itself as "nothing changed".
        raise GateError(
            EVIDENCE_UNREADABLE,
            f"{event_name} resolved base and head to the same commit {base_sha}; "
            "the event payload did not supply a comparable range",
        )

    proc = _run_git(
        candidate_dir,
        [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--raw",
            "--abbrev=40",
            "-z",
            f"{base_sha}...{head_sha}",
        ],
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "git diff failed"
        raise GateError(EVIDENCE_UNREADABLE, f"changed set is unreadable: {detail}")

    fields = proc.stdout.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    changes: list[Change] = []
    index = 0
    while index < len(fields):
        meta = fields[index].decode("utf-8", "replace")
        if not meta.startswith(":"):
            raise GateError(
                EVIDENCE_UNREADABLE, f"git diff emitted an unrecognised record: {meta!r}"
            )
        if index + 1 >= len(fields):
            raise GateError(EVIDENCE_UNREADABLE, "git diff emitted a record with no path")
        parts = meta[1:].split()
        if len(parts) != 5:
            raise GateError(
                EVIDENCE_UNREADABLE, f"git diff emitted a malformed record: {meta!r}"
            )
        _src_mode, dst_mode, _src_sha, dst_sha, status = parts
        path = _safe_relpath(os.fsdecode(fields[index + 1]))
        changes.append(Change(status, path, dst_mode, dst_sha))
        index += 2
    return changes


def blob_sizes(candidate_dir: str, shas: list[str]) -> dict[str, int]:
    """Declared size of each blob, without reading any content."""
    if not shas:
        return {}
    proc = _run_git(candidate_dir, ["cat-file", "--batch-check"], stdin="\n".join(shas) + "\n")
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "git cat-file failed"
        raise GateError(EVIDENCE_UNREADABLE, f"cannot size candidate content: {detail}")
    sizes: dict[str, int] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            sizes[parts[0]] = int(parts[2])
    return sizes


def read_blobs(candidate_dir: str, shas: list[str]) -> dict[str, bytes]:
    """Read blob content by object id. The working tree is never consulted."""
    if not shas:
        return {}
    proc = _run_git(candidate_dir, ["cat-file", "--batch"], stdin="\n".join(shas) + "\n")
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "git cat-file failed"
        raise GateError(EVIDENCE_UNREADABLE, f"cannot read candidate content: {detail}")

    out = proc.stdout
    blobs: dict[str, bytes] = {}
    pos = 0
    while pos < len(out):
        end = out.find(b"\n", pos)
        if end < 0:
            raise GateError(EVIDENCE_UNREADABLE, "git cat-file emitted a truncated header")
        header = out[pos:end].decode("utf-8", "replace").split()
        if len(header) == 2 and header[1] in ("missing", "ambiguous"):
            raise GateError(
                EVIDENCE_UNREADABLE,
                f"candidate content {header[0]} is {header[1]} from the object store",
            )
        if len(header) != 3:
            raise GateError(
                EVIDENCE_UNREADABLE, f"git cat-file emitted a malformed header: {header!r}"
            )
        sha, _obj_type, raw_size = header
        size = int(raw_size)
        start = end + 1
        blobs[sha] = out[start : start + size]
        pos = start + size + 1  # content is followed by a newline
    return blobs


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------
def control_plane_violations(paths: list[str], repository: str) -> list[str]:
    prefixes = list(CONTROL_PLANE_PREFIXES)
    if (repository or "").strip().lower() == POLICY_REPOSITORY:
        prefixes.extend(POLICY_SELF_PREFIXES)
    # Case-insensitive: matching only the exact lowercase spelling would let a
    # differently-cased path slip past a rule that exists to be unskippable.
    return sorted(
        {
            p
            for p in paths
            if any(p.lower().startswith(pre) for pre in prefixes)
            or p.lower() in CONTROL_PLANE_PATHS
        }
    )


class GateConfig:
    """The optional, operator-governed `.github/aeos-gate.json` declaration."""

    __slots__ = ("secret_shape_allowlist", "present")

    def __init__(self, secret_shape_allowlist: tuple[str, ...] = (), present: bool = False) -> None:
        self.secret_shape_allowlist = secret_shape_allowlist
        self.present = present

    def exempts_secret_shapes(self, path: str) -> bool:
        return any(
            path_matches_glob(path, pattern) for pattern in self.secret_shape_allowlist
        )


def path_matches_glob(path: str, pattern: str) -> bool:
    """Glob semantics for allowlist entries: ``fnmatch.fnmatchcase``.

    fnmatch is chosen over ``PurePath.match`` because ``PurePath.match`` is
    right-anchored and, before Python 3.13, gives ``**`` no recursive meaning at
    all. Under fnmatch a ``*`` is not separator-aware: it spans ``/`` freely, so
    ``docs/*.md`` already matches ``docs/a/b.md`` and ``Engine/tests/**`` matches
    everything beneath that directory at any depth.

    One documented extension, matching gitignore and gitleaks: a ``/**/`` segment
    also matches a single separator, so ``docs/**/*.md`` covers ``docs/a.md`` as
    well as ``docs/guide/a.md``. Without it an operator writing the obvious
    pattern would silently fail to exempt the top level of the directory.
    """
    if fnmatch.fnmatchcase(path, pattern):
        return True
    if "/**/" in pattern:
        return fnmatch.fnmatchcase(path, pattern.replace("/**/", "/"))
    return False


def load_gate_config(candidate_dir: str, base_sha: str) -> GateConfig:
    """Read the gate configuration from the BASE commit, never from the worktree.

    The blob is addressed as ``<base_sha>:<path>``. ``base_sha`` comes from the
    event payload, and git objects are content-addressed, so a branch cannot make
    that address resolve to bytes of its own choosing. The candidate working tree
    is never consulted, and a branch that proposes a change to this file is
    stopped by the control-plane check before this function's result is used.

    An absent file is normal and yields no exemptions. A present but malformed
    file is ``GATE_CONFIG_INVALID`` -- degrading to "no exemptions" would be a
    silent, unmeasured change of what a required check enforces.
    """
    listing = _run_git(candidate_dir, ["ls-tree", "-z", base_sha, "--", GATE_CONFIG_PATH])
    if listing.returncode != 0:
        detail = listing.stderr.decode("utf-8", "replace").strip() or "git ls-tree failed"
        raise GateError(EVIDENCE_UNREADABLE, f"cannot inspect the base tree: {detail}")
    record = listing.stdout.split(b"\0")[0].decode("utf-8", "replace").strip()
    if not record:
        return GateConfig()  # absent: normal

    try:
        meta, _ = record.split("\t", 1)
        _mode, obj_type, blob_sha = meta.split()
    except ValueError as exc:
        raise GateError(
            EVIDENCE_UNREADABLE, f"unreadable base tree entry for {GATE_CONFIG_PATH}: {exc}"
        ) from exc
    if obj_type != "blob":
        raise GateError(
            GATE_CONFIG_INVALID, f"{GATE_CONFIG_PATH} is a {obj_type}, not a file"
        )
    if _mode == MODE_SYMLINK:
        # cat-file would return the link text, never the target's content, but
        # say why rather than letting it fail as "not valid JSON".
        raise GateError(
            GATE_CONFIG_INVALID, f"{GATE_CONFIG_PATH} is a symlink, not a regular file"
        )

    sizing = _run_git(candidate_dir, ["cat-file", "-s", blob_sha])
    if sizing.returncode == 0:
        try:
            declared = int(sizing.stdout.decode().strip())
        except ValueError:
            declared = 0
        if declared > MAX_GATE_CONFIG_BYTES:
            # Measured before the bytes are buffered, not after.
            raise GateError(
                GATE_CONFIG_INVALID,
                f"{GATE_CONFIG_PATH} is {declared} bytes, over the "
                f"{MAX_GATE_CONFIG_BYTES}-byte limit",
            )

    blob = _run_git(candidate_dir, ["cat-file", "blob", blob_sha])
    if blob.returncode != 0:
        detail = blob.stderr.decode("utf-8", "replace").strip() or "git cat-file failed"
        raise GateError(EVIDENCE_UNREADABLE, f"cannot read {GATE_CONFIG_PATH}: {detail}")
    if len(blob.stdout) > MAX_GATE_CONFIG_BYTES:
        raise GateError(
            GATE_CONFIG_INVALID,
            f"{GATE_CONFIG_PATH} exceeds {MAX_GATE_CONFIG_BYTES} bytes",
        )
    return parse_gate_config(blob.stdout)


def parse_gate_config(raw: bytes) -> GateConfig:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GateError(GATE_CONFIG_INVALID, f"{GATE_CONFIG_PATH} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise GateError(GATE_CONFIG_INVALID, f"{GATE_CONFIG_PATH} must contain a JSON object")

    version = document.get("schema_version")
    # `not in` would compare with ==, and True == 1 and 1.0 == 1, so a boolean or
    # a float would be accepted as version 1.
    if not isinstance(version, (str, int)) or isinstance(version, bool) or (
        version not in GATE_CONFIG_SCHEMA_VERSIONS
    ):
        raise GateError(
            GATE_CONFIG_INVALID,
            f"{GATE_CONFIG_PATH} has schema_version {version!r}; "
            f"this gate understands {GATE_CONFIG_SCHEMA_VERSIONS[0]!r}",
        )

    allowlist = document.get("secret_shape_allowlist", [])
    if not isinstance(allowlist, list) or isinstance(allowlist, (str, bytes)):
        raise GateError(
            GATE_CONFIG_INVALID, f"{GATE_CONFIG_PATH}: secret_shape_allowlist must be a list"
        )
    if len(allowlist) > MAX_ALLOWLIST_PATTERNS:
        raise GateError(
            GATE_CONFIG_INVALID,
            f"{GATE_CONFIG_PATH}: secret_shape_allowlist holds {len(allowlist)} entries, "
            f"over the {MAX_ALLOWLIST_PATTERNS} limit",
        )
    for entry in allowlist:
        if not isinstance(entry, str) or not entry:
            raise GateError(
                GATE_CONFIG_INVALID,
                f"{GATE_CONFIG_PATH}: secret_shape_allowlist entries must be non-empty strings, "
                f"found {entry!r}",
            )
    # Unknown top-level keys are ignored so a newer declaration stays readable.
    return GateConfig(secret_shape_allowlist=tuple(allowlist), present=True)


SECRET_SHAPES_COMBINED = re.compile(
    "|".join(f"(?P<{name}>{pattern.pattern})" for name, pattern in SECRET_SHAPES)
)
"""One alternation over the whole buffer. A per-line loop across eight separate
patterns costs roughly an order of magnitude more on a large changed set, and
the budget is the thing that decides whether the organization can merge."""


def is_placeholder(value: str) -> bool:
    if hashlib.sha256(value.encode()).hexdigest() in PUBLISHED_EXAMPLE_DIGESTS:
        return True
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def scan_secret_shapes(path: str, data: bytes) -> tuple[list[Finding], str | None]:
    """Return ``(findings, skip_reason)`` for one file's bytes.

    A skip reason is returned rather than an empty result whenever the scan did
    not actually happen, so that a file the gate could not read never reads as a
    file the gate found nothing in. A single NUL or one invalid UTF-8 byte would
    otherwise disable this check invisibly.
    """
    if b"\0" in data[:SNIFF_BYTES]:
        return [], "binary content, secret-shape scan not applicable"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [], "not valid UTF-8, secret-shape scan not applicable"

    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for match in SECRET_SHAPES_COMBINED.finditer(text):
        shape = match.lastgroup or "unknown"
        if is_placeholder(match.group(0)):
            continue
        # Line numbers are computed only for the rare match, not per line.
        lineno = text.count("\n", 0, match.start()) + 1
        key = (lineno, shape)
        if key in seen:
            continue
        seen.add(key)
        # Report the shape and the location only. The matched value is never
        # echoed.
        findings.append(Finding(SECRET_SHAPE_DETECTED, path, f"line {lineno}: {shape}"))
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            break
    return findings, None


_NOT_BRACKETS = re.compile(r"[^\[\]{}]+")


def flow_nesting_depth(text: str) -> int:
    """Upper bound on flow-style nesting depth.

    Everything that is not a flow indicator is stripped first, so nesting spread
    across whitespace, keys and scalars is measured the same as ``[[[[``.
    Brackets inside quoted scalars are counted too, so this over-estimates and
    can only ever reject, never wave through. A document needs two hundred more
    unclosed openers than closers before it trips.
    """
    # Only flow indicators are counted. Block-style nesting is expressed by
    # indentation and needs a line per level, so MAX_PARSE_BYTES already bounds
    # it far below where either parser is in trouble -- measured clean at 2800
    # levels, and 4 MiB does not buy many more.
    if text.count("[") + text.count("{") < MAX_STRUCTURE_DEPTH:
        return 0  # cannot reach the bound; skip the scan entirely
    depth = 0
    deepest = 0
    for char in _NOT_BRACKETS.sub("", text):
        if char in "[{":
            depth += 1
            if depth > deepest:
                deepest = depth
                if deepest > MAX_STRUCTURE_DEPTH:
                    return deepest
        elif depth:
            depth -= 1
    return deepest


def parse_structured(path: str, data: bytes) -> list[Finding]:
    lower = path.lower()
    is_json = lower.endswith(STRUCTURED_JSON_SUFFIXES)
    is_yaml = lower.endswith(STRUCTURED_YAML_SUFFIXES)
    if is_json or is_yaml:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            kind = "JSON" if is_json else "YAML"
            return [Finding(STRUCTURED_DATA_UNPARSEABLE, path, f"invalid {kind}: {exc}")]
        depth = flow_nesting_depth(text)
        if depth > MAX_STRUCTURE_DEPTH:
            # Refused before the bytes reach a recursive parser.
            return [
                Finding(
                    STRUCTURED_DATA_UNPARSEABLE,
                    path,
                    f"nesting depth exceeds the {MAX_STRUCTURE_DEPTH}-level limit",
                )
            ]
    if is_json:
        try:
            json.loads(text)
        except (ValueError, RecursionError) as exc:
            return [Finding(STRUCTURED_DATA_UNPARSEABLE, path, f"invalid JSON: {exc}")]
        return []
    if is_yaml:
        if _yaml is None:
            raise GateError(
                EVIDENCE_UNREADABLE,
                f"PyYAML is unavailable, so changed YAML file {path} cannot be validated",
            )
        try:
            # A safe loader only, over every document in the stream. The default
            # full constructor (yaml.load / yaml.Loader) is never used, so no
            # candidate tag can instantiate a Python object.
            list(_yaml.load_all(text, Loader=_YAML_SAFE_LOADER))
        except Exception as exc:  # yaml.YAMLError, or anything the loader raises
            return [Finding(STRUCTURED_DATA_UNPARSEABLE, path, f"invalid YAML: {exc}")]
    return []


def parse_python(path: str, data: bytes) -> list[Finding]:
    if not path.lower().endswith(PYTHON_SUFFIXES):
        return []
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [Finding(SYNTAX_ERROR, path, f"not valid UTF-8: {exc}")]
    try:
        # Parse only. Never import, never compile to a callable, never execute.
        ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Finding(SYNTAX_ERROR, path, f"line {exc.lineno}: {exc.msg}")]
    except ValueError as exc:  # e.g. source containing NUL bytes
        return [Finding(SYNTAX_ERROR, path, f"unparseable source: {exc}")]
    return []


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
class Report:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.skipped: list[str] = []
        self.exempted: list[str] = []
        self.config = GateConfig()
        self.scanned = 0
        self.deleted = 0
        self.elapsed = 0.0
        self.primary: str | None = None

    @property
    def passed(self) -> bool:
        return self.primary is None

    def resolve_primary(self) -> None:
        codes = {f.code for f in self.findings}
        for code in REASON_CODES:
            if code in codes:
                self.primary = code
                return
        # Fail closed on an unregistered code. Returning None here would render
        # findings alongside a PASS the day a code is added and not listed.
        self.primary = self.findings[0].code if self.findings else None


def evaluate(
    candidate_dir: str,
    repository: str,
    base_sha: str,
    head_sha: str,
    event_name: str = "",
    hard_budget: float = DEFAULT_HARD_BUDGET_SECONDS,
    soft_budget: float = DEFAULT_SOFT_BUDGET_SECONDS,
    clock=time.monotonic,
) -> Report:
    started = clock()
    report = Report()

    def elapsed() -> float:
        return clock() - started

    def budget_tripped() -> bool:
        return elapsed() > hard_budget

    try:
        changes = changed_records(candidate_dir, base_sha, head_sha, event_name)
    except GateError as exc:
        report.findings.append(Finding(exc.code, "-", exc.detail))
        report.elapsed = elapsed()
        report.resolve_primary()
        return report
    except Exception as exc:  # noqa: BLE001 - see _abort
        return _abort(report, elapsed(), "resolving the changed set", exc)

    violations = control_plane_violations([c.path for c in changes], repository)
    if violations:
        # Short-circuit: an operator-governed change is decided by path alone.
        # No candidate content is read at all on this route.
        for path in violations:
            report.findings.append(
                Finding(
                    CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR,
                    path,
                    "control-plane path; an operator must review and merge this change",
                )
            )
        report.elapsed = elapsed()
        report.resolve_primary()
        return report

    # Only now, once no control-plane path is in play, may exemptions matter.
    # A branch proposing a change to the configuration never reaches this line.
    try:
        report.config = load_gate_config(candidate_dir, base_sha)
    except GateError as exc:
        report.findings.append(Finding(exc.code, GATE_CONFIG_PATH, exc.detail))
        report.elapsed = elapsed()
        report.resolve_primary()
        return report
    except Exception as exc:  # noqa: BLE001 - see _abort
        return _abort(report, elapsed(), "reading the gate configuration", exc)

    try:
        # Decide what is readable from the head-side mode alone. Deleted paths
        # are never read; a symlink is a link, not the file it names; a gitlink
        # is a pointer into a repository that was never checked out.
        readable: list[Change] = []
        for change in changes:
            if change.deleted:
                report.deleted += 1
            elif change.mode == MODE_GITLINK:
                report.skipped.append(
                    f"{change.path}: submodule reference, content is not in this repository"
                )
            elif change.mode == MODE_SYMLINK:
                report.skipped.append(f"{change.path}: symlink, target not followed")
            elif change.mode not in REGULAR_MODES:
                report.skipped.append(f"{change.path}: unsupported file mode {change.mode}")
            else:
                readable.append(change)

        sizes = blob_sizes(candidate_dir, sorted({c.blob_sha for c in readable}))

        # Group into batches bounded by declared size, so the bytes held at once
        # stay bounded no matter how large the changed set is.
        batches: list[list[Change]] = []
        batch: list[Change] = []
        running = 0
        for change in readable:
            size = sizes.get(change.blob_sha)
            if size is None:
                raise GateError(
                    EVIDENCE_UNREADABLE,
                    f"{change.path}: content {change.blob_sha} is not a readable blob",
                )
            cap = MAX_PARSE_BYTES if _needs_parse(change.path) else MAX_SCAN_BYTES
            if size > cap:
                report.skipped.append(
                    f"{change.path}: exceeds the {cap}-byte cap ({size} bytes)"
                )
                continue
            if batch and running + size > BATCH_BYTES:
                batches.append(batch)
                batch, running = [], 0
            batch.append(change)
            running += size
        if batch:
            batches.append(batch)

        over_budget = False
        for group in batches:
            if over_budget:
                break
            blobs = read_blobs(candidate_dir, sorted({c.blob_sha for c in group}))
            for change in group:
                if budget_tripped():
                    report.findings.append(
                        Finding(
                            BUDGET_EXCEEDED,
                            change.path,
                            f"hard budget of {hard_budget:g}s exhausted after "
                            f"{report.scanned} files",
                        )
                    )
                    over_budget = True
                    break

                data = blobs.get(change.blob_sha)
                if data is None:
                    raise GateError(
                        EVIDENCE_UNREADABLE,
                        f"{change.path}: content {change.blob_sha} was not returned",
                    )

                report.scanned += 1
                if len(data) <= MAX_SCAN_BYTES:
                    secret_findings, skip_reason = scan_secret_shapes(change.path, data)
                    if skip_reason:
                        report.skipped.append(f"{change.path}: {skip_reason}")
                    elif secret_findings and report.config.exempts_secret_shapes(change.path):
                        # The allowlist exempts this conjunct and no other: the
                        # structured-data and syntax floors below still run, and
                        # the suppression is reported rather than made invisible.
                        report.exempted.extend(
                            f"{change.path} ({f.detail})" for f in secret_findings
                        )
                    else:
                        report.findings.extend(secret_findings)
                else:
                    report.skipped.append(
                        f"{change.path}: secret-shape scan skipped, over "
                        f"{MAX_SCAN_BYTES} bytes"
                    )
                report.findings.extend(parse_structured(change.path, data))
                report.findings.extend(parse_python(change.path, data))
    except GateError as exc:
        report.findings.append(Finding(exc.code, "-", exc.detail))
        report.elapsed = elapsed()
        report.resolve_primary()
        return report
    except Exception as exc:  # noqa: BLE001 - see _abort
        return _abort(report, elapsed(), "reading the changed set", exc)

    # The budget assertion is unconditional on the success path: a PASS is only
    # ever returned after the gate has measured itself.
    report.elapsed = elapsed()
    if report.elapsed > hard_budget and not any(
        f.code == BUDGET_EXCEEDED for f in report.findings
    ):
        report.findings.append(
            Finding(
                BUDGET_EXCEEDED,
                "-",
                f"gate body took {report.elapsed:.3f}s, over the {hard_budget:g}s hard budget",
            )
        )
    if report.elapsed > soft_budget:
        report.notes.append(
            f"gate body took {report.elapsed:.3f}s, over the {soft_budget:g}s soft target"
        )
    report.resolve_primary()
    return report


def _abort(report: Report, elapsed: float, stage: str, exc: BaseException) -> Report:
    """Turn an unexpected exception into a typed, fail-closed verdict.

    Candidate bytes are adversarial input to parsers that can raise things no
    call site anticipates -- RecursionError, MemoryError, a decoder's OSError.
    Letting one escape would end the run with a bare traceback and no reason
    code, which reads as "the gate is broken" rather than "this branch is not
    mergeable". Every route out of the gate carries a code from the closed
    vocabulary.
    """
    report.findings.append(
        Finding(
            EVIDENCE_UNREADABLE,
            "-",
            f"the gate aborted while {stage}: {type(exc).__name__}: {exc}".strip(),
        )
    )
    report.elapsed = elapsed
    report.resolve_primary()
    return report


def _needs_parse(path: str) -> bool:
    lower = path.lower()
    return lower.endswith(
        STRUCTURED_JSON_SUFFIXES + STRUCTURED_YAML_SUFFIXES + PYTHON_SUFFIXES
    )


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def render(report: Report, repository: str, event_name: str, base_sha: str, head_sha: str) -> str:
    lines = [
        "## aeos-merge-ready",
        "",
        f"- repository: `{repository or '(unset)'}`",
        f"- event: `{event_name or '(unset)'}`",
        f"- base sha: `{base_sha or '(unset)'}`",
        f"- head sha: `{head_sha or '(unset)'}`",
        f"- changed files scanned: {report.scanned} (deleted, not read: {report.deleted})",
        f"- gate body: {report.elapsed:.3f}s",
    ]
    if _yaml is None:
        lines.append("- yaml parser: unavailable (changed YAML files fail closed)")
    if report.config.present:
        lines.append(
            f"- gate config: `{GATE_CONFIG_PATH}` on the base commit, "
            f"{len(report.config.secret_shape_allowlist)} secret-shape allowlist pattern(s)"
        )
    if report.exempted:
        lines.append("")
        lines.append("### Secret shapes exempted by the operator allowlist")
        for note in report.exempted[:MAX_FINDINGS_REPORTED]:
            lines.append(f"- {note}")
    if report.skipped:
        lines.append("")
        lines.append("### Skipped")
        for note in report.skipped[:MAX_FINDINGS_REPORTED]:
            lines.append(f"- {note}")
    if report.notes:
        lines.append("")
        for note in report.notes:
            lines.append(f"> note: {note}")
    lines.append("")
    if report.passed:
        lines.append(f"{RESULT_PREFIX} PASS")
    else:
        lines.append(f"{RESULT_PREFIX} FAIL {report.primary}")
        lines.append("")
        lines.append("### Findings")
        for finding in report.findings[:MAX_FINDINGS_REPORTED]:
            lines.append(f"- `{finding.code}` `{finding.path}` — {finding.detail}")
        if len(report.findings) > MAX_FINDINGS_REPORTED:
            lines.append(f"- … {len(report.findings) - MAX_FINDINGS_REPORTED} more")
    return "\n".join(lines) + "\n"


def _evaluate_guarded(**kwargs) -> Report:
    """Last resort: ``evaluate`` already traps per-stage failures, but a PASS must
    never be reachable through an unhandled exception at any depth."""
    try:
        return evaluate(**kwargs)
    except Exception as exc:  # noqa: BLE001
        return _abort(Report(), 0.0, "evaluating the candidate", exc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AEOS organization merge-ready gate")
    parser.add_argument("--candidate-dir", required=True)
    parser.add_argument("--repository", default=os.environ.get("AEOS_REPOSITORY", ""))
    parser.add_argument("--event-name", default=os.environ.get("AEOS_EVENT_NAME", ""))
    parser.add_argument("--base-sha", default=os.environ.get("AEOS_BASE_SHA", ""))
    parser.add_argument("--head-sha", default=os.environ.get("AEOS_HEAD_SHA", ""))
    parser.add_argument("--hard-budget-seconds", type=float, default=DEFAULT_HARD_BUDGET_SECONDS)
    parser.add_argument("--soft-budget-seconds", type=float, default=DEFAULT_SOFT_BUDGET_SECONDS)
    args = parser.parse_args(argv)

    report = _evaluate_guarded(
        candidate_dir=args.candidate_dir,
        repository=args.repository,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        event_name=args.event_name,
        hard_budget=args.hard_budget_seconds,
        soft_budget=args.soft_budget_seconds,
    )
    text = render(report, args.repository, args.event_name, args.base_sha, args.head_sha)
    sys.stdout.write(text)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write(text)
        except OSError as exc:  # pragma: no cover - runner filesystem failure
            sys.stdout.write(f"could not write step summary: {exc}\n")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
