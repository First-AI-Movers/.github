#!/usr/bin/env python3
"""control_plane_proof.py -- the deterministic lane that replaces a human verdict.

``CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR`` decided a merge-control change by path
alone and read no candidate content at all. It was safe and it was a queue: every
workflow edit in the organization waited for a person, and the person had no
machine-checked evidence to read when they arrived.

This module is the replacement. A control-plane candidate is judged, not
deferred: its bytes are parsed as data and measured against floors that are
specific to *what kind* of merge-control surface it changes.

  ``.github/workflows/**``   workflow policy      (``workflow_policy.py``)
  ``.github/actions/**``     workflow policy      (``workflow_policy.py``)
  ``.github/aeos-gate.json`` allowlist integrity  (below)
  ``.github/aeos-smoke.json`` rail integrity      (below)
  ``aeos/**`` in the policy repository  gate-source integrity (below)

Two properties hold everywhere in here:

**Candidate code is never executed.** Workflow YAML is safe-loaded; the gate's own
candidate source is read with :func:`ast.parse`, which builds a syntax tree and
runs nothing. No import, no ``exec``, no subprocess, no network.

**The judge is always the predecessor.** These functions live in the trusted
checkout the gate resolved from the base commit, so a branch proposing a change
to them is measured by the copy already on ``main``, never by its own.
"""

from __future__ import annotations

import ast
import json

try:  # the gate already resolves a safe loader; mirror that resolution
    import yaml as _yaml
except Exception:  # pragma: no cover - a runner without PyYAML
    _yaml = None
    _SAFE_LOADER = None
else:
    _SAFE_LOADER = getattr(_yaml, "CSafeLoader", None) or _yaml.SafeLoader

from workflow_policy import (  # noqa: E402 - sibling module, path set by the gate
    WORKFLOW_POLICY_VIOLATION,
    evaluate_workflow,
    is_workflow_path,
)

CONTROL_PLANE_PROOF_FAILED = "CONTROL_PLANE_PROOF_FAILED"

GATE_CONFIG_PATH = ".github/aeos-gate.json"
SMOKE_CONFIG_PATH = ".github/aeos-smoke.json"
POLICY_SOURCE_PREFIX = "aeos/"

# --------------------------------------------------------------------------
# Allowlist integrity
# --------------------------------------------------------------------------
BLANKET_PATTERNS = frozenset({"*", "**", "*.*", "**/*", "./*", "/*", ""})
"""Patterns that exempt the whole repository from secret-shape detection.

The allowlist exists so a fixture holding a credential-shaped constant can be
named and reasoned about. A blanket entry is not a narrower version of that -- it
turns the one check standing between a token and a public branch into a no-op,
for every file, permanently. `repo-hygiene-policy` already forbids a wildcard
file-allow waiving secret detection in prose; this is the same rule with an exit
code."""


def _blanket_entries(patterns: object) -> list[str]:
    if not isinstance(patterns, list):
        return []
    return sorted(
        {p.strip() for p in patterns if isinstance(p, str) and p.strip() in BLANKET_PATTERNS}
    )


def evaluate_gate_config(path: str, data: bytes) -> list[str]:
    """Floors for a candidate ``.github/aeos-gate.json``.

    The candidate's copy never judges the candidate -- ``load_gate_config`` reads
    the base commit. What it does decide is every *later* pull request, which is
    exactly why merging one unread was an operator's job.
    """
    try:
        document = json.loads(data.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - candidate bytes are adversarial
        return [f"{path}: is not readable JSON ({type(exc).__name__})"]
    if not isinstance(document, dict):
        return [f"{path}: top level is {type(document).__name__}, not an object"]

    out: list[str] = []
    version = document.get("schema_version")
    if version not in ("1", 1):
        out.append(f"{path}: `schema_version` is {version!r}, not the supported \"1\"")
    allowlist = document.get("secret_shape_allowlist", [])
    if allowlist is not None and not isinstance(allowlist, list):
        out.append(
            f"{path}: `secret_shape_allowlist` is "
            f"{type(allowlist).__name__}, not a list"
        )
    for entry in _blanket_entries(allowlist):
        out.append(
            f"{path}: `secret_shape_allowlist` entry {entry!r} exempts the whole "
            f"repository from secret-shape detection"
        )
    return out


# --------------------------------------------------------------------------
# Rail integrity
# --------------------------------------------------------------------------
def evaluate_smoke_config(path: str, data: bytes) -> list[str]:
    """Floors for a candidate ``.github/aeos-smoke.json``.

    This file declares what the post-merge rail actually runs. Rewritten to an
    empty suite list it disarms that rail silently: the check still reports green
    and now measures nothing, which is worse than a red one because nobody looks
    at it again. The floor is therefore non-emptiness, not correctness -- what the
    suites *are* is a delivery decision, that there are any is a safety one.
    """
    try:
        document = json.loads(data.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - candidate bytes are adversarial
        return [f"{path}: is not readable JSON ({type(exc).__name__})"]
    if not isinstance(document, dict):
        return [f"{path}: top level is {type(document).__name__}, not an object"]

    out: list[str] = []
    for key in ("smoke_suites", "compile_roots"):
        if key not in document:
            continue  # absent means "keep the built-in default", not "run nothing"
        value = document.get(key)
        if not isinstance(value, list):
            out.append(f"{path}: `{key}` is {type(value).__name__}, not a list")
        elif not [v for v in value if isinstance(v, str) and v.strip()]:
            out.append(
                f"{path}: `{key}` is empty -- the post-merge rail would report "
                f"green while measuring nothing"
            )
    return out


# --------------------------------------------------------------------------
# Gate-source integrity
# --------------------------------------------------------------------------
REQUIRED_GATE_CONSTANTS = (
    "CONTROL_PLANE_PREFIXES",
    "CONTROL_PLANE_PATHS",
    "SECRET_SHAPES",
    "REASON_CODES",
)
"""Names ``merge_ready_gate.py`` must still bind at module level.

This is the anti-ratchet floor, and it is deliberately structural rather than
semantic. A deterministic check cannot decide whether an edit to the gate makes
it *weaker* -- that is a judgement about meaning. It can decide whether the edit
deleted a load-bearing declaration outright, which is what a weakening actually
looks like in this file: the control-plane path set disappears, the secret-shape
catalogue disappears, the reason vocabulary disappears. Anything subtler than
that still merges, and that is an accepted, stated limit of this lane rather than
a claim it does not have one.

The candidate is read with :func:`ast.parse`. Nothing in it runs.
"""


def _module_level_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, (ast.AnnAssign,)) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
    return names


def evaluate_policy_source(path: str, data: bytes) -> list[str]:
    """Floors for a candidate change to the gate's own source in the policy repo."""
    if not path.lower().endswith(".py"):
        return []
    try:
        tree = ast.parse(data.decode("utf-8"), filename=path)
    except Exception as exc:  # noqa: BLE001 - the syntax floor reports this too
        return [f"{path}: is not parseable Python ({type(exc).__name__})"]
    if not path.lower().endswith("merge_ready_gate.py"):
        return []
    names = _module_level_names(tree)
    missing = [c for c in REQUIRED_GATE_CONSTANTS if c not in names]
    return [
        f"{path}: no longer declares `{name}` -- the gate cannot lose a "
        f"load-bearing declaration through an autonomous merge"
        for name in missing
    ]


# --------------------------------------------------------------------------
# Deletion -- the one shape with no bytes to judge
# --------------------------------------------------------------------------
POLICY_REPOSITORY = "first-ai-movers/.github"


def evaluate_control_plane_deletion(path: str, repository: str) -> list[tuple[str, str]]:
    """A deleted control-plane path has no content, so no content floor applies.

    That is not a licence to wave it through. The question is what the deletion
    can actually reach:

    * In a **consumer** repository it reaches local workflows only. The required
      `aeos-merge-ready` verdict is injected by the organization ruleset from
      `First-AI-Movers/.github`, so no branch here can delete the check that
      judges it, and `.github/aeos-smoke.json` falling away restores the rail's
      built-in defaults -- a stricter posture, not a weaker one. Removing a local
      advisory workflow is a delivery decision. It merges.

    * In the **policy** repository it reaches the organization's gate itself.
      Deleting `aeos/merge_ready_gate.py`, or the workflow that runs it, disarms
      merge control for all eight repositories at once, and there is no candidate
      content that could prove such a change safe. This is the residual human
      gate, and it is deliberately the only one left.
    """
    if (repository or "").strip().lower() != POLICY_REPOSITORY:
        return []
    return [
        (
            "CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR",
            f"{path}: deleting the organization's own merge-control source cannot "
            f"be proven safe from candidate content -- an operator must merge this",
        )
    ]


# --------------------------------------------------------------------------
# The lane
# --------------------------------------------------------------------------
def evaluate_control_plane_file(path: str, data: bytes, repository: str) -> list[tuple[str, str]]:
    """``(reason_code, detail)`` for one changed control-plane file.

    Returns an empty list when the candidate satisfies every floor that applies to
    its kind -- which is the whole point: a control-plane change that earns its
    proof merges without anyone being paged.
    """
    lower = path.lower()
    out: list[tuple[str, str]] = []

    if is_workflow_path(lower):
        if _yaml is None:
            return [
                (
                    CONTROL_PLANE_PROOF_FAILED,
                    f"{path}: no YAML parser is available, so workflow policy "
                    f"cannot be measured -- failing closed",
                )
            ]
        try:
            document = _yaml.load(data.decode("utf-8"), Loader=_SAFE_LOADER)
        except Exception as exc:  # noqa: BLE001 - the structured floor reports this too
            return [
                (
                    CONTROL_PLANE_PROOF_FAILED,
                    f"{path}: is not readable YAML ({type(exc).__name__})",
                )
            ]
        out.extend(
            (WORKFLOW_POLICY_VIOLATION, d)
            for d in evaluate_workflow(path, document, repository)
        )
        return out

    if lower == GATE_CONFIG_PATH:
        return [(CONTROL_PLANE_PROOF_FAILED, d) for d in evaluate_gate_config(path, data)]
    if lower == SMOKE_CONFIG_PATH:
        return [(CONTROL_PLANE_PROOF_FAILED, d) for d in evaluate_smoke_config(path, data)]
    if (repository or "").strip().lower() == "first-ai-movers/.github" and lower.startswith(
        POLICY_SOURCE_PREFIX
    ):
        return [(CONTROL_PLANE_PROOF_FAILED, d) for d in evaluate_policy_source(path, data)]
    return out
