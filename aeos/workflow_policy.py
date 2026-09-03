#!/usr/bin/env python3
"""workflow_policy.py -- deterministic static policy for candidate workflow bytes.

A change under ``.github/workflows/`` or ``.github/actions/`` is a merge-control
change by construction: every PR-triggered workflow holds a repository token that
can post check-runs or arm auto-merge. Until now the gate answered that with
``CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR`` -- a human verdict, and therefore a
queue.

This module is the deterministic answer that replaces the queue. It reads the
candidate's workflow YAML **as data** and reports the properties that make a
workflow a privilege-escalation vector. It never executes candidate code, never
imports it, never resolves an action, and never touches the network: the only
thing it does with a candidate file is parse it with a safe loader and walk the
resulting plain Python objects.

Every rule here is enforced against the whole organization, so each one is
calibrated to be a floor the existing population already stands on rather than a
wall it would hit. Measured 2026-09-03 across all 20 workflows in
``First-AI-Movers/agent-toolkit`` and ``First-AI-Movers/.github``:

  * ``pull_request_target`` triggers: 0
  * workflows with no declared ``permissions``: 0
  * third-party ``uses:`` refs not pinned to a 40-hex commit: 0 (after the three
    the first cut of this rule found are pinned)
  * ``${{ secrets.* }}`` interpolated inside a ``run:`` body: 0
  * injection-prone free-text contexts inside a ``run:`` body: 0

So the rules below reject what nobody is doing and permit everything that is.

Pure stdlib apart from the YAML parser the gate already loads. No network, no
clock, no subprocess, no filesystem write.
"""

from __future__ import annotations

import re

WORKFLOW_POLICY_VIOLATION = "WORKFLOW_POLICY_VIOLATION"

WORKFLOW_PREFIX = ".github/workflows/"
ACTION_PREFIX = ".github/actions/"
YAML_SUFFIXES = (".yml", ".yaml")

# --------------------------------------------------------------------------
# Rule 1 -- privileged trigger
# --------------------------------------------------------------------------
FORBIDDEN_TRIGGERS = ("pull_request_target",)
"""``pull_request_target`` runs with the base repository's write token and its
secrets while the event describes a fork's branch. It is the single trigger that
turns "somebody opened a pull request" into "somebody ran code near my
credentials", and GitHub's own hardening guidance treats it as the exception that
needs a reason. A workflow that genuinely needs it is a decision somebody
accountable makes, not a fast merge."""

# --------------------------------------------------------------------------
# Rule 2 -- declared, bounded permissions
# --------------------------------------------------------------------------
BROAD_PERMISSION_TOKENS = ("write-all",)
"""``permissions: write-all`` hands a job every write scope the token can carry.
Naming the scopes is the whole mechanism; a blanket grant opts out of it."""

WRITE_SCOPE_VALUES = ("write",)

# --------------------------------------------------------------------------
# Rule 3 -- action pinning
# --------------------------------------------------------------------------
SHA_PIN_RE = re.compile(r"^[0-9a-f]{40}$")
LOCAL_USES_RE = re.compile(r"^\./")
DOCKER_USES_RE = re.compile(r"^docker://")

TRUSTED_REUSABLE_OWNER = "first-ai-movers"
"""A reusable workflow from this organization may be referenced at ``@main``.

It is not an unpinned third party: it lives under the same ownership boundary as
the policy that judges it, it is itself gated by this same required workflow, and
pinning it to a commit would freeze consumers on a stale copy of a control plane
the organization deliberately updates in one place."""

FIRST_PARTY_ACTION_OWNERS = ("actions", "github")
"""Action owners whose version tag is accepted without a commit pin.

The rule this narrows exists for one threat: a third-party maintainer's account is
compromised, the attacker moves a mutable tag, and every workflow referencing that
tag executes new code with the repository's token. Pinning to a commit is the
mitigation, and for a third party it is the only one.

``actions/*`` and ``github/*`` are published by GitHub from repositories GitHub
controls -- the same party that already owns the runner, the token and the whole
execution environment. A commit pin there does not close a hole; if that trust
boundary fails, a pinned checkout action is not what saves you. GitHub's own
hardening guidance draws the line in exactly this place, and so does the
overwhelming convention.

Measured before narrowing (2026-09-03, all 68 workflows in the eight
First-AI-Movers repositories): requiring a commit pin for every owner flagged 23
of 68 workflows -- 22 of them in one repository -- which is a wall, not a floor.
Narrowed to third parties it flags **three distinct actions**, each a real
supply-chain exposure, and those are being pinned rather than exempted.

Pinning first-party actions too is the stronger posture, and `agent-toolkit`
already does it for all five it uses. This rule is the floor, not the ceiling."""

# --------------------------------------------------------------------------
# Rule 4 -- script injection
# --------------------------------------------------------------------------
INJECTION_CONTEXT_RE = re.compile(
    r"\$\{\{[^}]*?\b(?:"
    r"github\.head_ref"
    r"|github\.event\.(?:"
    r"(?:pull_request|issue|discussion)\.(?:title|body)"
    r"|(?:comment|review|review_comment)\.body"
    r"|pull_request\.head\.(?:ref|label)"
    r"|(?:head_commit|commits\[[^]]*\])\.(?:message|author\.(?:name|email))"
    r"|(?:pull_request|issue|discussion)\.user\.login"
    r"|pages\[[^]]*\]\.page_name"
    r"|(?:repository|pull_request\.head\.repo)\.(?:description|homepage|default_branch)"
    r")"
    r")\b[^}]*?\}\}",
    re.IGNORECASE,
)
"""Contexts whose value is free text a pull-request author controls.

Interpolating one of these directly into a ``run:`` body splices attacker text
into the shell script *before* the shell ever sees it, so no amount of quoting
inside the script helps -- a branch named ``a"; curl evil ...`` is code. The fix
is always the same shape: bind the value to an ``env:`` entry and reference
``"$VAR"``, which passes it as data. Contexts whose value GitHub constrains --
a commit SHA, a PR number, an event name, ``full_name`` -- are deliberately not
listed: they are not free text, and listing them would reject the organization's
entire existing population for no safety gain."""

SECRET_IN_RUN_RE = re.compile(r"\$\{\{[^}]*?\bsecrets\.[A-Za-z_][A-Za-z0-9_]*[^}]*?\}\}")
"""A secret interpolated into a ``run:`` body is expanded into the script text,
where it can land in a trace, an error message, or a process listing. ``env:``
exists for exactly this and keeps the value out of the rendered script."""


# --------------------------------------------------------------------------
# Rule 6 -- reserved identity of the organization gate
# --------------------------------------------------------------------------
POLICY_REPOSITORY = "first-ai-movers/.github"

ORG_GATE_WORKFLOW_PATH = ".github/workflows/aeos-merge-ready.yml"
RESERVED_CHECK_JOB_NAMES = ("aeos-merge-ready",)
"""The required check's NAME belongs to the organization source, not to a branch.

A ruleset binds a required workflow to a workflow *identity*, but most readers --
dashboards, scripts, humans -- match a check by its name. A consumer repository
that carries its own file at the organization's path, or names a job
`aeos-merge-ready`, publishes a SECOND check-run with the required context's name
that the candidate controls. Measured on agent-toolkit PR #3227 (2026-09-02):
two runs at the same path, both named `aeos-merge-ready`, one the organization
gate and one the repository's own. The ruleset was never satisfied by the twin --
what the twin did was burn a duplicate run and hand any name-matching reader a
candidate-controlled green. Only the policy repository may use either."""


def _reserved_identity_findings(path: str, document: dict, repository: str) -> list[str]:
    if (repository or "").strip().lower() == POLICY_REPOSITORY:
        return []
    out: list[str] = []
    if path.lower() == ORG_GATE_WORKFLOW_PATH:
        out.append(
            f"{path}: this is the organization gate's own path -- a repository "
            f"file here publishes a second check-run carrying the required "
            f"context's name"
        )
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        for name, job in sorted(jobs.items(), key=lambda kv: str(kv[0])):
            declared = job.get("name") if isinstance(job, dict) else None
            for candidate in (str(name), declared):
                if isinstance(candidate, str) and candidate.strip() in RESERVED_CHECK_JOB_NAMES:
                    out.append(
                        f"{path}: job `{name}` publishes the check name "
                        f"`{candidate.strip()}`, which is reserved for the "
                        f"organization gate"
                    )
                    break
    return out


def is_workflow_path(path: str) -> bool:
    lower = path.lower()
    return lower.startswith((WORKFLOW_PREFIX, ACTION_PREFIX)) and lower.endswith(YAML_SUFFIXES)


def _triggers(document: object) -> set[str]:
    """The event names a workflow declares.

    ``on`` is the YAML 1.1 boolean ``true``, so a safe loader hands it back under
    the key ``True`` and a naive ``doc.get("on")`` silently reads nothing --
    which would make every trigger rule vacuous. Both spellings are read.
    """
    if not isinstance(document, dict):
        return set()
    raw = document.get("on", document.get(True))
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, dict):
        return {str(k) for k in raw}
    if isinstance(raw, list):
        return {str(v) for v in raw if isinstance(v, (str, int, float))}
    return set()


def _permission_findings(where: str, permissions: object) -> list[str]:
    if isinstance(permissions, str):
        if permissions.strip().lower() in BROAD_PERMISSION_TOKENS:
            return [f"{where}: `permissions: {permissions.strip()}` grants every write scope"]
        return []
    if isinstance(permissions, dict):
        broad = sorted(
            str(scope)
            for scope, value in permissions.items()
            if isinstance(value, str) and value.strip().lower() in BROAD_PERMISSION_TOKENS
        )
        return [f"{where}: scope `{s}` is granted `write-all`" for s in broad]
    return []


def _steps(job: object) -> list[dict]:
    if not isinstance(job, dict):
        return []
    steps = job.get("steps")
    if not isinstance(steps, list):
        return []
    return [s for s in steps if isinstance(s, dict)]


def _uses_finding(where: str, uses: str) -> str | None:
    ref = uses.strip()
    if not ref or LOCAL_USES_RE.match(ref) or DOCKER_USES_RE.match(ref):
        return None
    if "@" not in ref:
        return f"{where}: `uses: {ref}` names no ref at all"
    target, _, rev = ref.rpartition("@")
    if SHA_PIN_RE.match(rev):
        return None
    owner = target.split("/", 1)[0].lower()
    if owner == TRUSTED_REUSABLE_OWNER or owner in FIRST_PARTY_ACTION_OWNERS:
        return None
    return (
        f"{where}: third-party `uses: {ref}` is not pinned to a 40-hex commit -- "
        f"a tag is a mutable pointer, so \"the action we reviewed\" and \"the action "
        f"that runs tomorrow\" are not the same bytes"
    )


def evaluate_workflow(path: str, document: object, repository: str = "") -> list[str]:
    """Every policy violation in one parsed workflow document, as detail strings.

    ``document`` is the already-parsed result of a *safe* load. This function
    never parses, never executes, and never resolves anything; it walks plain
    dicts, lists and strings. A document that is not a mapping produces no
    findings here -- the gate's structured-data floor is what rejects a workflow
    that is not a mapping, and duplicating that verdict would report one defect
    twice under two different codes.
    """
    if not isinstance(document, dict):
        return []

    out: list[str] = []
    out.extend(_reserved_identity_findings(path, document, repository))

    for trigger in sorted(_triggers(document) & set(FORBIDDEN_TRIGGERS)):
        out.append(
            f"{path}: trigger `{trigger}` runs with the base repository's write "
            f"token and secrets in a fork's context"
        )

    jobs = document.get("jobs")
    jobs = jobs if isinstance(jobs, dict) else {}

    top_permissions = document.get("permissions")
    if top_permissions is None:
        undeclared = sorted(
            str(name)
            for name, job in jobs.items()
            if isinstance(job, dict) and job.get("permissions") is None
        )
        for name in undeclared:
            out.append(
                f"{path}: job `{name}` declares no `permissions` and the workflow "
                f"declares none either -- the token keeps the repository default"
            )
    out.extend(_permission_findings(path, top_permissions))

    for name, job in sorted(jobs.items(), key=lambda kv: str(kv[0])):
        where = f"{path}: job `{name}`"
        if isinstance(job, dict):
            out.extend(_permission_findings(where, job.get("permissions")))
            job_uses = job.get("uses")
            if isinstance(job_uses, str):
                finding = _uses_finding(where, job_uses)
                if finding:
                    out.append(finding)
        for index, step in enumerate(_steps(job)):
            step_where = f"{where} step {index}"
            uses = step.get("uses")
            if isinstance(uses, str):
                finding = _uses_finding(step_where, uses)
                if finding:
                    out.append(finding)
            run = step.get("run")
            if isinstance(run, str):
                if INJECTION_CONTEXT_RE.search(run):
                    out.append(
                        f"{step_where}: `run:` interpolates author-controlled text "
                        f"directly into the script -- bind it to `env:` and use \"$VAR\""
                    )
                if SECRET_IN_RUN_RE.search(run):
                    out.append(
                        f"{step_where}: `run:` interpolates a secret into the script "
                        f"body -- bind it to `env:` instead"
                    )
    return out
