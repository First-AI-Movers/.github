"""An exact protected change the operator accepted in trusted policy (agent-toolkit #3052).

A protected file is Python the trust machinery imports (machine identity, the standing ceiling, the dispatcher and
their closure), so a standing delegation over one would let a carrier change what its own checks do: a module can
rebind another module's validator without touching that validator's bytes. A change to one of them is a decision
about one exact change, never a class. The operator makes it ONCE for a set of such
changes, by approving the policy change that lists them here, instead of approving each pull request.

An entry names the change, not a pull request: the repository and the canonical protected-diff digest the gate
already computes (``derivation_policy.protected_diff_digest``: every protected path with its status and the SHA-256
of its bytes before and after). The digest carries no base or head commit, so a carrier whose protected bytes are
unchanged keeps its entry when ``main`` moves or the carrier is rebuilt; any byte that differs is a different
change, and it is not admitted. A machine-authored carrier is admitted when:

* the machine route's own identity conjuncts hold (PR author, run actor and head-commit author are the machine),
  checked first, and its body carries no grant marker;
* the evidence carries :data:`BARRIER`, which only a workflow definition whose job carries the publication recheck
  writes, so a re-run of an older definition never admits;
* its protected diff digest equals an entry's for this repository, and its protected paths (both sides of a
  rename) are exactly the entry's ``paths``;
* the entry is enabled, and the evaluation instant lies in ``[issued_at, not_after)``. ``not_after`` is at most
  :data:`MAX_LIFETIME_SECONDS` after ``issued_at``: an acceptance is short-lived by construction, and nothing
  renews it. A later acceptance is a new policy change, and so a new decision;
* the pull request, read fresh before and after the reviews, still has the evaluated head and description (the
  approval collector's ``CURRENT`` context);
* every protected path is a regular file on every side that exists.

An entry never lists anything under ``.github/`` or ``aeos/`` (a repository's control plane and its manifest slot)
or a path outside the derivation allowlist: the policy refuses to load one that does. Revocation is the policy entry
itself: ``activation: disabled`` or removal. The executor cannot add, widen or renew an entry: each is a change to
this repository's ``aeos/``, which only the operator decides.

A pass that rests on an entry records it, and the trusted workflow re-reads the pull request's context and then,
last, current policy just before publishing (``withdrawn``): an entry revoked, disabled or expired meanwhile never publishes a
pass. A pass already published is not re-judged by a later revocation (see aeos/README.md).

Pure stdlib, networkless: it judges only the protected diff the gate computed and the evidence the trusted workflow
recorded.
"""
from __future__ import annotations

import datetime as _dt
import re

import scoped_grant

SCHEMA = "aeos-accepted-change/v1"
ACTIVATIONS = ("enabled", "disabled")
ENTRY_KEYS = frozenset({"schema", "repository", "protected_diff_sha256", "paths", "issued_at", "not_after",
                        "activation", "decision"})
MAX_ENTRIES = 16
MAX_PATHS = 32
MAX_DECISION_CHARS = 500
#: Seven days: an acceptance outlives one review cycle, never a standing grant.
MAX_LIFETIME_SECONDS = 7 * 24 * 3600
#: Never reachable from an entry: a repository's control plane and its manifest slot.
EXCLUDED_PREFIXES = (".github/", "aeos/")
#: The approval collector's context for a pull request that, read fresh twice, still has the event's head and body.
CONTEXT_CURRENT = "CURRENT"
#: Written into the evidence ONLY by a workflow definition whose job carries the publication recheck below. A re-run
#: of an older definition (GitHub re-runs keep the original definition) records no such capability, so it can never
#: admit through an acceptance it would not recheck.
BARRIER = "aeos-accepted-change-barrier/v1"

ACCEPTED_CHANGE_BARRIER_ABSENT = "ACCEPTED_CHANGE_BARRIER_ABSENT"
ACCEPTED_CHANGE_DISABLED = "ACCEPTED_CHANGE_DISABLED"
ACCEPTED_CHANGE_NOT_YET_VALID = "ACCEPTED_CHANGE_NOT_YET_VALID"
ACCEPTED_CHANGE_EXPIRED = "ACCEPTED_CHANGE_EXPIRED"
ACCEPTED_CHANGE_STALE_CONTEXT = "ACCEPTED_CHANGE_STALE_CONTEXT"
ACCEPTED_CHANGE_PATHS_MISMATCH = "ACCEPTED_CHANGE_PATHS_MISMATCH"
ACCEPTED_CHANGE_NOT_REGULAR_FILE = "ACCEPTED_CHANGE_NOT_REGULAR_FILE"
#: Publication-time recheck (``withdrawn``): the entry a pass rested on is gone from current policy.
ACCEPTED_CHANGE_REVOKED = "ACCEPTED_CHANGE_REVOKED"
#: Publication-time recheck: the gate's record of what its pass rested on cannot be read.
ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE = "ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE"

_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_SEGMENT = re.compile(r"[A-Za-z0-9_.@+-]+")


def _exact_path(path) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/") or path.endswith("/"):
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") and _SEGMENT.fullmatch(part) for part in parts)


def _stamp(value):
    """``YYYY-MM-DDTHH:MM:SSZ`` as epoch seconds, or ``None``."""
    if not isinstance(value, str) or not _STAMP.fullmatch(value):
        return None
    try:
        return _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc).timestamp()
    except ValueError:
        return None


def validate(entries, *, target_repository, in_allowlist) -> None:
    """``ValueError`` unless ``entries`` is a list of well-formed, short-lived acceptances for ``target_repository``
    whose paths stay inside the derivation allowlist and outside every control plane."""
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError("accepted_changes must be a list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS or entry.get("schema") != SCHEMA:
            raise ValueError(f"each accepted change is exactly {sorted(ENTRY_KEYS)} with schema {SCHEMA}")
        repository = entry["repository"]
        if (not isinstance(repository, str) or not _REPO.fullmatch(repository)
                or repository.lower() != target_repository):
            raise ValueError("accepted change must name the policy's target repository")
        digest = entry["protected_diff_sha256"]
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest) or digest in seen:
            raise ValueError("accepted change must carry a unique lower-case SHA-256 protected-diff digest")
        seen.add(digest)
        if entry["activation"] not in ACTIVATIONS:
            raise ValueError("accepted change activation must be enabled or disabled")
        issued, not_after = _stamp(entry["issued_at"]), _stamp(entry["not_after"])
        if issued is None or not_after is None or not issued < not_after <= issued + MAX_LIFETIME_SECONDS:
            raise ValueError("accepted change must hold issued_at < not_after <= issued_at + 7 days")
        decision = entry["decision"]
        if not isinstance(decision, str) or not decision.strip() or len(decision) > MAX_DECISION_CHARS:
            raise ValueError("accepted change must record its decision")
        paths = entry["paths"]
        if (not isinstance(paths, list) or not 1 <= len(paths) <= MAX_PATHS
                or not all(_exact_path(p) for p in paths) or len(set(paths)) != len(paths)):
            raise ValueError("accepted change paths must list 1..32 exact, unique paths")
        for path in paths:
            if path.lower().startswith(EXCLUDED_PREFIXES) or not in_allowlist(path):
                raise ValueError(f"accepted change path {path!r} may never be accepted")


def entry_for(entries, repository: str, digest: str):
    """The entry accepting ``digest`` in ``repository`` (enabled or not), or ``None``."""
    repo = (repository or "").strip().lower()
    for entry in entries or ():
        if entry["repository"].lower() == repo and entry["protected_diff_sha256"] == digest:
            return entry
    return None


def refusal(entry, evidence, *, entries, now: float) -> str | None:
    """``None`` when this machine-authored carrier is the accepted change; otherwise the ONE typed reason.

    ``entries`` are the candidate's protected entries (``path``, ``rename_from`` and the modes). The machine route has
    already checked the author, actor, head-commit author, evidence repository and the grant marker."""
    if not isinstance(evidence, dict) or evidence.get("accepted_change_barrier") != BARRIER:
        return ACCEPTED_CHANGE_BARRIER_ABSENT
    if entry.get("activation") != "enabled":
        return ACCEPTED_CHANGE_DISABLED
    issued, not_after = _stamp(entry.get("issued_at")), _stamp(entry.get("not_after"))
    if issued is None or now < issued:
        return ACCEPTED_CHANGE_NOT_YET_VALID
    if not_after is None or now >= not_after:
        return ACCEPTED_CHANGE_EXPIRED
    pr = evidence.get("pull_request") if isinstance(evidence, dict) else None
    approval = pr.get("approval") if isinstance(pr, dict) else None
    if not isinstance(approval, dict) or approval.get("context") != CONTEXT_CURRENT:
        return ACCEPTED_CHANGE_STALE_CONTEXT
    touched = {p for item in entries for p in (item.path, item.rename_from) if p is not None}
    if touched != set(entry["paths"]):
        return ACCEPTED_CHANGE_PATHS_MISMATCH
    if not all(scoped_grant._regular_file_entry(item) for item in entries):
        return ACCEPTED_CHANGE_NOT_REGULAR_FILE
    return None


def withdrawn(entries, dependence, *, context, now: float) -> str | None:
    """Why an acceptance that a pass rested on no longer holds at publication; ``None`` when it still holds.

    ``entries`` are the accepted changes of the policy read FRESH from the policy source just before the run
    publishes, never the checkout the run judged with; ``dependence`` is the gate's record of the entry its pass
    rested on (``{repository, protected_diff_sha256}``); ``context`` is the approval collector's fresh context for
    the pull request. A removal, a disabling or an expiry since the run read its policy, or a head or description
    that moved since the run collected its evidence, keeps the pass from publishing. The protected bytes cannot
    have changed under a ``CURRENT`` context: the digest is of the evaluated head."""
    if (not isinstance(dependence, dict) or not isinstance(dependence.get("repository"), str)
            or not isinstance(dependence.get("protected_diff_sha256"), str)):
        return ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE
    entry = entry_for(entries, dependence["repository"], dependence["protected_diff_sha256"])
    if entry is None:
        return ACCEPTED_CHANGE_REVOKED
    if entry.get("activation") != "enabled":
        return ACCEPTED_CHANGE_DISABLED
    issued, not_after = _stamp(entry.get("issued_at")), _stamp(entry.get("not_after"))
    if issued is None or now < issued:
        return ACCEPTED_CHANGE_NOT_YET_VALID
    if not_after is None or now >= not_after:
        return ACCEPTED_CHANGE_EXPIRED
    if context != CONTEXT_CURRENT:
        return ACCEPTED_CHANGE_STALE_CONTEXT
    return None
