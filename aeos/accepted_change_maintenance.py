"""Accepted-change maintenance: refreshing and retiring the trusted list of accepted protected changes without a click.

``machine_route.accepted_changes`` in ``aeos/standing-governor-policy.json`` is the list of exact protected changes
the operator accepted (``accepted_change``). Refreshing it is mechanical: each batch adds the entries for the carrier
pull requests that are open and drops the entries whose carriers are done. Yet the file is trust data, so every batch
reached ``main`` only on the operator's no-content APPROVE of the exact head (``operator_approval``), 23 times between
#59 and #84, although both organization rulesets already require zero approving reviews (agent-toolkit #3052,
principal direction 2026-11-07).

This module is the smallest deterministic class that removes that click and nothing else. A pull request in this
repository is admitted WITHOUT an approving review only when every one of these holds; each failure is one closed
reason and leaves the pull request exactly where it was, on the approval route:

1. the machine principal authored it, triggered the run and committed the head (``operator_approval.identity_refusal``,
   the same conjuncts, not a restatement);
2. the pull request, read fresh before and after the carriers, still has the evaluated head and description;
3. it changes exactly one path, ``aeos/standing-governor-policy.json``, as a modification of a regular file, on the
   base the trusted policy is (the trusted policy and the pull request's own base agree);
4. the head parses as a valid policy, and removing ``machine_route.accepted_changes`` from both documents leaves them
   equal. Any other key (roots, allowlists, members, signers, principals, any ``activation``, ``operator_approval``,
   ``scoped_grant``, ``authority_compiler``, and this class's own binding, ceilings included) is the operator's;
5. every entry the head adds or changes is for the policy's own target repository, expires inside the base policy's
   lifetime ceiling and has not yet expired, pins its carrier pull request and head, and that carrier, read from GitHub
   by the trusted workflow under a read credential and never from the candidate, is open, authored by the machine
   principal, still at the pinned head, and has the pinned protected-diff digest RECOMPUTED from its actual head by
   the trusted policy. Its protected paths are exactly the entry's, each inside the derivation allowlist, none a root
   or a package replacing one, none under ``.github/`` or ``aeos/``, and it deletes no protected path and no control-
   plane or credential path;
6. every entry the head removes is spent (its carrier is closed or merged) or lapsed (``not_after`` passed), or was
   never live (disabled). An unspent live entry is never removed by this class;
7. the entries after the change are at most the base policy's ceiling.

The bounds (``max_entries``, ``max_lifetime_seconds``) and the repository live in the BASE policy and in this judge,
which a pull request is judged by the copy already on ``main`` of: a candidate that changes them changes this
class's binding (rule 4), which is the operator's. Adding or changing this class is itself such a change, so the
predecessor judges it and it takes the operator's approval once.

Pure stdlib. ``collect`` runs in the trusted workflow, with the job's token for this repository and a separate read
credential for the carrier's repository; ``refusal`` is networkless and judges only recorded evidence. Nothing here
executes candidate or carrier bytes: the carrier is fetched as data, and the existing derivation functions parse it.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile

import accepted_change
import operator_approval

SCHEMA = "aeos-accepted-change-maintenance/v1"
EVIDENCE_SCHEMA = "aeos-accepted-change-maintenance-evidence/v1"
ACTIVATIONS = ("enabled", "disabled")
BINDING_KEYS = frozenset({"schema", "activation", "max_entries", "max_lifetime_seconds"})
POLICY_PATH = "aeos/standing-governor-policy.json"
REGULAR_MODE = "100644"
CONTEXT_CURRENT = operator_approval.CONTEXT_CURRENT
CONTEXT_UNREAD = operator_approval.CONTEXT_UNREAD
MAX_CARRIERS = 2 * accepted_change.MAX_ENTRIES
FETCH_TIMEOUT_SECONDS = 120
MAX_PREFETCH_BLOBS = 1500

_PREFIX = "ACCEPTED_CHANGE_MAINTENANCE_"
UNBOUND = _PREFIX + "UNBOUND"
DISABLED = _PREFIX + "DISABLED"
STALE_CONTEXT = _PREFIX + "STALE_CONTEXT"
NOT_ONLY_POLICY_FILE = _PREFIX + "NOT_ONLY_POLICY_FILE"
BASE_NOT_CURRENT = _PREFIX + "BASE_NOT_CURRENT"
HEAD_POLICY_INVALID = _PREFIX + "HEAD_POLICY_INVALID"
OTHER_KEYS_CHANGED = _PREFIX + "OTHER_KEYS_CHANGED"
NO_CHANGE = _PREFIX + "NO_CHANGE"
CEILING_EXCEEDED = _PREFIX + "CEILING_EXCEEDED"
REPOSITORY_OUT_OF_CLASS = _PREFIX + "REPOSITORY_OUT_OF_CLASS"
ENTRY_NOT_YET_VALID = _PREFIX + "ENTRY_NOT_YET_VALID"
ENTRY_EXPIRED = _PREFIX + "ENTRY_EXPIRED"
LIFETIME_EXCEEDED = _PREFIX + "LIFETIME_EXCEEDED"
CARRIER_UNPINNED = _PREFIX + "CARRIER_UNPINNED"
CARRIER_UNREAD = _PREFIX + "CARRIER_UNREAD"
CARRIER_NOT_OPEN = _PREFIX + "CARRIER_NOT_OPEN"
CARRIER_NOT_MACHINE = _PREFIX + "CARRIER_NOT_MACHINE"
CARRIER_HEAD_MISMATCH = _PREFIX + "CARRIER_HEAD_MISMATCH"
CARRIER_DIGEST_MISMATCH = _PREFIX + "CARRIER_DIGEST_MISMATCH"
CARRIER_PATHS_MISMATCH = _PREFIX + "CARRIER_PATHS_MISMATCH"
PATH_OUT_OF_CLASS = _PREFIX + "PATH_OUT_OF_CLASS"
CARRIER_DELETES_PROTECTED_PATH = _PREFIX + "CARRIER_DELETES_PROTECTED_PATH"
CARRIER_DELETES_CONTROL_PLANE = _PREFIX + "CARRIER_DELETES_CONTROL_PLANE"
UNSPENT_ENTRY_REMOVED = _PREFIX + "UNSPENT_ENTRY_REMOVED"

#: A deleted path under one of these, or named like a credential, makes a carrier out of class whatever else it does.
CONTROL_PLANE_PREFIXES = (".github/", "aeos/")
_CREDENTIAL_SEGMENTS = frozenset({"secrets", "credentials", ".ssh", ".gnupg"})
_CREDENTIAL_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx", ".jks")
_CREDENTIAL_NAMES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")
_HEAD = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


# --------------------------------------------------------------------------
# The binding
# --------------------------------------------------------------------------
def enabled(binding) -> bool:
    """Whether the trusted binding switches the class on. The workflow collects nothing otherwise."""
    return isinstance(binding, dict) and binding.get("activation") == "enabled"


def validate_binding(binding) -> None:
    """``ValueError`` unless ``binding`` is exactly ``{schema, activation, max_entries, max_lifetime_seconds}`` with
    bounds no wider than the acceptance route's own hard limits."""
    if (not isinstance(binding, dict) or set(binding) != BINDING_KEYS or binding.get("schema") != SCHEMA
            or binding.get("activation") not in ACTIVATIONS):
        raise ValueError(f"accepted_change_maintenance must be {{schema: {SCHEMA!r}, activation: enabled|disabled, "
                         "max_entries, max_lifetime_seconds}}")
    entries, lifetime = binding["max_entries"], binding["max_lifetime_seconds"]
    if type(entries) is not int or not 1 <= entries <= accepted_change.MAX_ENTRIES:
        raise ValueError(f"accepted_change_maintenance.max_entries must be 1..{accepted_change.MAX_ENTRIES}")
    if type(lifetime) is not int or not 1 <= lifetime <= accepted_change.MAX_LIFETIME_SECONDS:
        raise ValueError("accepted_change_maintenance.max_lifetime_seconds must be 1..7 days")


# --------------------------------------------------------------------------
# The entry difference both the collector and the judge read
# --------------------------------------------------------------------------
def _key(entry):
    return (entry["repository"].strip().lower(), entry["protected_diff_sha256"])


def _entries_of(document) -> list | None:
    route = document.get("machine_route") if isinstance(document, dict) else None
    entries = route.get("accepted_changes") if isinstance(route, dict) else None
    if entries is None:
        return []
    if not isinstance(entries, list) or not all(isinstance(e, dict) and "repository" in e
                                                and "protected_diff_sha256" in e for e in entries):
        return None
    if not all(isinstance(e["repository"], str) and isinstance(e["protected_diff_sha256"], str) for e in entries):
        return None
    return entries


def _without_entries(document):
    """``document`` with ``machine_route.accepted_changes`` taken out, or ``None`` when there is no machine route."""
    route = document.get("machine_route") if isinstance(document, dict) else None
    if not isinstance(route, dict):
        return None
    stripped_route = {k: v for k, v in route.items() if k != "accepted_changes"}
    return {**document, "machine_route": stripped_route}


def difference(base_entries, head_entries):
    """``(added, removed)``: the head entries that are new or changed, and the base entries the head no longer has."""
    base = {_key(e): e for e in base_entries}
    head = {_key(e): e for e in head_entries}
    added = [e for e in head_entries if base.get(_key(e)) != e]
    removed = [e for k, e in base.items() if k not in head]
    return added, removed


def _pin(entry):
    carrier = entry.get(accepted_change.CARRIER_KEY)
    return carrier if accepted_change.carrier_pin(carrier) else None


def _control_or_credential(path: str) -> bool:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    return (lowered.startswith(CONTROL_PLANE_PREFIXES) or name == ".gitattributes" or name.startswith(".env")
            or name.endswith(_CREDENTIAL_SUFFIXES) or name.startswith(_CREDENTIAL_NAMES)
            or any(part in _CREDENTIAL_SEGMENTS for part in lowered.split("/")))


# --------------------------------------------------------------------------
# The judge: networkless, evidence only
# --------------------------------------------------------------------------
def _carrier_row(evidence_block, repository: str, number: int):
    rows = evidence_block.get("carriers") if isinstance(evidence_block, dict) else None
    if not isinstance(rows, list):
        return None
    found = [r for r in rows if isinstance(r, dict) and str(r.get("repository", "")).lower() == repository.lower()
             and r.get("pull_request") == number]
    return found[0] if len(found) == 1 else None


def refusal(policy, evidence, repository: str, head_sha: str, *, changed, trusted_raw: bytes, base_raw: bytes,
            head_policy, head_raw: bytes, now: float) -> str | None:
    """``None`` when this machine-authored pull request is an in-class refresh of the accepted-change list; otherwise
    the ONE typed reason it is not (the pull request then takes the approval route unchanged).

    ``policy`` is the TRUSTED policy (``derivation_policy.Policy``) and ``trusted_raw`` its bytes. ``changed`` is
    the pull request's whole changed set (objects with ``status``, ``path``, ``mode`` and ``base_mode``);
    ``base_raw`` and ``head_raw`` are the policy file at the pull request's base and head; ``head_policy`` is
    ``head_raw`` parsed and validated by the policy loader, or ``None`` when that failed."""
    binding = getattr(policy, "accepted_change_maintenance", None)
    if binding is None:
        return UNBOUND
    if binding.get("activation") != "enabled":
        return DISABLED
    identity = operator_approval.identity_refusal(policy, evidence, repository, head_sha)
    if identity is not None:
        return identity
    block = evidence.get("accepted_change_maintenance")
    if not isinstance(block, dict) or block.get("context") != CONTEXT_CURRENT:
        return STALE_CONTEXT
    if (len(changed) != 1 or changed[0].path != POLICY_PATH or changed[0].status != "M"
            or changed[0].mode != REGULAR_MODE or changed[0].base_mode != REGULAR_MODE):
        return NOT_ONLY_POLICY_FILE
    try:
        trusted, base, head = (json.loads(raw.decode("utf-8")) for raw in (trusted_raw, base_raw, head_raw))
    except (UnicodeDecodeError, ValueError):
        return HEAD_POLICY_INVALID
    if base != trusted:
        return BASE_NOT_CURRENT
    if head_policy is None:
        return HEAD_POLICY_INVALID
    trusted_rest, head_rest = _without_entries(trusted), _without_entries(head)
    if trusted_rest is None or head_rest is None or trusted_rest != head_rest:
        return OTHER_KEYS_CHANGED
    base_entries, head_entries = _entries_of(trusted), _entries_of(head)
    if base_entries is None or head_entries is None:
        return HEAD_POLICY_INVALID
    if len(head_entries) > binding["max_entries"]:
        return CEILING_EXCEEDED
    added, removed = difference(base_entries, head_entries)
    if not added and not removed:
        return NO_CHANGE
    for entry in added:
        reason = _added_refusal(policy, binding, block, entry, now)
        if reason is not None:
            return reason
    for entry in removed:
        reason = _removed_refusal(block, entry, now)
        if reason is not None:
            return reason
    return None


def _added_refusal(policy, binding, block, entry, now: float):
    if entry["repository"].strip().lower() != policy.target_repository:
        return REPOSITORY_OUT_OF_CLASS
    issued, not_after = accepted_change._stamp(entry["issued_at"]), accepted_change._stamp(entry["not_after"])
    if issued is None or not_after is None or now < issued:
        return ENTRY_NOT_YET_VALID
    if now >= not_after:
        return ENTRY_EXPIRED
    if not_after - now > binding["max_lifetime_seconds"]:
        return LIFETIME_EXCEEDED
    pin = _pin(entry)
    if pin is None:
        return CARRIER_UNPINNED
    row = _carrier_row(block, entry["repository"], pin["pull_request"])
    if row is None:
        return CARRIER_UNREAD
    if row.get("state") != "open" or row.get("merged") is not False:
        return CARRIER_NOT_OPEN
    if (row.get("author_login"), row.get("author_type")) not in set(policy.machine_principals):
        return CARRIER_NOT_MACHINE
    if row.get("head_sha") != pin["head_sha"]:
        return CARRIER_HEAD_MISMATCH
    digest, paths, deleted = row.get("digest"), row.get("paths"), row.get("deleted_paths")
    if (not isinstance(digest, str) or not isinstance(paths, list) or not isinstance(deleted, list)
            or not all(isinstance(p, str) for p in paths + deleted)):
        return CARRIER_UNREAD
    if digest != entry["protected_diff_sha256"]:
        return CARRIER_DIGEST_MISMATCH
    if set(paths) != set(entry["paths"]):
        return CARRIER_PATHS_MISMATCH
    for path in entry["paths"]:
        if (_control_or_credential(path) or not policy.in_allowlist(path) or policy.root_or_shadow(path)):
            return PATH_OUT_OF_CLASS
    if set(deleted) & set(entry["paths"]):
        return CARRIER_DELETES_PROTECTED_PATH
    if any(_control_or_credential(path) for path in deleted):
        return CARRIER_DELETES_CONTROL_PLANE
    return None


def _removed_refusal(block, entry, now: float):
    if entry.get("activation") != "enabled":
        return None  # never live: removing it narrows nothing
    not_after = accepted_change._stamp(entry.get("not_after"))
    if not_after is not None and now >= not_after:
        return None  # lapsed
    pin = _pin(entry)
    row = _carrier_row(block, entry["repository"], pin["pull_request"]) if pin is not None else None
    if row is not None and row.get("state") == "closed":
        return None  # spent: merged or closed, GitHub says closed either way
    return UNSPENT_ENTRY_REMOVED


# --------------------------------------------------------------------------
# The collector: trusted workflow, read-only
# --------------------------------------------------------------------------
def recompute(policy, work_dir: str, base: str, head: str) -> dict:
    """The carrier's protected-diff digest and paths as the consumer's judge computes them: the existing derivation
    functions, the TRUSTED policy, and the carrier's two commits as data. ``base`` is the carrier's merge base."""
    import derivation_policy as dp
    protected, entering, drift = dp.candidate_protected_sets(work_dir, base, head, policy)
    if drift is not None:
        raise dp.PolicyError(dp.DERIVATION_POLICY_DRIFT, drift[1], drift[2])
    changes = dp.raw_diff(work_dir, base, head)
    entries = dp.candidate_entries(work_dir, base, head, protected, entering, changes)
    return {"digest": dp.protected_diff_digest(entries),
            "paths": sorted({p for e in entries for p in (e.path, e.rename_from) if p is not None}),
            "deleted_paths": sorted({c.old for c in changes if c.code in ("D", "R")})}


def fetch_commits(url: str, shas, token: str, dest: str, wanted=None) -> None:
    """Fetch exactly ``shas`` of ``url`` into a new repository at ``dest``, as data, with blobs on demand.

    The credential travels in an extra-header written to the throwaway repository's own config and removed with it:
    never on a command line and never in the caller's environment. ``wanted(path)`` selects the modules whose blobs
    are requested up front (the closure only reads the allowlisted ones); every other blob stays on the server."""
    def git(*args, timeout=FETCH_TIMEOUT_SECONDS):
        done = subprocess.run(["git", "-C", dest, "--no-pager", *args], capture_output=True, timeout=timeout,
                              check=False, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": dest,
                                                "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"})
        if done.returncode != 0:
            raise RuntimeError(f"git {args[0]} failed")
        return done.stdout
    git("init", "-q")
    git("remote", "add", "origin", url)
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        # Written to the file, not passed to `git config`: an argument would be visible to every process on the host.
        config = os.path.join(dest, ".git", "config")
        fd = os.open(config, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, f"[http]\n\textraheader = AUTHORIZATION: basic {basic}\n".encode())
        finally:
            os.close(fd)
    git("config", "--local", "remote.origin.promisor", "true")
    git("config", "--local", "remote.origin.partialclonefilter", "blob:none")
    git("fetch", "-q", "--no-tags", "--depth=1", "--filter=blob:none", "origin", *sorted(set(shas)))
    # The closure reads every Python module under scripts/ at both commits. Ask for those blobs in one request,
    # rather than letting each read fetch its own.
    blobs = set()
    for sha in set(shas):
        for record in git("ls-tree", "-r", "-z", "--full-tree", sha, "--", "scripts/").split(b"\0"):
            meta, _, path = record.partition(b"\t")
            parts = meta.decode("utf-8", "replace").split()
            if (len(parts) == 3 and parts[1] == "blob" and path.endswith(b".py")
                    and (wanted is None or wanted(os.fsdecode(path)))):
                blobs.add(parts[2])
    if len(blobs) > MAX_PREFETCH_BLOBS:
        raise RuntimeError("carrier has too many modules to prefetch")
    if blobs:
        git("fetch", "-q", "--no-tags", "origin", *sorted(blobs))


def _carrier_facts(policy, repository, pin, token, api, fetch, remote_url, needs_digest) -> dict | None:
    number = pin["pull_request"]
    pull = api(f"repos/{repository}/pulls/{number}")
    if not isinstance(pull, dict) or not isinstance(pull.get("head"), dict) or not isinstance(pull.get("base"), dict):
        return None
    user = pull.get("user") if isinstance(pull.get("user"), dict) else {}
    row = {"repository": repository, "pull_request": number, "state": pull.get("state"), "merged": pull.get("merged"),
           "author_login": user.get("login"), "author_type": user.get("type"), "head_sha": pull["head"].get("sha"),
           "digest": None, "paths": [], "deleted_paths": []}
    if not needs_digest:
        return row
    head, base_tip = row["head_sha"], pull["base"].get("sha")
    if not (isinstance(head, str) and _HEAD.fullmatch(head) and isinstance(base_tip, str) and _HEAD.fullmatch(base_tip)):
        return row
    compare = api(f"repos/{repository}/compare/{base_tip}...{head}")
    merge_base = ((compare or {}).get("merge_base_commit") or {}).get("sha") if isinstance(compare, dict) else None
    if not isinstance(merge_base, str) or not _HEAD.fullmatch(merge_base):
        return row
    work = tempfile.mkdtemp(prefix="aeos-carrier-")
    try:
        fetch(remote_url, (merge_base, head), token, work, wanted=policy.in_allowlist)
        row.update(recompute(policy, work, merge_base, head))
    except Exception:  # noqa: BLE001 - an unrecomputable carrier is unread, never a guess
        row.update(digest=None, paths=[], deleted_paths=[])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return row


def collect(policy, repository: str, head_raw: bytes, api, carrier_api, number, head_sha, body, *,
            token: str = "", fetch=fetch_commits, remote_url=None) -> dict:
    """The evidence block ``accepted_change_maintenance`` for one pull request, as the judge reads it.

    ``api`` reads this repository with the job token; ``carrier_api`` reads the carrier's repository with a separate
    read-only credential (``None`` records the carrier as unread, so the class refuses and the approval route
    stands). The pull request is read fresh before AND after the carriers, and both reads must still show the
    event's head and description."""
    block = {"schema": EVIDENCE_SCHEMA, "context": CONTEXT_UNREAD, "carriers": []}
    before = operator_approval.pull_context(api, repository, number, head_sha, body)
    if before != CONTEXT_CURRENT:
        block["context"] = before
        return block
    try:
        head_entries = _entries_of(json.loads(head_raw.decode("utf-8")))
    except (UnicodeDecodeError, ValueError):
        head_entries = None
    if head_entries is None:
        block["context"] = CONTEXT_CURRENT
        return block
    added, removed = difference(policy.accepted_changes, head_entries)
    wanted: dict = {}
    for entries, needs_digest in ((added, True), (removed, False)):
        for entry in entries:
            pin = _pin(entry)
            repo = entry["repository"]
            if pin is not None and _REPO.fullmatch(repo) and repo.strip().lower() == policy.target_repository:
                key = (repo, pin["pull_request"])
                wanted[key] = (pin, wanted.get(key, (None, False))[1] or needs_digest)
    if len(wanted) > MAX_CARRIERS:
        wanted = dict(list(wanted.items())[:MAX_CARRIERS])
    if wanted and carrier_api is None:
        block["unavailable"] = "no read credential for the carrier repository"
    else:
        for (repo, _number), (pin, needs_digest) in wanted.items():
            try:
                row = _carrier_facts(policy, repo, pin, token, carrier_api, fetch,
                                     remote_url or f"https://github.com/{repo}.git", needs_digest)
            except Exception:  # noqa: BLE001 - recorded as absent: the judge refuses it as unread
                row = None
            if row is not None:
                block["carriers"].append(row)
    after = operator_approval.pull_context(api, repository, number, head_sha, body)
    block["context"] = CONTEXT_CURRENT if after == CONTEXT_CURRENT else after
    return block

