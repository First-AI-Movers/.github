#!/usr/bin/env python3
"""Circuit breaker and automatic revert for the AEOS post-main rail.

Consumes ``aeos-main-smoke`` outcomes and decides -- deterministically, with no
model -- whether a squash commit on the default branch must be reverted, then
performs the revert through GitHub's normal pull-request path. It never pushes
the default branch directly.

``decide`` (pure, given git plus the evidence files) returns exactly one typed
decision:

    REVERT                                  confirmed: two identical CODE_FAILURE signatures on the
                                            same SHA, the SHA is exactly one squash commit on top of
                                            ``before``, the parent does NOT fail the same way, and the
                                            commit touched no protected control-plane path
    PASS_NOTHING_TO_DO                      the first smoke passed
    INFRA_UNAVAILABLE                       either smoke was INFRA_UNAVAILABLE -- never revert on an outage
    NOT_CONFIRMED_FLAKY                     the rerun passed, or failed with a different signature
    ORIGIN_UNPROVEN                         no usable parent evidence -- the commit cannot be shown to be
                                            the origin of the failure
    INHERITED_FAILURE_NOT_ORIGIN            the parent already fails the same way -- this commit is
                                            innocent, and the origin's own run owns the revert
    REVERT_ATTRIBUTION_AMBIGUOUS            ``before..sha`` is not exactly one single-parent commit
    CONTROL_PLANE_REVERT_REQUIRES_OPERATOR  the commit changed a protected path -- reverting the merge
                                            control plane is operator-governed, never automatic
    SMOKE_EVIDENCE_INVALID                  an evidence file is malformed, or is for another SHA

``execute`` (only for ``REVERT``) creates ``aeos/revert-<sha12>`` from the remote
default branch, reverts exactly that one commit -- a conflict is the typed hard
stop ``REVERT_CONFLICT``, never resolved by guessing -- pushes the branch, opens
the revert pull request and arms squash auto-merge.

Every outward write authenticates with the short-lived GitHub App installation
token the workflow mints at runtime (``GH_TOKEN``). A pull request opened with
that token fires the required ``aeos-merge-ready`` workflow natively, so this
controller posts no check-run and needs no ``checks`` scope. No token present is
the typed, fail-closed ``AUTOREVERT_AUTH_UNAVAILABLE`` -- never a fallback to the
repository token, whose pull requests fire no workflow at all and so could never
be judged by the required gate.

Repository-agnostic: it reads no repository-specific declaration. The protected
set is the organization control plane, the same paths the merge gate refuses.

Exit codes: 0 decision or execution recorded - 3 REVERT_CONFLICT - 4 an outward
write failed - 5 credentials or identity unavailable - 2 usage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gitobject  # noqa: E402

SCHEMA_VERSION = "1"
CHECK_CONTEXT = "aeos-main-smoke"
ZERO_SHA = gitobject.ZERO_SHA
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")

#: The organization control plane, matched case-insensitively. Reverting what
#: decides whether things may merge is an operator act in every repository -- an
#: automatic rail that could revert its own gate is a rail that can disable
#: itself.
PROTECTED_PREFIXES = (".github/workflows/", ".github/actions/")
PROTECTED_PATHS = (".github/aeos-gate.json", ".github/aeos-smoke.json")

DECISIONS = (
    "REVERT", "PASS_NOTHING_TO_DO", "INFRA_UNAVAILABLE", "NOT_CONFIRMED_FLAKY",
    "ORIGIN_UNPROVEN", "INHERITED_FAILURE_NOT_ORIGIN", "REVERT_ATTRIBUTION_AMBIGUOUS",
    "CONTROL_PLANE_REVERT_REQUIRES_OPERATOR", "SMOKE_EVIDENCE_INVALID",
)
EXECUTIONS = (
    "REVERT_PR_OPENED", "REVERT_PR_EXISTS", "ALREADY_REVERTED", "REVERT_CONFLICT",
    "DRY_RUN", "PUSH_FAILED", "PR_CREATE_FAILED", "AUTOMERGE_ARM_FAILED",
    "NOT_A_REVERT_DECISION", "AUTOREVERT_AUTH_UNAVAILABLE", "AUTOREVERT_IDENTITY_UNAVAILABLE",
)

#: The ONLY environment variable that may carry the App installation token.
#: ``GITHUB_TOKEN`` is deliberately not accepted, so the "no fallback" guarantee
#: is enforced here and not only in YAML.
AUTH_ENV_VARS = ("GH_TOKEN",)
#: The git identity the revert commit is authored with -- the App's bot user. An
#: unattributed author trips the organization ruleset's extra-approval rule, and
#: the armed auto-merge would then never fire, so a missing identity is a stop.
IDENTITY_ENV_VARS = ("AEOS_REVERT_GIT_NAME", "AEOS_REVERT_GIT_EMAIL")

REVERT_TRAILER = "aeos-revert-of"
BRANCH_PREFIX = "aeos/revert-"
ALREADY_REVERTED_SCAN = 400


def auth_available(environ=None) -> bool:
    env = os.environ if environ is None else environ
    return any((env.get(k) or "").strip() for k in AUTH_ENV_VARS)


def git_identity(environ=None):
    env = os.environ if environ is None else environ
    name, email = ((env.get(k) or "").strip() for k in IDENTITY_ENV_VARS)
    return (name, email) if name and email and "@" in email else None


def is_protected(path: str) -> bool:
    lowered = path.lower()
    return lowered in PROTECTED_PATHS or any(lowered.startswith(p) for p in PROTECTED_PREFIXES)


def check_ids(evidence) -> frozenset:
    """Every check id an outcome reports, whatever its status."""
    if not isinstance(evidence, dict):
        return frozenset()
    return frozenset(str(c.get("id")) for c in evidence.get("checks") or []
                     if isinstance(c, dict))


def failing_ids(evidence) -> frozenset:
    """Check ids an outcome reports as CODE_FAILURE, ignoring the reason.

    Origin is compared on the check identity alone. Folding the reason in would
    make an exit code that merely shifts -- pytest reporting 1 for failures and
    2 when the same broken suite is interrupted -- look like a failure this
    commit introduced, and revert a commit that introduced nothing.
    """
    return frozenset(cid for cid, _reason in failing_set(evidence))


def plan_source(evidence):
    return (evidence or {}).get("source") if isinstance(evidence, dict) else None


def failing_set(evidence) -> frozenset:
    """The ``(check id, reason)`` pairs an outcome reports as CODE_FAILURE."""
    if not isinstance(evidence, dict):
        return frozenset()
    return frozenset(
        (str(c.get("id")), str(c.get("reason")))
        for c in evidence.get("checks") or []
        if isinstance(c, dict) and c.get("status") == "CODE_FAILURE"
    )


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


# ---------- decide --------------------------------------------------------------

def _evidence(obj, sha, label):
    """Validate one smoke outcome for ``sha``; returns ``(outcome, signature)``."""
    if not isinstance(obj, dict):
        raise ValueError(f"{label}: not an object")
    if obj.get("check_context") != CHECK_CONTEXT:
        raise ValueError(f"{label}: not an {CHECK_CONTEXT} outcome")
    if obj.get("outcome") not in ("PASS", "CODE_FAILURE", "INFRA_UNAVAILABLE"):
        raise ValueError(f"{label}: unrecognised outcome {obj.get('outcome')!r}")
    if obj.get("sha") != sha:
        raise ValueError(f"{label}: outcome is for another SHA")
    sig = obj.get("signature")
    if obj["outcome"] == "CODE_FAILURE" and not (isinstance(sig, str) and _SIGNATURE_RE.match(sig)):
        raise ValueError(f"{label}: CODE_FAILURE without a signature")
    return obj["outcome"], sig


def attribution(repo_root, sha: str, before: str) -> tuple[bool, str]:
    """True only when ``sha`` is exactly ONE single-parent commit over ``before``."""
    if not gitobject.is_full_sha(sha):
        return False, "sha is not a full commit id"
    if not gitobject.is_full_sha(before) or before == ZERO_SHA:
        return False, "before is missing or zero (branch creation) -- the push cannot be bounded"
    parents = _git(repo_root, "rev-list", "--parents", "-n", "1", sha)
    if parents.returncode != 0:
        return False, "sha is unknown to the checkout"
    ids = parents.stdout.split()
    if len(ids) != 2:
        return False, f"sha has {len(ids) - 1} parent(s); a squash commit has exactly one"
    if ids[1] != before:
        return False, "sha's parent is not `before` -- more than one commit landed in this push"
    count = _git(repo_root, "rev-list", "--count", f"{before}..{sha}")
    if count.returncode != 0 or count.stdout.strip() != "1":
        return False, f"before..sha spans {count.stdout.strip() or '?'} commit(s), not exactly one"
    return True, "exactly one single-parent squash commit on top of before"


class ChangedPathsUnreadable(Exception):
    """git could not say what a commit touched."""


def changed_paths_of(repo_root, sha: str) -> list[str]:
    """Never fails open.

    Swallowing a git error here would turn "I cannot read what this commit
    touched" into "it touched nothing protected", which satisfies the
    control-plane conjunct vacuously and also empties the decision's
    ``changed_paths`` -- which is what ``execute``'s containment guard compares
    against. Two guarantees would be lost to one unread file.
    """
    try:
        return gitobject.changed_paths(repo_root, sha)
    except (gitobject.GitUnavailable, gitobject.MalformedPath) as exc:
        raise ChangedPathsUnreadable(str(exc)) from exc


def decide(first, second, parent, sha: str, before: str, repo_root) -> dict:
    repo_root = Path(repo_root)
    base = {"schema_version": SCHEMA_VERSION, "sha": sha, "before": before,
            "decision": None, "detail": ""}

    def out(decision, detail, **extra):
        result = {**base, "decision": decision, "detail": detail}
        result.update(extra)
        return result

    try:
        o1, s1 = _evidence(first, sha, "first")
        o2, s2 = (_evidence(second, sha, "second") if second is not None else (None, None))
    except ValueError as exc:
        # The one decision shape that suggests tampering rather than a normal
        # stop, so it is the one that exits non-zero.
        return out("SMOKE_EVIDENCE_INVALID", str(exc), exit_code=1)

    if o1 == "PASS":
        return out("PASS_NOTHING_TO_DO", "the first smoke passed")
    if o1 == "INFRA_UNAVAILABLE" or o2 == "INFRA_UNAVAILABLE":
        return out("INFRA_UNAVAILABLE",
                   "a smoke run was INFRA_UNAVAILABLE -- an outage is never code evidence; no revert")
    if o2 is None:
        return out("NOT_CONFIRMED_FLAKY",
                   "no confirming rerun evidence -- a single failure never reverts")
    if o2 != "CODE_FAILURE" or s1 != s2:
        return out("NOT_CONFIRMED_FLAKY",
                   "the rerun did not reproduce the identical deterministic failure",
                   first_signature=s1, second_signature=s2)

    ok, why = attribution(repo_root, sha, before)
    if not ok:
        return out("REVERT_ATTRIBUTION_AMBIGUOUS", why + " -- typed hard stop, no revert")

    if parent is None:
        return out("ORIGIN_UNPROVEN",
                   "no parent smoke evidence -- this commit cannot be shown to be the origin; no revert",
                   signature=s1)
    try:
        po, ps = _evidence(parent, before, "parent")
    except ValueError as exc:
        return out("SMOKE_EVIDENCE_INVALID", str(exc), exit_code=1)
    if po == "INFRA_UNAVAILABLE":
        return out("ORIGIN_UNPROVEN",
                   "the parent smoke was INFRA_UNAVAILABLE -- origin unprovable; no revert", signature=s1)

    if po == "CODE_FAILURE" and ps == s1:
        # The strongest inherited signal there is: the parent fails identically.
        return out("INHERITED_FAILURE_NOT_ORIGIN",
                   "the parent fails with the identical signature -- inherited, not the origin; "
                   "the origin's own run owns the revert",
                   signature=s1, parent_failures=sorted(list(x) for x in failing_set(parent)))

    # A baseline is only a baseline if it measured the same thing. If the commit
    # changed which smoke runs -- adding the first Python file, or a `test`
    # script, or editing the declaration -- the parent's run is not a comparison
    # and cannot establish that this commit originated anything.
    if plan_source(first) != plan_source(parent):
        return out("ORIGIN_UNPROVEN",
                   f"the parent ran a different smoke plan ({plan_source(parent)!r} vs "
                   f"{plan_source(first)!r}) -- there is no comparable baseline; no revert",
                   signature=s1)

    introduced_ids = failing_ids(first) - failing_ids(parent)
    unbaselined = sorted(introduced_ids - check_ids(parent))
    if unbaselined:
        # A check the parent never ran has no baseline, so a failure of it cannot
        # be shown to have been introduced here rather than to have been failing
        # all along. This is also the path a newly added test takes when a
        # reproducing transient breaks it.
        return out("ORIGIN_UNPROVEN",
                   "the parent has no baseline for check(s) " + ", ".join(unbaselined) +
                   " -- a check with no comparison cannot prove an origin; no revert",
                   signature=s1)

    if po == "CODE_FAILURE":
        # Origin is decided by failing SETS, not by whole-signature equality. On
        # an already-red default branch, a later commit that adds no new failure
        # is inheriting one even though its signature differs. A commit is the
        # origin only of the failures it INTRODUCED -- which is also what stops
        # the rail oscillating, because reverting this commit restores exactly
        # the parent's failure set and no more.
        if ps == s1 or not introduced_ids:
            return out("INHERITED_FAILURE_NOT_ORIGIN",
                       "the parent already fails every check this commit fails -- inherited, "
                       "not the origin; the origin's own run owns the revert",
                       signature=s1, parent_failures=sorted(list(x) for x in failing_set(parent)))
        origin_note = f"introduced {len(introduced_ids)} newly failing check(s) on an already-red branch"
    else:
        origin_note = "the parent passed"
    introduced = sorted(introduced_ids)

    try:
        changed = changed_paths_of(repo_root, sha)
    except ChangedPathsUnreadable as exc:
        return out("REVERT_ATTRIBUTION_AMBIGUOUS",
                   f"git could not report what this commit touched ({exc}) -- the control-plane "
                   "conjunct cannot be evaluated; no revert", signature=s1)
    touched = sorted(p for p in changed if is_protected(p))
    if touched:
        return out("CONTROL_PLANE_REVERT_REQUIRES_OPERATOR",
                   "the commit changed protected merge-control path(s); reverting the control plane "
                   "is operator-governed: " + ", ".join(touched), signature=s1, touched=touched)

    subject = _git(repo_root, "log", "-n", "1", "--format=%s", sha).stdout.strip()
    return out("REVERT",
               "confirmed identical deterministic CODE_FAILURE twice on one attributable squash "
               f"commit; {origin_note}",
               signature=s1, subject=subject, branch=f"{BRANCH_PREFIX}{sha[:12]}",
               changed_paths=changed, introduced_failures=introduced)


# ---------- execute -------------------------------------------------------------

class Gh:
    """Thin ``gh`` seam; tests substitute a recording shim via ``argv0``."""

    def __init__(self, argv0=("gh",), env=None):
        self.argv0 = list(argv0)
        self.env = env

    def run(self, *args, timeout=120):
        return subprocess.run([*self.argv0, *args], capture_output=True, text=True,
                              timeout=timeout, env=self.env)


_UNSAFE_SUBJECT_RE = re.compile(r"[`\r\n]|@[A-Za-z0-9]|#\d")


def safe_subject(decision) -> str:
    """The offending commit's subject, made safe to place in a PR title and body.

    The subject is written by whoever authored the commit being reverted, and it
    lands in a pull request body where an ``@name`` would notify a person or a
    whole team and a backtick would break out of the code span it is quoted in.
    Neither is a catastrophe; neither is something this rail should do on
    somebody's behalf either.
    """
    subject = (decision.get("subject") or decision.get("sha", "")[:12]).strip()
    def defuse(match):
        token = match.group(0)
        if token in "`\r\n":
            return " "
        # A zero-width space after the sigil keeps the text readable while
        # stopping GitHub resolving it. `#123` in a PR *body* is honoured as a
        # closing reference, so a reverted commit's subject could close an
        # unrelated issue the moment the revert merges.
        return token[0] + "\u200b" + token[1:]

    subject = _UNSAFE_SUBJECT_RE.sub(defuse, subject)
    # Strip again: a subject made only of stripped characters is now blank, and a
    # blank title is worse than no title.
    return subject[:160].strip() or decision.get("sha", "")[:12]


def _revert_message(decision, run_url) -> str:
    sha = decision["sha"]
    return "\n".join([
        f"revert(aeos): {safe_subject(decision)} [{REVERT_TRAILER}: {sha[:12]}]",
        "",
        "Automatic revert by the AEOS post-main circuit breaker: aeos-main-smoke reported the "
        "identical deterministic CODE_FAILURE twice on this exact squash commit, its parent did "
        "not fail the same way, and no merge-control path was involved. Reverts exactly one "
        "commit; never pushes the default branch directly.",
        "",
        f"aeos-main-smoke signature: {decision.get('signature')}",
        f"evidence: {run_url or 'n/a'}",
        "",
        f"{REVERT_TRAILER}: {sha}",
    ]) + "\n"


def _pr_body(decision, run_url) -> str:
    sha = decision["sha"]
    return "\n".join([
        "Automatic revert opened by the AEOS post-main circuit breaker.",
        "",
        f"`aeos-main-smoke` reported the **identical deterministic `CODE_FAILURE` twice** on squash "
        f"commit `{sha}` (`{safe_subject(decision)}`), its parent did not fail the same way, "
        "and the commit touched no merge-control path. This pull request reverts exactly that one "
        "commit through the normal auto-squash path; nothing was pushed to the default branch "
        "directly.",
        "",
        f"- signature: `{decision.get('signature')}`",
        f"- evidence run: {run_url or 'n/a'}",
        "- this pull request is judged by the required `aeos-merge-ready` gate like any other.",
        "",
        "Fix-forward is welcome after this lands; do not fight the revert on the default branch.",
        "",
        f"{REVERT_TRAILER}: {sha}",
    ]) + "\n"


def already_reverted(repo_root, sha: str, base_ref: str) -> bool:
    """True when the base branch already carries a revert of ``sha``.

    Anchored to a whole trailer line rather than matched as a substring
    anywhere in the log. An unanchored match fired on a documentation example
    quoting the format, on a revert-of-a-revert, and on anything else that
    happened to contain the string -- and because this is a proof that exits 0,
    a false positive silently retires a SHA from the rail.

    Deliberately NOT keyed on the author or committer: GitHub rewrites the
    committer when it squash-merges the revert PR, so an identity check would
    fail to recognise the rail's own reverts. A planted trailer therefore still
    suppresses one SHA -- but planting one requires the ability to land a commit
    on the default branch, which is strictly more power than evading the rail.
    """
    fmt = "%B%x1e"
    proc = _git(repo_root, "log", base_ref, "-n", str(ALREADY_REVERTED_SCAN), f"--format={fmt}")
    trailer = f"{REVERT_TRAILER}: {sha}"
    return any(
        line.strip() == trailer
        for record in proc.stdout.split("\x1e")
        for line in record.splitlines()
    )


def execute(decision: dict, repo_root, repo_slug: str, *, dry_run: bool = True, run_url: str = "",
            gh: Gh | None = None, push_remote: str = "origin", base_branch: str = "main",
            environ=None) -> dict:
    repo_root = Path(repo_root)
    gh = gh or Gh()
    base_ref = f"{push_remote}/{base_branch}"
    res = {"schema_version": SCHEMA_VERSION, "sha": decision.get("sha"), "execution": None,
           "detail": "", "branch": decision.get("branch"), "dry_run": dry_run,
           "base_branch": base_branch}

    def out(execution, detail, code=0, **extra):
        res.update({"execution": execution, "detail": detail, "exit_code": code})
        res.update(extra)
        return res

    if decision.get("decision") != "REVERT":
        return out("NOT_A_REVERT_DECISION", f"decision was {decision.get('decision')!r}; nothing executed")
    if not dry_run and not auth_available(environ):
        return out("AUTOREVERT_AUTH_UNAVAILABLE",
                   "no App installation token in GH_TOKEN -- the revert rail cannot authenticate; "
                   "the confirmed decision is recorded and NOT executed (no fallback to the "
                   "repository token)", 5)
    identity = git_identity(environ) or (
        ("aeos-revert (dry run)", "aeos-revert@dry-run.invalid") if dry_run else None
    )
    if identity is None:
        return out("AUTOREVERT_IDENTITY_UNAVAILABLE",
                   "no App bot git identity in AEOS_REVERT_GIT_NAME/AEOS_REVERT_GIT_EMAIL -- an "
                   "unattributed revert commit would never auto-merge under the organization "
                   "ruleset; not executed", 5)
    git_name, git_email = identity
    sha, branch = decision.get("sha") or "", decision.get("branch") or ""

    # The decision file is trusted input today, but this is the function that
    # turns a string into `git push HEAD:refs/heads/<branch>`. A branch of
    # "main" would push the default branch directly and defeat the loudest
    # guarantee this rail makes, so the shape is asserted rather than assumed.
    if not gitobject.is_full_sha(sha):
        return out("NOT_A_REVERT_DECISION", "the decision does not name a full commit id")
    if branch != f"{BRANCH_PREFIX}{sha[:12]}":
        return out("NOT_A_REVERT_DECISION",
                   f"the decision's branch {branch!r} is not this rail's branch for {sha[:12]}")

    if _git(repo_root, "fetch", "--quiet", push_remote, base_branch).returncode != 0:
        return out("PUSH_FAILED", f"could not fetch {base_ref}", 4)
    if already_reverted(repo_root, sha, base_ref):
        return out("ALREADY_REVERTED", f"{base_ref} already carries a `{REVERT_TRAILER}: {sha}` trailer")
    if not dry_run:
        existing = gh.run("pr", "list", "--repo", repo_slug, "--head", branch, "--state", "open",
                          "--json", "number,url")
        try:
            rows = json.loads(existing.stdout or "[]") if existing.returncode == 0 else []
        except ValueError:
            rows = []
        if rows:
            return out("REVERT_PR_EXISTS", f"an open revert PR already exists: {rows[0].get('url')}",
                       pr_number=rows[0].get("number"), pr_url=rows[0].get("url"))

    work = Path(tempfile.mkdtemp(prefix="aeos-revert-"))
    try:
        if _git(repo_root, "worktree", "add", "--detach", "--quiet", str(work), base_ref).returncode != 0:
            return out("PUSH_FAILED", "could not create the revert worktree", 4)
        _git(work, "checkout", "--quiet", "-B", branch)
        rv = _git(work, "-c", f"user.name={git_name}", "-c", f"user.email={git_email}",
                  "revert", "--no-edit", sha)
        if rv.returncode != 0:
            conflicts = [ln for ln in
                         _git(work, "diff", "--name-only", "--diff-filter=U").stdout.splitlines() if ln]
            _git(work, "revert", "--abort")
            return out("REVERT_CONFLICT",
                       "the revert of the offending commit does not apply cleanly on the current "
                       "default branch -- typed hard stop; no branch, no PR, no guess",
                       3, conflict_paths=conflicts)

        msg = work / ".aeos-revert-msg"
        msg.write_text(_revert_message(decision, run_url), encoding="utf-8")
        _git(work, "-c", f"user.name={git_name}", "-c", f"user.email={git_email}",
             "commit", "--quiet", "--amend", "--reset-author", "-F", str(msg))
        msg.unlink()
        res["author"] = f"{git_name} <{git_email}>"

        revert_sha = _git(work, "rev-parse", "HEAD").stdout.strip()
        base_sha = _git(work, "rev-parse", base_ref).stdout.strip()
        changed = [ln for ln in _git(work, "diff", "--name-only", base_sha, "HEAD").stdout.splitlines() if ln]
        ahead = _git(work, "rev-list", "--count", f"{base_sha}..HEAD").stdout.strip()
        res.update({"revert_sha": revert_sha, "base_sha": base_sha,
                    "changed_paths": changed, "commits_ahead": ahead})
        if ahead != "1" or set(changed) - set(decision.get("changed_paths") or changed):
            return out("REVERT_CONFLICT",
                       "the revert commit is not exactly one commit over exactly the offending "
                       "commit's paths -- refusing", 3)
        if any(is_protected(p) for p in changed):
            # Belt and braces: `decide` already refused a protected commit, but a
            # revert that reaches the control plane by any route is operator work.
            return out("REVERT_CONFLICT",
                       "the prepared revert touches a protected control-plane path -- refusing", 3)
        if dry_run:
            return out("DRY_RUN", "revert commit prepared locally; no push, no PR (dry run)")

        push = _git(work, "push", "--quiet", "--set-upstream", push_remote, f"HEAD:refs/heads/{branch}")
        if push.returncode != 0:
            return out("PUSH_FAILED", "git push of the revert branch failed", 4)

        body = work / ".aeos-revert-body.md"
        body.write_text(_pr_body(decision, run_url), encoding="utf-8")
        title = f"revert(aeos): {safe_subject(decision)} [{REVERT_TRAILER}: {sha[:12]}]"
        created = gh.run("pr", "create", "--repo", repo_slug, "--base", base_branch, "--head", branch,
                         "--title", title[:240], "--body-file", str(body))
        body.unlink()
        if created.returncode != 0:
            # Typed only. gh's stderr can carry token-shaped or URL-shaped text
            # and this result is uploaded as an artifact, where log masking does
            # not apply.
            return out("PR_CREATE_FAILED", f"gh pr create exited {created.returncode} (output withheld)", 4)
        pr_url = created.stdout.strip().splitlines()[-1] if created.stdout.strip() else ""
        match = re.search(r"/pull/(\d+)", pr_url)
        pr_number = int(match.group(1)) if match else None
        res.update({"pr_url": pr_url, "pr_number": pr_number})

        armed = gh.run("pr", "merge", str(pr_number) if pr_number else pr_url, "--repo", repo_slug,
                       "--auto", "--squash")
        res["auto_merge_armed"] = armed.returncode == 0
        res["checks_trigger"] = "native required workflow (App installation token)"
        if not res["auto_merge_armed"]:
            # Arming is load-bearing: an un-armed revert PR sits open with nobody
            # watching it, which is exactly the outcome this rail exists to avoid.
            return out("AUTOMERGE_ARM_FAILED",
                       f"revert PR {pr_url} opened but arming auto-merge exited {armed.returncode} "
                       "-- auto-merge is NOT armed", 4, pr_url=pr_url, pr_number=pr_number)
        return out("REVERT_PR_OPENED", "revert PR opened and auto-merge armed",
                   pr_url=pr_url, pr_number=pr_number)
    finally:
        _git(repo_root, "worktree", "remove", "--force", str(work))
        _git(repo_root, "worktree", "prune")
        shutil.rmtree(work, ignore_errors=True)


# ---------- CLI -----------------------------------------------------------------

def _load(path):
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AEOS post-main circuit breaker and automatic revert.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decide", help="Reduce smoke evidence to one typed decision.")
    d.add_argument("--repo-root", required=True)
    d.add_argument("--sha", required=True)
    d.add_argument("--before", required=True)
    d.add_argument("--first", required=True)
    d.add_argument("--second")
    d.add_argument("--parent")
    d.add_argument("--out")

    e = sub.add_parser("execute", help="Perform a REVERT decision through the normal PR path.")
    e.add_argument("--repo-root", required=True)
    e.add_argument("--repo", required=True, help="owner/name")
    e.add_argument("--decision", required=True)
    e.add_argument("--base-branch", default="main")
    e.add_argument("--run-url", default="")
    e.add_argument("--execute", action="store_true", help="Perform outward writes (default: dry run).")
    e.add_argument("--out")

    args = ap.parse_args(argv)

    if args.cmd == "decide":
        result = decide(_load(args.first), _load(args.second), _load(args.parent),
                        args.sha.strip().lower(), args.before.strip().lower(), Path(args.repo_root))
    else:
        result = execute(_load(args.decision), Path(args.repo_root), args.repo,
                         dry_run=not args.execute, run_url=args.run_url,
                         base_branch=args.base_branch)
    print(json.dumps(result, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return int(result.get("exit_code", 0))


if __name__ == "__main__":
    raise SystemExit(main())
