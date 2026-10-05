# `aeos-merge-ready` — organization merge-ready gate

This directory holds the trusted policy behind the organization required
workflow [`.github/workflows/aeos-merge-ready.yml`](../.github/workflows/aeos-merge-ready.yml).

It publishes one check context, named exactly **`aeos-merge-ready`**. Rulesets
and auto-merge read that string, so renaming the job silently detaches them.

## What it is

A deterministic hygiene floor for the autonomous-main lifecycle: open a pull
request ready for review, let the gate and auto-merge do the rest. It is not a
review. It carries no model, no provider, no reviewer or thread input, no
pull-request-body semantics, and no waiting.

## What it checks

| Check | Reason code on failure |
| --- | --- |
| Changed control-plane paths satisfy the strict lane below | `WORKFLOW_POLICY_VIOLATION` · `CONTROL_PLANE_PROOF_FAILED` |
| A control-plane change in this policy repository neither authored and run by an identified operator nor approved by one on its exact machine-authored head | `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR` |
| A control-plane **deletion** in this policy repository | `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR` |
| No high-confidence credential shape in changed text | `SECRET_SHAPE_DETECTED` |
| No high-confidence credential shape in any revision the range introduces | `SECRET_SHAPE_DETECTED` |
| Changed `.json` parses; changed `.yml`/`.yaml` parses | `STRUCTURED_DATA_UNPARSEABLE` |
| Changed `.py` parses (parse only — never imported, never run) | `SYNTAX_ERROR` |
| The changed set itself is readable | `EVIDENCE_UNREADABLE` |
| The gate body stays inside its own time budget | `BUDGET_EXCEEDED` |
| The optional `.github/aeos-gate.json`, if present, is valid | `GATE_CONFIG_INVALID` |

Failures name the offending path (and line number for a credential shape). A
matched credential value is never echoed.

The secret-shape check deliberately ignores values that vendors publish in their
own documentation and the usual documentation placeholders — `sk-XXXX...`,
`xoxb-your-bot-token-here`, `AKIAIOSFODNN7EXAMPLE`. Firing on a setup guide
would make an ordinary README unmergeable across the whole organization, and
this floor is not what stops a determined leak.

The gate runs on `pull_request` and `merge_group` only. Those are the events
that carry a real two-endpoint commit range; anything else would have to invent
one, and an invented range produces a pass that measured nothing.

### The credential check reads the range, not just its endpoints

Every other check judges the head: the head is what merges, and a syntax error
in a revision that was superseded three commits ago is not a defect in what this
branch proposes. A credential is different in kind. Publishing it *is* the harm,
and the publishing already happened when the object was pushed.

So the credential check reads two populations: the changed set (`base...head`),
and every blob the range introduces that is not in the head tree
(`rev-list --objects head --not base`). The second population is the one that
catches a token committed by one commit and scrubbed by a later one before the
pull request was opened. Nothing else in the lifecycle looks at it:

- the endpoint diff cannot — the content is at neither endpoint;
- a post-merge history scan cannot, under the squash-only merge policy this gate
  is deployed behind, because the superseded commit never joins the default
  branch;
- deleting the branch does not remove it — `refs/pull/<n>/head` keeps the objects,
  and in a public repository anyone can fetch them.

Findings from a superseded revision carry the same reason code and name the path
and line; the value is never echoed, and the operator allowlist exempts a path's
superseded revisions exactly as it exempts its head revision. The extra work is
bounded by the same per-file byte cap, an object cap, and the same time budget —
a hundred files rewritten across ten commits (900 superseded revisions) measures
0.6 s against a 45 s budget. A shallow candidate checkout is refused rather than
scanned, because `rev-list` would stop at the graft boundary and report a
truncated range as a complete one.

## What it does not require

Nothing. The gate is repository-agnostic: it depends on no file existing in the
repository it runs against. A brand-new repository with no source tree, no
control plane and no toolchain pin passes. **Absence of a file is normal, not an
error.**

## Trust model

Candidate bytes are data, never code.

- The candidate is checked out into `candidate/` with `persist-credentials: false`.
- The policy — this directory — is checked out separately into `policy/`, always
  from `First-AI-Movers/.github@main`. Only `policy/` executes.
- The gate reads `candidate/` files as bytes and parses them. It never imports
  candidate modules, runs candidate tests, sources candidate configuration,
  executes candidate scripts, or honours a candidate-supplied command.
- **Content is read by object id, not from the working tree.** The changed set
  and every byte judged come from the commit named `head.sha` in the event
  payload — the same commit the check result is published against. A working
  tree is a place bytes happen to be sitting; a blob id is a statement about
  which bytes they are, so the verdict cannot be computed from one tree and
  reported against another.
- Permissions are `contents: read`. There are no secrets, no
  `pull_request_target`, no self-hosted runners, and no network calls beyond the
  two checkouts.
- Event values reach the gate as environment variables, never interpolated into
  a shell body.

## The control-plane set — and the strict lane

A changed path matching any of these is merge-control surface. Matching is
case-insensitive, and a deletion counts as a change.

- `.github/workflows/**`
- `.github/actions/**`
- `.github/aeos-gate.json`
- `.github/aeos-smoke.json`

Each decides how a check behaves, so a branch able to edit its own copy would be
choosing what it is judged by.

A test asserts this list matches the set the gate actually enforces, because the
documented set and the enforced set drift apart the moment either is spelled out
twice.

**These paths used to be decided by path alone** — one `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR`
verdict, no candidate byte read, and a queue in front of every workflow edit in
the organization. They are now **judged**. A control-plane path enters the strict
lane, where every ordinary floor still applies *and* these do:

| Surface | Floor |
| --- | --- |
| `.github/workflows/**`, `.github/actions/**` | no `pull_request_target`; `permissions` declared and never `write-all`; every non-local `uses:` pinned to a 40-hex commit; no author-controlled free text or `secrets.*` interpolated into a `run:` body; no consumer repository publishing the reserved `aeos-merge-ready` path or check name |
| `.github/aeos-gate.json` | valid schema; no blanket allowlist entry that would exempt the whole repository from secret-shape detection |
| `.github/aeos-smoke.json` | valid schema; a declared `smoke_suites` / `compile_roots` may not be empty — a rail rewritten to run nothing still reports green |
| `aeos/**` *(this repository only)* | parses; `merge_ready_gate.py` still declares its load-bearing constants, so the gate cannot lose one through an autonomous merge |

The allowlist **never** exempts a control-plane path. That conjunct is what keeps
the gate config a decision rather than a self-serve bypass, and it is now checked
where it bites: a real credential shape inside a workflow, with an allowlist that
covers it, is still a finding.

Every workflow rule is calibrated against the organization's live population
(measured 2026-09-03, all 20 workflows in `agent-toolkit` and this repository):
zero `pull_request_target` triggers, zero undeclared `permissions`, zero unpinned
third-party actions, zero secrets or author-controlled text in a `run:` body. The
lane rejects what nobody is doing and permits everything that is.

**Candidate code is never executed.** Workflow YAML is safe-loaded; candidate
Python is read with `ast.parse`, which builds a syntax tree and runs nothing. And
the judge is always the predecessor: these floors live in the trusted checkout
resolved from the base commit, so a branch proposing a change to them is measured
by the copy already on `main`.

### The residual human gates

Two conditions in **this** repository still need a person. The first is identity,
not content: a control-plane change is judged only when an identified operator
authors and runs it (see "Only a positively identified operator edits the judge"
under the machine route below). The second is deletion.

Deleting a control-plane path in **this** repository — the organization's own
merge-control source — still fails with `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR`.
A deletion has no bytes, so no content floor can measure it, and this deletion
reaches the gate that judges every repository in the organization. The same
deletion in a consumer repository merges: the required verdict is injected there
by the organization ruleset from a repository that branch cannot touch, and
`.github/aeos-smoke.json` falling away restores the rail's built-in defaults —
a stricter posture, not a weaker one.

The anti-ratchet floor on `merge_ready_gate.py` is deliberately structural, not
semantic: it catches a load-bearing declaration being deleted outright, which is
what a weakening actually looks like in that file. Anything subtler still merges.
That is a stated limit of this lane, not a claim it has none.

## The standing-governor derivation policy — a scoped signed-diff conjunct

Decided by `ADR:standing-governor-continuity-authority` (`First-AI-Movers/agent-toolkit`,
Accepted 2026-09-09) §D2 and §D15 Tier 1 item 1; authorized by #1951 operator decision
5600051094 item 2. Implemented by `aeos/derivation_policy.py`; declared by
`aeos/standing-governor-policy.json`. **Inert for every repository except the policy's
`target_repository`, and inert for every candidate there that touches no protected or
allowlisted path.** Ordinary behaviour outside that exact conjunct is unchanged.

Why it exists: on a Development Cell the node's GitHub credential is the operator's own,
so a resident process could widen the modules that read its own authority — the ceiling
parser, the narrowing chain, the deriver, the admission and replay enforcers — through an
ordinary auto-squashed pull request. This conjunct makes that require an off-node
operator signature.

- **Protected set.** `derivation_policy.members` is a *generated, bounded* list: the
  first-party import closure of `derivation_policy.roots` under `scripts/` (whole AST, so a
  lazy in-function import counts; package `__init__.py` modules count because they execute
  on import), intersected with `allowlist_prefixes` + `allowlist_files`. The gate
  regenerates that set from the **base** commit on every evaluation, with trusted code
  parsing candidate Python as data, and protects the union of `members` and that
  regenerated set. **Growth is not drift**: a member the closure gained after `members`
  was last committed is already protected by the regenerated set, so it is signed like
  any other member and strands no candidate. The gate refuses `DERIVATION_POLICY_DRIFT`
  only when a committed member is **no longer** in the base closure — which also refuses
  a candidate whose merge base predates members the list has since committed. The list is
  never hand-edited; it is **committed here and refreshed by an ordinary PR**
  (`derivation_policy.regenerate_closure(<clone>, <main sha>, policy)[1]`, sorted) when a
  member leaves the closure, and optionally to record growth — a stale list after growth
  blocks nothing. The gate regenerates the same
  closure at the **candidate head** too, and the set the candidate must sign is the union:
  a helper added under the allowlist and imported from a root is protected in the same
  change, so the signature covers the whole effective validator change. A file under the
  allowlist that no root imports is ordinary code; so is a newly imported helper outside
  the allowlist (the ADR's accepted residual).
- **Signed diff.** A candidate whose merge-base→head diff (rename-aware) touches a member
  must carry `aeos/derivation-policy-manifest.json` and `aeos/derivation-policy-manifest.sig`
  on its head. The manifest is the canonical representation of the protected diff — the
  trusted base SHA, the repository, the namespace, one entry per changed protected path
  with `status` ∈ {`added`,`modified`,`deleted`,`renamed`}, `pre_sha256` / `post_sha256`
  (the SHA-256 of the file bytes at the base / head, or `absent`; never a git object id)
  and `rename_from`, and `protected_diff_sha256`, the SHA-256 of the entries' canonical
  serialization — all serialized with sorted keys and no whitespace. It never binds the
  head SHA (which would depend on the manifest itself), and the manifest and signature are
  excluded from the diff they describe. The gate recomputes those bytes and requires byte
  equality, so a deleted validator cannot vanish from the manifest and a renamed one cannot
  escape it.
- **Signer.** The signature is `ssh-keygen -Y sign -n at-derivation-policy` by a key whose
  public half is pinned in `accepted_signers` (label, fingerprint, public key, `not_after`).
  The pinned `fingerprint` **must be** the SHA-256 fingerprint of `public_key` (the value
  `ssh-keygen -lf` prints); the gate computes it from the key and refuses the whole policy
  as `GATE_CONFIG_INVALID` on a mismatch, so the reviewed fingerprint is the boundary and a
  key that does not produce it can never become the trusted verifier key. Verification is
  `ssh-keygen -Y verify` against an allowed-signers file the gate writes from that trusted
  data — never from the candidate. A signer whose `not_after` is `null` is **not active**
  and every protected diff is refused; an expired signer is stale; removing the entry is
  the durable revocation.
- **Reason codes.** `DERIVATION_POLICY_DIFF_UNSIGNED` (no manifest/signature, unpinned key,
  wrong namespace, inactive or expired signer); `DERIVATION_POLICY_MANIFEST_INCOMPLETE`
  (manifest bytes are not the canonical protected diff — a missing deletion, rename or
  newly-imported-helper entry, a git-object-id representation or a wrong digest lands
  here); `DERIVATION_POLICY_DRIFT` (a committed member is no longer in the regenerated
  base closure, or a declared root is absent at the base or the head); an unreadable or
  self-inconsistent policy document is `GATE_CONFIG_INVALID`.
- **Judge.** The policy document lives beside the gate in this repository, so a candidate
  that ships its own copy, or its own key, is judged by the trusted one. Changing the policy
  document here is an `aeos/**` control-plane change judged by the predecessor.

The exact bytes an operator signs for a candidate are `derivation_policy.expected_manifest(...)`
— what the gate will recompute; an implementation lane posts them, the operator signs off-node.

## The machine route — an admitted machine principal needs no operator signature

Decided by agent-toolkit#3752 (ratified) and implemented as its Slice A. The signed-manifest
conjunct above was compensation for a shared operator/machine identity. When the candidate is
authored by a **separate, pinned machine principal** inside a **current operator-authored
programme authority**, the gate admits a protected diff without an SSH signature. The gate
stays networkless: the trusted workflow writes one `aeos-actor-evidence/v1` file from
GitHub-authenticated facts under its own read-only token, and the gate judges that file.

- **Principals.** `machine_route.machine_principals` (`{login: "<app>[bot]", type: "Bot"}`) and
  `machine_route.operator_principals` (human logins) in `aeos/standing-governor-policy.json`;
  the sets must be disjoint and unique or the policy is `GATE_CONFIG_INVALID`. Without the
  block the route is off and only the signed route exists.
- **Evidence** (written by the workflow, never the candidate): the pull request's author login
  and type, the workflow actor, the head commit's author, and — for the programme the PR body
  names with exactly one `<!-- aeos-programme: owner/repo#N -->` marker — that Issue's state,
  author, body and content-edit history (`userContentEdits`). On `merge_group` the queued PR is
  resolved from the queue's head ref. Every read failure is recorded as unavailable.
- **M5 authority compilation.** `machine_route.authority_compiler`, when present, binds one
  existing operator-authored programme by its exact `owner/repo#N` reference and its existing
  `Policy / Programme ID`. It stores neither a path list nor a grant. Once that source has passed
  the ordinary Issue-author/edit, repository, ACTIVE and expiry checks below, it compiles exactly
  the protected paths in the candidate's already-recomputed diff. Those paths must remain inside
  the existing derivation-policy allowlist; a candidate marker, candidate prose, bot edit, or a
  path outside that outer boundary does not compile. This is the #3752 zero-crypto route for an
  already-admitted programme, not a per-head signature, per-file callback or second authority
  store. Programmes without this trusted binding retain their `standing-authority/v2.path_envelope`
  route unchanged. Its required dogfood order is one #5277 machine-authorized protected change
  first; #5280 may reuse the same generic compilation only after that readback.
- **All of these must hold**, each refusing with its own `MACHINE_ROUTE_*` reason inside the
  `DERIVATION_POLICY_DIFF_UNSIGNED` detail: PR author, workflow actor and head-commit author are
  the pinned machine principal and none is an operator principal; evidence repository equals the
  candidate repository; the programme Issue is open, authored by an operator principal (type
  User), and every recorded edit was by an operator principal (an unreadable history is not
  "no edits"); its `standing-authority/v2` block names the same `owner/repo#N`, is `ACTIVE`, and its
  `not_after` is `null` or still ahead; every protected changed path — both paths of a rename — is inside its
  `path_envelope`. Absent or malformed evidence and events with no pull request are
  unprovable.
- **Revocation, not a calendar, ends programme authority** (operator decision
  agent-toolkit#3752 `5925947456`). `not_after: null` is standing intent: it holds until the
  operator closes the Issue (`MACHINE_ROUTE_PROGRAMME_NOT_OPEN`), moves `state` off `ACTIVE`
  (`MACHINE_ROUTE_AUTHORITY_NOT_ACTIVE`) or supersedes the block. A non-null `not_after` is an
  end the operator chose and is honoured (`MACHINE_ROUTE_AUTHORITY_EXPIRED`); elapsed time alone
  revokes nothing, and there is no ceiling on how far ahead it may lie. Short-lived credentials
  (signers, App tokens) keep their own expiry. Scope still cannot widen: a declared derivation **root** is
  admitted only by an exact-path envelope entry, never by a directory prefix
  (`MACHINE_ROUTE_ROOT_NEEDS_EXACT_ENVELOPE`), so `scripts/agent_relay/` can never quietly
  authorise rewriting the ceiling parser; a malformed envelope entry anywhere invalidates the
  block; evidence that resolves inside the candidate tree is malformed.
- **Only the operator decides a change to the judge.** In this repository, a control-plane
  change (`aeos/**`, the workflows) is judged on its content only when the trusted evidence
  either names a pinned operator principal (type User) as PR author and an operator principal as
  the run's actor, **or** shows the operator approved exactly this machine-authored head (the
  operator-approval route below). A machine principal without that approval, any other `[bot]`,
  or an empty/unreadable author or actor is `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR`, whatever
  else the candidate passes. The App installation may reach this repository; the gate does not
  let it decide the facts it is judged by. (The operator-side complement is scoping the
  installation to selected repositories.)
- **The operator-approval route** (`aeos/operator_approval.py`, agent-toolkit #3052, bound by
  `machine_route.operator_approval` = `{schema: aeos-operator-approval/v1, activation}`). The
  machine carries the mechanics: it authors the pull request, triggers the run and authors the
  head commit. The operator's **Approve** on that exact head is the decision. It admits:
  - a control-plane change in this repository (lock 5 above); and
  - a protected Agent Toolkit change on the machine route, in place of a programme envelope.
  A grant-marked pull request stays with the scoped-grant judge only.

  Each conjunct refuses with its own `OPERATOR_APPROVAL_*` reason:
  - the event is `pull_request` (a merge-group commit is never something a review names);
  - PR author, run actor and head-commit author are the pinned machine principal;
  - the evidence repository is the candidate's;
  - the evidence head is the evaluated head;
  - the pull request, read fresh by the trusted workflow before and after the reviews, still has
    that head and the very body the rest of the gate judges (`OPERATOR_APPROVAL_CONTEXT_CHANGED`
    otherwise). A re-run replays its original event, so a body edited since then, say to add a
    grant marker, is never judged as the old one, including an edit that lands mid-read;
  - the review list was read completely (at most three pages of 100; more is unreadable, never
    "no review"). The workflow reads reviews only while `activation` is `enabled`, and a failed
    read records `UNREAD` without costing any other evidence;
  - the latest decisive review (`APPROVED`, `CHANGES_REQUESTED` or `DISMISSED`, ordered by
    `submitted_at`, then id) by a pinned operator principal of type User is `APPROVED`, on that
    head. A later push makes it stale, and a change request or dismissal revokes it. `COMMENTED`
    and `PENDING` never decide.

  The identity standard is the predecessor's: the same pinned logins. What is bound is one commit,
  narrower than any envelope. The machine never approves, and GitHub never lets a pull request's
  author approve it.

  Two pieces keep a verdict current when the decision changes:
  - **The barrier is the gate job's last step.** The gate records, in a marker its CLI writes on a
    pass, whether that pass rested on the approval (lock 5, or the derivation machine route). Only
    an explicit "no" skips the step; a missing or unreadable marker counts as "yes". When the pass
    rested on it, the step re-reads the approval and the pull request with the same collector just
    before the pass publishes. If the approval was withdrawn, or the head or description changed,
    while the run was judging, the run fails with the route's typed reason
    (`DERIVATION_POLICY_DIFF_UNSIGNED`, or `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR` here), whichever
    run it is and whatever else is in flight. A run whose evidence carries no approval, or whose
    approval never held, is untouched.
  - **`.github/workflows/aeos-approval-rerun.yml` re-judges verdicts that had already settled.** On
    an approval, a change request, a dismissal or a description edit, it re-runs the latest gate run
    at the head once it has settled, whatever it concluded. It selects the gate by its exact workflow
    path, which the workflow floor reserves to the organization; a display name proves nothing. Jobs
    queue per pull request on the job itself. A run it cannot find or re-run within the bound fails
    the job visibly; absence is never believed. The consumer route exists only for the policy's
    target repository, which carries the same file (agent-toolkit `.github/workflows/aeos-approval-rerun.yml`,
    with its CI-portfolio register entry).

  A re-run executes the workflow definition of the run it repeats. Every definition that collects
  approvals also carries the recheck, both arriving in one change; an older definition collects
  none, so the route refuses it (`OPERATOR_APPROVAL_REVIEWS_UNREADABLE`).

  Residual, stated: observing and publishing are not atomic. A revocation, edit or push that lands
  after the run's last read of the reviews and the pull request cannot stop the pass that read
  publishes, nor an auto-merge that consumes it. That window runs from the last observation to the
  merge, normally seconds. It is the same window an operator-opened change has today between a
  green gate and its merge, and the remedy is a revert. Closing it would need merge-time review
  enforcement on every pull request, a ruleset change outside this design. Residual, as above: a
  process acting under the operator's own credential could submit an approval, exactly as it
  could author a pull request today; identity separation (#3752 M4) removes both. Rollback:
  `activation: disabled` restores the predecessor exactly.
- **Operational rule.** The run's actor must be the machine principal too, so an operator who
  reopens or un-drafts a machine-route PR flips its verdict to `MACHINE_ROUTE_TRIGGER_NOT_MACHINE`
  until the machine pushes again; that is the correct answer for a push and the price of it for a
  reopen. A non-root protected member under a directory-prefix entry is the route's intended
  power: the ceiling on that power is the root's own exact-entry rule.
- **Fallback is closed, not open.** When the machine route refuses, the signed route is tried
  and its refusal names both reasons. There is no ambient-identity fallback in the gate.
- **Residual until #3752 M4.** A process still acting under the operator's own credential can
  edit an operator-created Issue and would appear as an operator edit; identity separation of
  the execution path is what removes that, which is why it is P0 there.

### Accepted protected changes

A protected file is Python that the trust machinery imports, so a standing delegation over it would let a carrier
change what its own checks do: a module can rebind another module's validator without touching that validator's
bytes. A change to one of them is therefore a decision about one exact change, never a class. `machine_route.accepted_changes` (`aeos/accepted_change.py`, agent-toolkit #3052) lets the operator make
that decision once for a set of such changes, by approving the policy change that lists them, instead of
approving each pull request. Each entry is exactly
`{schema: aeos-accepted-change/v1, repository, protected_diff_sha256, paths, issued_at, not_after, activation, decision}`.

An entry names the change, not a pull request: the canonical protected-diff digest the gate already computes (every
protected path with its status and the SHA-256 of its bytes before and after). The digest carries no base or head
commit, so a carrier keeps its entry when `main` moves or the carrier is rebuilt with the same protected bytes. Any
byte that differs is a different change and takes the route an unlisted change takes today.

A machine-authored pull request is admitted under an entry when all of these hold. Each refuses with its own
`ACCEPTED_CHANGE_*` reason inside `DERIVATION_POLICY_DIFF_UNSIGNED`:
- the machine route's identity conjuncts pass. The operator-approval route is decided first;
- the evidence carries the publication-recheck capability (`accepted_change_barrier`, below);
- the body carries no grant marker. No description selects the entry: the digest does;
- the digest matches an entry for this repository, and the protected paths, both sides of a rename, are exactly
  the entry's `paths`;
- the entry is enabled, and the evaluation instant lies in `[issued_at, not_after)`;
- the pull request, read fresh before and after the reviews, still has the evaluated head and description (the
  approval collector's `CURRENT` context);
- every protected path is a regular file on every side that exists.

The policy refuses to load an entry that:
- names another repository;
- lists anything under `.github/` or `aeos/`;
- lists a path outside the derivation allowlist;
- lives longer than seven days (`not_after` at most `issued_at` plus 7 days).

Nothing renews an entry. The executor cannot add, widen or renew one: each is a change here, which only the operator
decides. The durable revocation is the entry itself: `activation: disabled` or removal.

A pass that rests on an entry records it in the gate's marker (`accepted_change`). The job's step "Recheck an
accepted protected change before this verdict publishes" then works in this order:
1. It reads the marker first. A pass that rests on no acceptance is untouched.
2. It re-collects the pull request's context.
3. As its last external observation, it reads that entry from the policy currently on `main`.
4. It judges the time after that read (`accepted_change.withdrawn`).

An entry revoked, disabled or expired before that final read, or a head or description that moved, fails the run
instead of publishing a success. So does an acceptance-dependent pass whose evidence cannot be read. A marker that
cannot be read fails closed for a machine-authored pull request, or any merge-group event, in the policy's target
repository, the only places an acceptance can exist. That is judged from the event itself, not from the evidence
file.

The route admits only when the evidence carries the capability `accepted_change_barrier:
aeos-accepted-change-barrier/v1`. Only a workflow definition whose job carries that step writes it. A re-run of an
older definition (GitHub re-runs keep the original definition) therefore never admits through an acceptance it would
not recheck.

Residuals, stated:
- Between the step's final policy read and the publication of the verdict, normally seconds, a revocation is not
  observed.
- A pass that already published is not re-judged by a later revocation or expiry. A consumer's gate runs on its
  own events, and this repository cannot re-run another repository's checks. Between that publication and the merge,
  a revocation does not stop the merge. Carriers arm auto-merge, so that window is normally minutes. To stop one
  inside it, close the pull request or disable its auto-merge. Any push to it re-runs the gate under current policy.
- An entry admits its exact bytes again if they reappear inside its window, for example after a revert. That is the
  same change the operator accepted, and the window bounds it.
- As with every route that judges a candidate's diff from its merge base, two separately accepted changes to one
  file that merge cleanly together land as their union.

### Machine-route reason on signature-route findings

When the machine route does not admit a protected diff, the gate falls back to the operator's signature over a
canonical manifest. Every finding of that fallback names `machine route: <reason>`, the manifest findings first
of all, so a candidate waiting for an approval never reads as a mechanical manifest defect.

### Constrained comment source operand

The optional `machine_route.comment_operand` is one reviewed lowering in the
**trusted policy**, not a candidate grant or a prose interpreter. It is absent
from the shipped policy. Adding a real operand requires the existing policy
review path and authenticated programme/admission/registration lineage; this
adapter does not infer that lineage or create admission or continuation state.
The original operator ratification remains the authority source. A later bot
receipt may be evidence of admission or registration, never operator ratification.

`aeos-comment-operand/v1` has exactly these fields:

| Field | Binding |
| --- | --- |
| `schema` | `aeos-comment-operand/v1` |
| `programme` | Exact `owner/repo#N` |
| `scope` | `repository-code` only |
| `generation` | `programme + "@sha256:" + SHA256(canonical remaining fields)` |
| `sources` | Exactly three ordered records: `ratification`, `admission`, `registration` |
| `authority`, `ceiling` | Exact six-field `standing-authority/v2` objects: schema, state, repository, issue, not_after, path_envelope |

Each source has exactly `role`, `ref`, `comment_id`, `issue_body_sha256`,
`comment_body_sha256`, and `frontier_sha256`. Comment identities must be distinct;
ratification belongs to the programme. Both authority objects must name that
programme and be ACTIVE. Authority expiry cannot exceed the reviewed ceiling (a `null` ceiling bounds nothing by time; a `null` authority under a dated ceiling would outlive it and is refused);
its envelope is a subset of the ceiling's exact files, without directory grants.
The generation is an operand version, not a runtime seat or generation store.
Canonical JSON uses sorted keys, compact separators and UTF-8 without ASCII
escaping; body hashes cover exact UTF-8 bytes. The frontier hashes the complete,
ascending comment list projected to `id`, `body_sha256`, `author_login`,
`author_type`, `updated_at`.

The existing read-only workflow API collects these sources twice and requires
equal complete snapshots, including immutable Issue identity. Each observation
follows authenticated GraphQL cursors through at most ten pages of 100 comments
(1,000 comments per source). Every page must retain the same Issue identity,
repository, body, state, author, edit history and total count. Cursors must advance
without repetition; comment IDs must be positive, unique and increasing. A terminal
page must account for the exact total; missing/partial pages, unknown pagination,
hidden/minimized or deleted nodes and budget exhaustion are unavailable, never a
partial frontier. Issue edit histories remain capped at 100 complete records and
every editor must be a User; a missing/deleted editor or unknown type refuses.
The selected comment must occur exactly once across the complete frontier and
have a known integer zero edit count. The existing evidence-file byte cap still
applies. Cursor/page boundaries are not authority: the v1 frontier hash continues
to cover the same ordered row projection over **all** comments, and the operand
shape, body/comment digests and generation formula are unchanged.
The networkless gate accepts facts at most 300 seconds old. Every source Issue
must be open and operator-authored with only operator edits. Selected comments
must be unedited; ratification must be by a pinned User operator, while admission
and registration may also be by a pinned machine principal. Exact body hashes,
source identities and the whole frontier must match the independently reviewed
policy. Any subsequent comment, deletion, edit, revocation or supersession
changes the frontier and refuses the old binding. This conservative design
requires a fresh reviewed operand after even an unrelated comment; it never
guesses whether later prose revokes authority.

Missing, untrusted, stale or ambiguous facts refuse with the existing
`MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID`; malformed policy is `GATE_CONFIG_INVALID`.
A body authority block alongside the bound comment source is ambiguous and
refused. With no operand for that programme, the legacy Issue-body path is
unchanged. Normalized input reuses the existing principal, repository, expiry,
root and changed-path checks; signed routes and the predecessor judge remain
unchanged. No active source, route, runtime action or provider effect is installed.

## Operator allowlist — `.github/aeos-gate.json` (optional)

Some repositories deliberately commit credential-shaped literals as verified
non-secret canaries in tests and documentation. A repository may declare those
paths exempt from the **secret-shape check only**, by committing this file to
its default branch:

```json
{
  "schema_version": "1",
  "secret_shape_allowlist": [
    "Engine/scripts/tests/**",
    "docs/**/*.md",
    "tests/test_alert_privacy.py"
  ]
}
```

- **The file is optional.** Absent means no exemptions, and that is the normal
  case. A repository without one behaves exactly as it does with an empty list.
- **It is read from the base commit**, addressed as `<base_sha>:.github/aeos-gate.json`.
  Git objects are content-addressed and `base_sha` comes from the event payload,
  so a branch cannot make that address resolve to bytes of its own choosing. The
  candidate working tree is never consulted.
- **The file is itself control plane** (see the set above). A pull request that
  adds or edits it goes through the strict lane: it must be valid, and it may not
  carry a blanket entry (`*`, `**`, `**/*`, empty) that would exempt the whole
  repository. Narrowness is what makes the allowlist a decision rather than a
  self-serve bypass, and it is now enforced rather than asked for.
- **Present but malformed fails closed** with `GATE_CONFIG_INVALID`. Invalid
  JSON, an unrecognised `schema_version`, or a `secret_shape_allowlist` that is
  not a list of non-empty strings will not silently degrade to "no exemptions".
  Unknown top-level keys are ignored so a newer declaration stays readable.
- **It exempts the secret-shape check and nothing else**, and never on a
  control-plane path. Structured-data parsing, the Python syntax floor, and the
  strict lane all still apply to an allowlisted path.
- Every suppression is listed in the job summary, so an exemption is visible
  rather than silent.

### Glob semantics

Entries are matched against the repository-relative changed path with
`fnmatch.fnmatchcase`, chosen over `pathlib.PurePath.match` because the latter
is right-anchored and gives `**` no recursive meaning before Python 3.13.

| Pattern | Matches |
| --- | --- |
| `Engine/scripts/tests/**` | anything beneath that directory, at any depth |
| `docs/**/*.md` | `docs/a.md` and `docs/guide/a.md` |
| `tests/test_alert_privacy.py` | that exact path |

These are not `gitignore` semantics, and the differences all widen a pattern, so
read them before writing one:

- **`*` is not separator-aware — it spans `/`.** `docs/*.md` matches
  `docs/a/b/c.md`, and a bare suffix pattern like `*.env` exempts every `.env`
  anywhere in the repository.
- **`*` or `**` alone exempts the whole repository**, turning the secret-shape
  check off in a single line. That is a legitimate operator decision, but it
  should be a deliberate one.
- **`/**/` also matches a single separator** — the one extension over plain
  `fnmatch`, so `docs/**/*.md` covers the top level of `docs/` as well as its
  subdirectories. The collapse is all-or-nothing: `a/**/b/**/c.txt` matches
  `a/b/c.txt`, not `a/x/b/c.txt`.
- **`[` and `]` are a character class**, as in any glob. `t/a[1].py` does *not*
  match a file literally named `t/a[1].py`, and *does* match `t/a1.py`.
- **Matching is case-sensitive**, so `docs/**/*.md` does not exempt
  `Docs/a.md`. Control-plane matching is deliberately case-*in*sensitive
  instead: both directions lean towards refusing rather than exempting.

## Failing the gate

`CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR` is not a defect: changing what runs on
merge is the operator's decision. For a change, the machine opens the pull request
with the decision in plain words at the top, arms auto-merge, and the operator's
Approve on that head admits it (the finding's detail names the missing
`OPERATOR_APPROVAL_*` conjunct). A control-plane deletion is still merged by an
organization administrator under a ruleset bypass. Every other code is a defect in
the branch: fix it and push.

`GATE_CONFIG_INVALID` likewise needs an operator, and note the shape of it: a
malformed configuration reds every pull request in the repository, and the
repair touches a control-plane path, so the repairing pull request fails the
gate too. An organization administrator merges it under a ruleset bypass. That
is the intended escape hatch, not a deadlock — but it does mean the file is
worth validating before it is merged.

In this repository, a pull request that touches `.github/workflows/**` or `aeos/**`,
including a change to the gate itself, is judged on its content only when an
identified operator authors and runs it, or approves its exact machine-authored
head. Anything else is refused by design.

## Tests

Plain `unittest`; no third-party runner required.

```sh
python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
```

Programme reference: AEOS `AUTONOMOUS-MAIN-2031`.
