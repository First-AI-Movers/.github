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

### The one residual human gate

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
merge is an operator-governed act. Split the control-plane change into its own
pull request for an organization administrator, who merges it under a ruleset
bypass. Every other code is a defect in the branch — fix it and push.

`GATE_CONFIG_INVALID` likewise needs an operator, and note the shape of it: a
malformed configuration reds every pull request in the repository, and the
repair touches a control-plane path, so the repairing pull request fails the
gate too. An organization administrator merges it under a ruleset bypass. That
is the intended escape hatch, not a deadlock — but it does mean the file is
worth validating before it is merged.

Pull requests against this repository that touch `.github/workflows/**` or
`aeos/**` self-reject by design, including changes to the gate itself.

## Tests

Plain `unittest`; no third-party runner required.

```sh
python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
```

Programme reference: AEOS `AUTONOMOUS-MAIN-2031`.
