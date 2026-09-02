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
| No changed path under `.github/workflows/**` or `.github/actions/**`, and none equal to `.github/aeos-gate.json` | `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR` |
| No high-confidence credential shape in changed text | `SECRET_SHAPE_DETECTED` |
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
- **The file is itself control plane.** A pull request that adds or edits it
  fails with `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR`. An exemption is an
  operator decision by construction — that conjunct is what makes the allowlist
  a decision rather than a self-serve bypass.
- **Present but malformed fails closed** with `GATE_CONFIG_INVALID`. Invalid
  JSON, an unrecognised `schema_version`, or a `secret_shape_allowlist` that is
  not a list of non-empty strings will not silently degrade to "no exemptions".
  Unknown top-level keys are ignored so a newer declaration stays readable.
- **It exempts the secret-shape check and nothing else.** Structured-data
  parsing, the Python syntax floor, and the control-plane check all still apply
  to an allowlisted path.
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
