# `aeos-main-smoke` — the post-main rail

What happens *after* a squash lands:

```
merge → smoke the exact merged SHA → PASS | CODE_FAILURE | INFRA_UNAVAILABLE
```

Implemented by the reusable workflow
[`.github/workflows/aeos-main-smoke.yml`](../.github/workflows/aeos-main-smoke.yml)
and the modules beside this file. Nothing in it waits on anything.

## Adopting it

Add this file to your repository as `.github/workflows/main-smoke.yml`. That is
the whole integration — every decision lives in the reusable workflow on `main`,
so the rail can be changed in one place instead of in every repository that
adopted it.

```yaml
name: main-smoke
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  smoke:
    uses: First-AI-Movers/.github/.github/workflows/aeos-main-smoke.yml@main
    secrets: inherit
```

A caller is unavoidable: GitHub has no required-workflow equivalent for `push`,
so each repository must opt in with these lines. Keep them exactly this size.

`secrets: inherit` passes the organization's revert credentials through. Without
it the smoke still runs and still reports; only the automatic revert is
unavailable, and it says so in a typed way rather than failing quietly.

## The three outcomes

| Outcome | Meaning | Exit |
| --- | --- | --- |
| `PASS` | every check ran to completion and passed | 0 |
| `CODE_FAILURE` | a check ran and reported a defect, and nothing was prevented from running | 1 |
| `INFRA_UNAVAILABLE` | a check could not be executed at all | 3 |

`INFRA_UNAVAILABLE` is **never** evidence about the code. A runner, network or
tooling outage produces infrastructure health evidence and stops. It never
drives a revert, and it must never be read as a bad commit. It is still **red**:
withholding the revert is not the same as hiding the failure.

A failing command whose output carries an outage signature — `Could not resolve
host`, `connection reset by peer`, `503` — is reclassified from `CODE_FAILURE`
to `INFRA_UNAVAILABLE`. That text is repository-controlled, so a repository
could in principle print it deliberately and never be auto-reverted. This is a
deliberate bias and the trade is worth stating plainly: the alternative is that
a transient network failure inside a test, reproducing on the confirm run,
auto-reverts an innocent commit. A false revert is a destructive autonomous act;
evasion only returns the repository to where it was before the rail existed, with
its `main` still visibly red.

The classification is structural rather than heuristic: each check declares what
"could not run" means for it versus what "ran and found a defect" means. A run
with *any* infrastructure failure is `INFRA_UNAVAILABLE` even when another check
reported a defect — a degraded measurement is not a confirmation.

## What gets smoked

Derived from the merged SHA, in order:

1. **`.github/aeos-smoke.json`** — the repository names its own commands.
2. **Language defaults** — for Python, a syntax and undefined-name floor
   (`compileall`, plus `ruff --select E9,F63,F7,F82`); for Node, `npm test`, and
   only where a `test` script actually exists.
3. **Neither** — `NO_SMOKE_DEFINED`, reported as a **PASS with an explicit
   note** and a `source` job output of `none`.

Be precise about what the third case means. It is not "this repository has no
tests"; it is **"this rail could not derive a smoke"**. Derivation covers Python
and Node-with-a-`test`-script only, so a Go, Rust, Java, Ruby or Terraform
repository with a full suite lands here and is permanently green until it
declares a smoke. And a declared `{"name": "noop", "run": "true"}` is a
legitimate, permanent, un-flaggable green too.

The guarantee this rail offers is *"a repository that honestly declares its
smoke gets reverted when that smoke breaks"* — never *"a bad commit gets
reverted"*. A green here is a statement about what ran, not about the code.

Vendored and generated trees (`node_modules`, `vendor`, `.venv`, `build`, …) are
excluded from the defaults. A syntax floor that fails on a checked-in dependency
is reporting on somebody else's code — and on this rail, that would drive a
revert.

### `.github/aeos-smoke.json`

```json
{
  "schema_version": "1",
  "timeout_seconds": 600,
  "setup":    [{ "name": "deps", "run": "pip install -r requirements.txt" }],
  "commands": [{ "name": "unit", "run": "python3 -m pytest -q tests/smoke" }]
}
```

- **Absent is normal** and means "fall back to the defaults".
- Read **content-addressed from the merged SHA**, never from the working tree.
  (The *checks* themselves necessarily run in a working tree; the derived ones
  are scoped to the files tracked at that SHA, so a dependency tree a `setup`
  step generated into the checkout is never mistaken for the commit's own code.)
- **Present but malformed** is a typed `SMOKE_CONFIG_INVALID`, never a silent
  fallback: quietly reverting to defaults would change what a rail enforces
  without anyone deciding to.
- A **`setup`** failure is `INFRA_UNAVAILABLE` — provisioning is not the subject
  under test. A **`commands`** failure is `CODE_FAILURE`.
- The file is **control plane** to the breaker: a commit that touched it is
  never auto-reverted, because a rail that can revert its own configuration can
  disable itself. Adding it to the merge gate's control-plane set, so that
  changing it also needs an operator on the way in, is a one-line follow-up
  tracked against the gate.

## The circuit breaker

On `CODE_FAILURE` only, and never on an outage:

1. **confirm** — rerun the identical smoke on the identical SHA in a fresh runner;
2. **parent-smoke** — smoke the parent (`before`), so an inherited failure is
   never attributed to an innocent later squash;
3. **decide** — deterministic and typed, with no model.

A revert happens only when **all** of these hold: both signatures are identical,
the SHA is exactly one single-parent commit over `before`, the parent does not
fail the same way, and no protected control-plane path changed.

| Decision | Meaning |
| --- | --- |
| `REVERT` | every conjunct held |
| `PASS_NOTHING_TO_DO` | the first smoke passed |
| `INFRA_UNAVAILABLE` | an outage is never code evidence |
| `NOT_CONFIRMED_FLAKY` | the rerun passed, or failed differently |
| `ORIGIN_UNPROVEN` | no usable parent evidence |
| `INHERITED_FAILURE_NOT_ORIGIN` | the parent already fails this way |
| `REVERT_ATTRIBUTION_AMBIGUOUS` | `before..sha` is not exactly one single-parent commit |
| `CONTROL_PLANE_REVERT_REQUIRES_OPERATOR` | the commit touched a protected path |
| `SMOKE_EVIDENCE_INVALID` | an evidence file is malformed or for another SHA |

Origin is decided by the failing **check ids**, not by whole-signature equality
and not by the failure's reason. On an already-red branch, a later commit that
adds no newly failing check is inheriting the failure even though its signature
differs — a commit is the origin only of the checks it *newly broke*. Comparing
reasons instead would make a merely shifted exit code (pytest reports 1 for
failures and 2 when the same broken suite is interrupted) look like a failure
this commit introduced, and revert a commit that introduced nothing.

Two further conditions guard the comparison, because a baseline is only a
baseline if it measured the same thing:

- if the parent ran a **different smoke plan** — the commit added the first
  Python file, or a `test` script, or changed the declaration — there is no
  comparison, and the decision is `ORIGIN_UNPROVEN`;
- if a newly failing check has **no baseline on the parent at all**, the same.
  A check the parent never ran cannot be shown to have been broken here rather
  than to have been broken all along. This is also the path a newly added test
  takes when a reproducing transient breaks it.

A known asymmetry: because `items` are in the signature but not in the failing
set, once a branch is red on a check no later commit can be auto-reverted for a
*new* failure of that same check. One un-revertible red disarms that check class
until it is fixed. The rail biases towards not acting.

The **signature** is built only from identifiers that are stable across two runs
of the same commit — check id, typed reason, and sorted findings where a tool
emits structured ones. Raw process output never contributes: a timestamp or a
temporary path in a signature would make every failure look flaky, and the rail
would never fire.

### Executing a revert

The revert is an **ordinary pull request**: a branch, squash auto-merge armed,
judged by the required `aeos-merge-ready` gate like anything else. The default
branch is **never** pushed directly. A revert that does not apply cleanly is the
typed hard stop `REVERT_CONFLICT` — no branch, no pull request, no guess.

Repository commands run with the runner's credentials and its *file command*
variables (`GITHUB_OUTPUT`, `GITHUB_ENV`, `GITHUB_PATH`, …) stripped from their
environment, and each runs in its own process group that is torn down when it
returns or times out — otherwise a command could background a writer that
outlives the measurement and rewrite the result afterwards.

Neither is load-bearing on its own. Stripping a variable does not hide the file
it names, which is reachable from `RUNNER_TEMP`; a smoke command is running
arbitrary code and will always be able to write anywhere the job can. So the
**outcome published to the breaker is derived from the gate's exit code**, which
repository content cannot reach, and the outcome file is then required to agree
with it. A disagreement is reported as `EVIDENCE_MISMATCH` and makes no code
claim at all. The file is corroborating evidence; it is never the verdict.

Credentials are a short-lived GitHub App installation token minted at runtime
and scoped to **contents: write + pull-requests: write** only. There is
deliberately no fallback to `GITHUB_TOKEN`: a pull request opened with it fires
no `pull_request` workflow, so the required gate could never report on the
revert. Missing credentials are `AUTOREVERT_AUTH_UNAVAILABLE`; an unresolvable
App bot identity is `AUTOREVERT_IDENTITY_UNAVAILABLE` — an unattributed commit
trips the organization ruleset's extra-approval rule, so its auto-merge would
never fire. Both are typed, fail closed, and record the decision without acting
on it.

## Assumptions a repository must meet

The rail is repository-agnostic about *content* — a repository with no tests
passes — but adopting it does assume four things about the repository's GitHub
configuration. Each one degrades to a typed red rather than to a silent green:

| Assumption | If unmet |
| --- | --- |
| the branch pushed to is the one named in the caller | the caller simply never fires |
| the organization's App id and key are visible to it | `AUTOREVERT_AUTH_UNAVAILABLE` — decision recorded, not executed |
| the App is *installed* on the repository | the token mint fails with the action's own error — **not** one of the typed stops |
| squash auto-merge is enabled in repository settings | `AUTOMERGE_ARM_FAILED` — the revert PR is open but nobody is watching it, so it is reported red |

The rail reads the base branch from the push event rather than assuming `main`,
so a repository whose default branch is named something else works, provided its
caller names that branch. The adoption snippet hard-codes `branches: [main]`;
change it if yours differs.

### Two things adoption should be decided on, not discovered

**The revert pull request is only *judged* where the required `aeos-merge-ready`
gate covers the repository.** Where it does not, `--auto --squash` on a
repository with no required checks merges the revert **immediately**. "The
default branch is never pushed directly" is then a distinction without a
difference: the net effect is an automated, unreviewed write to the default
branch. Adopt the rail on repositories the gate covers, or accept that.

**`secrets: inherit` means the organization's App private key is visible to the
repository.** Once an organization secret is visible to a repository, any
workflow in it — authored by anyone who can push a branch there — can read that
secret and exfiltrate it; masking does not survive chunking. The key is
long-lived and mints installation tokens carrying the App's **full installation
permissions on every repository the App is installed on**. Scoping *this*
token to contents + pull-requests narrows the token, not the key. So the honest
statement of the credential's blast radius is: **adoption grants every committer
on the adopting repository the App's org-wide write capability.** Hold the App's
own installation permissions to exactly contents + pull-requests, install it
only where the rail is adopted, and treat a broader structural fix — an
organization-side dispatch or broker that never distributes the key — as the
real answer.

## Attribution safety

`concurrency` is keyed **per SHA** and **never cancels**. An older run cancelled
because a newer merge landed would make that squash unattributable, which is the
one thing this rail cannot afford.

## Tests

Plain `unittest`; no third-party runner required.

```sh
python3 -m unittest discover -s aeos/tests -p 'test_*.py' -v
```

Programme reference: AEOS `AUTONOMOUS-MAIN-2031`.
