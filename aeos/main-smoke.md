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
    secrets:
      AEOS_REVERT_APP_PRIVATE_KEY: ${{ secrets.AEOS_REVERT_APP_PRIVATE_KEY }}
```

A caller is unavoidable: GitHub has no required-workflow equivalent for `push`,
so each repository must opt in with these lines. Keep them exactly this size.

The secret is passed **by name rather than with `secrets: inherit`**. Be clear
about what that does and does not achieve. It does **not** reduce the key's
exposure: the organization secret has All-repositories visibility, so any
workflow in any organization repository can already read it, with or without this
rail. What the explicit form does is stop this reusable workflow receiving every
unrelated secret the adopting repository holds, and make the dependency visible
in the caller instead of implicit. That is hygiene, not mitigation.

The secret is optional. Omit the `secrets:` block entirely and the smoke still
runs and still reports; only the automatic revert is unavailable, and it says so
with a typed `AUTOREVERT_AUTH_UNAVAILABLE` rather than failing quietly.

### Before adopting, in this order

1. **`aeos-merge-ready` must already be required on the repository.** Not a
   preference — a precondition. The revert is an ordinary pull request with
   `--auto --squash` armed, so on a repository with no required checks it merges
   **immediately and unjudged**. "The default branch is never pushed directly"
   then becomes a distinction without a difference: the net effect is an
   automated, unreviewed write to the default branch. Adopt the rail only where
   the gate already covers the repository.
2. **Squash auto-merge must be enabled** in repository settings, or arming fails
   and the revert pull request sits open unattended (reported red).
3. **The revert App must be installed** on the repository.
4. **Then** add the caller above, naming the branch you actually push to.

## The three outcomes

| Outcome | Meaning | Exit |
| --- | --- | --- |
| `PASS` | every check ran to completion and passed | 0 |
| `CODE_FAILURE` | a check ran and reported a defect, and nothing was prevented from running | 1 |
| `INFRA_UNAVAILABLE` | a check could not be executed at all | 3 |

`INFRA_UNAVAILABLE` on one commit is **never** evidence about the code. A
runner, network or tooling outage produces infrastructure health evidence and
stops. It never drives a revert, and it must never be read as a bad commit. It
is still **red**: withholding the revert is not the same as hiding the failure.
The same reason on the next commit is another matter: see
[A repeated outage](#a-repeated-outage).

The outage signatures — `Could not resolve host`, `connection reset by peer`,
`503` — are read on a failing **setup** step only, and there they only add a
note to the step's detail. A failing declared command is `CODE_FAILURE` whatever
it prints. Its output is the repository's own text: on 2026-10-14 a pytest
collection listing printed test ids containing `Could not resolve host` and
`API rate limit exceeded`, sixteen merges in a row read as an outage, and the
breaker never ran for about 17 hours. The operator decided this on 2026-10-15.

The old reading guarded against the opposite mistake, a network failure inside a
test reverting an innocent commit. The parent smoke still guards against it: it
runs alongside the confirm run, and a failure the parent shares is inherited,
never reverted. What remains is an outage that breaks the first and confirm runs
but clears before the parent smoke. That is the trade this rule accepts.

The classification is structural rather than heuristic: each check declares what
"could not run" means for it versus what "ran and found a defect" means. A run
with *any* infrastructure failure is `INFRA_UNAVAILABLE` even when another check
reported a defect — a degraded measurement is not a confirmation.

## What gets smoked

Two things, and they **add up** rather than replacing one another:

1. **The language floor**, derived from the merged SHA. Where the repository has
   Python, that is `compileall` plus `ruff --select E9,F63,F7,F82` — the subset
   that says the code cannot work, not that it is styled differently. Its checks
   are named `floor:compile` and `floor:ruff`.
2. **`.github/aeos-smoke.json`**, where the repository names its own commands.

A declaration used to *replace* the floor, so an adopter who declared a smoke
silently lost it unless they happened to re-declare it themselves — ending up
with less checking than doing nothing, while believing they had added a smoke.
The floor now runs alongside a declaration. Removing it takes an explicit
`"language_floor": false`, in a field named for what it does.

Where the repository declares nothing, the floor is joined by the derived Node
default: `npm test`, and only where a `test` script actually exists. That one is
a test runner rather than a floor, so a declaration does replace it — if you are
naming your own commands, you are already saying how your tests run.

If neither applies, the outcome is **`NO_SMOKE_DEFINED`** — a PASS with an
explicit note and a `source` job output of `none`.

Be precise about what that last case means. It is not "this repository has no
tests"; it is **"this rail found nothing it could run"**. The floor covers Python
only, so a Go, Rust, Java or Terraform repository is permanently green until it
declares a smoke. And a declared `{"name": "noop", "run": "true"}` is a
legitimate, permanent, un-flaggable green too.

The guarantee this rail offers is *"a repository that honestly declares its
smoke gets reverted when that smoke breaks"* — never *"a bad commit gets
reverted"*. A green here is a statement about what ran, not about the code.

Vendored and generated trees (`node_modules`, `vendor`, `.venv`, `build`, …) are
excluded from the floor, which is also scoped to the files tracked at the SHA.
A syntax floor that fails on a checked-in dependency, or on something a `setup`
step generated into the checkout, is reporting on code the commit did not
contain — and on this rail, that would drive a revert.

### Your commands run in your repository's context

The rail does not impose its own interpreter settings on what it runs. In
particular `PYTHONSAFEPATH`, which protects the trusted policy interpreter from
a repository shadowing a stdlib name, is **not** visible to repository commands:
a module executed as a script importing a sibling by name is ordinary in a
repository's own context, and inheriting that setting turned healthy
repositories' first post-main run into a `ModuleNotFoundError` that said nothing
about their code. Nothing is set job-wide; the hardening is applied to the policy
steps only. You should not need `env -u` anything.

### `.github/aeos-smoke.json`

```json
{
  "schema_version": "1",
  "timeout_seconds": 600,
  "language_floor": true,
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
  under test. A **`commands`** failure is `CODE_FAILURE`, whatever it prints.
- The floor's own `ruff` install is *best effort*: if it fails it leaves a note
  rather than an outcome. `compileall` needs no install, and if `ruff` turns out
  to be on the runner anyway the floor simply runs. Only `floor:ruff` reporting
  `TOOL_MISSING:ruff` makes the run `INFRA_UNAVAILABLE` — the check that could
  not run says so itself, rather than a provisioning step deciding it on the
  check's behalf.
- `"language_floor": false` removes the derived floor. It must be a literal
  `true` or `false` — `"false"` and `0` are refused rather than read as truthy,
  because those are exactly the values someone reaches for when they mean the
  opposite. Say plainly what it gives up: the repository keeps only the commands
  it declares, so a syntax error or an undefined name in a file no declared
  command imports will not be caught here.
- The file is **control plane**, on both sides. The merge gate refuses a pull
  request that changes it, and the breaker never auto-reverts a commit that
  touched it — a rail that can revert its own configuration can disable itself.

## The circuit breaker

On `CODE_FAILURE`, and on `INFRA_UNAVAILABLE` so that a repeated outage can be
seen (an outage on one commit still never reverts anything):

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
| `INFRA_UNAVAILABLE` | an outage on this commit alone is never code evidence |
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

### A repeated outage

The same `INFRA_UNAVAILABLE` reason on this commit and on its parent is not an
outage, and the breaker judges it as `CODE_FAILURE` (operator decision,
2026-10-15). When the first run and the parent run meet all of these, `decide`
promotes both, and promotes the confirm run against the parent on the same
terms:

- are `INFRA_UNAVAILABLE` for two different commits, and each proved which commit
  it measured;
- ran the same smoke plan;
- report exactly the same set of INFRA `(check id, reason)` pairs.

Each of those checks becomes `CODE_FAILURE` with the reason
`REPEATED_INFRA:<reason>`, the signature is rebuilt, and the decision records the
pairs as `repeated_infra`. Every conjunct above then applies unchanged:

- **The repeat alone never reverts the later commit.** The parent fails the same
  way by definition, so once the rerun reproduces it and the push is one squash
  commit, the decision is `INHERITED_FAILURE_NOT_ORIGIN`; an earlier stop, such as
  a rerun that passed, wins as before. The commit that introduced the condition
  is the one to fix; its own run saw it once and stayed `INFRA_UNAVAILABLE`.
- **A repeated outage no longer hides a real failure.** A check that passes on the
  parent and fails on this commit, beside the same outage on both, is confirmed
  and reverted like any other failure this commit introduced.
- **The confirm run must reproduce it.** A rerun that passes, or hits a different
  outage, promotes nothing into a revert.

The previous commit is measured by the parent smoke, a few minutes after the
first run, not by that commit's own earlier run, which a caller's `contents: read`
token cannot read. An outage that lasts through both runs is therefore promoted
too; it is typed inherited and reverts nothing. The `main-smoke` job's own
outcome stays `INFRA_UNAVAILABLE`: the promotion is in the decision. On an outage
the rail now also runs the confirm, parent and decide jobs, which it skipped
before.

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
| `aeos-merge-ready` is required on the repository | nothing fails — the revert merges immediately and unjudged (see the adoption order above) |
| the branch pushed to is the one named in the caller | the caller simply never fires |
| the organization's App id and key are visible to it | `AUTOREVERT_AUTH_UNAVAILABLE` — decision recorded, not executed |
| the App is *installed* on the repository | the token mint fails with the action's own error — **not** one of the typed stops |
| squash auto-merge is enabled in repository settings | `AUTOMERGE_ARM_FAILED` — the revert PR is open but nobody is watching it, so it is reported red |

The first row is the one that fails silently rather than loudly, which is why it
is a precondition and not a caveat.

The rail reads the base branch from the push event rather than assuming `main`,
so a repository whose default branch is named something else works, provided its
caller names that branch. The adoption snippet hard-codes `branches: [main]`;
change it if yours differs.

### The credential's blast radius

The organization's App private key has All-repositories visibility. Any workflow
in any organization repository — authored by anyone who can push a branch there
— can read it and exfiltrate it; masking does not survive chunking. **This is a
property of the secret's visibility, not of this rail**, and passing the secret
by name instead of inheriting it does not change it.

What is bounded is the damage: the key mints installation tokens carrying the
App's **installed** permissions, so holding the App to exactly contents and
pull-requests is what bounds the blast radius, and installing it only where the
rail is adopted is what bounds its reach. The real fix is structural — an
organization-side broker that never distributes the key at all — and is an
operator decision, not something this rail can make for itself.

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
