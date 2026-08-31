# First-AI-Movers/.github

This repository holds the GitHub organization profile for **First AI Movers**.

The displayed content is in [`profile/README.md`](./profile/README.md), which GitHub renders at the top of <https://github.com/First-AI-Movers>.

For canonical company information, see:

- Company website: <https://www.firstaimovers.com>
- GitHub Pages bridge: <https://first-ai-movers.github.io/>

## Organization-wide defaults

GitHub applies the files below to any **public** `First-AI-Movers/*` repository that does **not** ship its own copy. A repository's own file always overrides the default.

**Private and internal repositories inherit nothing.** GitHub's default community-health mechanism covers public repositories only. Most First-AI-Movers repositories are private, so for most of the organization these files are a *reference* to adopt deliberately, not a default that arrives on its own. To check the split for yourself:

```bash
gh api orgs/First-AI-Movers/repos --paginate --slurp \
  | jq '[.[][] | .visibility] | group_by(.) | map({(.[0]): length}) | add'
```

| File | Applies when a repository has no own copy |
|---|---|
| [`SECURITY.md`](./SECURITY.md) | how to report a vulnerability privately |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | how a change reaches a default branch |
| [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) | Contributor Covenant v2.1, org enforcement contact |

## Adoption and onboarding contract

The canonical, client-neutral contract for standing up a new repository — or aligning an existing one — is the **GitHub-native adoption kit** at [`First-AI-Movers/agent-toolkit` → `templates/github-native/`](https://github.com/First-AI-Movers/agent-toolkit/tree/main/templates/github-native). **`agent-toolkit` is private**, so this link resolves for organization members and returns `404` to everyone else. This repository is public; that one is not.

It is projection-only: it grants no authority, mutates no ruleset, and installs no GitHub App. Repository class and sensitivity are owned by the federation registry and mirrored one-way onto GitHub organization properties — GitHub is never written back into the registry.

This repo intentionally stays minimal — it holds organization defaults and profile metadata only. It does not host code, workflows, or templates.
