# ADR 0010: Protect the Main Branch With a Ruleset

Status: Proposed (2026-10-14), applied only with the owner's approval in chat (AGENTS.md 3.10)

## Context
Audit finding F-PIPE-01 (docs/audit/review-2026-10-14/03-github-pipeline.md): `main` has no branch protection and no ruleset. Nothing requires CI to pass, nothing blocks force-push or deletion, and the evidence files the channel gates trust (release/channels.json, release/legal-review.json) can be rewritten by any direct push. F-PIPE-02: no CODEOWNERS.

The promote workflow's `record` job must keep pushing the promotion record to `main` directly (promote.yml), with the default `GITHUB_TOKEN`, so the ruleset needs exactly one bypass actor: the GitHub Actions app.

## Decision
One repository ruleset named `main` on the default branch:

- Pull request required before merging (the owner merges their own pull requests: zero required approvals, because a solo maintainer cannot approve their own work, and GitHub does not count the author).
- Required status check `ci` (the job in .github/workflows/ci.yml, named `ci`, reported by the GitHub Actions app, integration id 15368), strict (the branch must be up to date).
- Block force pushes (`non_fast_forward`), block deletion, require linear history.
- Bypass list: the GitHub Actions app only (`actor_type: Integration`, `actor_id: 15368`, `bypass_mode: always`). This is how `record` keeps working: a workflow run authenticating with `GITHUB_TOKEN` acts as that app, so `git push origin HEAD:main` from the record job is allowed; every other push to `main` must come through a pull request with `ci` green.
- Not included: `required_signatures`. The record job commits with the default token over git, which produces unsigned commits; requiring signatures would stop every promotion record. Revisit if the record step moves to the GraphQL `createCommitOnBranch` mutation (which yields GitHub-signed commits).
- Not included yet: code owner review. `.github/CODEOWNERS` names the team `@OpenVAPT/maintainers` for the pipeline, safety-boundary and legal paths; the team does not exist yet, so the lines resolve to nobody. When the owner creates the team and gives it Write access, set `require_code_owner_review` to true.

Repository settings that go with it: secret scanning, push protection and Dependabot security updates on; web commit sign-off required (DCO, CONTRIBUTING.md); `sha_pinning_required` on for Actions.

## Ruleset JSON
Save as `ruleset-main.json`:

```json
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 15368, "actor_type": "Integration", "bypass_mode": "always" }
  ],
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["merge", "squash", "rebase"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "ci", "integration_id": 15368 }
        ]
      }
    }
  ]
}
```

## Commands (coordinator, after the owner's yes)
```sh
# 1. Confirm the app id and that no ruleset exists yet
gh api apps/github-actions --jq .id                       # expect 15368
gh api repos/OpenVAPT/openvapt/rulesets                   # expect []

# 2. Create the ruleset
gh api --method POST repos/OpenVAPT/openvapt/rulesets --input ruleset-main.json

# 3. Verify
gh api repos/OpenVAPT/openvapt/rulesets --jq '.[] | {id, name, enforcement}'
gh api repos/OpenVAPT/openvapt/rules/branches/main --jq '.[].type'

# 4. Repository settings (free on public repositories)
gh api --method PATCH repos/OpenVAPT/openvapt \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_non_provider_patterns][status]=enabled'
gh api --method PUT repos/OpenVAPT/openvapt/automated-security-fixes   # Dependabot security updates
gh api --method PATCH repos/OpenVAPT/openvapt -F web_commit_signoff_required=true
gh api --method PUT repos/OpenVAPT/openvapt/actions/permissions \
  -F enabled=true -f allowed_actions=all -F sha_pinning_required=true

# 5. Code owner review, once the team exists and has Write on the repository
#    (Settings > Teams > New team "maintainers"; add the owner; grant Write)
RULESET_ID=$(gh api repos/OpenVAPT/openvapt/rulesets --jq '.[] | select(.name=="main") | .id')
gh api --method PUT "repos/OpenVAPT/openvapt/rulesets/$RULESET_ID" --input ruleset-main.json  # after setting require_code_owner_review to true in the file
```

Update an existing ruleset with `--method PUT repos/OpenVAPT/openvapt/rulesets/<id>`; delete only with the owner's approval (AGENTS.md 3.10).

## Consequences
- Every change to `main` (including the owner's) goes through a pull request with `ci` green: tests, lab proof, DCO trailer check, installer test and the no-data grep all run on the proposed workflow files before they can take effect.
- The record job's direct push still works through the bypass; it is the only path that writes to `main` without a pull request, and it runs only `setup-go` and `go run ./cmd/channel`.
- Any workflow in this repository with `contents: write` could use the same bypass. Today only `record` has it; CODEOWNERS and the pull request rule put every change to `.github/` in front of a reviewer.
- History cannot be rewritten or deleted through the API or git by any user; AGENTS.md 3.3 (no force push, no history rewrite) is now enforced at the technical layer.
- Branch protection rules (the older API at `branches/main/protection`) are not used; rulesets supersede them and support the Integration bypass actor.

## Note (2026-10-14, second verifier)

`required_linear_history` was removed from the ruleset: the project merges work branches with `--no-ff` on purpose (merge commits are the audit trail, and `channel head` reads first-parent history), so a linear-history rule would reject every integration merge. Force pushes and deletions stay blocked.
