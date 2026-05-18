# Releasing SessionScope

This runbook cuts a new SessionScope GitHub Release. End-user artifact
verification instructions live in
[docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md).

SessionScope uses a semi-manual release flow:

1. `cargo release` creates a local version-bump commit and local `vX.Y.Z` tag.
2. The release commit moves through a protected-branch PR.
3. After merge, the maintainer pushes the tag.
4. `.github/workflows/release.yml` builds artifacts, checksums, provenance, and
   the GitHub Release.

Release tags are part of the release authorization boundary. The repository
must have an active GitHub ruleset named `Protect release tags` that protects
`refs/tags/v*` before any release tag is pushed.

## One-time setup

```sh
cargo install cargo-release
gh auth status
```

For post-release provenance checks, install `slsa-verifier` from the upstream
release page or with Go:

```sh
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

## First release: v0.1.0

The first packaged release is special because the workspace version is already
`0.1.0`. Do not run `cargo release patch` to create `v0.1.0`; it would bump to
`0.1.1`.

Before tagging:

- `main` is green on the Rust, security, docs, dependency determinism, and
  release-relevant workflows.
- You are on an up-to-date `main`: `git switch main && git pull --ff-only`.
- The working tree is clean.
- `CHANGELOG.md` has accurate user-facing notes under `## 0.1.0 - YYYY-MM-DD`.
- `refs/tags/v*` is protected by an active repository ruleset.
- No PR is mid-merge.

Create and push the first tag only after those checks are true:

```sh
git tag -a v0.1.0 -m "Release v0.1.0"

ruleset_name=""
while IFS= read -r ruleset_id; do
  candidate="$(gh api "repos/Ozark-Security-Labs/SessionScope/rulesets/${ruleset_id}" \
    --jq 'select(.name == "Protect release tags" and .target == "tag" and .enforcement == "active" and ((.conditions.ref_name.include // []) | index("refs/tags/v*"))) | .name')"
  if [ -n "${candidate}" ]; then
    ruleset_name="${candidate}"
    break
  fi
done < <(gh api repos/Ozark-Security-Labs/SessionScope/rulesets \
  --jq '.[] | select(.target == "tag" and .enforcement == "active") | .id')
test "${ruleset_name}" = "Protect release tags"

git merge-base --is-ancestor v0.1.0 main \
  && echo "tag commit reachable from main" \
  || { echo "tag commit is not reachable from main"; exit 1; }

git push origin v0.1.0
```

The tag push triggers the release workflow for
`Ozark-Security-Labs/SessionScope`.

## Future releases

For releases after `v0.1.0`, use `cargo-release`.

## Pre-flight

- `main` is green on the Rust, security, docs, dependency determinism, and
  release workflows.
- You are on an up-to-date `main`: `git switch main && git pull --ff-only`.
- The working tree is clean.
- `CHANGELOG.md` has accurate user-facing notes under `## Unreleased`.
- `refs/tags/v*` is protected by an active repository ruleset.
- No PR is mid-merge.

Move the changelog entries into the release section before running
`cargo-release`:

```sh
VERSION=0.1.1
DATE=$(date +%F)

# Edit CHANGELOG.md so it contains an empty "## Unreleased" section followed by:
# ## ${VERSION} - ${DATE}
```

## Dry-run

```sh
cargo release patch --dry-run
```

Use `minor` or `major` instead of `patch` when the release scope requires it.
Read the version bump, commit message, and tag name before continuing.

## Cut the local release commit and tag

```sh
cargo release patch --execute
```

The release config runs `cargo test --workspace --locked`, bumps the shared
workspace version, commits `chore: release X.Y.Z`, and creates local tag
`vX.Y.Z`. It does not push and does not rewrite `CHANGELOG.md`.

## Move the release commit through a PR

```sh
VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)

git branch "release/v${VERSION}"
git reset --hard origin/main
git switch "release/v${VERSION}"
git push -u origin "release/v${VERSION}"

gh pr create --base main --head "release/v${VERSION}" \
  --title "chore: release ${VERSION}" \
  --body "Release commit + local v${VERSION} tag. Merge with a merge commit only. NEVER squash or rebase."
```

Merge the PR with a merge commit only. Never squash or rebase. The local tag
points at the release commit SHA, and that SHA must remain reachable from
`main`.

## Push the tag

After the PR merges:

```sh
git switch main
git pull --ff-only

ruleset_name=""
while IFS= read -r ruleset_id; do
  candidate="$(gh api "repos/Ozark-Security-Labs/SessionScope/rulesets/${ruleset_id}" \
    --jq 'select(.name == "Protect release tags" and .target == "tag" and .enforcement == "active" and ((.conditions.ref_name.include // []) | index("refs/tags/v*"))) | .name')"
  if [ -n "${candidate}" ]; then
    ruleset_name="${candidate}"
    break
  fi
done < <(gh api repos/Ozark-Security-Labs/SessionScope/rulesets \
  --jq '.[] | select(.target == "tag" and .enforcement == "active") | .id')
test "${ruleset_name}" = "Protect release tags"

git merge-base --is-ancestor "v${VERSION}" main \
  && echo "tag commit reachable from main" \
  || { echo "tag commit is not reachable from main"; exit 1; }

git push origin "v${VERSION}"
```

The tag push triggers the release workflow.

## Watch and verify

Watch the release workflow:

```sh
gh run watch -R Ozark-Security-Labs/SessionScope
```

After the release publishes, verify at least one binary archive:

```sh
TAG=v0.1.0
HOST=x86_64-unknown-linux-gnu
gh release download "$TAG" -R Ozark-Security-Labs/SessionScope \
  -p '*.tar.gz' -p '*.zip' -p '*.sha256' -p '*.intoto.jsonl'

sha256sum --check "sessionscope-${TAG#v}-${HOST}.tar.gz.sha256"

slsa-verifier verify-artifact \
  --provenance-path "sessionscope-${TAG#v}.intoto.jsonl" \
  --source-uri github.com/Ozark-Security-Labs/SessionScope \
  --source-tag "$TAG" \
  "sessionscope-${TAG#v}-${HOST}.tar.gz"
```

Unpack one platform archive and run:

```sh
sessionscope --help
sessionscope version
```

## Rollback

If the tag points at the wrong commit or the release artifacts are bad:

```sh
git tag -d vX.Y.Z
git push --delete origin vX.Y.Z
gh release delete vX.Y.Z -R Ozark-Security-Labs/SessionScope --cleanup-tag --yes
```

Do not reuse a version number once users may have downloaded it. Cut the next
patch version after fixing the issue.
