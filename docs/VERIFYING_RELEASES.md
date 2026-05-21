# Verifying SessionScope Releases

SessionScope release artifacts include SHA-256 sidecars, a CycloneDX SBOM,
and SLSA provenance. Use them together before trusting a downloaded binary
in a sensitive environment.

## What verification covers

SLSA verification confirms that an artifact digest appears in a Sigstore-signed
attestation for:

- source repo `github.com/Ozark-Security-Labs/SessionScope`;
- source tag `vX.Y.Z`;
- the release workflow at that tag; and
- GitHub Actions workflow identity recorded in the attestation.

It does not prove the source code is bug-free or that a scan result is a
confirmed vulnerability.

The release pipeline additionally runs a reproducible-build verification job
that produces the release binary twice on a single Linux runner (cold and warm
`target/`) under a stable `SOURCE_DATE_EPOCH` derived from the tagged commit
timestamp. The job fails the release if the two builds do not match
byte-for-byte, so the published Linux artifact has been shown to reproduce
deterministically at release time.

## Install tools

Install `gh` and `slsa-verifier`. One option for `slsa-verifier` is:

```sh
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

## Verify checksums

```sh
TAG=v0.1.0
HOST=x86_64-unknown-linux-gnu

gh release download "$TAG" -R Ozark-Security-Labs/SessionScope \
  -p '*.tar.gz' -p '*.zip' -p '*.sha256' -p '*.intoto.jsonl'

sha256sum --check "sessionscope-${TAG#v}-${HOST}.tar.gz.sha256"
```

For macOS or Windows archives, check the matching
`sessionscope-${TAG#v}-...` `.sha256` file for your platform.

## Verify SLSA provenance

```sh
slsa-verifier verify-artifact \
  --provenance-path "sessionscope-${TAG#v}.intoto.jsonl" \
  --source-uri github.com/Ozark-Security-Labs/SessionScope \
  --source-tag "$TAG" \
  "sessionscope-${TAG#v}-${HOST}.tar.gz"
```

A successful run ends with `PASSED: SLSA verification passed`.

## Validate the CycloneDX SBOM

Each release publishes a CycloneDX 1.x JSON SBOM that lists the Rust crates
linked into the released `sessionscope` CLI binary. The SBOM is attached to the
GitHub Release as `sessionscope-${TAG#v}.cdx.json` with a matching
`.sha256` sidecar.

```sh
gh release download "$TAG" -R Ozark-Security-Labs/SessionScope \
  -p '*.cdx.json' -p '*.cdx.json.sha256'

sha256sum --check "sessionscope-${TAG#v}.cdx.json.sha256"
```

Validate it parses as CycloneDX JSON and inspect components:

```sh
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); \
  assert d.get("bomFormat") == "CycloneDX"; \
  print("components:", len(d.get("components", [])))' \
  "sessionscope-${TAG#v}.cdx.json"
```

Optionally diff SBOMs between releases to see dependency changes:

```sh
jq -S '.components | map({name,version}) | sort_by(.name)' \
  "sessionscope-${TAG#v}.cdx.json" \
  > "sessionscope-${TAG#v}.components.json"
```

Tools that consume CycloneDX (such as `osv-scanner` or `grype`) can scan the
SBOM directly for known advisories against the recorded dependency versions.

## Smoke test the binary

Unpack the archive for your platform and run:

```sh
./sessionscope --help
./sessionscope version
```

On Windows, run `sessionscope.exe --help` and `sessionscope.exe version` from
the expanded archive.

If checksum or SLSA verification fails, do not run the artifact. Open an issue
with the verifier output.
