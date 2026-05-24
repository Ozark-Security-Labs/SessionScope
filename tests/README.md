# Integration Tests

Workspace-level integration scenarios should live here when they need to scan
fixture repositories or compare multiple output formats. Crate-local unit and
CLI tests should stay next to their crate when possible.

## False-positive fixture contract

Clean baseline fixtures live under `fixtures/*/clean-baseline-*`. Their
`expected_findings` arrays are intentionally empty, and the fixture harness
asserts that scanning each clean baseline produces no findings. These fixtures
provide the cumulative false-positive guard for every v0.2 P1-P4 check ID.

## JSON snapshots

Canonical JSON report snapshots live in `tests/integration/snapshots/` and are
checked by the hand-rolled `sessionscope-testing` integration test. Regenerate
them after intentional report-output changes with:

```bash
SESSIONSCOPE_UPDATE_JSON_SNAPSHOTS=1 cargo test -p sessionscope-testing --test json_snapshots
```

