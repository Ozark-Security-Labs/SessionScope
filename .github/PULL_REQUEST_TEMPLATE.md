## Summary

Describe what changed and why.

## Type of change

- [ ] Documentation
- [ ] CLI or packaging
- [ ] Detector or lifecycle extraction
- [ ] Evidence model or schema
- [ ] Reporting or classification
- [ ] CI, security, or release

## Defensive-use check

- [ ] This change does not add exploit automation, payload generation, credential theft, bypass instructions, or unauthorized live-system scanning.
- [ ] Findings and reporting language remain evidence-bound and do not overstate certainty.
- [ ] Any test fixtures are sanitized and do not include real credentials, tokens, customer data, or production configuration.

## Testing

List the checks you ran.

```text
cargo test --workspace --all-targets
```

## Notes for reviewers

Call out schema changes, compatibility concerns, new dependencies, or areas where reviewer attention would help.

