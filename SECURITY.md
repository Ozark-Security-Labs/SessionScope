# Security Policy

## Intended use

This project is intended for defensive, authorized application and product-security analysis.

Acceptable use includes:

- Reviewing software you own or are authorized to test
- Improving secure code review coverage
- Building CI guardrails
- Generating evidence for human security review
- Producing defensive documentation and test cases

Unacceptable use includes:

- Exploit automation
- Payload generation for attacking live systems
- Unauthorized scanning
- Credential theft or token abuse
- Instructions for bypassing security controls

## Supported versions

SessionScope is early-stage software. Until the first stable release, security
fixes will target the default branch and the latest tagged release, if one
exists.

## Reporting vulnerabilities

If you discover a security issue in SessionScope itself, please open a private
report through GitHub Security Advisories:

https://github.com/Ozark-Security-Labs/SessionScope/security/advisories/new

Do not disclose sensitive customer data, credentials, tokens, exploit payloads,
or detailed bypass instructions in public issues.

## Finding language

This project should report evidence-bound hypotheses unless a finding is mechanically proven. Reports should avoid overstating confidence and should include source evidence and reviewer questions.

## Sensitive test data

Fixtures, tests, reports, and documentation examples must use obvious
placeholders only. Do not add real tokens, API keys, private keys, production
cookies, customer code, or copied vulnerability data to this repository.

## Third-party dependency reviews

Security-relevant manual reviews of transitive crate dependencies are recorded
in [`docs/DEPENDENCY_REVIEW.md`](docs/DEPENDENCY_REVIEW.md). Reviewers should
update that log when introducing, removing, or pinning a sensitive
dependency.
