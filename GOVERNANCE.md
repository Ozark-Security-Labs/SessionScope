# Governance

SessionScope is currently maintained by the repository owner with community
input through issues and pull requests.

## Maintainer Responsibilities

Maintainers are responsible for:

- preserving the project's defensive, authorized-use boundary
- reviewing changes to analyzer behavior, reporting language, and security
  posture
- keeping dependency, CI, and release practices suitable for a security tool
- triaging issues and pull requests according to project priorities
- enforcing the code of conduct

## Decision Making

For now, decisions are made by maintainer consensus, with the repository owner
as final decision maker when consensus is not possible. Major changes should be
discussed in issues before implementation, especially changes to:

- output schema or compatibility
- supported frameworks, parsers, and detector strategy
- classification and risk language
- CI, release, or supply-chain security posture
- project scope and non-goals

## Contribution Path

Contributors should start with focused issues or pull requests that include
tests or fixtures when analyzer behavior changes. New framework or library
detectors should follow the detector contracts documented in the architecture.

## Security Decisions

Security-sensitive reports, potential vulnerabilities in SessionScope, and
maintainer trust concerns should be handled privately first. Public disclosure
should happen only after sensitive details are removed or a fix is available.

