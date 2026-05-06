# Architecture

SessionScope is designed around token lifecycle reconstruction:

```text
source files and config
  -> framework/library detectors
  -> auth artifact inventory
  -> lifecycle evidence extraction
  -> risk classification
  -> reports
```

## Components

### 1. Framework and library detectors

Detectors identify auth/session/token APIs in supported languages and frameworks.

Initial detector families:

- cookie-setting APIs
- JWT issue/verify APIs
- session middleware
- password-reset token patterns
- refresh-token stores
- logout/revocation handlers

### 2. Auth artifact inventory

The inventory normalizes discovered artifacts:

- name
- type
- issue location
- validation locations
- storage/transmission method
- expiry evidence
- revocation evidence
- scope/audience/issuer evidence

### 3. Lifecycle evidence extraction

Evidence extractors attach facts to lifecycle stages:

- issue
- store
- transmit
- validate
- refresh
- revoke
- expire

### 4. Risk classifier

The classifier converts missing or weak lifecycle evidence into reviewable findings.

Example categories:

- high_confidence_misconfiguration
- missing_validation_evidence
- lifecycle_gap
- dynamic_review_required
- framework_default_assumed

### 5. Reporters

Reporters should support:

- Markdown
- JSON
- SARIF
- GitHub Actions summary

## Trust boundary

SessionScope should never collect or print real tokens. It analyzes source code and configuration patterns, not production traffic or secret values.
