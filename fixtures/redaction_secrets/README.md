# Redaction context fixtures (F-09)

These fixtures exercise the context-aware redaction path in
`sessionscope-core::redaction::safe_excerpt_with_context`.

Each file contains a literal that the existing sensitive-name regexes will
not match (the assigned variable name is intentionally neutral) but that the
context-aware literal-stripping pass must redact when a detector indicates a
Cookies, Jwt, Bearer, or ApiKey domain.

The fixtures are intentionally short and do not contain real secrets — the
literal `abcDEF12345678901234` is a structural sample chosen because it is
longer than the 16-character literal-stripping threshold but shorter than the
32-character LONG_TOKEN regex that already redacts high-entropy tokens.
