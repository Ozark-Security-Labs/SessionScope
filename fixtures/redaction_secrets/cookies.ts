// Cookies-domain redaction fixture for F-09.
// Detectors in the cookies domain pass RedactionContext::Cookies into the
// safe-excerpt API, which must strip any string literal longer than 16
// characters even when the surrounding variable name is neutral. This file
// stays under fixtures/ so it is never imported by source/tests but can be
// loaded by detector- and redaction-level integration tests.
const magic_token = "abcDEF12345678901234";
const innocuous = "ok";
document.cookie = `session=${magic_token}; HttpOnly; Secure`;
