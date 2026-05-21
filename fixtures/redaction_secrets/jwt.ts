// JWT-domain redaction fixture for F-09. See cookies.ts for the rationale.
const magic_token = "abcDEF12345678901234";
jwt.sign({ sub: "u" }, magic_token);
