const jwt = require("jsonwebtoken");

const PUBLIC_KEY = "PLACEHOLDER_PUBLIC_KEY_DO_NOT_USE";
const ISSUER = "https://placeholder.issuer.invalid";
const AUDIENCE = "placeholder-service";

function verifyAccessJwt(token) {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ["none"],
    issuer: ISSUER,
    audience: AUDIENCE,
    ignoreNotBefore: false,
  });
}

module.exports = { verifyAccessJwt };
