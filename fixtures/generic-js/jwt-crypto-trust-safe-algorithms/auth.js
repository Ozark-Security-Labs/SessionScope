const jwt = require("jsonwebtoken");

const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";
const ISSUER = "https://placeholder.issuer.invalid";
const AUDIENCE = "placeholder-service";

function verifyAccessJwt(token) {
  return jwt.verify(token, JWT_SECRET, {
    algorithms: ["HS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
    ignoreNotBefore: false,
  });
}

module.exports = { verifyAccessJwt };
