const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const axios = require('axios');

const region = process.env.COGNITO_REGION;
const userPoolId = process.env.COGNITO_USER_POOL_ID;
const cognitoIssuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;

let cacheKeys;

async function getPublicKeys() {
  if (!cacheKeys) {
    const url = `${cognitoIssuer}/.well-known/jwks.json`;
    const { data } = await axios.get(url);
    cacheKeys = data.keys;
  }
  return cacheKeys;
}

async function verifyToken(token) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded) {
    throw new Error('Invalid token');
  }

  const keys = await getPublicKeys();
  const key = keys.find(k => k.kid === decoded.header.kid);
  if (!key) {
    throw new Error('Public key not found');
  }

  const pem = jwkToPem(key);
  return jwt.verify(token, pem, { issuer: cognitoIssuer, algorithms: ['RS256'] });
}

module.exports = { verifyToken };
