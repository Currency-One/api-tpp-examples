#!/usr/bin/env node

const fs = require('fs')
const crypto = require('node:crypto')
const https = require('https')

const certPath = '../qseal.cer'
const privKeyPath = '../qseal.key'
const clientCertUrl = '<public_link_to_your_cert>'

const certPem = fs.readFileSync(certPath).toString()
const privPem = fs.readFileSync(privKeyPath).toString()

const thumbprint = Buffer.from(new crypto.X509Certificate(certPem).fingerprint256.replaceAll(':', ''), 'hex').toString(
  'base64url',
)

const headers = Buffer.from(
  JSON.stringify({
    kid: thumbprint,
    x5u: clientCertUrl,
    'x5t#S256': thumbprint,
    alg: 'RS256',
    crit: ["iat"],
    iat: Math.round(Date.now() / 1000),
  }),
).toString('base64url')

const payload = { 
  submitId: crypto.randomUUID(),
  validityPeriod: 'MONTHS_6',
  redirectUrl: 'https://www.domain.com/callback',
  scopes: ['AccountBalance', 'AccountBasicData', 'AccountTransactions', 'FX', 'PaymentGate', 'TransferInitiation'],
}

var signature = crypto
  .createSign('RSA-SHA256')
  .update(headers + '.' + Buffer.from(JSON.stringify(payload)).toString('base64url'))
  .sign({ key: privPem }, 'base64url')

const options = {
  cert: certPem,
  key: privPem,
  host: 'tpp.walutomat.dev',
  path: '/api/v3/consent/create',
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-JWS-SIGNATURE': `${headers}..${signature}` },
}

const req = https.request(options, (res) => {
  let response = ''
  res.on('data', (chunk) => {
    response += chunk
  })
  res.on('end', () => console.log(response))
})

req.write(JSON.stringify(payload))
req.end()
