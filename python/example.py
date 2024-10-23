import requests
import base64
import time
import json
import uuid
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.IO import PEM


def strToBase64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().replace('=', '')


def jsonToBase64(data: str) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().replace('=', '')


def sign(message: str, private_key_str: str) -> str:
    priv_key = RSA.importKey(private_key_str)
    signature = PKCS1_v1_5.new(priv_key).sign(SHA256.new(message.encode()))
    result = strToBase64(signature)
    return result


def fingerprint(pemPublicKey: str) -> str:
    key = PEM.decode(pemPublicKey)

    h = SHA256.new()
    h.update(key[0])
    return strToBase64(h.digest())


body = {
    'submitId': str(uuid.uuid4()),
    'validityPeriod': 'MONTHS_6',
    'redirectUrl': 'https://www.domain.com/callback',
    'scopes': ['AccountBalance', 'AccountBasicData', 'AccountTransactions', 'FX', 'PaymentGate', 'TransferInitiation'],
}

certFile = open('../qseal.cer', 'r').read()
privKeyFile = open('../qseal.key', 'r').read()
clientCertUrl = '<public_link_to_your_cert>'

thumbprint = fingerprint(certFile)
signHeaders = { 'kid': thumbprint, 'x5u': clientCertUrl, 'x5t#S256': thumbprint, 'alg': 'RS256', 'crit': ["iat"], 'iat': round(time.time()) }

signHeadersBase64 = jsonToBase64(signHeaders)
bodyStr = jsonToBase64(body)
strToSign = signHeadersBase64 + '.' + bodyStr

signatureBase64 = sign(strToSign, privKeyFile)

requestHeaders = { 'Content-Type': 'application/json', 'X-JWS-SIGNATURE': signHeadersBase64 + '..' + signatureBase64 }

try:
    response = requests.post('https://tpp.walutomat.dev/api/v3/consent/create', json=body, cert=('../qseal.cer', '../qseal.key'), headers=requestHeaders)

    print(response.text)
    
except Exception as e:
    print(e)