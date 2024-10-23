#!/bin/bash

CERT="../qseal.cer"
KEY="../qseal.key"

# https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5
CERT_URL=<public_link_to_your_cert>

# https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8
THUMBPRINT=$(openssl x509 -in ${CERT} -fingerprint -noout -sha256 | sed 's/sha256 Fingerprint=//gi' | sed 's/://g' | xxd -r -p | openssl enc -a | tr -d '=' | tr '/+' '_-')

# https://datatracker.ietf.org/doc/html/rfc7515#section-4
ISSUED_AT=$(date +%s)
HEADER_RAW='{"alg":"RS256","kid":"'"${THUMBPRINT}"'","x5u":"'"${CERT_URL}"'","x5t#S256":"'"${THUMBPRINT}"'","crit":["iat"],"iat":'"${ISSUED_AT}"'}'
HEADER=$( echo -n "${HEADER_RAW}" | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )

UUID=uuidgen
PAYLOAD_RAW='{"submitId":"'"${UUID}"'","validityPeriod":"MONTHS_6","redirectUrl":"https://www.domain.com/callback","scopes":["AccountBalance","AccountBasicData","AccountTransactions","FX","PaymentGate","TransferInitiation"]}'
PAYLOAD=$( echo -n "${PAYLOAD_RAW}" | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )

HEADER_PAYLOAD="${HEADER}"."${PAYLOAD}"
SIGNATURE=$(echo -n "${HEADER_PAYLOAD}" | openssl dgst -sha256 -sign ${KEY} | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )

JWT="${HEADER}".."${SIGNATURE}"

curl -H "X-JWS-SIGNATURE: $JWT" -X POST -d "${PAYLOAD_RAW}" --key ${KEY} --cert ${CERT} https://tpp.walutomat.dev/api/v3/consent/create
