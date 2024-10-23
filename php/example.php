<?php

function base64url_encode($str) {
    return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
}

function uuid() {
    $data = random_bytes(16);

    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

/**
 * cURL extension is required to be enabled for this function
 */
function httpPost($url, $data, $certPath, $privKeyPath, $headers) {
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_SLASHES));
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_SSLKEY, $privKeyPath);
    curl_setopt($curl, CURLOPT_SSLCERT, $certPath);
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($curl);
    curl_close($curl);

    return $response;
}

$certPath = '../qseal.cer';
$privKeyPath = '../qseal.key';
$clientCertUrl = '<public_link_to_your_cert>';

$cert = file_get_contents($certPath);
$privKey = file_get_contents($privKeyPath);

$thumbprint = base64url_encode(openssl_x509_fingerprint($cert, 'sha256', true));

$signHeaders = [
    'kid' => $thumbprint,
    'x5u' => $clientCertUrl,
    'x5t#S256' => $thumbprint,
    'alg' => 'RS256',
    'crit' => ['iat'],
    'iat' => time(),
];

$signHeadersBase64 = base64url_encode(json_encode($signHeaders, JSON_UNESCAPED_SLASHES));

$payload = [ 
    'submitId' => uuid(),
    'validityPeriod' => 'MONTHS_6',
    'redirectUrl' => 'https://www.domain.com/callback',
    'scopes' => ['AccountBalance', 'AccountBasicData', 'AccountTransactions', 'FX', 'PaymentGate', 'TransferInitiation'],
];

openssl_sign(
    $signHeadersBase64 . '.' . base64url_encode(json_encode($payload, JSON_UNESCAPED_SLASHES)),
    $signature,
    $privKey,
    OPENSSL_ALGO_SHA256
);

$headers = [
    'Content-Type: application/json',
    'X-JWS-SIGNATURE: ' . $signHeadersBase64 . '..' . base64url_encode($signature),
];

$response = httpPost('https://tpp.walutomat.dev/api/v3/consent/create', $payload, $certPath, $privKeyPath, $headers);

var_dump($response);