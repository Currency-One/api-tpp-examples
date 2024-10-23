package com.example;

import java.nio.file.Files;
import java.nio.file.Path;
import java.net.URL;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.Security;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.UUID;
import java.util.ArrayList;
import java.time.Instant;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Example {
    private static String readFileContent(String path) throws IOException {
        return Files.readString(Path.of(path));
    }

    private static String getThumbprint(String cert)
    throws CertificateException, NoSuchAlgorithmException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getBytes()));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] thumbprint = md.digest(x509Cert.getEncoded());

        return Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprint);
    }

    private static byte[] privateKeyBytes(String privKey) {
        String privKeyBase64 = privKey
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll("\\n", "")
            .replace("-----END PRIVATE KEY-----", "");

        return Base64.getDecoder().decode(privKeyBase64);
    }

    private static PrivateKey getPrivateKey(String privKey)
    throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes(privKey)));
    }

    private static String sign(String input, String privKey)
    throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        PrivateKey key = getPrivateKey(privKey);
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);

        signature.update(input.getBytes());

        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }

    public static void main(String[] args) {
        try {
            String certPath = "../qseal.cer";
            String privKeyPath = "../qseal.key";
            String clientCertUrl = "<public_link_to_your_cert>";

            String cert = Example.readFileContent(certPath);
            String privKey = Example.readFileContent(privKeyPath);

            String thumbprint = Example.getThumbprint(cert);

            ObjectMapper om = new ObjectMapper();

            List<String> crit = new ArrayList<>();
            crit.add("iat");

            Map<String, Object> headers = new HashMap<>();
            headers.put("kid", thumbprint);
            headers.put("x5u", clientCertUrl);
            headers.put("x5t#S256", thumbprint);
            headers.put("alg", "RS256");
            headers.put("crit", crit);
            headers.put("iat", Instant.now().getEpochSecond());
            String headersBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(om.writeValueAsString(headers).getBytes());
            
            List<String> scopes = new ArrayList<>();
            scopes.add("AccountBalance");
            scopes.add("AccountBasicData");
            scopes.add("AccountTransactions");
            scopes.add("FX");
            scopes.add("PaymentGate");
            scopes.add("TransferInitiation");

            Map<String, Object> payload = new HashMap<>();
            payload.put("submitId", UUID.randomUUID());
            payload.put("validityPeriod", "MONTHS_6");
            payload.put("redirectUrl", "https://www.domain.com/callback");
            payload.put("scopes", scopes);
            String payloadBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(om.writeValueAsString(payload).getBytes());
            String payloadJson = om.writeValueAsString(payload);

            String signature = Example.sign(headersBase64 + "." + payloadBase64, privKey);

            Security.addProvider(new BouncyCastleProvider());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate pubCert = certFactory.generateCertificate(new ByteArrayInputStream(cert.getBytes()));

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, "".toCharArray());
            keyStore.setCertificateEntry("alias", pubCert);
            keyStore.setKeyEntry("alias", getPrivateKey(privKey), "".toCharArray(), new Certificate[]{pubCert});

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
            sslContext.init(keyManagers, null, null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            URL url = new URL("https://tpp.walutomat.dev/api/v3/consent/create");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(sslSocketFactory);
            connection.setRequestProperty("X-JWS-SIGNATURE", headersBase64 + ".." + signature);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);

            try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
                wr.writeBytes(payloadJson);
                wr.flush();
            }

            BufferedReader in;
            if (connection.getResponseCode() == 200) {
                in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            } else {
                in = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            }

            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }

            System.out.println(response.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}