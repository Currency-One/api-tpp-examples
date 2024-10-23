# PIS-AIS API usage examples
Full documentation is available at [https://tpp.walutomat.dev/v3/](https://tpp.walutomat.dev/v3/)

[`qseal.cer`](qseal.cer) and [`qseal.key`](qseal.key) files are provided as examples. You need to provide valid cert/key pair on your own.

Make sure the private key you are using is in PKCS#8 format and starts with `-----BEGIN PRIVATE KEY-----` header. If your key is in different format, you can convert it using f.e. openssl command: `openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs1.key -out pkcs8.key`
### Working with certificates, keys and keystores
It is possible to use `openssl`/`keytool` command line tools but we highly recommend this GUI:
[https://keystore-explorer.org](https://keystore-explorer.org)

### Postman
1. Go to Settings -> Certificates
1. Set API host (for example sandbox instance is `tpp.walutomat.dev`)
1. Set CRT file to your certificate
1. Set KEY file to your private key
1. Import [`example.postman_collection.json`](example.postman_collection.json) collection
1. Run at least once `Lib install` request
1. Due to Postman limitations you have to paste content of cert/key to collection variables, to do so:
    1. Click three dots near the collection name, select `Edit` and then `Variables` tab
    1. Paste private key file content into `Current value` of `privkey_pem` variable
    1. Paste certificate file content into `Current value` of `cert_pem` variable
1. Now you can run `Example request`

### bash
[`example.sh`](bash/example.sh)
```
sh example.sh
```

### java
[`Example.java`](java/src/main/java/com/example/Example.java)
```
mvn package && java -jar target/example-1.0-SNAPSHOT-jar-with-dependencies.jar
```

### js
[`example.js`](js/example.js)
```
node example.js
```

### php
[`example.php`](php/example.php)
```
php example.php
```

### python
[`example.py`](python/example.py)
```
python example.py
```