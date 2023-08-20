# GOEDS - Encryption Decryption Service
GOEDS aims to provide a service to encrypt and decrypt data by sharing knowledge of encryption keys.

The client only knows the name of the encryption key and owns the data.
The EDS service stores the key name & content association and provides an API for key creation and on-the-fly data encryption/decryption

---
## TODO

- Analyse if we could implement a better way to manage the master pass phrase
- KMIP protocol implementation ?
- Create a separate project like go-eds-ws to make a better implementation of the webserv example (with TLS support with auth ?)
- Provide a way to rotate the master key and all keys encrypted with it
- Add Unit Tests

---

License
-------

MIT, see [LICENSE](LICENSE)