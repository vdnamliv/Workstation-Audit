Place your TLS assets here before starting docker-compose:

- ca.pem: Root or issuing CA certificate that signs client certs.
- ca.key: Private key matching ca.pem (used by vt-server to mint leaf certificates).
- server.pem / server.key: Certificate/key pair presented by nginx (mtls_gateway).

Keep these files private. Never commit them to source control.
