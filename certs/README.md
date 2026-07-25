# TLS Certificates

This directory is mounted into the C2 listener container. Generate self-signed certs for local testing:

```bash
mkdir -p tls
openssl req -x509 -newkey rsa:4096 -keyout tls/server.key -out tls/server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

For production, use a cert from your redirector domain (Let's Encrypt, or a purchased cert that matches your cover domain).

The `.gitignore` excludes `*.key` and `*.crt` — never commit actual certificates.
