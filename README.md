

### 1. Certyfikaty

```bash
mkdir -p certs
cd certs
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 \
  -subj "/C=PL/ST=State/L=City/O=Organization/CN=localhost"
cd ..
```

### 2.Docker

```bash
docker-compose up -d
```


