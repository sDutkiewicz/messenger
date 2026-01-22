#!/bin/bash

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate self-signed certificate for development
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes \
  -subj "/C=PL/ST=Poland/L=Poland/O=Messenger/OU=Dev/CN=localhost"

echo "✓ Certificates generated in ./certs/"
