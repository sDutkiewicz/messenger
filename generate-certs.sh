#!/bin/bash


# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo "ERROR: OpenSSL is not installed"
    echo "Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  macOS: brew install openssl"
    echo "  CentOS/RHEL: sudo yum install openssl"
    exit 1
fi

echo ""
echo "OpenSSL found: $(which openssl)"

# Create certs directory if it doesn't exist
mkdir -p certs

echo ""
echo "Generating self-signed certificate..."
echo "This certificate is valid for 365 days"

# Generate self-signed certificate
cd certs

openssl req -x509 \
    -newkey rsa:4096 \
    -nodes \
    -out cert.pem \
    -keyout key.pem \
    -days 365 \
    -subj "/C=PL/ST=Masovia/L=Warsaw/O=Messenger/CN=localhost"

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Certificate generated successfully!"
    echo "  Certificate: cert.pem"
    echo "  Private key: key.pem"
    
    echo ""
    echo "Certificate Details:"
    echo "====================="
    openssl x509 -in cert.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|Public-Key"
else
    echo ""
    echo "✗ Error generating certificate"
    exit 1
fi

cd ..

