#!/usr/bin/env python3
"""
SSL Certificate Generator for HTTPS Interception
=================================================
Generates self-signed SSL certificates for HTTPS traffic interception.

WARNING: Only use on systems you own or have explicit permission to test.
Installing root certificates can be a security risk.
"""

import os
import sys
import ipaddress
from datetime import datetime, timedelta


def generate_certificate():
    """Generate self-signed SSL certificate"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("Error: cryptography library is required")
        print("Install with: pip install cryptography")
        sys.exit(1)

    print("Generating SSL certificate...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"HTTP/HTTPS Viewer"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.DNSName(u"*.localhost"),
            x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1")),
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).sign(private_key, hashes.SHA256())

    # Save private key
    with open("proxy_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save certificate
    with open("proxy_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✓ Certificate generated successfully!")
    print("  - Private key: proxy_key.pem")
    print("  - Certificate: proxy_cert.pem")
    print("\nTo trust this certificate:")
    print("  Linux:   sudo cp proxy_cert.pem /usr/local/share/ca-certificates/ && sudo update-ca-certificates")
    print("  macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxy_cert.pem")
    print("  Windows: certutil -addstore -f \"ROOT\" proxy_cert.pem")


if __name__ == '__main__':
    # Check if files already exist
    if os.path.exists("proxy_key.pem") or os.path.exists("proxy_cert.pem"):
        response = input("Certificate files already exist. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(0)

    generate_certificate()
