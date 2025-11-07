#!/usr/bin/env python3
"""
Generate TLS Certificates using Python (Final Fixed Version with LAN IP)
======================================================================
Includes AKI, SKI, Key Usage, and Subject Alternative Names for local and LAN IPs.
"""

import os
import sys
import ipaddress
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def create_certificates():
    print("[INFO] Generating TLS certificates for EMQX MQTT broker...")

    cert_dir = "certs"
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
        print(f"[SUCCESS] Created certificates directory: {cert_dir}")

    # Generate CA private key
    print("[INFO] Generating CA private key...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Generate CA certificate
    print("[INFO] Generating CA certificate...")
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ho Chi Minh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT Security Testing"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, "IoT-CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()), critical=False
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )

    # Generate server private key
    print("[INFO] Generating server private key...")
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Generate server CSR
    print("[INFO] Generating server certificate signing request...")
    server_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ho Chi Minh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT Security Testing"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, "emqx"),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(server_name)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("emqx"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv4Address("192.168.1.38")),  # Added LAN IP
            ]),
            critical=False,
        )
        .sign(server_private_key, hashes.SHA256(), default_backend())
    )

    # Generate server certificate signed by CA
    print("[INFO] Generating server certificate...")
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("emqx"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv4Address("192.168.1.38")),  # Added LAN IP
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )

    # Save files
    with open(os.path.join(cert_dir, "ca-key.pem"), "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(os.path.join(cert_dir, "ca-cert.pem"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    with open(os.path.join(cert_dir, "server-key.pem"), "wb") as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(os.path.join(cert_dir, "server-cert.pem"), "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print("[SUCCESS] TLS certificates generated successfully!")
    print("")
    print("Certificate files:")
    print(f"   CA Certificate: {cert_dir}/ca-cert.pem")
    print(f"   CA Private Key: {cert_dir}/ca-key.pem")
    print(f"   Server Certificate: {cert_dir}/server-cert.pem")
    print(f"   Server Private Key: {cert_dir}/server-key.pem")
    print("")
    print("Next steps:")
    print("   1. Update docker-compose.yml to use TLS certificates")
    print("   2. Configure EMQX TLS listeners")
    print("   3. Update client connections to use TLS")
    print("   4. Test TLS connections")

def main():
    try:
        create_certificates()
    except ImportError:
        print("[ERROR] cryptography library not found! Please install it with: pip install cryptography")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error generating certificates: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
