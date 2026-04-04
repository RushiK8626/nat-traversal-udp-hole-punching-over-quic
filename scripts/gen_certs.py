"""
Generate self-signed TLS certificates for QUIC connections.
"""

import os
import sys
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend


def generate_certificate(
    cert_file: str,
    key_file: str,
    common_name: str = "nat-traversal",
    days_valid: int = 365,
    key_type: str = "rsa",  # "rsa" or "ec"
    key_size: int = 2048,
    san_ips: list = None,
    san_dns: list = None
):
    """
    Generate a self-signed certificate for QUIC.
    
    Args:
        cert_file: Output certificate file path
        key_file: Output private key file path
        common_name: Certificate common name
        days_valid: Certificate validity in days
        key_type: Key type ("rsa" or "ec")
        key_size: RSA key size (ignored for EC)
        san_ips: List of IP addresses for Subject Alternative Names
        san_dns: List of DNS names for Subject Alternative Names
    """
    # Generate private key
    if key_type == "ec":
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    
    # Build subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NAT Traversal"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build Subject Alternative Names
    san_list = []
    
    if san_dns is None:
        san_dns = ["localhost"]
    for dns in san_dns:
        san_list.append(x509.DNSName(dns))
    
    if san_ips is None:
        san_ips = ["127.0.0.1", "::1"]
    for ip in san_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            san_list.append(x509.IPAddress(ip_obj))
        except ValueError:
            print(f"Warning: Invalid IP address '{ip}', skipping")
    
    # Build certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False
        )
    )
    
    if san_list:
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
    
    # Sign the certificate
    certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(cert_file) or '.', exist_ok=True)
    
    # Write private key
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate
    with open(cert_file, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"Generated certificate: {cert_file}")
    print(f"Generated private key: {key_file}")
    print(f"Valid for: {days_valid} days")
    print(f"SANs: {san_dns + san_ips}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate TLS certificates for NAT traversal')
    parser.add_argument('--cert', default='certs/cert.pem', help='Certificate output file')
    parser.add_argument('--key', default='certs/key.pem', help='Private key output file')
    parser.add_argument('--name', default='nat-traversal', help='Common name')
    parser.add_argument('--days', type=int, default=365, help='Days valid')
    parser.add_argument('--key-type', choices=['rsa', 'ec'], default='rsa', help='Key type')
    parser.add_argument('--key-size', type=int, default=2048, help='RSA key size')
    parser.add_argument('--ip', action='append', default=[], help='Additional IP SANs')
    parser.add_argument('--dns', action='append', default=[], help='Additional DNS SANs')
    
    args = parser.parse_args()
    
    san_ips = ['127.0.0.1', '::1'] + args.ip
    san_dns = ['localhost'] + args.dns
    
    generate_certificate(
        cert_file=args.cert,
        key_file=args.key,
        common_name=args.name,
        days_valid=args.days,
        key_type=args.key_type,
        key_size=args.key_size,
        san_ips=san_ips,
        san_dns=san_dns
    )


if __name__ == '__main__':
    main()
