#!/usr/bin/env python3
import sys
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate, FILETYPE_PEM


def load_certificates_from_file(file_path):
    with open(file_path, 'r') as f:
        certs_data = f.read()

    # Split the certificates
    certs = certs_data.split("-----END CERTIFICATE-----\n")
    certs = [c + "-----END CERTIFICATE-----\n" for c in certs if c.strip()]
    return [load_certificate(FILETYPE_PEM, cert) for cert in certs]


def identify_certificates(certs):
    cert_chain = []

    for cert in certs:
        subject = cert.get_subject()
        issuer = cert.get_issuer()

        # Check if it's a root certificate (self-signed)
        if subject == issuer:
            cert_type = "Root"
        else:
            cert_type = "Intermediate"

        cert_info = {
            "type": cert_type,
            "subject": str(subject),
            "issuer": str(issuer)
        }
        cert_chain.append(cert_info)

    # The leaf certificate is typically the one where no other certificate in the chain is issued by this certificate
    for cert_info in cert_chain:
        is_leaf = True
        for other_cert_info in cert_chain:
            if cert_info['subject'] == other_cert_info['issuer']:
                is_leaf = False
                break
        if is_leaf:
            cert_info['type'] = "Leaf"

    return cert_chain


def print_cert_chain(cert_chain):
    for i, cert_info in enumerate(cert_chain):
        print(f"Certificate {i + 1}:")
        print(f"  Type: {cert_info['type']}")
        print(f"  Subject: {cert_info['subject']}")
        print(f"  Issuer: {cert_info['issuer']}")
        print()


def main(file_path):
    certs = load_certificates_from_file(file_path)
    cert_chain = identify_certificates(certs)
    print_cert_chain(cert_chain)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_certificate_chain_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)

