#!/usr/bin/env python3
import sys
import re

def extract_certificates(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            data = f.read()

        match = re.search(r'"CertificateString"\s*:\s*"([^"]*)"', data)

        if not match:
            print("CertificateString field not found.")
            return

        cert_string = match.group(1).replace('\\n', '\n')

        with open(output_file, 'w') as f:
            f.write(cert_string)

        print(f"Certificates successfully extracted to {output_file}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file_pem>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    extract_certificates(input_file, output_file)

