#!/usr/bin/env python3
"""Convert RSA JWK to PEM format.

Usage:
    echo '{"n": "...", "e": "..."}' | python3 jwk-to-pem.py
    python3 jwk-to-pem.py < jwk.json
"""

import base64
import json
import sys


def b64url_decode(data: str) -> bytes:
    """Base64 URL-safe decode with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def encode_length(length: int) -> bytes:
    """DER length encoding."""
    if length < 128:
        return bytes([length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def encode_integer(value: int) -> bytes:
    """DER integer encoding."""
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, "big")
    # Add leading zero if high bit is set (to avoid negative interpretation)
    if value_bytes[0] & 0x80:
        value_bytes = b"\x00" + value_bytes
    return b"\x02" + encode_length(len(value_bytes)) + value_bytes


def jwk_to_pem(n_b64: str, e_b64: str) -> str:
    """Convert RSA JWK parameters to PEM format."""
    # Decode the base64url-encoded values
    n = int.from_bytes(b64url_decode(n_b64), "big")
    e = int.from_bytes(b64url_decode(e_b64), "big")

    # Build RSA public key sequence
    rsa_sequence = encode_integer(n) + encode_integer(e)
    rsa_der = b"\x30" + encode_length(len(rsa_sequence)) + rsa_sequence

    # RSA OID: 1.2.840.113549.1.1.1
    oid_sequence = b"\x30" + encode_length(13) + b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"

    # Wrap in bit string
    bit_string = b"\x03" + encode_length(len(rsa_der) + 1) + b"\x00" + rsa_der

    # Build SubjectPublicKeyInfo
    spki = b"\x30" + encode_length(len(oid_sequence) + len(bit_string)) + oid_sequence + bit_string

    # Encode as PEM
    pem_body = base64.b64encode(spki).decode()
    return f"-----BEGIN PUBLIC KEY-----\n{pem_body}\n-----END PUBLIC KEY-----"


def main():
    # Read JSON from stdin
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    # Handle both direct JWK and JWKS format
    if "keys" in data:
        # JWKS format - use first key
        if not data["keys"]:
            print("Error: No keys in JWKS", file=sys.stderr)
            sys.exit(1)
        key = data["keys"][0]
    else:
        key = data

    n = key.get("n")
    e = key.get("e")

    if not n or not e:
        print("Error: Missing 'n' or 'e' in JWK", file=sys.stderr)
        sys.exit(1)

    pem = jwk_to_pem(n, e)
    print(pem)


if __name__ == "__main__":
    main()
