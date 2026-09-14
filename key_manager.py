"""
key_manager.py

Handles RSA key pair generation and storage for the JWKS server.

Design:
    - On startup, two RSA key pairs are generated:
        1. A "good" key that has NOT expired (used for normal /auth calls).
        2. An "expired" key whose expiry timestamp is already in the past
           (used only when the caller explicitly asks for an expired JWT).
    - Each key is given a unique Key ID (kid) so that JWTs can advertise
      which key signed them, and JWKS consumers can look up the matching
      public key to verify a signature.
    - The JWKS endpoint only ever exposes keys that have NOT expired,
      per the assignment requirements.

This is intentionally kept in-memory (no database) since the assignment
only requires the server to function for the lifetime of the process.
"""

import base64
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa


def _b64url_uint(value: int) -> str:
    """Base64url-encode an unsigned integer without padding.

    JWK requires the RSA modulus (n) and exponent (e) to be encoded this
    way (RFC 7518, Section 6.3.1).
    """
    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")


@dataclass
class SigningKey:
    """Represents a single RSA key pair with metadata used by JWKS/JWT."""

    kid: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    expiry: int  # Unix timestamp (seconds)

    def is_expired(self, now: float = None) -> bool:
        now = time.time() if now is None else now
        return self.expiry <= now

    def to_jwk(self) -> dict:
        """Return the public portion of this key as a JWK dict."""
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


def generate_rsa_key(expiry_offset_seconds: int) -> SigningKey:
    """Generate a new RSA key pair with a unique kid and given expiry offset.

    Args:
        expiry_offset_seconds: seconds from "now" when this key should
            expire. Use a negative value to create an already-expired key.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())
    expiry = int(time.time()) + expiry_offset_seconds
    return SigningKey(kid=kid, private_key=private_key, public_key=public_key, expiry=expiry)


class KeyStore:
    """In-memory store holding the active and expired signing keys."""

    def __init__(self):
        # Active key: valid for the next hour.
        self.active_key = generate_rsa_key(expiry_offset_seconds=3600)
        # Expired key: expired an hour ago. Kept around solely so the
        # server can demonstrate issuing/verifying JWTs signed with an
        # expired key, per the assignment's "expired" query parameter.
        self.expired_key = generate_rsa_key(expiry_offset_seconds=-3600)

    def get_signing_key(self, expired: bool) -> SigningKey:
        return self.expired_key if expired else self.active_key

    def get_valid_jwks(self) -> list:
        """Return JWKs for all keys that have not expired."""
        all_keys = [self.active_key, self.expired_key]
        return [key.to_jwk() for key in all_keys if not key.is_expired()]
