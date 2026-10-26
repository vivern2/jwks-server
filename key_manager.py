"""Persist RSA private keys in SQLite and expose public JWKs."""

import base64
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_FILENAME = "totally_not_my_privateKeys.db"


def _b64url_uint(value):
    """Encode an RSA public integer using unpadded base64url."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class SigningKey:
    """A database key with its identifier and expiration timestamp."""

    kid: str
    private_key: rsa.RSAPrivateKey
    expiry: int

    @property
    def public_key(self):
        """Derive the public key from the stored private key."""
        return self.private_key.public_key()

    def is_expired(self, now=None):
        """Return whether the key has reached its expiration."""
        now = time.time() if now is None else now
        return self.expiry <= now

    def to_jwk(self):
        """Return only public RSA information."""
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


class KeyStore:
    """Store PEM-encoded private keys using parameterized SQL."""

    def __init__(self, db_path=DB_FILENAME):
        self.db_path = str(db_path)

        with closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS keys(
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL
                    )
                    """
                )

        self.ensure_keys()

    def save_key(self, expiry):
        """Generate a private key and persist its PKCS1 PEM bytes."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO keys (key, exp) VALUES (?, ?)",
                    (pem, expiry),
                )
                kid = cursor.lastrowid

        return SigningKey(str(kid), private_key, expiry)

    @staticmethod
    def _deserialize(row):
        """Reconstruct a signing key from a database row."""
        kid, pem, expiry = row
        private_key = serialization.load_pem_private_key(
            pem,
            password=None,
        )
        return SigningKey(str(kid), private_key, expiry)

    def ensure_keys(self):
        """Preserve stored keys and ensure suitable signing keys exist."""
        now = int(time.time())

        with closing(sqlite3.connect(self.db_path)) as connection:
            expired = connection.execute(
                "SELECT kid FROM keys WHERE exp <= ? LIMIT 1",
                (now,),
            ).fetchone()

            active = connection.execute(
                "SELECT kid FROM keys WHERE exp >= ? LIMIT 1",
                (now + 3600,),
            ).fetchone()

        if expired is None:
            self.save_key(now - 3600)

        if active is None:
            # Extra lifetime keeps a key available for at least an hour.
            self.save_key(now + 7200)

    def get_signing_key(self, expired=False):
        """Read an expired or unexpired private key from the database."""
        now = int(time.time())

        if expired:
            query = (
                "SELECT kid, key, exp FROM keys "
                "WHERE exp <= ? ORDER BY exp DESC, kid DESC LIMIT 1"
            )
        else:
            query = (
                "SELECT kid, key, exp FROM keys "
                "WHERE exp > ? ORDER BY exp DESC, kid DESC LIMIT 1"
            )

        with closing(sqlite3.connect(self.db_path)) as connection:
            row = connection.execute(query, (now,)).fetchone()

        if row is None:
            raise LookupError("No suitable signing key is available")

        return self._deserialize(row)

    def get_valid_jwks(self):
        """Read every unexpired key and return its public JWK."""
        with closing(sqlite3.connect(self.db_path)) as connection:
            rows = connection.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
                (int(time.time()),),
            ).fetchall()

        return [self._deserialize(row).to_jwk() for row in rows]