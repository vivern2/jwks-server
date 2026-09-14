"""
test_app.py

Pytest test suite for the JWKS server (app.py + key_manager.py).

Run with:
    pytest --cov=. --cov-report=term-missing

Covers:
    - JWKS endpoint returns only unexpired keys, in valid JWK format.
    - /auth issues a valid JWT signed with the active key, verifiable
      using the public key served by JWKS.
    - /auth?expired=... issues a JWT signed with the expired key, whose
      `kid` is NOT present in the JWKS response, and whose `exp` claim
      is in the past.
    - Disallowed HTTP methods return 405.
    - key_manager helper functions behave correctly (kid uniqueness,
      expiry detection, JWK field correctness).
"""

import time

import jwt
import pytest

from app import app as flask_app
from key_manager import KeyStore, generate_rsa_key


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# JWKS endpoint tests
# ---------------------------------------------------------------------------


def test_jwks_returns_200_and_json(client):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.is_json


def test_jwks_contains_only_unexpired_keys(client):
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()
    assert "keys" in data
    kids = [key["kid"] for key in data["keys"]]

    from app import key_store

    assert key_store.active_key.kid in kids
    assert key_store.expired_key.kid not in kids


def test_jwks_key_fields(client):
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()
    assert len(data["keys"]) >= 1
    for jwk in data["keys"]:
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert "kid" in jwk
        assert "n" in jwk
        assert "e" in jwk


def test_jwks_rejects_post(client):
    response = client.post("/.well-known/jwks.json")
    assert response.status_code == 405


# ---------------------------------------------------------------------------
# /auth endpoint tests
# ---------------------------------------------------------------------------


def test_auth_returns_200(client):
    response = client.post("/auth")
    assert response.status_code == 200


def test_auth_returns_valid_jwt_signed_with_active_key(client):
    from app import key_store

    response = client.post("/auth")
    token = response.get_data(as_text=True)

    header = jwt.get_unverified_header(token)
    assert header["kid"] == key_store.active_key.kid

    public_key = key_store.active_key.public_key
    decoded = jwt.decode(token, key=public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] > time.time()


def test_auth_get_not_allowed(client):
    response = client.get("/auth")
    assert response.status_code == 405


def test_auth_expired_query_param_uses_expired_key(client):
    from app import key_store

    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    token = response.get_data(as_text=True)

    header = jwt.get_unverified_header(token)
    assert header["kid"] == key_store.expired_key.kid

    public_key = key_store.expired_key.public_key
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, key=public_key, algorithms=["RS256"])

    decoded = jwt.decode(
        token, key=public_key, algorithms=["RS256"], options={"verify_exp": False}
    )
    assert decoded["exp"] < time.time()


def test_auth_expired_flag_present_without_value(client):
    """The 'expired' param should trigger expired behavior even with no value."""
    from app import key_store

    response = client.post("/auth?expired")
    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == key_store.expired_key.kid


# ---------------------------------------------------------------------------
# key_manager unit tests
# ---------------------------------------------------------------------------


def test_generate_rsa_key_future_expiry_not_expired():
    key = generate_rsa_key(expiry_offset_seconds=3600)
    assert not key.is_expired()


def test_generate_rsa_key_past_expiry_is_expired():
    key = generate_rsa_key(expiry_offset_seconds=-3600)
    assert key.is_expired()


def test_generate_rsa_key_unique_kids():
    key_a = generate_rsa_key(expiry_offset_seconds=3600)
    key_b = generate_rsa_key(expiry_offset_seconds=3600)
    assert key_a.kid != key_b.kid


def test_key_store_get_signing_key():
    store = KeyStore()
    assert store.get_signing_key(expired=False) is store.active_key
    assert store.get_signing_key(expired=True) is store.expired_key


def test_key_store_valid_jwks_excludes_expired():
    store = KeyStore()
    jwks_list = store.get_valid_jwks()
    kids = [k["kid"] for k in jwks_list]
    assert store.active_key.kid in kids
    assert store.expired_key.kid not in kids


def test_to_jwk_matches_public_numbers():
    key = generate_rsa_key(expiry_offset_seconds=3600)
    jwk = key.to_jwk()
    numbers = key.public_key.public_numbers()

    import base64

    def b64url_decode_to_int(s):
        padding = "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(s + padding), "big")

    assert b64url_decode_to_int(jwk["n"]) == numbers.n
    assert b64url_decode_to_int(jwk["e"]) == numbers.e
