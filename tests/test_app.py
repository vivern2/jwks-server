"""Tests for SQLite storage, JWT issuance, and public JWKS responses."""

import sqlite3
import time
from contextlib import closing

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app import create_app
from key_manager import KeyStore


@pytest.fixture
def application(tmp_path):
    app = create_app(tmp_path / "test.db")
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(application):
    return application.test_client()


@pytest.fixture
def store(application):
    return application.extensions["key_store"]


def test_database_schema(store):
    with closing(sqlite3.connect(store.db_path)) as connection:
        columns = connection.execute("PRAGMA table_info(keys)").fetchall()
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = ?",
            ("keys",),
        ).fetchone()[0]

    assert [(column[1], column[2]) for column in columns] == [
        ("kid", "INTEGER"),
        ("key", "BLOB"),
        ("exp", "INTEGER"),
    ]
    assert columns[0][5] == 1
    assert columns[1][3] == 1
    assert columns[2][3] == 1
    assert "AUTOINCREMENT" in schema.upper()


def test_database_contains_expired_and_future_keys(store):
    now = int(time.time())

    with closing(sqlite3.connect(store.db_path)) as connection:
        rows = connection.execute("SELECT key, exp FROM keys").fetchall()

    assert any(expiry <= now for _, expiry in rows)
    assert any(expiry >= now + 3600 for _, expiry in rows)

    for pem, _ in rows:
        assert isinstance(pem, bytes)
        assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        private_key = serialization.load_pem_private_key(
            pem,
            password=None,
        )
        assert private_key.key_size == 2048


def test_keys_persist_after_reopening(store):
    original = store.get_signing_key()
    reopened = KeyStore(store.db_path)
    restored = reopened.get_signing_key()

    assert restored.kid == original.kid
    assert (
        restored.private_key.private_numbers()
        == original.private_key.private_numbers()
    )


def test_initialization_does_not_duplicate_keys(store):
    with closing(sqlite3.connect(store.db_path)) as connection:
        before = connection.execute(
            "SELECT COUNT(*) FROM keys"
        ).fetchone()[0]

    store.ensure_keys()

    with closing(sqlite3.connect(store.db_path)) as connection:
        after = connection.execute(
            "SELECT COUNT(*) FROM keys"
        ).fetchone()[0]

    assert after == before


def test_key_expiration_and_unique_ids(store):
    active = store.get_signing_key()
    expired = store.get_signing_key(expired=True)

    assert active.kid != expired.kid
    assert not active.is_expired()
    assert expired.is_expired()
    assert active.is_expired(now=active.expiry)


def test_jwks_returns_public_keys_only(client, store):
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert response.is_json

    keys = response.get_json()["keys"]
    kids = [key["kid"] for key in keys]

    assert store.get_signing_key().kid in kids
    assert store.get_signing_key(expired=True).kid not in kids

    for key in keys:
        assert set(key) == {"kty", "use", "alg", "kid", "n", "e"}
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"


def test_jwks_reads_all_valid_database_keys(client, store):
    additional = store.save_key(int(time.time()) + 10000)
    keys = client.get("/.well-known/jwks.json").get_json()["keys"]

    assert len(keys) == 2
    assert additional.kid in {key["kid"] for key in keys}


@pytest.mark.parametrize("credentials", ["none", "basic", "json"])
def test_auth_signature_verified_with_published_jwk(client, credentials):
    options = {}

    if credentials == "basic":
        options["headers"] = {
            "Authorization": "Basic dXNlckFCQzpwYXNzd29yZDEyMw=="
        }
    elif credentials == "json":
        options["json"] = {
            "username": "userABC",
            "password": "password123",
        }

    response = client.post("/auth", **options)

    assert response.status_code == 200

    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    keys = client.get("/.well-known/jwks.json").get_json()["keys"]
    matching = next(key for key in keys if key["kid"] == header["kid"])
    public_key = jwt.PyJWK.from_dict(matching).key
    payload = jwt.decode(token, public_key, algorithms=["RS256"])

    assert header["alg"] == "RS256"
    assert payload["sub"] == "userABC"
    assert payload["exp"] > time.time()


@pytest.mark.parametrize(
    "query",
    ["?expired", "?expired=true", "?expired=false"],
)
def test_expired_parameter_presence(client, store, query):
    response = client.post("/auth" + query)

    assert response.status_code == 200

    token = response.get_data(as_text=True)
    expired = store.get_signing_key(expired=True)

    assert jwt.get_unverified_header(token)["kid"] == expired.kid

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, expired.public_key, algorithms=["RS256"])

    payload = jwt.decode(
        token,
        expired.public_key,
        algorithms=["RS256"],
        options={"verify_exp": False},
    )

    assert payload["exp"] == expired.expiry
    assert payload["exp"] <= time.time()


@pytest.mark.parametrize(
    "path, method",
    [
        ("/auth", "GET"),
        ("/auth", "PUT"),
        ("/auth", "DELETE"),
        ("/.well-known/jwks.json", "POST"),
    ],
)
def test_unsupported_methods(client, path, method):
    response = client.open(path, method=method)

    assert response.status_code == 405
    assert response.get_json() == {"error": "method not allowed"}


def test_expiration_boundary_excluded_from_jwks(store, monkeypatch):
    boundary = 2000000000
    monkeypatch.setattr("key_manager.time.time", lambda: boundary)
    key = store.save_key(boundary)

    assert key.kid not in {
        item["kid"] for item in store.get_valid_jwks()
    }
    assert store.get_signing_key(expired=True).kid == key.kid


@pytest.mark.parametrize("expired", [False, True])
def test_missing_key_raises_lookup_error(store, expired):
    with closing(sqlite3.connect(store.db_path)) as connection:
        with connection:
            connection.execute("DELETE FROM keys")

    with pytest.raises(LookupError):
        store.get_signing_key(expired=expired)


def test_auth_recovers_when_no_keys_remain(client, store):
    with closing(sqlite3.connect(store.db_path)) as connection:
        with connection:
            connection.execute("DELETE FROM keys")

    assert client.post("/auth").status_code == 200
    assert len(
        client.get("/.well-known/jwks.json").get_json()["keys"]
    ) == 1


def test_parameterized_insert_does_not_execute_sql(store):
    value = "0); DROP TABLE keys; --"
    key = store.save_key(value)

    with closing(sqlite3.connect(store.db_path)) as connection:
        stored = connection.execute(
            "SELECT exp FROM keys WHERE kid = ?",
            (int(key.kid),),
        ).fetchone()[0]

        count = connection.execute(
            "SELECT COUNT(*) FROM keys"
        ).fetchone()[0]

    assert stored == value
    assert count >= 3