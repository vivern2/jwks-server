"""Flask JWKS server backed by SQLite, listening on port 8080."""

import time

import jwt
from flask import Flask, jsonify, request

from key_manager import DB_FILENAME, KeyStore


def create_app(db_path=DB_FILENAME):
    """Create the application and initialize persistent key storage."""
    app = Flask(__name__)
    store = KeyStore(db_path)
    app.extensions["key_store"] = store

    @app.route("/.well-known/jwks.json", methods=["GET"])
    def jwks():
        """Serve public information for all unexpired database keys."""
        return jsonify({"keys": store.get_valid_jwks()}), 200

    @app.route("/auth", methods=["POST"])
    def auth():
        """Issue a JWT for a mock user without validating credentials."""
        use_expired = "expired" in request.args

        # Ensure signing keys remain available during long server runs.
        store.ensure_keys()
        signing_key = store.get_signing_key(expired=use_expired)

        now = int(time.time())
        expires_at = signing_key.expiry

        if use_expired:
            issued_at = expires_at - 3600
        else:
            issued_at = now
            expires_at = min(now + 3600, signing_key.expiry)

        payload = {
            "sub": "userABC",
            "iat": issued_at,
            "exp": expires_at,
        }

        token = jwt.encode(
            payload,
            signing_key.private_key,
            algorithm="RS256",
            headers={"kid": signing_key.kid},
        )

        return token, 200, {"Content-Type": "text/plain"}

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({"error": "method not allowed"}), 405

    return app


if __name__ == "__main__":  # pragma: no cover
    create_app().run(host="0.0.0.0", port=8080)