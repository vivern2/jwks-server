"""
app.py

A minimal RESTful JWKS server built with Flask.

Endpoints:
    GET  /.well-known/jwks.json  -> Serves unexpired public keys as a JWKS.
    POST /auth                   -> Issues a signed JWT for a (mock) user.
                                     If the "expired" query parameter is
                                     present, the JWT is signed with the
                                     expired key and has an expired `exp`
                                     claim.

Any other method on these routes returns 405 Method Not Allowed (handled
automatically by Flask's routing since we only register the methods we
support).

Run with:  python app.py
Server listens on 0.0.0.0:8080 as required by the assignment.
"""

import time

import jwt
from flask import Flask, jsonify, request

from key_manager import KeyStore

app = Flask(__name__)

# Single, process-wide key store. Created once at import/startup time so
# that the "expired" key genuinely predates the "active" key and both
# persist for the life of the server process.
key_store = KeyStore()


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return the JWKS document containing only unexpired public keys."""
    return jsonify({"keys": key_store.get_valid_jwks()}), 200


@app.route("/auth", methods=["POST"])
def auth():
    # """Mock authentication endpoint.

    # No real credential checking is performed (per the assignment spec,
    # the test client POSTs with no body and expects a valid JWT back
    # regardless). We simply issue a JWT for a fake user.

    # Query parameter:
    #     expired (any value or none, e.g. ?expired or ?expired=true) ->
    #         When present, the JWT is signed with the expired key and
    #         given an already-past expiry, to demonstrate/exercise
    #         expired-key handling.

    use_expired = "expired" in request.args

    signing_key = key_store.get_signing_key(expired=use_expired)

    now = int(time.time())
    if use_expired:
        # Force the token's own expiry into the past as well, so that a
        # verifier checking `exp` (in addition to key expiry) also sees
        # an expired token.
        issued_at = now - 7200
        expires_at = now - 3600
    else:
        issued_at = now
        expires_at = now + 3600

    payload = {
        "sub": "fake-user",
        "iat": issued_at,
        "exp": expires_at,
    }

    token = jwt.encode(
        payload,
        signing_key.private_key,
        algorithm="RS256",
        headers={"kid": signing_key.kid},
    )

    # PyJWT returns a str in modern versions; ensure that's what we send.
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return token, 200, {"Content-Type": "text/plain"}


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"error": "method not allowed"}), 405


if __name__ == "__main__":
    # host 0.0.0.0 so the server is reachable from outside the container/VM
    # (useful under WSL), port 8080 as required by the assignment.
    app.run(host="0.0.0.0", port=8080)
