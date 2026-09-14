# JWKS Server

A minimal RESTful JWKS (JSON Web Key Set) server, built with **Python** and
**Flask**, for the "Implementing a basic JWKS Server" assignment.

## What it does

- Generates two RSA key pairs on startup:
  - An **active** key (expires 1 hour from now).
  - An **expired** key (expired 1 hour ago).
- Each key has a unique `kid` (Key ID).
- `GET /.well-known/jwks.json` — returns a JWKS document containing only
  the **unexpired** public key(s), in standard JWK format.
- `POST /auth` — issues a signed JWT for a mock user.
  - Normally signs with the active key and a future `exp`.
  - If a query parameter named `expired` is present
    (e.g. `POST /auth?expired=true`), signs with the expired key and an
    already-past `exp`, so you can exercise expired-key handling.
- Runs on port **8080**.

## Project layout
jwks-server/
├── app.py # Flask app: routes / HTTP layer
├── key_manager.py # RSA key generation, kid, expiry, JWK encoding
├── requirements.txt
├── setup.cfg # flake8 config
├── tests/
│ └── test_app.py # pytest test suite (99% coverage)
└── README.md


## Setup (WSL / Ubuntu / Linux)

```bash
cd ~/Projects/School/SeniorCybersecurity/jwks-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running the server

```bash
python app.py
```

Listens on `http://0.0.0.0:8080`.

## Trying it manually

```bash
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
curl http://localhost:8080/.well-known/jwks.json
```

## Running the test suite / coverage

```bash
python -m pytest --cov=. --cov-report=term-missing
```

Currently reports **99% coverage** (target: >80%).

## Linting

```bash
flake8 .
```

## Running the official (blackbox) test client

Test client releases: https://github.com/jh125486/CSCE3550/releases

1. With `app.py` running, download the correct Linux asset for your
   architecture (`uname -m`), `chmod +x` it, and run it per the release
   instructions against `localhost:8080`.
2. Screenshot the output (with identifying info visible).

## Deliverables checklist

- [ ] Push this repo to your own GitHub account.
- [ ] Screenshot of the test client running successfully.
- [ ] Screenshot of `pytest --cov` output showing >80% coverage.
- [ ] Both screenshots show identifying information.

## Notes

- Keys are generated in memory at process startup — no database needed.
- `/auth` does not perform real credential checking, per the assignment.
- Only unexpired keys are ever returned from the JWKS endpoint.
- Educational project only — not a production authentication system.