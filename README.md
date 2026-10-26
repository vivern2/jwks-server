# Project 2: SQLite-Backed JWKS Server

**Author:** Moshood Abisoye  
**Course:** CSCE 3550

A Flask JWKS server that persists RSA private keys in SQLite and issues
RS256-signed JWTs for a mock user.

## Features

- Runs on port 8080.
- Stores private keys in `totally_not_my_privateKeys.db`.
- Serializes RSA private keys as PKCS1 PEM bytes.
- Uses parameterized SQL queries.
- Preserves keys across server restarts.
- Ensures an expired key and a key valid for at least one hour exist.
- Publishes only unexpired public keys.
- Uses database key identifiers as JWT and JWK `kid` values.

## Database schema

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

The database is created in the working directory when the server starts.
Generated databases are excluded from Git because they contain private keys.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

SQLite support is included with Python.

## Run

From the repository root:

```bash
python app.py
```

The server listens on port 8080.

## Endpoints

### GET /.well-known/jwks.json

Queries all unexpired database keys and returns their public RSA components
in a JWKS document. Private key material is never included.

### POST /auth

Queries an unexpired private key and returns a signed JWT for `userABC`.

If the `expired` query parameter is present, regardless of its value,
the server uses an expired database key and an expired JWT expiration claim.

Authentication is mocked. Requests with no credentials, HTTP Basic
credentials, or JSON credentials are accepted without credential validation.

Examples:

```bash
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired"
curl -X POST -u userABC:password123 http://localhost:8080/auth
curl http://localhost:8080/.well-known/jwks.json
```

Unsupported methods such as GET /auth return HTTP 405.

## Tests and coverage

```bash
python -m pytest --cov=app --cov=key_manager --cov-branch --cov-report=term-missing --cov-fail-under=81
```

Verified results: **22 tests passed, with 100% statement and branch coverage**
for `app.py` and `key_manager.py`.

Tests cover database schema, PEM storage, persistence, parameterized
inserts, expiration boundaries, JWT signature verification, mock
credential formats, and unsupported HTTP methods.

## Linting

```bash
python -m flake8 app.py key_manager.py tests/test_app.py
```

## Gradebot

Stop any manually running server before executing Gradebot.
Run from the repository root:

```bash
./gradebot project-2 --dir="." --run="./venv/bin/python app.py"
```

Verified Gradebot result: **98.93%**, with full points for all functional
checks and 4.25/5 for quality.

## Screenshots

### Gradebot rubric

![Gradebot results with identification](screenshots/gradebot-project2-with-name.png)

### Test coverage

![Test coverage with identification](screenshots/coverage-project2-with-name.png)

## Project structure

- `app.py`: Flask application factory and HTTP endpoints.
- `key_manager.py`: RSA generation, SQLite storage, and JWK serialization.
- `tests/test_app.py`: automated tests using temporary databases.
- `requirements.txt`: Python dependencies.
- `setup.cfg`: lint configuration.
- `screenshots/`: identified Gradebot and coverage screenshots.

## Limitations

This is an educational implementation. It mocks authentication and stores
unencrypted private keys in a local database. It is not a production
authentication service.