JWT Server

A FastAPI-based JWT authentication server with encrypted RSA key storage, rate limiting, and JWKS support.

Features

User Registration with Argon2-hashed passwords

JWT Authentication using RSA keys encrypted via AES-GCM

Automatic Key Generation & Rotation

JWKS Endpoint to expose current public keys

Per-IP Rate Limiting for authentication attempts

Authentication Logging with timestamp and IP

Key Cleanup Utility (clean_up_expired_keys()) for removing expired keys

Requirements

Python 3.8 or higher

SQLite3 (bundled with Python)

A modern operating system (Linux, macOS, Windows)

Installation

Clone the repository

git clone https://github.com/your-repo/jwt-server.git
cd jwt-server

Create a virtual environment and activate it:

python -m venv venv                # create venv
source venv/bin/activate           # on macOS/Linux
venv\Scripts\activate            # on Windows

Install dependencies:

pip install fastapi uvicorn python-dotenv pydantic jose cryptography argon2-cffi

(Optional) install testing dependencies:

pip install pytest pytest-cov

Configuration

Create a file named .env in the project root:

NOT_MY_KEY=<BASE64-ENCODED-32-BYTE-KEY>

To generate a suitable key, run in Python:

import os, base64
print(base64.b64encode(os.urandom(32)).decode())

Database Initialization

On startup, the server will automatically initialize (or reset) the SQLite database file totally_not_my_privateKeys.db, creating these tables:

keys — stores encrypted RSA private keys, nonces, and expiry timestamps

users — stores user credentials and metadata

auth_logs — logs each successful authentication by IP and timestamp

An admin user (username: admin, password: password) is seeded by default.

Running the Server

uvicorn jwt_server:app --reload --host 0.0.0.0 --port 8080

API Endpoints

POST /register

Register a new user.

Request Body (JSON):

{
  "username": "your_username",
  "email": "optional@example.com"
}

Response: 200 OK (or 201 Created)

{ "password": "<generated-password>" }

POST /auth

Authenticate a user and receive a JWT.

Query Parameters:

expired (bool, optional): if true, issues an already-expired token (for testing).

Request Body (JSON):

{
  "username": "your_username",
  "password": "your_password"
}

Responses:

200 OK — { "jwt": "<token>" }

401 Unauthorized — invalid credentials

429 Too Many Requests — rate limit exceeded (one attempt per 5 seconds)

GET /.well-known/jwks.json

Retrieve the JSON Web Key Set of active public keys.

Response: 200 OK

{
  "keys": [
    {
      "kty": "RSA",
      "kid": "<key-id>",
      "alg": "RS256",
      "use": "sig",
      "n": "<modulus>",
      "e": "AQAB"
    }
    // ... more keys
  ]
}

Utilities

Key Cleanup: If you need to purge expired keys manually (used in testing), import and call:

from jwt_server import clean_up_expired_keys
clean_up_expired_keys()

Testing

Run the provided test suite using pytest:

pytest test_jwt_server.py

The tests cover:

User registration

Authentication success/failure

JWKS content

Expired token handling

Expired-key cleanup

HTTP method validations

Rate limiting

Authentication logging

License

This project is licensed under the MIT License. See the LICENSE file for details.

Author

Grishab Mishra

