import pytest
from fastapi.testclient import TestClient
from jwt_server import app, generate_rsa_key, clean_up_expired_keys
import sqlite3
import uuid
import time
from jose import jwt, JWTError
import base64
from cryptography.hazmat.primitives.asymmetric import rsa

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_db():
    """Clean database before each test."""
    with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
        conn.execute("DELETE FROM keys")
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM auth_logs")
        conn.commit()
    yield

def register_user():
    username = f"user_{uuid.uuid4()}"
    email = f"{username}@example.com"
    response = client.post("/register", json={"username": username, "email": email})
    assert response.status_code in (200, 201)
    return username, response.json()["password"]

def test_register():
    username = f"user_{uuid.uuid4()}"
    email = f"{username}@example.com"
    response = client.post("/register", json={"username": username, "email": email})
    assert response.status_code in (200, 201)
    assert "password" in response.json()

def test_auth():
    username, password = register_user()
    response = client.post("/auth", json={"username": username, "password": password})
    assert response.status_code == 200
    assert "jwt" in response.json()

def test_invalid_auth():
    username, password = register_user()
    response = client.post("/auth", json={"username": username, "password": "wrong_password"})
    assert response.status_code == 401  # Unauthorized

def test_jwks():
    generate_rsa_key()
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert "keys" in response.json()
    assert isinstance(response.json()["keys"], list)

def test_expired_auth_token():
    # Create expired key and user
    generate_rsa_key(expired=True)
    username, password = register_user()

    # Try to manually request expired token (simulate query param if supported)
    response = client.post("/auth?expired=true", json={"username": username, "password": password})
    assert response.status_code == 200
    token = response.json()["jwt"]

    # Get JWKS for key lookup
    header = jwt.get_unverified_header(token)
    jwks = client.get("/.well-known/jwks.json").json()
    key = next((k for k in jwks["keys"] if k["kid"] == header["kid"]), None)
    assert key is not None, "Matching key should exist"

    n = key["n"] + "=" * (-len(key["n"]) % 4)
    e = key["e"] + "=" * (-len(key["e"]) % 4)

    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(n), "big"),
        int.from_bytes(base64.urlsafe_b64decode(e), "big")
    ).public_key()

    with pytest.raises(JWTError):
        jwt.decode(token, public_key, algorithms=["RS256"])

def test_key_cleanup():
    """Ensure expired keys are removed from DB and JWKS."""
    kid = generate_rsa_key(expired=True)
    generate_rsa_key()  # Ensure there's at least one valid
    clean_up_expired_keys()
    response = client.get("/.well-known/jwks.json")
    keys = response.json()["keys"]
    assert kid not in [k["kid"] for k in keys]

def test_invalid_methods():
    assert client.put("/.well-known/jwks.json").status_code == 405
    assert client.get("/auth").status_code == 405
    assert client.put("/register").status_code == 405

def test_rate_limiter():
    username, password = register_user()
    passed, failed = 0, 0

    for i in range(12):  # 12 attempts
        response = client.post("/auth", json={"username": username, "password": password})
        if response.status_code == 429:
            failed += 1
        elif response.status_code == 200:
            passed += 1
        time.sleep(0.05)  # 50ms between calls

    assert passed <= 10
    assert failed >= 1

def test_auth_logging():
    username, password = register_user()
    client.post("/auth", json={"username": username, "password": password})

    with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM auth_logs")
        count = cursor.fetchone()[0]
        assert count >= 1