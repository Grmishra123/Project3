import os
import uuid
import base64
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Query
from pydantic import BaseModel
from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from argon2 import PasswordHasher

app = FastAPI()

# Load environment variables
load_dotenv()
NOT_MY_KEY = os.getenv("NOT_MY_KEY")
if NOT_MY_KEY is None:
    raise ValueError("NOT_MY_KEY is not set in environment")
AES_KEY = base64.b64decode(NOT_MY_KEY)

# Database and crypto constants
DB_FILE = "totally_not_my_privateKeys.db"
KEY_EXPIRY_HOURS = 1
ph = PasswordHasher()

# Simple per-IP rate limit
auth_attempts = defaultdict(list)
RATE_LIMIT_WINDOW = 5  # seconds

# Pydantic models
class UserRegistration(BaseModel):
    username: str
    email: Optional[str] = None

class AuthRequest(BaseModel):
    username: str
    password: str

# Initialize or reset database
def init_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    with sqlite3.connect(DB_FILE) as conn:
        # Create table for encrypted keys
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                kid TEXT PRIMARY KEY,
                key BLOB NOT NULL,
                nonce BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        # Create users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        # Create auth_logs table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        # Seed admin user
        pwd_hash = ph.hash("password")
        conn.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            ("admin", pwd_hash, "admin@example.com")
        )
        conn.commit()

# Generate RSA key, encrypt & store in DB
def generate_rsa_key(expired: bool = False):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = str(uuid.uuid4())
    expiry = (
        datetime.now(timezone.utc) - timedelta(hours=1)
        if expired
        else datetime.now(timezone.utc) + timedelta(hours=KEY_EXPIRY_HOURS)
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    nonce = os.urandom(12)
    aesgcm = AESGCM(AES_KEY)
    encrypted_blob = aesgcm.encrypt(nonce, pem, None)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO keys (kid, key, nonce, exp) VALUES (?, ?, ?, ?)",
            (kid, encrypted_blob, nonce, int(expiry.timestamp()))
        )
        conn.commit()
    return kid

# Decrypt AES-encrypted blob
def decrypt_key(enc_blob: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(AES_KEY)
    return aesgcm.decrypt(nonce, enc_blob, None)

# Retrieve private key for signing
def get_private_key(expired: bool = False):
    op = "<=" if expired else ">"
    order = "DESC" if expired else "ASC"
    query = f"SELECT kid, key, nonce FROM keys WHERE exp {op} ? ORDER BY exp {order} LIMIT 1"
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute(query, (datetime.now(timezone.utc).timestamp(),))
        row = cur.fetchone()
    if not row:
        return None, None
    kid, enc_blob, nonce = row
    pem = decrypt_key(enc_blob, nonce)
    priv_key = serialization.load_pem_private_key(pem, password=None)
    return kid, priv_key

# Registration endpoint
@app.post("/register")
def register(user: UserRegistration):
    pwd = str(uuid.uuid4())
    pwd_hash = ph.hash(pwd)
    with sqlite3.connect(DB_FILE) as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (user.username, pwd_hash, user.email)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Username or email already taken")
    return {"password": pwd}

# Authentication endpoint with simple rate limiting
@app.post("/auth")
def auth(auth_req: AuthRequest, request: Request, expired: Optional[bool] = Query(False)):
    ip = request.client.host
    now = time.time()
    auth_attempts[ip] = [t for t in auth_attempts[ip] if now - t < RATE_LIMIT_WINDOW]
    if auth_attempts[ip]:
        raise HTTPException(status_code=429, detail="Too many requests. Please wait.")
    auth_attempts[ip].append(now)

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (auth_req.username,))
        rec = cur.fetchone()
        if not rec:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user_id, db_hash = rec
        try:
            ph.verify(db_hash, auth_req.password)
        except:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now(timezone.utc), user_id))
        conn.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?,?)", (ip, user_id))
        conn.commit()

    kid, priv_key = get_private_key(expired)
    if not priv_key:
        raise HTTPException(status_code=500, detail="No valid private keys available")
    exp_time = datetime.now(timezone.utc) + timedelta(hours=1)
    if expired:
        exp_time = datetime.now(timezone.utc) - timedelta(hours=1)
    private_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    token = jwt.encode({"sub": auth_req.username, "exp": exp_time.timestamp()}, private_pem,
                       algorithm="RS256", headers={"kid": kid})
    return {"jwt": token}

# JWKS endpoint
@app.get("/.well-known/jwks.json")
def jwks():
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT kid, key, nonce FROM keys WHERE exp > ?", (datetime.now(timezone.utc).timestamp(),))
        rows = cur.fetchall()
    jwk_set = {"keys": []}
    for kid, enc_blob, nonce in rows:
        pem = decrypt_key(enc_blob, nonce)
        pub = serialization.load_pem_private_key(pem, password=None).public_key()
        nums = pub.public_numbers()
        n = base64.urlsafe_b64encode(nums.n.to_bytes((nums.n.bit_length()+7)//8, "big")).decode().rstrip("=")
        jwk_set["keys"].append({"kty":"RSA","kid":kid,"alg":"RS256","use":"sig","n":n,"e":"AQAB"})
    return jwk_set

# Startup
init_db()
generate_rsa_key()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("jwt_server:app", host="0.0.0.0", port=8080, reload=True)
