import os
import bcrypt
import jwt
import datetime
from app.database.database import db

JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_ALGO = "HS256"
TOKEN_EXPIRY_HOURS = 12


def create_users_table():
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def hash_password(plain_password):
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password, password_hash):
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))


def create_user(username, plain_password, role="viewer"):
    existing = db.fetchone("SELECT id FROM users WHERE username=?", (username,))
    if existing:
        return {"success": False, "message": "Username already exists."}

    if role not in ("admin", "viewer"):
        return {"success": False, "message": "Role must be 'admin' or 'viewer'."}

    db.execute(
        "INSERT INTO users(username, password_hash, role) VALUES(?,?,?)",
        (username, hash_password(plain_password), role)
    )
    return {"success": True, "message": f"User '{username}' created with role '{role}'."}


def delete_user(username):
    db.execute("DELETE FROM users WHERE username=?", (username,))
    return {"success": True, "message": f"User '{username}' deleted (if it existed)."}


def list_users():
    rows = db.fetchall("SELECT id, username, role, created_at FROM users ORDER BY created_at")
    return [dict(r) for r in rows]


def authenticate(username, plain_password):
    row = db.fetchone("SELECT * FROM users WHERE username=?", (username,))
    if not row or not verify_password(plain_password, row["password_hash"]):
        return None

    payload = {
        "sub": username,
        "role": row["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return {"token": token, "username": username, "role": row["role"]}


def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
