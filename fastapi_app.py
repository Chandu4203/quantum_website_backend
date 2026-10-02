import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import psycopg
from dotenv import load_dotenv
from fastapi import Cookie, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent
FRONTEND_ROOT = ROOT.parent / "frontend"
load_dotenv(ROOT / ".env")

JWT_SECRET = os.getenv("JWT_SECRET", "project-pulse-development-secret-change-me")
PORT = int(os.getenv("PORT", "4204"))
DATABASE_CONFIG = {
    "host": os.getenv("PGHOST", "localhost"),
    "port": int(os.getenv("PGPORT", "5432")),
    "dbname": os.getenv("PGDATABASE", "Quantum_Computing"),
    "user": os.getenv("PGUSER", "postgres"),
    "password": os.getenv("PGPASSWORD", ""),
    "sslmode": "require" if os.getenv("DATABASE_SSL", "false").lower() == "true" else "disable",
}

app = FastAPI(title="Project Pulse API")

MEMBERS = {
    "23BQ1A4202": ("A.Sai Charan", "23BQ1A4202"),
    "23BQ1A4231": ("CH.Aparna", "23BQ1A4231"),
    "23BQ1A4251": ("G.Kamesh", "23BQ1A4251"),
    "24BQ5A4203": ("K.chandra sekhar", "24BQ5A4203"),
}


class LoginRequest(BaseModel):
    username: str
    password: str


class ResultRequest(BaseModel):
    score: int
    totalQuestions: int
    durationSeconds: int


def db():
    return psycopg.connect(**DATABASE_CONFIG)


def db_execute(connection, query: str, params: tuple = ()):
    return connection.execute(query, params)


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=64).hex()
    return f"{salt}:{digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, expected = stored.split(":", 1)
    actual = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=64).hex()
    return hmac.compare_digest(actual, expected)


def public_user(row):
    return {"email": row[1], "username": row[2], "displayName": row[3]}


def current_user(token: str | None):
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError):
        return None
    with db() as connection:
        return db_execute(connection, "SELECT id, email, username, display_name FROM users WHERE id = %s", (user_id,)).fetchone()


def initialize_database():
    with db() as connection:
        db_execute(connection, """
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db_execute(connection, """
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id),
                score INTEGER NOT NULL CHECK (score >= 0),
                total_questions INTEGER NOT NULL CHECK (total_questions > 0),
                duration_seconds INTEGER NOT NULL CHECK (duration_seconds >= 0),
                completed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db_execute(connection, "CREATE INDEX IF NOT EXISTS quiz_attempts_user_id_idx ON quiz_attempts(user_id)")
        for username, (display_name, password) in MEMBERS.items():
            db_execute(connection, """
                INSERT INTO users (email, username, display_name, password_hash)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT(username) DO UPDATE SET
                    display_name = excluded.display_name,
                    password_hash = excluded.password_hash
            """, (f"{username}@project.local", username, display_name, hash_password(password)))
        connection.commit()


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/")
def index():
    return FileResponse(FRONTEND_ROOT / "index.html")


@app.post("/api/login")
def login(payload: LoginRequest, response: Response):
    with db() as connection:
        row = db_execute(connection, "SELECT id, email, username, display_name, password_hash FROM users WHERE username = %s", (payload.username.strip(),)).fetchone()
    if not row or not verify_password(payload.password, row[4]):
        raise HTTPException(status_code=401, detail="That username or password is not recognised.")
    token = jwt.encode({"sub": str(row[0]), "exp": datetime.now(timezone.utc) + timedelta(hours=8)}, JWT_SECRET, algorithm="HS256")
    response.set_cookie("project_pulse_token", token, httponly=True, samesite="lax", max_age=28800)
    return {"user": public_user(row)}


@app.get("/api/me")
def me(project_pulse_token: str | None = Cookie(default=None)):
    user = current_user(project_pulse_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return {"user": public_user(user)}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("project_pulse_token")
    return {"ok": True}


@app.post("/api/results", status_code=201)
def save_result(payload: ResultRequest, project_pulse_token: str | None = Cookie(default=None)):
    user = current_user(project_pulse_token)
    if not user:
        raise HTTPException(status_code=401, detail="Your session has expired.")
    if payload.score < 0 or payload.totalQuestions < 1 or payload.score > payload.totalQuestions or payload.durationSeconds < 0:
        raise HTTPException(status_code=400, detail="Invalid quiz result.")
    with db() as connection:
        cursor = db_execute(connection, """
            INSERT INTO quiz_attempts (user_id, score, total_questions, duration_seconds)
            VALUES (%s, %s, %s, %s)
        """, (user[0], payload.score, payload.totalQuestions, payload.durationSeconds))
        connection.commit()
        result = (cursor.lastrowid, datetime.now(timezone.utc))
    if result is None:
        raise HTTPException(status_code=500, detail="Result could not be saved.")
    return {"result": {"id": str(result[0]), "completed_at": result[1]}}


@app.get("/{file_path:path}")
def static_file(file_path: str):
    requested = (FRONTEND_ROOT / file_path).resolve()
    if not requested.is_relative_to(FRONTEND_ROOT) or not requested.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(requested)
