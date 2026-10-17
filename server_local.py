import os
import sqlite3
import bcrypt
import secrets
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import HTMLResponse

active_challenges = {}

app = FastAPI(
    title="PQChat Local Server",
    version="1.0-local",
    description="Local development backend running on SQLite."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "local_pqchat.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def execute_query(cursor, query, params=()):
    #SQLite query wrapper
    formatted_query = query.replace("%s", "?")
    cursor.execute(formatted_query, params)
    return cursor

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    execute_query(cursor, """
        CREATE TABLE IF NOT EXISTS users (
            username VARCHAR(255) PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            public_key_b64 TEXT NOT NULL,
            sig_public_key_b64 TEXT NOT NULL,
            encrypted_sk_b64 TEXT NOT NULL,
            encrypted_sig_sk_b64 TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    execute_query(cursor, """
        CREATE TABLE IF NOT EXISTS sessions (
            username VARCHAR(255) PRIMARY KEY,
            token VARCHAR(255) NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
        )
    """)

    execute_query(cursor, """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient VARCHAR(255) NOT NULL,
            sender VARCHAR(255) NOT NULL,
            ciphertext_b64 TEXT NOT NULL,
            msg_ciphertext_b64 TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            timestamp BIGINT NOT NULL,
            nonce_b64 TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    cursor.close()
    conn.close()

init_db()

# --- Request Schemas ---

class UserRegister(BaseModel):
    username: str
    password: str
    public_key_b64: str
    sig_public_key_b64: str
    encrypted_sk_b64: str
    encrypted_sig_sk_b64: str

class AuthChallenge(BaseModel):
    username: str

class ChallengeVerify(BaseModel):
    username: str
    challenge: str
    signature_b64: str

class MessagePayload(BaseModel):
    recipient: str
    ciphertext_b64: str
    msg_ciphertext_b64: str
    signature_b64: str
    timestamp: int
    nonce_b64: str

def get_current_user(request: Request):
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Session cookie missing.")
    
    conn = get_db()
    cursor = conn.cursor()
    execute_query(cursor, "SELECT username FROM sessions WHERE token = %s", (token,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    return row[0]

# --- Routes ---

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegister):
    conn = get_db()
    cursor = conn.cursor()
    
    execute_query(cursor, "SELECT username FROM users WHERE username = %s", (user.username,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Username taken.")

    pwd_hash = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    salt_b64 = secrets.token_hex(16)

    try:
        execute_query(cursor, """
            INSERT INTO users (username, password_hash, salt, public_key_b64, sig_public_key_b64, encrypted_sk_b64, encrypted_sig_sk_b64)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user.username, pwd_hash, salt_b64, user.public_key_b64, user.sig_public_key_b64, user.encrypted_sk_b64, user.encrypted_sig_sk_b64))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    return {"status": "ok", "message": f"User '{user.username}' registered successfully."}

@app.post("/auth/challenge")
def get_auth_challenge(data: AuthChallenge):
    conn = get_db()
    cursor = conn.cursor()
    execute_query(cursor, "SELECT username FROM users WHERE username = %s", (data.username,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    
    cursor.close()
    conn.close()

    challenge_token = secrets.token_hex(32)
    active_challenges[data.username] = challenge_token

    return {"status": "ok", "challenge": challenge_token}

@app.post("/login")
def login_user(payload: ChallengeVerify, response: Response):
    stored_challenge = active_challenges.get(payload.username)
    if not stored_challenge or stored_challenge != payload.challenge:
        raise HTTPException(status_code=401, detail="Invalid or expired challenge.")

    conn = get_db()
    cursor = conn.cursor()
    execute_query(cursor, "SELECT sig_public_key_b64, salt FROM users WHERE username = %s", (payload.username,))
    row = cursor.fetchone()
    
    if not row:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="User not found.")

    sig_public_key_b64, user_salt = row[0], row[1]
    del active_challenges[payload.username]

    token = secrets.token_hex(32)
    
    execute_query(cursor, "DELETE FROM sessions WHERE username = %s", (payload.username,))
    execute_query(cursor, "INSERT INTO sessions (username, token) VALUES (%s, %s)", (payload.username, token))
    
    conn.commit()
    cursor.close()
    conn.close()

    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=86400
    )

    return {"status": "ok", "salt_b64": user_salt, "message": f"Welcome back, {payload.username}."}

@app.get("/key/{username}")
def get_public_key(username: str):
    conn = get_db()
    cursor = conn.cursor()
    execute_query(cursor, "SELECT public_key_b64, sig_public_key_b64 FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"username": username, "public_key_b64": row[0], "sig_public_key_b64": row[1]}

@app.get("/my-keys")
def get_my_keys(current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    execute_query(cursor, "SELECT encrypted_sk_b64, encrypted_sig_sk_b64, salt FROM users WHERE username = %s", (current_user,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if row:
        return {
            "encrypted_sk_b64": row[0],
            "encrypted_sig_sk_b64": row[1],
            "salt_b64": row[2]
        }
    raise HTTPException(status_code=404, detail="User not found.")

@app.get("/my-keys-unauth/{username}")
def get_my_keys_unauth(username: str):
    conn = get_db()
    cursor = conn.cursor()
    execute_query(cursor, "SELECT encrypted_sk_b64, encrypted_sig_sk_b64, salt FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if row:
        return {
            "encrypted_sk_b64": row[0],
            "encrypted_sig_sk_b64": row[1],
            "salt_b64": row[2]
        }
    raise HTTPException(status_code=404, detail="User not found.")

@app.post("/send")
def send_message(msg: MessagePayload, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    execute_query(cursor, "SELECT username FROM users WHERE username = %s", (msg.recipient,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Recipient not found.")

    execute_query(cursor, """
        INSERT INTO messages (recipient, sender, ciphertext_b64, msg_ciphertext_b64, signature_b64, timestamp, nonce_b64)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (msg.recipient, current_user, msg.ciphertext_b64, msg.msg_ciphertext_b64, msg.signature_b64, msg.timestamp, msg.nonce_b64))
    
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "ok", "message": "Message sent."}

@app.get("/mailbox")
def get_mailbox(since_id: int = 0, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    execute_query(cursor, """
        SELECT id, sender, recipient, ciphertext_b64, msg_ciphertext_b64, signature_b64, timestamp, nonce_b64 
        FROM messages 
        WHERE (recipient = %s OR sender = %s) AND id > %s
        ORDER BY id ASC
    """, (current_user, current_user, since_id))
    
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    messages = []
    for row in rows:
        messages.append({
            "id": row[0],
            "sender": row[1],
            "recipient": row[2],
            "ciphertext_b64": row[3],
            "msg_ciphertext_b64": row[4],
            "signature_b64": row[5],
            "timestamp": row[6],
            "nonce_b64": row[7]
        })

    return {"messages": messages}

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    print(f"PQChat Local Server running at: http://127.0.0.1:8000\n")
    uvicorn.run("server_local:app", host="0.0.0.0", port=8000, reload=True)
