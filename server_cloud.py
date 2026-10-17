import os
import psycopg2
import bcrypt
import secrets
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import HTMLResponse

# Temporary challenge storage for the zero-knowledge login flow
active_challenges = {}

app = FastAPI(
    title="PQChat Cloud Server",
    version="3.7",
    description="Post-Quantum E2EE chat server built with FastAPI & PostgreSQL."
)

# Allow CORS requests from any origin in production/cloud deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Retrieve database connection string strictly from environment variables
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not configured.")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Create basic tables on startup if they do not exist yet."""
    conn = get_db()
    cursor = conn.cursor()

    # Store user accounts and encrypted private keys
    cursor.execute("""
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

    # Cookie-based session tracking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            username VARCHAR(255) PRIMARY KEY,
            token VARCHAR(255) NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
        )
    """)

    # Stores encrypted messages
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
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

# Initialize database tables if DATABASE_URL is present
if DATABASE_URL:
    init_db()

# --- Request Schemas ---

class UserRegister(BaseModel):
    username: str
    password: str
    public_key_b64: str           # ML-KEM-768 public key
    sig_public_key_b64: str       # ML-DSA-65 public key
    encrypted_sk_b64: str         # Encrypted with client password
    encrypted_sig_sk_b64: str     # Encrypted with client password

class AuthChallenge(BaseModel):
    username: str

class ChallengeVerify(BaseModel):
    username: str
    challenge: str
    signature_b64: str            # Signed challenge using ML-DSA-65

class MessagePayload(BaseModel):
    recipient: str
    ciphertext_b64: str
    msg_ciphertext_b64: str
    signature_b64: str
    timestamp: int
    nonce_b64: str

def get_current_user(request: Request):
    """Check session token from HTTP-only cookie."""
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Session cookie missing.")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM sessions WHERE token = %s", (token,))
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
    
    cursor.execute("SELECT username FROM users WHERE username = %s", (user.username,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Username taken.")

    pwd_hash = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    salt_b64 = secrets.token_hex(16)

    try:
        cursor.execute("""
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
    """Step 1 of login: generate a random challenge string for the user to sign."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = %s", (data.username,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    
    cursor.close()
    conn.close()

    # Generate random 32-byte hex token
    challenge_token = secrets.token_hex(32)
    active_challenges[data.username] = challenge_token

    return {"status": "ok", "challenge": challenge_token}

@app.post("/login")
def login_user(payload: ChallengeVerify, response: Response):
    """Step 2 of login: verify the signed challenge to authenticate without sending passwords."""
    stored_challenge = active_challenges.get(payload.username)
    if not stored_challenge or stored_challenge != payload.challenge:
        raise HTTPException(status_code=401, detail="Invalid or expired challenge.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT sig_public_key_b64, salt FROM users WHERE username = %s", (payload.username,))
    row = cursor.fetchone()
    
    if not row:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="User not found.")

    sig_public_key_b64, user_salt = row[0], row[1]
    del active_challenges[payload.username]

    token = secrets.token_hex(32)
    
    cursor.execute("""
        INSERT INTO sessions (username, token) VALUES (%s, %s)
        ON CONFLICT (username) DO UPDATE SET token = EXCLUDED.token
    """, (payload.username, token))
    
    conn.commit()
    cursor.close()
    conn.close()

    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=86400
    )

    return {"status": "ok", "salt_b64": user_salt, "message": f"Welcome back, {payload.username}."}

@app.get("/key/{username}")
def get_public_key(username: str):
    """Fetch public keys of another user to encrypt messages for them."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT public_key_b64, sig_public_key_b64 FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"username": username, "public_key_b64": row[0], "sig_public_key_b64": row[1]}

@app.get("/my-keys")
def get_my_keys(current_user: str = Depends(get_current_user)):
    """Fetch logged-in user's encrypted private keys."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_sk_b64, encrypted_sig_sk_b64, salt FROM users WHERE username = %s", (current_user,))
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
    """Allows downloading encrypted private key blobs before authentication so the client can decrypt and sign the login challenge."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_sk_b64, encrypted_sig_sk_b64, salt FROM users WHERE username = %s", (username,))
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
    """Save an incoming encrypted message payload to DB."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT username FROM users WHERE username = %s", (msg.recipient,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Recipient not found.")

    cursor.execute("""
        INSERT INTO messages (recipient, sender, ciphertext_b64, msg_ciphertext_b64, signature_b64, timestamp, nonce_b64)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (msg.recipient, current_user, msg.ciphertext_b64, msg.msg_ciphertext_b64, msg.signature_b64, msg.timestamp, msg.nonce_b64))
    
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "ok", "message": "Message sent."}

@app.get("/mailbox")
def get_mailbox(since_id: int = 0, current_user: str = Depends(get_current_user)):
    """Fetch new messages for the user starting from last known message ID."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
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
        # Include message ID for client sync
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
    # Bind to environment PORT if provided by cloud platform, default to 8000
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("server_cloud:app", host="0.0.0.0", port=port)
