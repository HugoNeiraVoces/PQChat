import os
import psycopg2
import bcrypt
import secrets
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from pywebpush import webpush, WebPushException
import json

#In-memory storage for push subscriptions per user
user_push_subscriptions = {}

#Retrieve VAPID private key strictly from environment variables
raw_vapid_key = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_PRIVATE_KEY = raw_vapid_key.replace("\\n", "\n").strip()
VAPID_CLAIMS = {"sub": "mailto:neiravoceshugo@gmail.com"}


#Temporary challenge storage for the zero-knowledge login flow
active_challenges = {}

app = FastAPI(
    title="PQChat Cloud Server",
    version="3.7",
    description="Post-Quantum E2EE chat server built with FastAPI & PostgreSQL."
)

#Serve manifest and service worker directly from root /
@app.get("/manifest.json")
async def get_manifest():
    return FileResponse("manifest.json", media_type="application/manifest+json")

@app.get("/sw.js")
async def get_sw():
    return FileResponse("sw.js", media_type="text/javascript")

@app.get("/.well-known/assetlinks.json")
async def get_assetlinks():
    return FileResponse(".well-known/assetlinks.json", media_type="application/json")

#Serve index.html as the frontend entrypoint
@app.get("/")
async def get_index():
    return FileResponse("index.html", media_type="text/html")

#Serve icons from pictures directory
app.mount("/pictures", StaticFiles(directory="pictures"), name="pictures")

#Allow CORS requests from any origin in production/cloud deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#Retrieve database connection string strictly from environment variables
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not configured.")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Create basic tables on startup if they do not exist yet."""
    conn = get_db()
    cursor = conn.cursor()

    #Store user accounts and encrypted private keys
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

    #Cookie-based session tracking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            username VARCHAR(255) PRIMARY KEY,
            token VARCHAR(255) NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
        )
    """)

    #Stores encrypted messages
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_users (
            id SERIAL PRIMARY KEY,
            blocker VARCHAR(255) NOT NULL,
            blocked VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(blocker, blocked),
            FOREIGN KEY(blocker) REFERENCES users(username) ON DELETE CASCADE,
            FOREIGN KEY(blocked) REFERENCES users(username) ON DELETE CASCADE
        )
    """)
    
    conn.commit()
    cursor.close()
    conn.close()

#Initialize database tables if DATABASE_URL is present
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

class BlockPayload(BaseModel):
    username: str

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

    #Generate random 32-byte hex token
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
    

@app.post("/subscribe-push")
async def subscribe_push(data: dict):
    username = data.get("username")
    subscription = data.get("subscription")
    if username and subscription:
        user_push_subscriptions[username] = subscription
        return {"status": "ok"}
    return {"status": "error"}

def send_push_notification(recipient_username, sender_username):
    #Avoid sending push notification if user self-sends a synchronization copy
    if recipient_username == sender_username:
        return

    sub = user_push_subscriptions.get(recipient_username)
    if not sub:
        return

    key_file_path = "vapid_private.pem"
    if not os.path.exists(key_file_path):
        with open(key_file_path, "w") as f:
            f.write(VAPID_PRIVATE_KEY.strip())

    try:
        webpush(
            subscription_info=sub,
            data=json.dumps({
                "title": f"New message from {sender_username}",
                "body": "You have a new message on PQChat",
                "tag": f"msg-{sender_username}"
            }),
            vapid_private_key=key_file_path,
            vapid_claims=VAPID_CLAIMS,
            headers={
                "Urgency": "high",
                "TTL": "86400"
            }
        )
    except Exception as ex:
        print(f"Error en WebPush: {ex}")
        

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
        SELECT 1 FROM blocked_users 
        WHERE (blocker = %s AND blocked = %s) OR (blocker = %s AND blocked = %s)
    """, (current_user, msg.recipient, msg.recipient, current_user))
    
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=403, detail="Sending blocked: a blocking restriction exists between users.")
    
    cursor.execute("""
        INSERT INTO messages (recipient, sender, ciphertext_b64, msg_ciphertext_b64, signature_b64, timestamp, nonce_b64)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (msg.recipient, current_user, msg.ciphertext_b64, msg.msg_ciphertext_b64, msg.signature_b64, msg.timestamp, msg.nonce_b64))

    #Commit message to database first
    conn.commit()
    cursor.close()
    conn.close()

    #Trigger push notification securely
    try:
        send_push_notification(msg.recipient, current_user)
    except Exception as e:
        print(f"Secondary error processing WebPush: {e}")

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
        #Include message ID for client sync
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

@app.post("/block")
def block_user(payload: BlockPayload, current_user: str = Depends(get_current_user)):
    """Block a user to prevent incoming/outgoing messages."""
    if payload.username == current_user:
        raise HTTPException(status_code=400, detail="You cannot block yourself.")
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT username FROM users WHERE username = %s", (payload.username,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        cursor.execute("""
            INSERT INTO blocked_users (blocker, blocked) VALUES (%s, %s)
            ON CONFLICT (blocker, blocked) DO NOTHING
        """, (current_user, payload.username))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    return {"status": "ok", "message": f"User {payload.username} blocked successfully."}

@app.delete("/block/{username}")
def unblock_user(username: str, current_user: str = Depends(get_current_user)):
    """Unblock a previously blocked user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM blocked_users WHERE blocker = %s AND blocked = %s
    """, (current_user, username))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "ok", "message": f"User {username} unblocked."}

@app.get("/blocked-list")
def get_blocked_list(current_user: str = Depends(get_current_user)):
    """Retrieve the list of users blocked by the current user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT blocked FROM blocked_users WHERE blocker = %s", (current_user,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return {"blocked": [row[0] for row in rows]}

@app.delete("/messages/{message_id}")
def delete_message(message_id: int, current_user: str = Depends(get_current_user)):
    """Delete a specific individual message."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT sender, recipient FROM messages WHERE id = %s", (message_id,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Message not found.")
    
    sender, recipient = row
    if sender != current_user and recipient != current_user:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=403, detail="You do not have permission to delete this message.")

    cursor.execute("DELETE FROM messages WHERE id = %s", (message_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return {"status": "ok", "message": "Message deleted successfully."}

@app.delete("/chat/{other_username}")
def clear_chat(other_username: str, current_user: str = Depends(get_current_user)):
    """Clear entire chat history between current user and another user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM messages 
        WHERE (sender = %s AND recipient = %s) OR (sender = %s AND recipient = %s)
    """, (current_user, other_username, other_username, current_user))
    
    conn.commit()
    cursor.close()
    conn.close()

    return {"status": "ok", "message": f"Chat history with {other_username} cleared."}


@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    #Bind to environment PORT if provided by cloud platform, default to 8000
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("server_cloud:app", host="0.0.0.0", port=port)
