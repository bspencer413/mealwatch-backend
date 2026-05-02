from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import psycopg2
import psycopg2.extras
import os
import json
import bcrypt
import jwt
import requests
from contextlib import contextmanager
from typing import Optional

# ── DB CREDS (hardcoded, MW pattern) ──────────────────────────────────────────
DB_HOST = "dpg-d7r4tdmgvqtc73b9p0qg-a.oregon-postgres.render.com"
DB_USER = "mealwatch_db_user"
DB_PASS = "J9WhUMsdW7SMUrKJwhgT48I73Jn0YmhM"
DB_NAME = "mealwatch_db"
DATABASE_URL = "postgresql://" + DB_USER + ":" + DB_PASS + "@" + DB_HOST + "/" + DB_NAME

# ── ENV VARS (set in Render) ──────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
OPENFDA_KEY = os.environ.get("OPENFDA_KEY", "")
USDA_FDC_KEY = os.environ.get("USDA_FDC_KEY", "")

API_VERSION = "0.1.3"
JWT_ALGO = "HS256"
JWT_EXPIRY_DAYS = 7
INGEST_WINDOW_DAYS = 90

app = FastAPI(title="Mealwatch API", version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── DB HELPERS ────────────────────────────────────────────────────────────────
@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS watchlist (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                kind TEXT DEFAULT 'product',
                brand TEXT NOT NULL,
                product_name TEXT,
                upc TEXT,
                monitoring BOOLEAN DEFAULT TRUE,
                has_recall BOOLEAN DEFAULT FALSE,
                last_recall_id TEXT,
                last_checked TIMESTAMP,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                watchlist_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                email_sent BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (watchlist_id) REFERENCES watchlist (id)
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS recalls (
                id SERIAL PRIMARY KEY,
                source TEXT NOT NULL,
                recall_id TEXT UNIQUE NOT NULL,
                brand TEXT,
                product_description TEXT,
                upc TEXT,
                classification TEXT,
                reason TEXT,
                recall_date TEXT,
                distribution TEXT,
                lot_codes TEXT,
                status TEXT,
                raw_json TEXT,
                fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_recalls_brand ON recalls (brand)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_recalls_upc ON recalls (upc)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_watchlist_user ON watchlist (user_id)")
            conn.commit()
            print("[init_db] tables ready")
    except Exception as e:
        print("[init_db] WARNING: " + str(e))


# ── AUTH HELPERS ──────────────────────────────────────────────────────────────
def hash_password(pw):
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(pw, hashed):
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def make_jwt(user_id, email):
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY_DAYS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)


def decode_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
    except Exception:
        return None


def require_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    token = authorization[7:]
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


def require_admin(x_admin_key: Optional[str] = Header(None)):
    if not x_admin_key or x_admin_key != SECRET_KEY:
        raise HTTPException(status_code=403, detail="Admin key required")
    return True


# ── MODELS ────────────────────────────────────────────────────────────────────
class RegisterIn(BaseModel):
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


# ── HEALTH ────────────────────────────────────────────────────────────────────
@app.api_route("/health", methods=["GET", "HEAD"])
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat(), "version": API_VERSION}


# ── AUTH ENDPOINTS ────────────────────────────────────────────────────────────
@app.post("/auth/register")
async def register(body: RegisterIn):
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE email = %s", (body.email,))
            if c.fetchone():
                raise HTTPException(status_code=409, detail="Email already registered")
            ph = hash_password(body.password)
            c.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id",
                      (body.email, ph))
            uid = c.fetchone()[0]
            conn.commit()
            return {"token": make_jwt(uid, body.email), "user_id": uid, "email": body.email}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Register failed: " + str(e))


@app.post("/auth/login")
async def login(body: LoginIn):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id, password_hash FROM users WHERE email = %s", (body.email,))
            row = c.fetchone()
            if not row or not verify_password(body.password, row[1]):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            uid = row[0]
            return {"token": make_jwt(uid, body.email), "user_id": uid, "email": body.email}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Login failed: " + str(e))


@app.get("/account")
async def account(user=Depends(require_user)):
    return {"user_id": user["user_id"], "email": user["email"]}


# ── RECALL INGEST ─────────────────────────────────────────────────────────────
def ingest_openfda(window_days=INGEST_WINDOW_DAYS):
    cutoff = (datetime.utcnow() - timedelta(days=window_days)).strftime("%Y%m%d")
    today = datetime.utcnow().strftime("%Y%m%d")
    url = "https://api.fda.gov/food/enforcement.json"
    # NOTE: openFDA needs literal '+TO+' in the search string. Build URL manually
    # since requests will URL-encode the '+' as '%2B' if passed via params.
    search_str = "report_date:[" + cutoff + "+TO+" + today + "]"
    full_url = url + "?search=" + search_str + "&limit=1000"
    if OPENFDA_KEY:
        full_url = full_url + "&api_key=" + OPENFDA_KEY
    headers = {"User-Agent": "Mozilla/5.0 (mealwatch/0.1.2)"}
    inserted = 0
    skipped = 0
    try:
        r = requests.get(full_url, headers=headers, timeout=30)
        if r.status_code != 200:
            return {"source": "openfda", "error": "HTTP " + str(r.status_code),
                    "url": full_url[:200], "body": r.text[:300], "inserted": 0}
        data = r.json()
        results = data.get("results", [])
        with get_db() as conn:
            c = conn.cursor()
            for rec in results:
                rid = "fda_" + (rec.get("recall_number") or rec.get("event_id") or "")
                if rid == "fda_":
                    skipped = skipped + 1
                    continue
                brand = (rec.get("recalling_firm") or "").strip()
                desc = (rec.get("product_description") or "").strip()
                cls = (rec.get("classification") or "").replace("Class ", "").strip()
                reason = (rec.get("reason_for_recall") or "").strip()
                rdate = (rec.get("recall_initiation_date") or rec.get("report_date") or "").strip()
                dist = (rec.get("distribution_pattern") or "").strip()
                lots = (rec.get("code_info") or "").strip()
                status = (rec.get("status") or "").strip()
                try:
                    c.execute("""INSERT INTO recalls (source, recall_id, brand, product_description, upc,
                        classification, reason, recall_date, distribution, lot_codes, status, raw_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (recall_id) DO UPDATE SET
                            status = EXCLUDED.status, fetched_at = CURRENT_TIMESTAMP""",
                        ("fda", rid, brand, desc, "", cls, reason, rdate, dist, lots, status, json.dumps(rec)))
                    inserted = inserted + 1
                except Exception as e:
                    skipped = skipped + 1
                    print("[openfda] skip " + rid + ": " + str(e))
            conn.commit()
        return {"source": "openfda", "fetched": len(results), "inserted": inserted, "skipped": skipped}
    except Exception as e:
        return {"source": "openfda", "error": str(e), "inserted": inserted}


def ingest_fsis(window_days=INGEST_WINDOW_DAYS):
    cutoff = datetime.utcnow() - timedelta(days=window_days)
    url = "https://www.fsis.usda.gov/fsis/api/recall/v/1"
    inserted = 0
    skipped = 0
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            return {"source": "fsis", "error": "HTTP " + str(r.status_code),
                    "body": r.text[:300], "inserted": 0}
        data = r.json()
        with get_db() as conn:
            c = conn.cursor()
            for rec in data:
                rdate_str = (rec.get("field_recall_date") or "").strip()
                try:
                    rdate = datetime.strptime(rdate_str[:10], "%Y-%m-%d")
                    if rdate < cutoff:
                        continue
                except Exception:
                    pass
                rnum = (rec.get("field_recall_number") or "").strip()
                if not rnum:
                    skipped = skipped + 1
                    continue
                rid = "fsis_" + rnum
                brand = (rec.get("field_establishment") or "").strip()
                desc = (rec.get("field_product_items") or rec.get("field_summary") or "").strip()
                cls = (rec.get("field_recall_classification") or "").replace("Class ", "").strip()
                reason = (rec.get("field_recall_reason") or "").strip()
                dist = (rec.get("field_states") or "").strip()
                status = (rec.get("field_active_notice") or "").strip()
                try:
                    c.execute("""INSERT INTO recalls (source, recall_id, brand, product_description, upc,
                        classification, reason, recall_date, distribution, lot_codes, status, raw_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (recall_id) DO UPDATE SET
                            status = EXCLUDED.status, fetched_at = CURRENT_TIMESTAMP""",
                        ("fsis", rid, brand, desc, "", cls, reason, rdate_str, dist, "", status, json.dumps(rec)))
                    inserted = inserted + 1
                except Exception as e:
                    skipped = skipped + 1
                    print("[fsis] skip " + rid + ": " + str(e))
            conn.commit()
        return {"source": "fsis", "fetched": len(data), "inserted": inserted, "skipped": skipped}
    except Exception as e:
        return {"source": "fsis", "error": str(e), "inserted": inserted}


@app.post("/admin/refresh-recalls")
async def admin_refresh_recalls(_admin=Depends(require_admin)):
    fda_res = ingest_openfda()
    # FSIS disabled in v0.1.3 — Akamai blocks server-side requests.
    # Plan: re-enable via RSS feed in v0.2.
    fsis_res = {"source": "fsis", "status": "disabled", "note": "deferred to v0.2"}
    return {"fda": fda_res, "fsis": fsis_res, "ts": datetime.now().isoformat()}


@app.get("/admin/recall-count")
async def admin_recall_count(_admin=Depends(require_admin)):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT source, COUNT(*) FROM recalls GROUP BY source")
            rows = c.fetchall()
            return {"counts": {row[0]: row[1] for row in rows}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── SEARCH ────────────────────────────────────────────────────────────────────
def score_recall_match(recall, query):
    q = (query or "").lower().strip()
    if not q:
        return 0
    brand = (recall.get("brand") or "").lower()
    desc = (recall.get("product_description") or "").lower()
    score = 0
    if q in brand:
        score = score + (50 if brand == q else 30)
    if q in desc:
        score = score + (15 if len(q) > 3 else 5)
    if (recall.get("classification") or "").startswith("I"):
        score = score + 5
    return score


@app.get("/search")
async def search(q: str = ""):
    q = (q or "").strip()
    if len(q) < 2:
        raise HTTPException(status_code=400, detail="Query must be at least 2 characters")
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            like = "%" + q + "%"
            c.execute("""SELECT id, source, recall_id, brand, product_description, upc, classification,
                    reason, recall_date, distribution, lot_codes, status, fetched_at
                FROM recalls
                WHERE brand ILIKE %s OR product_description ILIKE %s
                ORDER BY recall_date DESC NULLS LAST
                LIMIT 200""", (like, like))
            rows = c.fetchall()
            scored = []
            for row in rows:
                d = dict(row)
                if d.get("fetched_at"):
                    d["fetched_at"] = d["fetched_at"].isoformat()
                d["_score"] = score_recall_match(d, q)
                scored.append(d)
            scored.sort(key=lambda x: (-x["_score"], x.get("recall_date") or ""))
            scored = [s for s in scored if s["_score"] >= 5][:50]
            return {"query": q, "count": len(scored), "results": scored}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Search failed: " + str(e))


# ── STARTUP ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    init_db()
    print("Mealwatch API v" + API_VERSION + " started")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
