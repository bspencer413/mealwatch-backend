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
import threading
import time as time_mod
import schedule
from contextlib import contextmanager
from typing import Optional, List

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

API_VERSION = "0.1.9"
JWT_ALGO = "HS256"
JWT_EXPIRY_DAYS = 7
INGEST_WINDOW_DAYS = 90
WATCHLIST_CHECK_INTERVAL_HOURS = 12  # free tier; premium will be 1hr

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
            # pg_trgm enables fuzzy similarity for /suggest endpoint (v0.1.6+)
            try:
                c.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
            except Exception as ex:
                print("[init_db] pg_trgm note: " + str(ex))
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


@app.get("/suggest")
async def suggest(q: str = ""):
    """Return up to 5 distinct brand strings from recalls that fuzzily match q.
    Scores against each TOKEN within the brand (e.g. 'Reser's', 'Fine', 'Foods')
    rather than the full company string, so 'Resar' can match 'Reser's Fine Foods, Inc.'
    Used by frontend when /search returns zero results."""
    q = (q or "").strip()
    if len(q) < 2:
        return {"query": q, "suggestions": []}
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # Tokenize each brand on whitespace and punctuation, score q against
            # each token, take MAX. unnest+regexp_split lets us inline this in SQL.
            # Threshold 0.35 keeps real typos (Resar→Reser) and rejects junk.
            c.execute("""
                SELECT brand, MAX(sim) AS sim FROM (
                    SELECT brand,
                        similarity(LOWER(token), LOWER(%s)) AS sim
                    FROM (
                        SELECT brand,
                            unnest(regexp_split_to_array(brand, '[\\s,.;:/&()'']+')) AS token
                        FROM recalls
                        WHERE brand IS NOT NULL AND brand <> ''
                    ) t
                    WHERE LENGTH(token) >= 2
                ) s
                WHERE sim > 0.3
                GROUP BY brand
                ORDER BY sim DESC
                LIMIT 5
            """, (q,))
            rows = c.fetchall()
            sugg = []
            for row in rows:
                sugg.append({"brand": row["brand"], "score": float(row["sim"])})
            return {"query": q, "suggestions": sugg}
    except Exception as e:
        print("[suggest] " + str(e))
        return {"query": q, "suggestions": [], "note": "trigram unavailable"}


@app.get("/recalls/recent")
async def recent_recalls(limit: int = 25):
    """Most recent FDA recalls, Class I + II only (the dangerous ones).
    Sorted by recall_date descending. Used by the Search page 'Latest recalls' view."""
    if limit < 1: limit = 1
    if limit > 100: limit = 100
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            c.execute("""SELECT id, source, recall_id, brand, product_description, upc,
                    classification, reason, recall_date, distribution, lot_codes,
                    status, fetched_at
                FROM recalls
                WHERE classification IN ('I', 'II', 'Class I', 'Class II')
                  OR classification ILIKE 'I' OR classification ILIKE 'II'
                ORDER BY recall_date DESC NULLS LAST
                LIMIT %s""", (limit,))
            rows = c.fetchall()
            out = []
            for row in rows:
                d = dict(row)
                if d.get("fetched_at"):
                    d["fetched_at"] = d["fetched_at"].isoformat()
                out.append(d)
            return {"count": len(out), "results": out}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Recent recalls failed: " + str(e))


# ── WATCHLIST MODELS ──────────────────────────────────────────────────────────
class WatchlistAddIn(BaseModel):
    brand: str
    product_name: Optional[str] = None
    upc: Optional[str] = None
    monitoring: bool = True  # True = Watchlist; False = Pantry (saved, no alerts)


class WatchlistMoveIn(BaseModel):
    monitoring: bool


# ── WATCHLIST HELPERS ─────────────────────────────────────────────────────────
def find_best_recall_for_watch(conn, brand, product_name, upc):
    """Return best matching recall row for a watch entry, or None.
    Checks UPC first (exact), then brand+product (fuzzy via ILIKE + scoring)."""
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # UPC exact match (when both have it)
    if upc:
        c.execute("SELECT * FROM recalls WHERE upc = %s LIMIT 1", (upc,))
        row = c.fetchone()
        if row:
            return dict(row)
    # Brand-based fuzzy
    if brand:
        like = "%" + brand + "%"
        c.execute("""SELECT * FROM recalls
            WHERE brand ILIKE %s OR product_description ILIKE %s
            ORDER BY recall_date DESC NULLS LAST LIMIT 50""", (like, like))
        rows = c.fetchall()
        best = None
        best_score = 0
        for row in rows:
            d = dict(row)
            s = 0
            b = (d.get("brand") or "").lower()
            desc = (d.get("product_description") or "").lower()
            br = (brand or "").lower()
            pn = (product_name or "").lower()
            if br and br in b:
                s = s + (50 if b == br else 30)
            if pn and pn in desc:
                s = s + 20
            elif pn and pn in b:
                s = s + 10
            if (d.get("classification") or "").startswith("I"):
                s = s + 5
            # require brand to actually match — don't surface unrelated recalls
            if br and br not in b and br not in desc:
                continue
            if s > best_score:
                best_score = s
                best = d
        # threshold for "this is a real match"
        if best and best_score >= 30:
            return best
    return None


def serialize_recall(d):
    """Make a recall dict JSON-safe."""
    if not d:
        return None
    out = {}
    for k, v in d.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


# ── WATCHLIST CRUD ────────────────────────────────────────────────────────────
@app.get("/watchlist")
async def list_watchlist(user=Depends(require_user)):
    """Return all active watchlist entries for the current user."""
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            c.execute("""SELECT id, brand, product_name, upc, monitoring, has_recall,
                last_recall_id, last_checked, created_at
                FROM watchlist
                WHERE user_id = %s AND status = 'active'
                ORDER BY created_at DESC""", (user["user_id"],))
            rows = c.fetchall()
            out = []
            for row in rows:
                d = dict(row)
                if d.get("last_checked"):
                    d["last_checked"] = d["last_checked"].isoformat()
                if d.get("created_at"):
                    d["created_at"] = d["created_at"].isoformat()
                out.append(d)
            return {"items": out, "count": len(out)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="List watchlist failed: " + str(e))


@app.post("/watchlist")
async def add_watchlist(body: WatchlistAddIn, user=Depends(require_user)):
    """Add a new entry. monitoring=True → Watchlist; False → Pantry."""
    brand = (body.brand or "").strip()
    if not brand:
        raise HTTPException(status_code=400, detail="brand is required")
    product_name = (body.product_name or "").strip() or None
    upc = (body.upc or "").strip() or None
    try:
        with get_db() as conn:
            c = conn.cursor()
            # de-dupe: same user + brand + product_name + upc + active
            c.execute("""SELECT id FROM watchlist
                WHERE user_id = %s AND brand = %s
                AND COALESCE(product_name,'') = COALESCE(%s,'')
                AND COALESCE(upc,'') = COALESCE(%s,'')
                AND status = 'active'""",
                (user["user_id"], brand, product_name, upc))
            existing = c.fetchone()
            if existing:
                return {"id": existing[0], "duplicate": True}
            kind = "brand" if not product_name and not upc else "product"
            c.execute("""INSERT INTO watchlist (user_id, kind, brand, product_name, upc, monitoring)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (user["user_id"], kind, brand, product_name, upc, body.monitoring))
            new_id = c.fetchone()[0]
            conn.commit()
            return {"id": new_id, "monitoring": body.monitoring, "duplicate": False}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Add watchlist failed: " + str(e))


@app.delete("/watchlist/{item_id}")
async def delete_watchlist(item_id: int, user=Depends(require_user)):
    """Soft-delete a watchlist entry (status='deleted') and clear notifications."""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM watchlist WHERE id = %s AND user_id = %s",
                      (item_id, user["user_id"]))
            if not c.fetchone():
                raise HTTPException(status_code=404, detail="Not found")
            c.execute("UPDATE watchlist SET status = 'deleted' WHERE id = %s", (item_id,))
            c.execute("DELETE FROM notifications WHERE watchlist_id = %s", (item_id,))
            conn.commit()
            return {"deleted": item_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Delete failed: " + str(e))


@app.patch("/watchlist/{item_id}/move")
async def move_watchlist(item_id: int, body: WatchlistMoveIn, user=Depends(require_user)):
    """Toggle monitoring flag. True = Watchlist (alerts on); False = Pantry (alerts off)."""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM watchlist WHERE id = %s AND user_id = %s AND status = 'active'",
                      (item_id, user["user_id"]))
            if not c.fetchone():
                raise HTTPException(status_code=404, detail="Not found")
            c.execute("UPDATE watchlist SET monitoring = %s WHERE id = %s",
                      (body.monitoring, item_id))
            # if moved to Pantry, clear stale notifications for this item
            if body.monitoring is False:
                c.execute("DELETE FROM notifications WHERE watchlist_id = %s", (item_id,))
            conn.commit()
            return {"id": item_id, "monitoring": body.monitoring}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Move failed: " + str(e))


@app.get("/watchlist/{item_id}/refresh")
async def refresh_watchlist_item(item_id: int, user=Depends(require_user)):
    """On-demand recheck for a single watchlist item — used by the drawer."""
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            c.execute("""SELECT id, brand, product_name, upc, monitoring
                FROM watchlist WHERE id = %s AND user_id = %s AND status = 'active'""",
                (item_id, user["user_id"]))
            wrow = c.fetchone()
            if not wrow:
                raise HTTPException(status_code=404, detail="Not found")
            best = find_best_recall_for_watch(conn, wrow["brand"], wrow["product_name"], wrow["upc"])
            now = datetime.utcnow()
            has_recall = best is not None
            last_recall_id = best["recall_id"] if best else None
            uc = conn.cursor()
            uc.execute("""UPDATE watchlist
                SET has_recall = %s, last_recall_id = %s, last_checked = %s
                WHERE id = %s""", (has_recall, last_recall_id, now, item_id))
            conn.commit()
            return {
                "id": item_id,
                "has_recall": has_recall,
                "recall": serialize_recall(best),
                "last_checked": now.isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Refresh failed: " + str(e))


# ── NOTIFICATIONS ─────────────────────────────────────────────────────────────
@app.get("/notifications")
async def list_notifications(user=Depends(require_user)):
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            c.execute("""SELECT n.id, n.watchlist_id, n.message, n.email_sent, n.created_at,
                w.brand, w.product_name, w.last_recall_id
                FROM notifications n
                LEFT JOIN watchlist w ON w.id = n.watchlist_id
                WHERE n.user_id = %s
                ORDER BY n.created_at DESC""", (user["user_id"],))
            rows = c.fetchall()
            out = []
            for row in rows:
                d = dict(row)
                if d.get("created_at"):
                    d["created_at"] = d["created_at"].isoformat()
                out.append(d)
            return {"items": out, "count": len(out)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="List notifications failed: " + str(e))


@app.delete("/notifications/{notif_id}")
async def delete_notification(notif_id: int, user=Depends(require_user)):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM notifications WHERE id = %s AND user_id = %s",
                      (notif_id, user["user_id"]))
            conn.commit()
            return {"deleted": notif_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Delete notification failed: " + str(e))


# ── CRON: WATCHLIST CHECK ─────────────────────────────────────────────────────
def run_watchlist_check():
    """Iterate active watchlist rows where monitoring=True. For each, find best
    matching recall. On a false→true transition, write a notification."""
    print("[cron] watchlist check starting at " + datetime.utcnow().isoformat())
    checked = 0
    new_alerts = 0
    try:
        with get_db() as conn:
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            c.execute("""SELECT id, user_id, brand, product_name, upc, has_recall, last_recall_id
                FROM watchlist WHERE status = 'active' AND monitoring = TRUE""")
            rows = c.fetchall()
            for w in rows:
                checked = checked + 1
                best = find_best_recall_for_watch(conn, w["brand"], w["product_name"], w["upc"])
                now = datetime.utcnow()
                has_recall_now = best is not None
                new_recall_id = best["recall_id"] if best else None
                uc = conn.cursor()
                uc.execute("""UPDATE watchlist
                    SET has_recall = %s, last_recall_id = %s, last_checked = %s
                    WHERE id = %s""",
                    (has_recall_now, new_recall_id, now, w["id"]))
                # Notification trigger: flipped from no-match to match,
                # OR same match-state but a different recall_id appeared
                fire = False
                if has_recall_now and not w["has_recall"]:
                    fire = True
                elif has_recall_now and new_recall_id and new_recall_id != w["last_recall_id"]:
                    fire = True
                if fire and best:
                    label = w["brand"] or ""
                    if w["product_name"]:
                        label = label + " " + w["product_name"]
                    msg = "Recall match for " + label.strip() + ": " + (
                        best.get("reason") or best.get("product_description") or "see details"
                    )[:240]
                    uc.execute("""INSERT INTO notifications (user_id, watchlist_id, message)
                        VALUES (%s, %s, %s)""", (w["user_id"], w["id"], msg))
                    new_alerts = new_alerts + 1
                conn.commit()
        print("[cron] watchlist check done — checked=" + str(checked) + " new_alerts=" + str(new_alerts))
    except Exception as e:
        print("[cron] watchlist check error: " + str(e))


def run_scheduler():
    """Background thread — runs `schedule` jobs forever."""
    schedule.every(WATCHLIST_CHECK_INTERVAL_HOURS).hours.do(run_watchlist_check)
    # also do a fresh recall ingest every 6hr so cron has fresh data
    schedule.every(6).hours.do(ingest_openfda)
    while True:
        schedule.run_pending()
        time_mod.sleep(60)


@app.post("/admin/run-watchlist-check")
async def admin_run_watchlist_check(_admin=Depends(require_admin)):
    """Manual trigger of the watchlist check (also runs on cron)."""
    run_watchlist_check()
    return {"status": "ok", "ts": datetime.utcnow().isoformat()}


# ── STARTUP ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    init_db()
    t = threading.Thread(target=run_scheduler, daemon=True)
    t.start()
    print("Mealwatch API v" + API_VERSION + " started (cron thread up)")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
