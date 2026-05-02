from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import psycopg2
import os
from contextlib import contextmanager

# ── REPLACE AFTER RENDER POSTGRES PROVISIONS (step 2 of setup) ────────────────
DB_HOST = "dpg-d7r4tdmgvqtc73b9p0qg-a.oregon-postgres.render.com"
DB_USER = "mealwatch_db_user"
DB_PASS = "J9WhUMsdW7SMUrKJwhgT48I73Jn0YmhM"
DB_NAME = "mealwatch_db"
DATABASE_URL = "postgresql://" + DB_USER + ":" + DB_PASS + "@" + DB_HOST + "/" + DB_NAME
# ──────────────────────────────────────────────────────────────────────────────

API_VERSION = "0.1.0"

app = FastAPI(title="Mealwatch API", version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Create all mealwatch tables. Safe to run on every boot."""
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
        print("[init_db] DB creds may not be set yet -- service will still start")


@app.api_route("/health", methods=["GET", "HEAD"])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": API_VERSION
    }


@app.on_event("startup")
async def startup_event():
    init_db()
    print("Mealwatch API v" + API_VERSION + " started")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
