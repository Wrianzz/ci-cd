from flask import Flask, request, jsonify
import os
import sqlite3
import secrets
from contextlib import closing
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------------------------------------------------------
# Konfigurasi dasar
# -----------------------------------------------------------------------------
app = Flask(__name__)

# Jangan simpan secret di kode; ambil dari environment
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")  # digunakan di sisi server saja, JANGAN diekspos

DB_PATH = os.environ.get("DB_PATH", "users.db")
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # batasi ukuran request 1MB
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))


# -----------------------------------------------------------------------------
# Util DB
# -----------------------------------------------------------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Sedikit pengaturan keamanan/performa untuk SQLite
    with closing(conn.cursor()) as cur:
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db():
    """Inisialisasi DB + migrasi sederhana dari skema lama (plaintext password)."""
    conn = get_db_connection()
    cur = conn.cursor()

    # Buat tabel jika belum ada (skema baru: password_hash)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
        """
    )
    conn.commit()

    # Cek apakah ada kolom lama 'password' (plaintext). Jika ada, migrasikan.
    cur.execute("PRAGMA table_info(users);")
    cols = [row["name"] for row in cur.fetchall()]
    if "password" in cols and "password_hash" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN password_hash TEXT;")
        conn.commit()
        # Migrasi isi password -> password_hash
        cur.execute("SELECT id, password FROM users;")
        rows = cur.fetchall()
        for r in rows:
            cur.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?;",
                (generate_password_hash(r["password"]), r["id"]),
            )
        conn.commit()
        # Kolom 'password' dibiarkan ada agar kompatibel dengan SQLite lama; tidak dipakai lagi.

    conn.close()


init_db()


# -----------------------------------------------------------------------------
# Security Headers
# -----------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # CSP minimal untuk respons HTML (app ini mostly JSON)
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    return resp


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return "Hello from SATNUSA secure app!"

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/register", methods=["POST"])
def register():
    """
    Body (JSON):
    {
      "username": "user",
      "password": "secret123"
    }
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    # Validasi sederhana
    if not username or not password:
        return jsonify({"error": "username dan password wajib diisi"}), 400
    if len(username) < 3 or len(username) > 64:
        return jsonify({"error": "panjang username harus 3-64 karakter"}), 400
    if len(password) < 8:
        return jsonify({"error": "password minimal 8 karakter"}), 400

    pwd_hash = generate_password_hash(password)

    conn = get_db_connection()
    try:
        with closing(conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?);",
                (username, pwd_hash),
            )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "username sudah dipakai"}), 409
    except Exception:
        conn.close()
        return jsonify({"error": "gagal membuat user"}), 500

    conn.close()
    return jsonify({"message": "akun berhasil dibuat"}), 201


@app.route("/login", methods=["POST"])
def login():
    """
    Terima JSON atau form-encoded.
    Tidak ada SQL Injection karena pakai parameter binding,
    dan password dicek via hash, bukan dibandingkan plaintext.
    """
    data = request.get_json(silent=True)
    if data:
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
    else:
        # fallback untuk form-data
        username = (request.form.get("username", "")).strip()
        password = request.form.get("password", "")

    if not username or not password:
        return jsonify({"error": "username dan password wajib diisi"}), 400

    conn = get_db_connection()
    user = None
    try:
        with closing(conn.cursor()) as cur:
            cur.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?;",
                (username,),
            )
            user = cur.fetchone()
    except Exception:
        conn.close()
        return jsonify({"error": "kesalahan basis data"}), 500
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        # Di produksi, sebaiknya kembalikan token (JWT atau session), ini contoh sederhana
        return jsonify({"message": f"Welcome, {user['username']}!"}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


# -----------------------------------------------------------------------------
# Endpoint berbahaya DIHAPUS:
#  - /exec (remote command execution)
#  - /show_key (membocorkan secret)
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Jalankan hanya di localhost dengan debug=False
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=False, host="127.0.0.1", port=port)
