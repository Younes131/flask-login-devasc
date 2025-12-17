from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3, hashlib, os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")  # zet in env in productie
DB_NAME = "user.db"


# ---- helpers -------------------------------------------------
def db():
    """Open een connectie naar de SQLite-database."""
    return sqlite3.connect(DB_NAME)


def ensure_tables():
    """Zorgt dat de veilige USER_HASH-tabel bestaat."""
    with db() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS USER_HASH (
                USERNAME TEXT PRIMARY KEY NOT NULL,
                HASH TEXT NOT NULL
            )
        """)
        conn.commit()


def verify_hash(username, password):
    """Controleert of gebruikersnaam en wachtwoord kloppen."""
    with db() as conn:
        c = conn.cursor()
        c.execute("SELECT HASH FROM USER_HASH WHERE USERNAME = ?", (username,))
        row = c.fetchone()
    return bool(row) and row[0] == hashlib.sha256(password.encode()).hexdigest()


# ---- maintenance (voor testscript) ---------------------------
@app.route('/delete/all', methods=['POST', 'DELETE'])
def delete_all():
    """Verwijdert alle records (handig voor testen)."""
    ensure_tables()
    with db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM USER_HASH")
        conn.commit()
    return "Test records deleted\n"


# ---- SECURE signup + login (v2-only) -------------------------
@app.route('/signup', methods=['POST'])
@app.route('/signup/v2', methods=['POST'])
def signup():
    """Aanmaken van een nieuwe gebruiker (veilig met SHA-256)."""
    ensure_tables()
    username = (request.form.get('username') or "").strip()
    password = request.form.get('password') or ""
    if not username or not password:
        return "username/password required\n", 400

    hv = hashlib.sha256(password.encode()).hexdigest()
    try:
        with db() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO USER_HASH (USERNAME, HASH) VALUES (?, ?)", (username, hv))
            conn.commit()
        return "Secure signup succeeded\n"
    except sqlite3.IntegrityError:
        return "Username has been registered\n"


@app.route('/login', methods=['POST'])
@app.route('/login/v2', methods=['POST'])
def login():
    """Inloggen (veilig met SHA-256)."""
    username = request.form.get('username') or ""
    password = request.form.get('password') or ""
    if verify_hash(username, password):
        session['user'] = username
        return "Login success, using hash\n"
    return "Invalid username/password\n"


# ---- Pages ---------------------------------------------------
@app.route('/')
def home():
    """Homepagina met loginstatus."""
    ensure_tables()
    return render_template('index.html', user=session.get('user'))


@app.route('/login', methods=['GET'])
def login_page():
    """Login-formulier."""
    return render_template('login.html')


@app.route('/signup', methods=['GET'])
def signup_page():
    """Signup-formulier."""
    return render_template('signup.html')


@app.route('/logout', methods=['POST'])
def logout():
    """Uitloggen en sessie wissen."""
    session.clear()
    flash("Logged out.")
    return redirect(url_for('home'))


# ---- main ----------------------------------------------------
if __name__ == "__main__":
    # HTTPS adhoc-cert zoals in de les → curl met -k gebruiken
    app.run(host="0.0.0.0", port=5556, ssl_context='adhoc')
