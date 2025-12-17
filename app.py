from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3, hashlib, os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")  # zet in env in productie
DB_NAME = "user.db"

# ---- helpers -------------------------------------------------
def db():
    return sqlite3.connect(DB_NAME)

def ensure_tables():
    with db() as conn:
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS USER_PLAIN (USERNAME TEXT PRIMARY KEY NOT NULL, PASSWORD TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS USER_HASH  (USERNAME TEXT PRIMARY KEY NOT NULL, HASH TEXT NOT NULL)")
        conn.commit()

# ---- maintenance (voor testscript docent) --------------------
@app.route('/delete/all', methods=['POST', 'DELETE'])
def delete_all():
    with db() as conn:
        c = conn.cursor()
        # Tabellen kunnen ontbreken bij een cold start → eerst aanmaken
        ensure_tables()
        c.execute("DELETE FROM USER_PLAIN")
        c.execute("DELETE FROM USER_HASH")
        conn.commit()
    return "Test records deleted\n"

# ---- INSECURE v1 (zoals bij docent) --------------------------
@app.route('/signup/v1', methods=['POST'])
def signup_v1():
    ensure_tables()
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    try:
        with db() as conn:
            c = conn.cursor()
            # onveilig: concateneert strings (gelaten voor compatibiliteit met les)
            c.execute(f"INSERT INTO USER_PLAIN (USERNAME, PASSWORD) VALUES ('{username}', '{password}')")
            conn.commit()
    except sqlite3.IntegrityError:
        return "Username has been registered, but is insecure\n"
    return "Signup success, but insecure\n"

def verify_plain(username, password):
    with db() as conn:
        c = conn.cursor()
        c.execute("SELECT PASSWORD FROM USER_PLAIN WHERE USERNAME = ?", (username,))
        row = c.fetchone()
    return bool(row) and row[0] == password

@app.route('/login/v1', methods=['POST', 'GET'])
def login_v1():
    if request.method != 'POST':
        return 'Invalid Method\n'
    ok = verify_plain(request.form.get('username',''), request.form.get('password',''))
    return 'Login success, but insecure\n' if ok else 'Invalid username/password\n'

# ---- SECURE v2 (parameterized + hash) ------------------------
@app.route('/signup/v2', methods=['POST'])
def signup_v2():
    ensure_tables()
    username = request.form.get('username','').strip()
    password = request.form.get('password','')
    if not username or not password:
        return "username/password required\n", 400
    hv = hashlib.sha256(password.encode()).hexdigest()
    try:
        with db() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO USER_HASH (USERNAME, HASH) VALUES (?, ?)", (username, hv))
            conn.commit()
    except sqlite3.IntegrityError:
        return "Username has been registered\n"
    return "Secure signup succeeded\n"

def verify_hash(username, password):
    with db() as conn:
        c = conn.cursor()
        c.execute("SELECT HASH FROM USER_HASH WHERE USERNAME = ?", (username,))
        row = c.fetchone()
    return bool(row) and row[0] == hashlib.sha256(password.encode()).hexdigest()

@app.route('/login/v2', methods=['POST', 'GET'])
def login_v2():
    if request.method != 'POST':
        return 'Invalid method\n'
    username = request.form.get('username','')
    password = request.form.get('password','')
    if verify_hash(username, password):
        session['user'] = username
        return 'Login sucess, using hash\n'
    return 'Invalid username/password\n'

# ---- Pages ---------------------------------------------------
@app.route('/')
def home():
    ensure_tables()
    return render_template('index.html', user=session.get('user'))

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('home'))

# ---- main ----------------------------------------------------
if __name__ == "__main__":
    # HTTPS adhoc-cert zoals in de les → curl met -k gebruiken
    app.run(host="0.0.0.0", port=5555, ssl_context='adhoc')
