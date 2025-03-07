from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import random
import re  # Import the regex module for validation

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management

DATABASE = 'voting_system.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS votes (username TEXT, candidate TEXT)")
    c.execute("""CREATE TABLE IF NOT EXISTS shares (
                    username TEXT, 
                    share_holder TEXT, 
                    share_value INTEGER, 
                    submitted INTEGER DEFAULT 0)""")
    c.execute("CREATE TABLE IF NOT EXISTS trusted_users (username TEXT, password TEXT)")

    trusted_user_data = [
        ("user1", "1234"),
        ("user2", "2345"),
        ("user3", "3456"),
        ("user4", "4567")
    ]
    for username, password in trusted_user_data:
        c.execute("INSERT OR IGNORE INTO trusted_users (username, password) VALUES (?, ?)", (username, password))
    
    conn.commit()
    conn.close()

def shamir_split(secret, n=4, k=4):
    secret = int(secret)
    coeff = [secret] + [random.randint(1, 100) for _ in range(k - 1)]
    shares = []
    for i in range(1, n + 1):
        share_value = sum(coeff[j] * (i ** j) for j in range(k)) % 251
        shares.append((i, share_value))
    return shares

def shamir_combine(shares):
    def _lagrange_interpolate(x, x_s, y_s):
        total = 0
        for i in range(len(x_s)):
            xi, yi = x_s[i], y_s[i]
            prod = yi
            for j in range(len(x_s)):
                if i != j:
                    prod *= (x - x_s[j]) * pow(xi - x_s[j], -1, 251)
            total += prod
        return total % 251

    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = username
            flash('Successfully logged in.', 'success')
            return redirect(url_for('vote'))
        else:
            flash('Login failed. Please check your username and password.', 'error')
            return redirect(url_for('login'))
        
        flash_timestamp = session.get('flash_timestamp')
        if flash_timestamp and time.time() - flash_timestamp > 2:
            session.pop('_flashes', None)  # Remove flashed messages
            session.pop('flash_timestamp', None)  # Remove the timestamp
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Username constraints
        if len(username) < 4 or len(username) > 20:
            flash('Username must be between 4 and 20 characters long.', 'error')
            return redirect(url_for('register'))
        if not re.match(r'^\w+$', username):
            flash('Username can only contain alphanumeric characters and underscores.', 'error')
            return redirect(url_for('register'))

        # Password constraints
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$'
        if not re.match(password_pattern, password):
            flash('Password must be between 8 and 20 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        if c.fetchone():
            flash('Username already registered.', 'error')
            conn.close()
            return redirect(url_for('register'))
        
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()

        flash('Registered successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'username' not in session:
        flash('You need to login first.', 'error')
        return redirect(url_for('login'))

    username = session['username']

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM votes WHERE username=?", (username,))
    if c.fetchone():
        flash('You have already cast your vote.', 'error')
        conn.close()
        return redirect(url_for('index'))

    if request.method == 'POST':
        candidate = request.form['candidate']

        shares = shamir_split(candidate, n=4, k=4)

        c.execute("INSERT INTO votes (username, candidate) VALUES (?, ?)", (username, candidate))
        
        trusted_users = ["user1", "user2", "user3", "user4"]
        for idx, share in enumerate(shares):
            c.execute("INSERT INTO shares (username, share_holder, share_value) VALUES (?, ?, ?)", (username, trusted_users[idx], share[1]))
        
        conn.commit()
        conn.close()

        flash('Vote successfully recorded.', 'success')
        return redirect(url_for('index'))

    candidates = {1: "Alice", 2: "Bob", 3: "Candice", 4: "Dove"}
    return render_template('vote.html', candidates=candidates)

@app.route('/submit_share', methods=['GET', 'POST'])
def submit_share():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM trusted_users WHERE username=? AND password=?", (username, password))
        if c.fetchone():
            c.execute("UPDATE shares SET submitted=1 WHERE share_holder=?", (username,))
            conn.commit()
            conn.close()
            flash(f"{username} has submitted their shares for tallying.", 'success')
            return redirect(url_for('index'))
        else:
            flash('Only trusted users can submit shares for tallying.', 'error')
            conn.close()
            return redirect(url_for('submit_share'))
    return render_template('submit_share.html')

@app.route('/tally_results', methods=['GET', 'POST'])
def tally_results():
    if request.method == 'POST':
        admin_password = request.form['admin_password']
        if admin_password != "admin":
            flash('Incorrect root admin password.', 'error')
            return redirect(url_for('tally_results'))

        candidates = {"Alice": 0, "Bob": 0, "Candice": 0, "Dove": 0}
        conn = get_db_connection()
        c = conn.cursor()

        c.execute("SELECT DISTINCT share_holder FROM shares WHERE submitted=1")
        if len(c.fetchall()) < 4:
            flash('Not all trusted users have submitted their shares yet.', 'error')
            conn.close()
            return redirect(url_for('index'))

        c.execute("SELECT DISTINCT username FROM shares")
        voters = [row[0] for row in c.fetchall()]

        for voter in voters:
            shares = []
            for user in ["user1", "user2", "user3", "user4"]:
                c.execute("SELECT share_value FROM shares WHERE username=? AND share_holder=?", (voter, user))
                share = c.fetchone()
                if share:
                    shares.append((["user1", "user2", "user3", "user4"].index(user) + 1, share[0]))

            reconstructed_vote = shamir_combine(shares)
            for idx, name in enumerate(candidates.keys()):
                if reconstructed_vote == idx + 1:
                    candidates[name] += 1

        conn.close()

        winner = max(candidates, key=candidates.get)
        margin = max(candidates.values()) - sorted(candidates.values())[-2]
        flash(f"{winner} won the election by a margin of {margin} votes.", 'success')
        return redirect(url_for('index'))
    return render_template('tally_results.html')

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)