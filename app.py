from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For session management


# Initialize the database
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            balance REAL DEFAULT 0
        )
    ''')

    # Transactions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT,
            amount REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Admin Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Create default admin
    cursor.execute("INSERT OR IGNORE INTO admin (id, username, password) VALUES (1, 'admin', 'password')")
    conn.commit()
    conn.close()


# Decorator to require admin login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE username = ? AND password = ?", (username, password))
        admin = cursor.fetchone()
        conn.close()

        if admin:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return "Invalid credentials"

    return render_template('admin_login.html')


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Fetch all users
    cursor.execute("SELECT id, username, balance FROM users")
    users = cursor.fetchall()

    # Fetch recent transactions
    cursor.execute("SELECT t.id, u.username, t.type, t.amount, t.timestamp FROM transactions t "
                   "JOIN users u ON t.user_id = u.id ORDER BY t.timestamp DESC LIMIT 10")
    transactions = cursor.fetchall()

    conn.close()

    return render_template('admin_dashboard.html', users=users, transactions=transactions)


@app.route('/admin/logout')
@login_required
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)

@app.route('/admin/edit_balance', methods=['POST'])
@login_required
def edit_balance():
    user_id = request.form['user_id']
    new_balance = float(request.form['new_balance'])

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    username = request.form['username']
    balance = float(request.form['balance'])

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, balance) VALUES (?, ?)", (username, balance))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user', methods=['POST'])
@login_required
def delete_user():
    user_id = request.form['user_id']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    cursor.execute("DELETE FROM transactions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))
