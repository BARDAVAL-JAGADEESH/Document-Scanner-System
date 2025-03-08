import os
from flask import Flask, render_template, request, redirect, session, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import sqlite3
from Levenshtein import distance as levenshtein_distance

app = Flask(__name__)
app.secret_key = '763a6281586470046cd8dc9c3941c17c3589517284b56c88'  # Replacing  with a strong secret key

#This will  Allowed file extensions and it can upload into a  folder
ALLOWED_EXTENSIONS = {'txt', 'csv', 'pdf'}
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            contact TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
                   
            credits INTEGER DEFAULT 20,
            last_reset DATE DEFAULT CURRENT_DATE
        )
    ''')
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            upload_date DATE DEFAULT CURRENT_DATE,
            topic TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS credit_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            requested_credits INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Create the credit_usage table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credit_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credits_used INTEGER NOT NULL,
            usage_date DATE DEFAULT CURRENT_DATE,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    
 
    conn.commit()
    conn.close()
# This function willtrack daily credits reset 
def reset_daily_credits():
    conn = get_db_connection()
    cursor = conn.cursor()
    today = datetime.now().date()
    cursor.execute(
        'UPDATE users SET credits = 20, last_reset = ? WHERE last_reset < ?', 
        (today, today)
    )
    conn.commit()
    conn.close()

# it will Check if file extension is allowed or not
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Homepage
@app.route('/')
def index():
    return render_template('index.htm')

# User Registration
@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        contact = request.form['contact']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (name, email, contact, password_hash) VALUES (?, ?, ?, ?)', 
                (name, email, contact, password_hash)
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect('/auth/login')
        except sqlite3.IntegrityError:
            flash('Email already registered. Please use a different email.', 'error')
        finally:
            conn.close()
    return render_template('register.htm')

# User Login
@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['name']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect('/user/profile')
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login.htm')

# User Profile
@app.route('/user/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect('/auth/login')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    cursor.execute('SELECT * FROM documents WHERE user_id = ?', (session['user_id'],))
    documents = cursor.fetchall()
    conn.close()
    return render_template('profile.htm', user=user, documents=documents)

# Admin Analytics Dashboard
@app.route('/admin/analytics')
def analytics_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to access this page.', 'error')
        return redirect('/admin/login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Scans per user per day (count of documents uploaded per user per day)
    cursor.execute('''
        SELECT user_id, strftime('%Y-%m-%d', upload_date) AS scan_date, COUNT(*) AS scans
        FROM documents
        GROUP BY user_id, scan_date
        ORDER BY scan_date DESC
    ''')
    scans_per_user = cursor.fetchall()

    # 2. Removed the topic query
    # Simply grouping by filename instead (or any other attribute you might need)
    cursor.execute('''
        SELECT filename, COUNT(*) AS file_count
        FROM documents
        GROUP BY filename
        ORDER BY file_count DESC
        LIMIT 10
    ''')
    common_topics = cursor.fetchall()

    # 3. Top users by scan count
    cursor.execute('''
        SELECT user_id, COUNT(*) AS scan_count
        FROM documents
        GROUP BY user_id
        ORDER BY scan_count DESC
        LIMIT 5
    ''')
    top_users_by_scans = cursor.fetchall()

    # 4. Credit usage statistics
    cursor.execute('''
        SELECT user_id, SUM(credits_used) AS total_credits
        FROM credit_usage
        GROUP BY user_id
        ORDER BY total_credits DESC
        LIMIT 5
    ''')
    top_users_by_credits = cursor.fetchall()

    conn.close()

    return render_template('admin_analytics.htm', 
                           scans_per_user=scans_per_user, 
                           common_topics=common_topics, 
                           top_users_by_scans=top_users_by_scans, 
                           top_users_by_credits=top_users_by_credits)


# Request Additional Credits
@app.route('/user/request_credit', methods=['GET', 'POST'])
def request_credits():
    if 'user_id' not in session:
        flash('Please log in to request credits.', 'error')
        return redirect('/auth/login')
    
    if request.method == 'POST':
        requested_credits = int(request.form['requested_credits'])
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO credit_requests (user_id, requested_credits) VALUES (?, ?)', 
            (session['user_id'], requested_credits)
        )
        conn.commit()
        conn.close()
        flash('Credit request submitted for approval.', 'success')
        return redirect('/user/profile')
    
    return render_template('credit_request.htm')

# Document Upload
@app.route('/scan', methods=['GET', 'POST'])
def upload_document():
    if 'user_id' not in session:
        flash('Please log in to upload documents.', 'error')
        return redirect('/auth/login')
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file uploaded.', 'error')
            return redirect('/scan')
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect('/scan')
        if not allowed_file(file.filename):
            flash('Only TXT, CSV, or PDF files are allowed.', 'error')
            return redirect('/scan')

        file_content = file.read()
        try:
            content = file_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content = file_content.decode('latin-1')
            except UnicodeDecodeError:
                flash('Unsupported file type. Please upload a valid text file.', 'error')
                return redirect('/scan')
        # Save file locally
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, 'wb') as f:
            f.write(file_content)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT credits FROM users WHERE id = ?', (session['user_id'],))
        user_credits = cursor.fetchone()['credits']
        if user_credits < 1:
            flash('Insufficient credits. Please request more.', 'error')
            return redirect('/user/profile')
        cursor.execute(
            'INSERT INTO documents (user_id, filename, content) VALUES (?, ?, ?)', 
            (session['user_id'], filename, content)
        )
        cursor.execute('UPDATE users SET credits = credits - 1 WHERE id = ?', (session['user_id'],))
        conn.commit()
        conn.close()
        flash('Document uploaded successfully!', 'success')
        return redirect('/user/profile')
    return render_template('upload.htm')

# Export Scan History
@app.route('/user/export')
def export_report():
    if 'user_id' not in session:
        flash('Please log in to export your report.', 'error')
        return redirect('/auth/login')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT filename, upload_date FROM documents WHERE user_id = ?', (session['user_id'],))
    documents = cursor.fetchall()
    conn.close()
    report = "Your Scan History:\n\n"
    for doc in documents:
        report += f"Filename: {doc['filename']} - Uploaded on: {doc['upload_date']}\n"
    return Response(report, mimetype='text/plain', headers={"Content-Disposition": "attachment;filename=scan_history.txt"})

# Logout
@app.route('/auth/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect('/')

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to access this page.', 'error')
        return redirect('/admin/login')

    # Connect to the database and fetch total users and documents
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]  # Get the total number of users

    cursor.execute('SELECT COUNT(*) FROM documents')
    total_documents = cursor.fetchone()[0]  # Get the total number of documents

   # Fetch pending credit requests
    cursor.execute(''' 
        SELECT credit_requests.id, credit_requests.requested_credits, users.name as username
        FROM credit_requests
        JOIN users ON credit_requests.user_id = users.id
        WHERE credit_requests.status = 'pending'
    ''')
    credit_requests = cursor.fetchall()

    conn.close()

    # Pass the total_users, total_documents, and credit_requests to the template
    return render_template('admin_dashboard.htm', 
                           total_users=total_users, 
                           total_documents=total_documents, 
                           credit_requests=credit_requests)
# Admin Credit Requests
@app.route('/admin/credits/requests')
def admin_credit_requests():
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to access this page.', 'error')
        return redirect('/admin/login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(''' 
        SELECT credit_requests.id, credit_requests.requested_credits, users.name as username
        FROM credit_requests
        JOIN users ON credit_requests.user_id = users.id
        WHERE credit_requests.status = 'pending'
    ''')
    requests = cursor.fetchall()
    conn.close()

    return render_template('admin_adjust_credits.htm', requests=requests)

# Admin Approve Credit Request
@app.route('/admin/credits/approve/<int:request_id>', methods=['POST'])
def approve_credit_request(request_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to approve credit requests.', 'error')
        return redirect('/admin/login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the credit request details
    cursor.execute('SELECT * FROM credit_requests WHERE id = ?', (request_id,))
    request = cursor.fetchone()

    if request and request['status'] == 'pending':
        # Add credits to the user's account
        cursor.execute('UPDATE users SET credits = credits + ? WHERE id = ?', 
                       (request['requested_credits'], request['user_id']))
        cursor.execute('UPDATE credit_requests SET status = "approved" WHERE id = ?', (request_id,))
        conn.commit()

        flash(f'Credit request for {request["requested_credits"]} credits has been approved.', 'success')
    else:
        flash('Invalid or already processed request.', 'error')

    conn.close()
    return redirect('/admin/credits/requests')

# Admin Deny Credit Request
@app.route('/admin/credits/deny/<int:request_id>', methods=['POST'])
def deny_credit_request(request_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to deny credit requests.', 'error')
        return redirect('/admin/login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Deny the credit request
    cursor.execute('UPDATE credit_requests SET status = "denied" WHERE id = ?', (request_id,))
    conn.commit()

    flash('Credit request has been denied.', 'success')
    conn.close()
    return redirect('/admin/credits/requests')

# Admin Adjust User Credits
@app.route('/admin/credits/adjust', methods=['GET', 'POST'])
def adjust_user_credits():
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to adjust user credits.', 'error')
        return redirect('/admin/login')

    if request.method == 'POST':
        user_id = int(request.form['user_id'])
        credit_adjustment = int(request.form['credit_adjustment'])
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # Update the user's credits
        cursor.execute('UPDATE users SET credits = credits + ? WHERE id = ?', 
                       (credit_adjustment, user_id))
        conn.commit()
        conn.close()

        flash(f'Credits adjusted by {credit_adjustment}.', 'success')
        return redirect('/admin/dashboard')

    # Show a form for adjusting credits
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_adjust_credits.htm', users=users)

# Admin Register
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        contact = request.form['contact']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Ensure the role is set to 'admin' during registration
            cursor.execute(
                'INSERT INTO users (name, email, contact, password_hash, role) VALUES (?, ?, ?, ?, ?)', 
                (name, email, contact, password_hash, 'admin')
            )
            conn.commit()
            flash('Admin registered successfully!', 'success')
            return redirect('/admin/login')
        except sqlite3.IntegrityError:
            flash('Email already registered. Please use a different email.', 'error')
        finally:
            conn.close()

    return render_template('admin_register.htm')
# Admin Login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'role' in session and session['role'] == 'admin':
        return redirect('/admin/dashboard')  # If already logged in, redirect to the dashboard.

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Look for the admin user in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and user['role'] == 'admin' and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['name']
            session['role'] = 'admin'
            flash('Admin login successful!', 'success')
            return redirect('/admin/dashboard')
        else:
            flash('Invalid email or password, or you are not an admin.', 'error')

    return render_template('admin_login.htm')
# Admin Logout Route
@app.route('/admin/logout')
def admin_logout():
    session.clear()  # Clear all session data
    flash('You have been logged out successfully.', 'success')
    return redirect('/admin/dashboard')  # Redirect to admin dashboard after logout




if __name__ == '__main__':
    # Initialize database and reset daily credits
    initialize_database()
    reset_daily_credits()  # This can be scheduled to run once a day in production
    app.run(debug=True)