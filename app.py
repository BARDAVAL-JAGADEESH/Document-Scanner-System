import os
from flask import Flask, render_template, request, redirect, session, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import sqlite3
from Levenshtein import distance as levenshtein_distance

app = Flask(__name__)
app.secret_key = '763a6281586470046cd8dc9c3941c17c3589517284b56c88'  # Replacing  with a strong secret key

#This function will allow user to upload file type like txt csv and pdf file only
ALLOWED_EXTENSIONS = {'txt', 'csv', 'pdf'}
UPLOADINTO_FOLDER = 'uploads'
if not os.path.exists(UPLOADINTO_FOLDER):
    os.makedirs(UPLOADINTO_FOLDER)

# Database connection helpers
def get_database_connection():
    connection = sqlite3.connect('database.db')
    connection.row_factory = sqlite3.Row
    return connection

#this function will initialize the data base like users ,documents and credit_request and credit usages
def Database_initializing():
    connection = get_database_connection()
    cursor = connection.cursor()
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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credit_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credits_used INTEGER NOT NULL,
            usage_date DATE DEFAULT CURRENT_DATE,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    
 
    connection.commit()
    connection.close()


# This function  is a Homepage
@app.route('/')
def index():
    return render_template('index.htm')

# This function allow User to Register 
@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        contact = request.form['contact']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        connection = get_database_connection()
        cursors = connection.cursor()
        try:
            cursors.execute(
                'INSERT INTO users (name, email, contact, password_hash) VALUES (?, ?, ?, ?)', 
                (name, email, contact, password_hash)
            )
            connection.commit()
            flash('Registrion successfull! Please login to account.', 'success')
            return redirect('/auth/login')
        except sqlite3.IntegrityError:
            flash('Email already exist. Please use a different email.', 'error')
        finally:
            connection.close()
    return render_template('register.htm')

#This function allow Users to Login into their account
@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        connection = get_database_connection()
        cursors = connection.cursor()
        cursors.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursors.fetchone()
        connection.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['name']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect('/user/profile')
        else:
            flash('Invalid password or email.', 'error')
    return render_template('login.htm')


# This function will allow users to Logout from the account
@app.route('/auth/logout')
def logout():
    session.clear()
    flash('logged out sucessfully .', 'success')
    return redirect('/')


# This function will check the kind of extensions allowed 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# This function allow user to upload Document 
@app.route('/scan', methods=['GET', 'POST'])
def upload_document():
    if 'user_id' not in session:
        flash('Please login to upload document.', 'error')
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
            flash('Only TXT, CSV, or PDF type of file allowed only.', 'error')
            return redirect('/scan')

        file_content = file.read()
        try:
            content = file_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content = file_content.decode('latin-1')
            except UnicodeDecodeError:
                flash('This kind of  file type not support. Please upload a valid file.', 'error')
                return redirect('/scan')

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOADINTO_FOLDER, filename)
        with open(filepath, 'wb') as f:
            f.write(file_content)

        connection = get_database_connection()
        cursors = connection.cursor()
        try:
            cursors.execute('BEGIN')
            cursors.execute('SELECT credits FROM users WHERE id = ?', (session['user_id'],))
            user_credits = cursors.fetchone()['credits']
            if user_credits < 1:
                flash('Insufficient credits balance. Please request more credits .', 'error')
                return redirect('/user/profile')
            cursors.execute(
                'INSERT INTO documents (user_id, filename, content) VALUES (?, ?, ?)', 
                (session['user_id'], filename, content)
            )
            cursors.execute('UPDATE users SET credits = credits - 1 WHERE id = ?', (session['user_id'],))
            cursors.execute('COMMIT')
            connection.commit()
            flash('Document uploaded successfully', 'success')
            return redirect('/user/profile')
        except Exception as e:
            cursors.execute('ROLLBACK')
            flash('An error . Please try again.', 'error')
            return redirect('/scan')
        finally:
            connection.close()
    return render_template('upload.htm')

# This function match the Documents
@app.route('/matches/<int:doc_id>')
def find_matches(doc_id):
    if 'user_id' not in session:
        flash(' Log in to view document matches.', 'error')
        return redirect('/auth/login')

    connection = get_database_connection()
    cursors = connection.cursor()

    # This will Get the current document
    cursors.execute('SELECT * FROM documents WHERE id = ?', (doc_id,))
    current_doc = cursors.fetchone()

    if not current_doc or current_doc['user_id'] != session['user_id']:
        flash('Document not found or access denied.', 'error')
        return redirect('/user/profile')

    # This will list  all other documents for the user
    cursors.execute('SELECT * FROM documents WHERE user_id = ? AND id != ?', (session['user_id'], doc_id))
    user_docs = cursors.fetchall()

    # This will Compare documents using Levenshtein distance algorithms
    matches = []
    for doc in user_docs:
        distance = levenshtein_distance(current_doc['content'], doc['content'])
        similarity = 1 - (distance / max(len(current_doc['content']), len(doc['content'])))
        if similarity > 0.8:  
            matches.append({
                'filename': doc['filename'],
                'similarity': similarity,
                'upload_date': doc['upload_date']
            })

    connection.close()
    return render_template('matches.htm', current_doc=current_doc, matches=matches)
#  Scan History
@app.route('/user/export')
def export_report():
    if 'user_id' not in session:
        flash('Please log in export report.', 'error')
        return redirect('/auth/login')
    connection =get_database_connection()
    cursors = connection.cursor()
    cursors.execute('SELECT filename, upload_date FROM documents WHERE user_id = ?', (session['user_id'],))
    documents = cursors.fetchall()
    connection.close()
    report = "User Scan History\n\n"
    for doc in documents:
        report += f"Filename: {doc['filename']} - Uploaded on: {doc['upload_date']}\n"
    return Response(report, mimetype='text/plain', headers={"Content-Disposition": "attachment;filename=scan_history.txt"})



# This function track daily credits  and reset the credits
def reset_daily_credits():
    connection = get_database_connection()
    cursors = connection.cursor()
    today = datetime.now().date()
    cursors.execute(
        'UPDATE users SET credits = 20, last_reset = ? WHERE last_reset < ?', 
        (today, today)
    )
    connection.commit()
    connection.close()


#This fucntion Smart Analytics Dashboard  (User Profile) where user can upload document and request for more credits
@app.route('/user/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to access dashboard.', 'error')
        return redirect('/auth/login')
    connection = get_database_connection()
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    cursor.execute('SELECT * FROM documents WHERE user_id = ?', (session['user_id'],))
    documents = cursor.fetchall()
    connection.close()
    return render_template('profile.htm', user=user, documents=documents)



# This function allow user to Request Additional Credits
@app.route('/user/request_credit', methods=['GET', 'POST'])
def request_credits():
    if 'user_id' not in session:
        flash('Please log in to request credits', 'error')
        return redirect('/auth/login')
    
    if request.method == 'POST':
        requested_credits = int(request.form['requested_credits'])
        connection = get_database_connection()
        cursor = connection.cursor()
        cursor.execute(
            'INSERT INTO credit_requests (user_id, requested_credits) VALUES (?, ?)', 
            (session['user_id'], requested_credits)
        )
        connection.commit()
        connection.close()
        flash('Credit request submitted successfully.', 'success')
        return redirect('/user/profile')
    
    return render_template('credit_request.htm')


# This function is about Admin Register only admin can use
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        contact = request.form['contact']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        connection = get_database_connection()
        cursors = connection.cursor()

        try:
            cursors.execute(
                'INSERT INTO users (name, email, contact, password_hash, role) VALUES (?, ?, ?, ?, ?)', 
                (name, email, contact, password_hash, 'admin')
            )
            connection.commit()
            flash('Admin registered successfully!', 'success')
            return redirect('/admin/login')
        except sqlite3.IntegrityError:
            flash('Email already registered. Please use a different email.', 'error')
        finally:
            connection.close()

    return render_template('admin_register.htm')
# This function allow Admin to Login If already logged in, redirect to the dashboard.

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'role' in session and session['role'] == 'admin':
        return redirect('/admin/dashboard') #If admin already logged in, it will redirect to the dashboard.  
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # This will Look  for  admin user in the database
        connection = get_database_connection()
        cursors = connection.cursor()
        cursors.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursors.fetchone()
        connection.close()

       #if the password and user name matched it will redirect to dashboard
        if user and user['role'] == 'admin' and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['name']
            session['role'] = 'admin'
            flash(' Login successful!', 'success')
            return redirect('/admin/dashboard')
        else:
            flash('Invalid email or password, or you are not an admin.', 'error')

    return render_template('admin_login.htm')

# Admin Logout 
@app.route('/admin/logout')
def admin_logout():
    session.clear()  # This will Clear all the active session data
    flash('Logged out  successfully.', 'success')
    return redirect('/admin/dashboard')  # This will Redirect to admin dashboard after logout


# This function is about Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to access this page.', 'error')
        return redirect('/admin/login')

    # This will Connect to the database and fetch total users and documents 
    connection = get_database_connection()
    cursors= connection.cursor()

    cursors.execute('SELECT COUNT(*) FROM users')  # This will Get the total number of users present 
    total_users = cursors.fetchone()[0] 

    cursors.execute('SELECT COUNT(*) FROM documents')
    total_documents = cursors.fetchone()[0]  #This will Get the total number of documents present 

   # This will Fetch all the  pending credit requests
    cursors.execute(''' 
        SELECT credit_requests.id, credit_requests.requested_credits, users.name as username
        FROM credit_requests
        JOIN users ON credit_requests.user_id = users.id
        WHERE credit_requests.status = 'pending'
    ''')
    credit_requests = cursors.fetchall()

    connection.close()

    # This show all the data of Pass to dashbaord of total users, total documents, and credit requests
    return render_template('admin_dashboard.htm', 
                           total_users=total_users, 
                           total_documents=total_documents, 
                           credit_requests=credit_requests)
#This function show admin to see   Credit Requests
@app.route('/admin/credits/requests')
def admin_credit_requests():
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to access this page', 'error')
        return redirect('/admin/login')

    connection =get_database_connection()
    cursors = connection.cursor()
    cursors.execute(''' 
        SELECT credit_requests.id, credit_requests.requested_credits, users.name as username
        FROM credit_requests
        JOIN users ON credit_requests.user_id = users.id
        WHERE credit_requests.status = 'pending'
    ''')
    requests = cursors.fetchall()
    connection.close()
    return render_template('admin_adjust_credits.htm', requests=requests)

# This fucntion allow Admin to Approve Credit Request got from users
@app.route('/admin/credits/approve/<int:request_id>', methods=['POST'])
def approve_credit_request(request_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to approve credit requests.', 'error')
        return redirect('/admin/login')

    connection =get_database_connection()
    cursors = connection.cursor()

    # This function will Get the credit request details from got users
    cursors.execute('SELECT * FROM credit_requests WHERE id = ?', (request_id,))
    request = cursors.fetchone()

    if request and request['status'] == 'pending':

        # Admin can Add credits to the user's accounts
        cursors.execute('UPDATE users SET credits = credits + ? WHERE id = ?', 
                       (request['requested_credits'], request['user_id']))
        cursors.execute('UPDATE credit_requests SET status = "approved" WHERE id = ?', (request_id,))
        connection.commit()

        flash(f'Credit request for {request["requested_credits"]} credits has been approved.', 'success')
    else:
        flash('Invalid or already processed request.', 'error')

    connection.close()
    return redirect('/admin/credits/requests')

# This function allow Admin Deny Credit Request got from users 
@app.route('/admin/credits/deny/<int:request_id>', methods=['POST'])
def deny_credit_request(request_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to deny credit requests.', 'error')
        return redirect('/admin/login')

    connection =get_database_connection()
    cursors = connection.cursor()

    # Deny the credit request
    cursors.execute('UPDATE credit_requests SET status = "denied" WHERE id = ?', (request_id,))
    connection.commit()

    flash('Credit request has been denied.', 'success')
    connection.close()
    return redirect('/admin/credits/requests')

# This function allow Admin to Adjust User Credits
@app.route('/admin/credits/adjust', methods=['GET', 'POST'])
def adjust_user_credits():
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to adjust user credits.', 'error')
        return redirect('/admin/login')

    if request.method == 'POST':
        user_id = int(request.form['user_id'])
        credit_adjustment = int(request.form['credit_adjustment'])
        
        connection =get_database_connection()
        cursors = connection.cursor()

        #This will Update the users credits
        cursors.execute('UPDATE users SET credits = credits + ? WHERE id = ?', 
                       (credit_adjustment, user_id))
        connection.commit()
        connection.close()

        flash(f'Credits adjusted by {credit_adjustment}.', 'success')
        return redirect('/admin/dashboard')

    # This will display a form for adjusting credits
    connection = get_database_connection()
    cursors = connection.cursor()
    cursors.execute('SELECT id, name FROM users')
    users = cursors.fetchall()
    connection.close()

    return render_template('admin_adjust_credits.htm', users=users)


# This function allow Admin  to see all the data(Analytics Dashboard)
@app.route('/admin/analytics')
def analytics_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('You must be an admin to access this page.', 'error')
        return redirect('/admin/login')

    connection = get_database_connection()
    cursors = connection.cursor()

    # 1.This one is condition user can Scans  per day (count th documents uploaded per user per day)
    cursors.execute('''
        SELECT user_id, strftime('%Y-%m-%d', upload_date) AS scan_date, COUNT(*) AS scans
        FROM documents
        GROUP BY user_id, scan_date
        ORDER BY scan_date DESC
    ''')
    scans_per_user = cursors.fetchall()

    # This will Simply grouping by filename instead (or any other attribute you might need)
    cursors.execute('''
        SELECT filename, COUNT(*) AS file_count
        FROM documents
        GROUP BY filename
        ORDER BY file_count DESC
        LIMIT 10
    ''')
    common_topics = cursors.fetchall()

    # 3. This will allow to see Top users by scan count
    cursors.execute('''
        SELECT user_id, COUNT(*) AS scan_count
        FROM documents
        GROUP BY user_id
        ORDER BY scan_count DESC
        LIMIT 5
    ''')
    top_users_by_scans = cursors.fetchall()

    # 4.This one show  Credit usage statistics
    cursors.execute('''
        SELECT user_id, SUM(credits_used) AS total_credits
        FROM credit_usage
        GROUP BY user_id
        ORDER BY total_credits DESC
        LIMIT 5
    ''')
    top_users_by_credits = cursors.fetchall()

    connection.close()

    return render_template('admin_analytics.htm', 
                           scans_per_user=scans_per_user, 
                           common_topics=common_topics, 
                           top_users_by_scans=top_users_by_scans, 
                           top_users_by_credits=top_users_by_credits)



if __name__ == '__main__':
    # Initializing  database and reset daily credits
    Database_initializing()
    reset_daily_credits()  
    app.run(debug=True)