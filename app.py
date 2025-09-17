import os
import functools
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from psycopg2 import errors
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)

# ==> CONFIGURATION <==
app.secret_key = os.environ.get('SECRET_KEY', 'a-default-secret-key-for-development')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_HOST = os.environ.get('DB_HOST')
DB_PORT = os.environ.get('DB_PORT', '5432')

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class StaffUser(UserMixin):
    def __init__(self, id, username, full_name, is_admin, must_change_password):
        self.id = id
        self.username = username
        self.full_name = full_name
        self.is_admin = is_admin
        self.must_change_password = must_change_password

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if not conn: return None
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM Staff WHERE staff_id = %s", [user_id])
    user = cur.fetchone()
    cur.close()
    conn.close()
    if user:
        return StaffUser(
            id=user['staff_id'],
            username=user['username'],
            full_name=user['full_name'],
            is_admin=user.get('is_admin', False),
            must_change_password=user.get('must_change_password', False)
        )
    return None

# --- Middleware for Forced Password Change (Admins Only) ---
@app.before_request
def before_request_callback():
    if current_user.is_authenticated and getattr(current_user, 'is_admin', False) and getattr(current_user, 'must_change_password', False):
        if request.endpoint and request.endpoint not in ('profile', 'logout', 'static'):
            flash("For security, you must change your default password before you can use the application.", "error")
            return redirect(url_for('profile'))

# --- Admin Required Decorator ---
def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not getattr(current_user, 'is_admin', False):
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Database Connection Helper ---
def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return handle_login_attempt(is_admin_login=False)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('login.html', is_admin_login=False)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        return handle_login_attempt(is_admin_login=True)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('login.html', is_admin_login=True)

def handle_login_attempt(is_admin_login):
    password = request.form['password']
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", "error")
        return redirect(request.url)

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    user = None

    if is_admin_login:
        username = request.form['username']
        cur.execute("SELECT * FROM Staff WHERE username = %s AND is_admin = TRUE;", (username,))
        user = cur.fetchone()
    else:
        secret_code = request.form['secret_code']
        cur.execute("SELECT * FROM Staff WHERE secret_code = %s AND is_admin = FALSE;", (secret_code,))
        user = cur.fetchone()

    cur.close()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        staff_member = StaffUser(
            id=user['staff_id'],
            username=user['username'],
            full_name=user['full_name'],
            is_admin=user.get('is_admin', False),
            must_change_password=user.get('must_change_password', False)
        )
        login_user(staff_member)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('index'))
    else:
        flash('Invalid credentials provided.', 'error')
        return redirect(request.url)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
@admin_required
def profile():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('The new passwords do not match. Please try again.', 'error')
            return redirect(url_for('profile'))

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT password_hash FROM Staff WHERE staff_id = %s;", (current_user.id,))
        user_data = cur.fetchone()
        
        if not user_data or not check_password_hash(user_data['password_hash'], current_password):
            flash('Your current password was incorrect.', 'error')
        else:
            new_password_hash = generate_password_hash(new_password)
            cur.execute("UPDATE Staff SET password_hash = %s, must_change_password = FALSE WHERE staff_id = %s;", (new_password_hash, current_user.id))
            conn.commit()
            flash('Your password has been updated successfully! You now have full access.', 'success')
            cur.close()
            conn.close()
            return redirect(url_for('index'))

    return render_template('profile.html')

# --- Admin Routes ---
@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT staff_id, username, full_name, is_admin, secret_code FROM Staff ORDER BY username;")
    staff_list = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_users.html', staff_list=staff_list)

@app.route('/admin/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    full_name = request.form['full_name']
    secret_code = request.form.get('secret_code')
    is_admin = 'is_admin' in request.form
    
    password_hash = generate_password_hash(password)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO Staff (username, password_hash, full_name, is_admin, secret_code, must_change_password) VALUES (%s, %s, %s, %s, %s, %s);",
                    (username, password_hash, full_name, is_admin, secret_code if not is_admin else None, is_admin))
        conn.commit()
        flash(f'User "{username}" created successfully!', 'success')
    except errors.UniqueViolation:
        conn.rollback()
        flash(f'Error: Username or Secret Code already exists.', 'error')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('manage_users'))

@app.route('/admin/users/delete/<int:staff_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(staff_id):
    if staff_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('manage_users'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM Staff WHERE staff_id = %s;", (staff_id,))
    conn.commit()
    cur.close()
    conn.close()
    flash("Staff user deleted successfully.", "success")
    return redirect(url_for('manage_users'))

# --- Standard Application Routes ---
@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    if not conn:
        return "<h1>Error: Could not connect to the database. Please check server logs.</h1>"
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT COUNT(*) FROM Donors;")
    total_donors = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM BloodInventory WHERE status = 'Available';")
    available_bags = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM BloodTransfusions;")
    total_transfusions = cur.fetchone()[0]
    stats = {
        'total_donors': total_donors,
        'available_bags': available_bags,
        'total_transfusions': total_transfusions
    }
    cur.execute("SELECT blood_group FROM BloodInventory WHERE status = 'Available' GROUP BY blood_group HAVING COUNT(bag_id) < 3;")
    shortages_rows = cur.fetchall()
    critical_shortages = [row['blood_group'] for row in shortages_rows]
    cur.execute("SELECT bi.bag_id, bi.blood_group, bb.bank_name, bi.expiry_date FROM BloodInventory bi JOIN BloodBanks bb ON bi.bank_id = bb.bank_id WHERE bi.status = 'Available' AND bi.expiry_date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '14 days' ORDER BY bi.expiry_date ASC;")
    expiring_soon = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('index.html', stats=stats, critical_shortages=critical_shortages, expiring_soon=expiring_soon)
    
# --- THE FIX: Admins can now VIEW donors ---
@app.route('/donors')
@login_required
def view_donors():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT donor_id, first_name, last_name, blood_group, contact_number FROM Donors ORDER BY first_name;")
    donors = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('donors.html', donors=donors)

# --- THE FIX: Admins can now VIEW donor details ---
@app.route('/donor/<int:donor_id>')
@login_required
def view_donor_detail(donor_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM Donors WHERE donor_id = %s;", (donor_id,))
    donor = cur.fetchone()
    cur.execute("SELECT bi.donation_date, bi.status, bb.bank_name FROM BloodInventory bi JOIN BloodBanks bb ON bi.bank_id = bb.bank_id WHERE bi.donor_id = %s ORDER BY bi.donation_date DESC;", (donor_id,))
    donations = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('donor_detail.html', donor=donor, donations=donations)

@app.route('/add_donor', methods=['GET', 'POST'])
@login_required
def add_donor():
    if getattr(current_user, 'is_admin', False):
        flash("Admins cannot perform this action.", "error")
        return redirect(url_for('index'))
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        blood_group = request.form['blood_group']
        contact_number = request.form['contact_number']
        email = request.form['email']
        address = request.form['address']
        date_of_birth = request.form['date_of_birth']
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO Donors (first_name, last_name, blood_group, contact_number, email, address, date_of_birth) VALUES (%s, %s, %s, %s, %s, %s, %s);",
                        (first_name, last_name, blood_group, contact_number, email, address, date_of_birth))
            conn.commit()
            flash('Donor added successfully!', 'success')
        except errors.UniqueViolation:
            conn.rollback()
            flash('Error: A donor with that contact number or email already exists.', 'error')
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('view_donors'))
    return render_template('add_donor.html')
    
@app.route('/add_inventory', methods=['GET', 'POST'])
@login_required
def add_inventory():
    if getattr(current_user, 'is_admin', False):
        flash("Admins cannot perform this action.", "error")
        return redirect(url_for('index'))
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST':
        donor_id = request.form['donor_id']
        bank_id = request.form['bank_id']
        donation_date_str = request.form['donation_date']
        donation_date = datetime.strptime(donation_date_str, '%Y-%m-%d').date()
        expiry_date = donation_date + timedelta(days=42)
        cur.execute("SELECT blood_group FROM Donors WHERE donor_id = %s;", (donor_id,))
        blood_group = cur.fetchone()['blood_group']
        cur.execute("INSERT INTO BloodInventory (donor_id, bank_id, blood_group, donation_date, expiry_date) VALUES (%s, %s, %s, %s, %s);",
                    (donor_id, bank_id, blood_group, donation_date, expiry_date))
        cur.execute("UPDATE Donors SET last_donation_date = %s WHERE donor_id = %s;", (donation_date, donor_id))
        conn.commit()
        flash('Blood bag added to inventory!', 'success')
        cur.close()
        conn.close()
        return redirect(url_for('view_inventory'))
    cur.execute("SELECT donor_id, first_name, last_name FROM Donors ORDER BY last_name, first_name;")
    donors = cur.fetchall()
    cur.execute("SELECT bank_id, bank_name FROM BloodBanks ORDER BY bank_name;")
    banks = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('add_inventory.html', donors=donors, banks=banks)

@app.route('/inventory')
@login_required
def view_inventory():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    search_group = request.args.get('blood_group', '')
    search_bank = request.args.get('bank_id', '')
    query = "SELECT bi.bag_id, bi.blood_group, bi.donation_date, bi.expiry_date, d.first_name || ' ' || d.last_name as donor_name, bb.bank_name FROM BloodInventory bi JOIN Donors d ON bi.donor_id = d.donor_id JOIN BloodBanks bb ON bi.bank_id = bb.bank_id WHERE bi.status = 'Available'"
    params = []
    if search_group:
        query += " AND bi.blood_group = %s"
        params.append(search_group)
    if search_bank:
        query += " AND bi.bank_id = %s"
        params.append(search_bank)
    query += " ORDER BY bi.expiry_date ASC;"
    cur.execute(query, tuple(params))
    inventory = cur.fetchall()
    cur.execute("SELECT * FROM BloodBanks ORDER BY bank_name;")
    banks = cur.fetchall()
    cur.execute("SELECT * FROM Recipients ORDER BY last_name, first_name;")
    recipients = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('inventory.html', inventory=inventory, banks=banks, recipients=recipients, search_group=search_group, search_bank=search_bank)

@app.route('/inventory/use/<int:bag_id>', methods=['POST'])
@login_required
def use_blood_bag(bag_id):
    if getattr(current_user, 'is_admin', False):
        flash("Admins cannot perform this action.", "error")
        return redirect(url_for('view_inventory'))
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    recipient_id = request.form.get('recipient_id')
    new_recipient_first_name = request.form.get('new_recipient_first_name')
    new_recipient_last_name = request.form.get('new_recipient_last_name')
    new_recipient_blood_group = request.form.get('new_recipient_blood_group')
    new_recipient_hospital = request.form.get('new_recipient_hospital')
    
    try:
        if new_recipient_first_name and new_recipient_last_name and new_recipient_blood_group:
            cur.execute(
                "INSERT INTO Recipients (first_name, last_name, blood_group, hospital_name) VALUES (%s, %s, %s, %s) RETURNING recipient_id;",
                (new_recipient_first_name, new_recipient_last_name, new_recipient_blood_group, new_recipient_hospital)
            )
            recipient_id = cur.fetchone()['recipient_id']
        
        if not recipient_id:
            flash('You must select an existing recipient or enter details for a new one.', 'error')
            return redirect(url_for('view_inventory'))

        cur.execute("UPDATE BloodInventory SET status = 'Used' WHERE bag_id = %s;", (bag_id,))
        cur.execute("INSERT INTO BloodTransfusions (bag_id, recipient_id) VALUES (%s, %s);", (bag_id, recipient_id))
        
        conn.commit()
        flash('Blood bag marked as used and transfusion recorded!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'An error occurred: {e}', 'error')
    finally:
        cur.close()
        conn.close()
        
    return redirect(url_for('view_inventory'))

@app.route('/reports')
@login_required
def view_reports():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT blood_group, COUNT(bag_id) as count FROM BloodInventory WHERE status = 'Available' GROUP BY blood_group;")
    inventory_rows = cur.fetchall()
    inventory_chart_data = [dict(row) for row in inventory_rows]
    cur.execute("SELECT TO_CHAR(donation_date, 'YYYY-MM') as month, COUNT(bag_id) as count FROM BloodInventory GROUP BY month ORDER BY month;")
    monthly_rows = cur.fetchall()
    monthly_chart_data = [dict(row) for row in monthly_rows]
    cur.execute("SELECT first_name, last_name, blood_group, contact_number, last_donation_date FROM Donors WHERE last_donation_date IS NULL OR last_donation_date <= CURRENT_DATE - INTERVAL '90 days' ORDER BY last_donation_date DESC NULLS FIRST;")
    eligible_donors = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('reports.html', inventory_chart_data=inventory_chart_data, monthly_chart_data=monthly_chart_data, eligible_donors=eligible_donors)

