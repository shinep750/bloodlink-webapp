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
        flash('Error: Username or Secret Code already exists.', 'error')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('manage_users'))

@app.route('/admin/users/edit/<int:staff_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(staff_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("SELECT * FROM Staff WHERE staff_id = %s;", (staff_id,))
    user = cur.fetchone()

    if not user:
        flash("User not found.", "error")
        cur.close()
        conn.close()
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form.get('username')
        secret_code = request.form.get('secret_code')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form

        try:
            if password.strip():
                password_hash = generate_password_hash(password)
                cur.execute("""
                    UPDATE Staff
                    SET full_name = %s, username = %s, secret_code = %s, is_admin = %s, password_hash = %s
                    WHERE staff_id = %s;
                """, (full_name, username, secret_code if not is_admin else None, is_admin, password_hash, staff_id))
            else:
                cur.execute("""
                    UPDATE Staff
                    SET full_name = %s, username = %s, secret_code = %s, is_admin = %s
                    WHERE staff_id = %s;
                """, (full_name, username, secret_code if not is_admin else None, is_admin, staff_id))

            conn.commit()
            flash("User updated successfully.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error updating user: {e}", "error")
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('manage_users'))

    cur.close()
    conn.close()
    return render_template('edit_user.html', user=user)

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

# --- Inventory Routes ---
@app.route('/inventory')
@login_required
def view_inventory():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT bi.bag_id, bi.blood_group, bb.bank_name, bi.status, bi.expiry_date FROM BloodInventory bi JOIN BloodBanks bb ON bi.bank_id = bb.bank_id ORDER BY bi.expiry_date ASC;")
    inventory = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('inventory.html', inventory=inventory)

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_inventory():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST':
        blood_group = request.form['blood_group']
        bank_id = request.form['bank_id']
        expiry_date = request.form['expiry_date']
        cur.execute("INSERT INTO BloodInventory (blood_group, bank_id, expiry_date, status) VALUES (%s, %s, %s, 'Available');", (blood_group, bank_id, expiry_date))
        conn.commit()
        flash("Blood bag added successfully.", "success")
        cur.close()
        conn.close()
        return redirect(url_for('view_inventory'))
    cur.execute("SELECT bank_id, bank_name FROM BloodBanks ORDER BY bank_name;")
    banks = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('add_inventory.html', banks=banks)

@app.route('/inventory/edit/<int:bag_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_inventory(bag_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM BloodInventory WHERE bag_id = %s;", (bag_id,))
    bag = cur.fetchone()
    if not bag:
        flash("Blood bag not found.", "error")
        cur.close()
        conn.close()
        return redirect(url_for('view_inventory'))
    if request.method == 'POST':
        blood_group = request.form['blood_group']
        bank_id = request.form['bank_id']
        expiry_date = request.form['expiry_date']
        status = request.form['status']
        cur.execute("UPDATE BloodInventory SET blood_group=%s, bank_id=%s, expiry_date=%s, status=%s WHERE bag_id=%s;", (blood_group, bank_id, expiry_date, status, bag_id))
        conn.commit()
        flash("Blood bag updated successfully.", "success")
        cur.close()
        conn.close()
        return redirect(url_for('view_inventory'))
    cur.execute("SELECT bank_id, bank_name FROM BloodBanks ORDER BY bank_name;")
    banks = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('edit_inventory.html', bag=bag, banks=banks)

@app.route('/inventory/delete/<int:bag_id>', methods=['POST'])
@login_required
@admin_required
def delete_inventory(bag_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM BloodInventory WHERE bag_id=%s;", (bag_id,))
    conn.commit()
    cur.close()
    conn.close()
    flash("Blood bag deleted successfully.", "success")
    return redirect(url_for('view_inventory'))

# --- Run App ---
if __name__ == '__main__':
    app.run(debug=True)
