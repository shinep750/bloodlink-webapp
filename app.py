import os
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)

# ==> IMPORTANT: LOAD CONFIGURATION FROM ENVIRONMENT VARIABLES <==
# This makes the app secure and configurable for deployment.
app.secret_key = os.environ.get('SECRET_KEY', 'a-default-secret-key-for-development')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_HOST = os.environ.get('DB_HOST')
DB_PORT = os.environ.get('DB_PORT', '5432')

# --- Database Connection Helper ---
def get_db_connection():
    """Establishes a connection to the database."""
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except Exception as e:
        # This will print the error to the server logs for debugging.
        print(f"Database connection error: {e}")
        return None

# --- Main Application Routes ---

@app.route('/')
def index():
    """Renders the main dashboard page."""
    conn = get_db_connection()
    if not conn:
        return "<h1>Error: Could not connect to the database. Please check server logs.</h1>"
    
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Dashboard stats
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
    
    # Shortage alerts (less than 3 units)
    cur.execute("""
        SELECT blood_group, COUNT(bag_id) as count
        FROM BloodInventory
        WHERE status = 'Available'
        GROUP BY blood_group
        HAVING COUNT(bag_id) < 3;
    """)
    shortages = cur.fetchall()

    # Expiring soon (in the next 14 days)
    cur.execute("""
        SELECT bi.bag_id, bi.blood_group, bb.bank_name, bi.expiry_date
        FROM BloodInventory bi
        JOIN BloodBanks bb ON bi.bank_id = bb.bank_id
        WHERE bi.status = 'Available' AND bi.expiry_date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '14 days'
        ORDER BY bi.expiry_date ASC;
    """)
    expiring_soon = cur.fetchall()

    cur.close()
    conn.close()
    return render_template('index.html', stats=stats, shortages=shortages, expiring_soon=expiring_soon)

@app.route('/donors')
def view_donors():
    """Displays a list of all donors."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT donor_id, first_name, last_name, blood_group, contact_number FROM Donors ORDER BY first_name;")
    donors = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('donors.html', donors=donors)

@app.route('/donor/<int:donor_id>')
def view_donor_detail(donor_id):
    """Displays the detail page for a single donor."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    cur.execute("SELECT * FROM Donors WHERE donor_id = %s;", (donor_id,))
    donor = cur.fetchone()
    
    cur.execute("""
        SELECT bi.bag_id, bi.donation_date, bi.expiry_date, bi.status, bb.bank_name
        FROM BloodInventory bi
        JOIN BloodBanks bb ON bi.bank_id = bb.bank_id
        WHERE bi.donor_id = %s ORDER BY bi.donation_date DESC;
    """, (donor_id,))
    history = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('donor_detail.html', donor=donor, history=history)

@app.route('/inventory')
def view_inventory():
    """Displays the available blood inventory with search filters."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    search_group = request.args.get('blood_group', '').strip()
    search_bank = request.args.get('bank_id', '').strip()
    
    query = """
        SELECT bi.bag_id, bi.blood_group, bi.donation_date, bi.expiry_date, 
               d.first_name || ' ' || d.last_name AS donor_name, bb.bank_name
        FROM BloodInventory bi
        JOIN Donors d ON bi.donor_id = d.donor_id
        JOIN BloodBanks bb ON bi.bank_id = bb.bank_id
        WHERE bi.status = 'Available'
    """
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
    
    cur.execute("SELECT bank_id, bank_name FROM BloodBanks ORDER BY bank_name;")
    banks = cur.fetchall()
    
    cur.close()
    conn.close()
    return render_template('inventory.html', inventory=inventory, banks=banks, search_group=search_group, search_bank=search_bank)

@app.route('/inventory/use/<int:bag_id>', methods=['POST'])
def use_blood_bag(bag_id):
    """Marks a blood bag as used."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # In a real app, you would also create a new recipient and transfusion record here.
        cur.execute("UPDATE BloodInventory SET status = 'Used' WHERE bag_id = %s;", (bag_id,))
        conn.commit()
        flash('Blood bag marked as used successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error updating inventory: {e}', 'error')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('view_inventory'))

@app.route('/reports')
def view_reports():
    """Renders the reports page with data visualizations."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Report 1: Inventory by Blood Group for Chart
    cur.execute("""
        SELECT blood_group, COUNT(bag_id) AS count
        FROM BloodInventory
        WHERE status = 'Available'
        GROUP BY blood_group ORDER BY blood_group;
    """)
    inventory_by_group_rows = cur.fetchall()
    
    # Report 2: Donations per month for Chart
    cur.execute("""
        SELECT TO_CHAR(donation_date, 'YYYY-MM') as month, COUNT(bag_id) as count
        FROM BloodInventory
        GROUP BY month ORDER BY month;
    """)
    donations_by_month_rows = cur.fetchall()
    
    # Report 3: Eligible Donors for Table
    cur.execute("""
        SELECT donor_id, first_name, last_name, blood_group, contact_number, last_donation_date
        FROM Donors
        WHERE last_donation_date IS NULL OR last_donation_date <= CURRENT_DATE - INTERVAL '90 days'
        ORDER BY last_donation_date DESC NULLS FIRST;
    """)
    eligible_donors = cur.fetchall()
    
    cur.close()
    conn.close()

    # Convert data into a JSON-friendly format for Chart.js
    inventory_chart_data = [dict(row) for row in inventory_by_group_rows]
    donations_chart_data = [dict(row) for row in donations_by_month_rows]

    return render_template('reports.html', 
                           eligible_donors=eligible_donors,
                           inventory_chart_data=inventory_chart_data,
                           donations_chart_data=donations_chart_data)

@app.route('/add_donor', methods=['GET', 'POST'])
def add_donor():
    """Handles the form for adding a new donor."""
    if request.method == 'POST':
        # Get data from the form
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
            cur.execute("""
                INSERT INTO Donors (first_name, last_name, blood_group, contact_number, email, address, date_of_birth)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            """, (first_name, last_name, blood_group, contact_number, email, address, date_of_birth))
            conn.commit()
            flash('Donor added successfully!', 'success')
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash('Error: A donor with this contact number or email already exists.', 'error')
        except Exception as e:
            conn.rollback()
            flash(f'An error occurred: {e}', 'error')
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('view_donors'))
    
    return render_template('add_donor.html')

@app.route('/add_inventory', methods=['GET', 'POST'])
def add_inventory():
    """Handles the form for adding a new blood bag to inventory."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    if request.method == 'POST':
        donor_id = request.form['donor_id']
        bank_id = request.form['bank_id']
        donation_date_str = request.form['donation_date']
        
        try:
            # Use strptime for Python 3.6 compatibility
            donation_date = datetime.strptime(donation_date_str, '%Y-%m-%d').date()
            expiry_date = donation_date + timedelta(days=42)
            
            cur.execute("SELECT blood_group FROM Donors WHERE donor_id = %s;", (donor_id,))
            donor_info = cur.fetchone()
            if not donor_info:
                flash('Error: Selected donor not found.', 'error')
                return redirect(url_for('add_inventory'))
            blood_group = donor_info['blood_group']

            cur.execute("""
                INSERT INTO BloodInventory (donor_id, bank_id, blood_group, donation_date, expiry_date, status)
                VALUES (%s, %s, %s, %s, %s, 'Available');
            """, (donor_id, bank_id, blood_group, donation_date, expiry_date))
            
            # Update the donor's last donation date
            cur.execute("UPDATE Donors SET last_donation_date = %s WHERE donor_id = %s;", (donation_date, donor_id))
            
            conn.commit()
            flash('Blood bag added to inventory successfully!', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'An error occurred while adding to inventory: {e}', 'error')
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('view_inventory'))

    # For the GET request, fetch donors and banks for the dropdowns
    cur.execute("SELECT donor_id, first_name, last_name FROM Donors ORDER BY first_name;")
    donors = cur.fetchall()
    cur.execute("SELECT bank_id, bank_name FROM BloodBanks ORDER BY bank_name;")
    banks = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('add_inventory.html', donors=donors, banks=banks)

# NOTE: We do not include app.run() in the production file.
# The Gunicorn server will run the 'app' object.


