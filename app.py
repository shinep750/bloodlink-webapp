from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import login_required
import psycopg2

app = Flask(__name__)

def get_db_connection():
    return psycopg2.connect(
        host="dpg-d33funqdbo4c73b6nkng-a.singapore-postgres.render.com",
        dbname="bloodlink_db",
        user="bloodlink_db_user",
        password="r1aEZVLmNvWf0kzzGF3zqKIcrV4BaZmJ"
    )

# -----------------------------
# Donor Registration (Modified)
# -----------------------------
@app.route("/add_donor", methods=["GET", "POST"])
@login_required
def add_donor():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        blood_group = request.form["blood_group"]
        contact_number = request.form["contact_number"]
        email = request.form.get("email")
        address = request.form.get("address")
        date_of_birth = request.form["date_of_birth"]

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                """
                INSERT INTO donors (first_name, last_name, blood_group, contact_number, email, address, date_of_birth)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING donor_code
                """,
                (first_name, last_name, blood_group, contact_number, email, address, date_of_birth)
            )
            donor_code = cur.fetchone()[0]
            conn.commit()

            flash(f"Donor added successfully! Assigned Donor ID: {donor_code}", "success")
            return render_template("donor_success.html", donor_code=donor_code)

        except psycopg2.Error as e:
            conn.rollback()
            flash("Error adding donor: " + str(e), "danger")
            return redirect(url_for("add_donor"))

        finally:
            cur.close()
            conn.close()

    return render_template("add_donor.html")
