import os
import psycopg2
from werkzeug.security import generate_password_hash

# This script securely resets the admin password.

# ==> CONFIGURATION <==
# It reads the same environment variables as your main app.
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_HOST = os.environ.get('DB_HOST')
DB_PORT = os.environ.get('DB_PORT', '5432')

def setup_admin_user():
    """Connects to the DB, deletes any old admin, and creates a new one."""
    try:
        print("Connecting to the database...")
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()
        print("Connection successful.")

        # Delete any old, incorrect admin user to ensure a clean state
        print("Removing old admin user (if exists)...")
        cur.execute("DELETE FROM Staff WHERE username = 'admin';")

        # Create the new admin user with the correct hashed password
        print("Creating new admin user with username 'admin' and password 'password'...")
        password_hash = generate_password_hash('password')
        cur.execute(
            "INSERT INTO Staff (username, password_hash, full_name, is_admin) VALUES (%s, %s, %s, %s);",
            ('admin', password_hash, 'Admin User', True)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("\nSUCCESS: The admin user has been reset successfully.")
        print("You can now run your main application and log in.")

    except psycopg2.OperationalError as e:
        print(f"\nERROR: Could not connect to the database.")
        print(f"Please make sure your environment variables (DB_HOST, DB_USER, DB_PASS, DB_NAME) are set correctly.")
        print(f"Details: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == '__main__':
    setup_admin_user()
