import os
import psycopg2
from werkzeug.security import generate_password_hash

# This script securely resets the admin password for the LOCAL database.

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

        print("Removing old admin user (if exists)...")
        cur.execute("DELETE FROM Staff WHERE username = 'admin';")

        print("Creating new admin user with username 'admin' and password 'password'...")
        password_hash = generate_password_hash('password')
        
        cur.execute(
            "INSERT INTO Staff (username, password_hash, full_name, is_admin, must_change_password, secret_code) VALUES (%s, %s, %s, %s, %s, %s);",
            ('admin', password_hash, 'Admin User', True, True, 'ADMIN_LOCAL_CODE')
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("\nSUCCESS: The local admin user has been reset successfully.")
        print("You can now run your main application and log in locally.")

    except psycopg2.OperationalError:
        print(f"\nERROR: Could not connect to the database.")
        print(f"Please make sure your environment variables (DB_HOST, DB_USER, DB_PASS, DB_NAME) are set correctly.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == '__main__':
    setup_admin_user()


