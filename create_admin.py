import bcrypt
import sqlite3
import getpass
import sys

DATABASE_PATH = 'users.db'

def create_admin():
    username = input("Admin-Username eingeben: ").strip()
    if not username:
        print("ERROR: Username darf nicht leer sein.")
        sys.exit(1)

    password = getpass.getpass("Admin-Passwort eingeben: ")
    confirm  = getpass.getpass("Passwort bestätigen: ")

    if password != confirm:
        print("ERROR: Passwörter stimmen nicht überein.")
        sys.exit(1)

    if len(password) < 12:
        print("ERROR: Passwort muss mindestens 12 Zeichen haben.")
        sys.exit(1)

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed)
        )
        conn.commit()
        print(f"✅ Admin-User '{username}' erfolgreich erstellt.")
    except sqlite3.IntegrityError:
        print(f"ERROR: Username '{username}' existiert bereits.")
        sys.exit(1)
    finally:
        conn.close()

if __name__ == '__main__':
    create_admin()