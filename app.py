from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify, session
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
import bcrypt  # Import bcrypt for password hashing
import os
import sqlite3
import base64
import json
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException

app = Flask(__name__)
# Change this to a stronger secret key in production
app.secret_key = '51855d52e41656e7b6af1d1056cbe967ae63a26358f47af0'
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
    PERMANENT_SESSION_LIFETIME=3600,
)
DATABASE_PATH = 'users.db'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Pre-created hashed password for admin user
# Update this with your generated hash
PRE_CREATED_HASH = "$2b$12$C0do3nPggj0GhzstDP1fgOf3U7nU/5X3T5NXPpG6JXTiUfieKkfQO"

# Generate encryption key, in production, keep this in a secure place.
KEY = Fernet.generate_key()
cipher_suite = Fernet(KEY)

# App configuration
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Max file size of 16MB
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# WebAuthn / FIDO2 configuration
RP_ID = os.environ.get("WEBAUTHN_RP_ID",   "localhost")
RP_NAME = os.environ.get("WEBAUTHN_RP_NAME",  "SkyVault")
WEBAUTHN_ORIGIN = os.environ.get(
    "WEBAUTHN_ORIGIN", "http://localhost:5000"
)


def get_db_connection():
    """Create a SQLite connection with row access by column name."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the users table for authentication."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
        '''
    )
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id            INTEGER  PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER  NOT NULL,
            credential_id BLOB     NOT NULL UNIQUE,
            public_key    BLOB     NOT NULL,
            sign_count    INTEGER  NOT NULL DEFAULT 0,
            aaguid        TEXT,
            transports    TEXT,
            name          TEXT     NOT NULL DEFAULT 'My passkey',
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        '''
    )
    conn.commit()
    conn.close()


def migrate_users_from_txt():
    """Import legacy users from users.txt into SQLite once."""
    legacy_file = 'users.txt'
    if not os.path.exists(legacy_file):
        return

    conn = get_db_connection()
    cursor = conn.cursor()
    imported = 0

    with open(legacy_file, 'r') as file:
        for line in file:
            raw = line.strip()
            if not raw or ',' not in raw:
                continue

            username, password_hash = raw.split(',', 1)
            username = username.strip()
            password_hash = password_hash.strip()

            if not username or not password_hash:
                continue

            cursor.execute(
                'INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash),
            )
            if cursor.rowcount == 1:
                imported += 1

    conn.commit()
    conn.close()
    print(f"User migration complete: imported {imported} users from users.txt")


def get_user_by_id(user_id):
    """Fetch an active user by database id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, username, password_hash, is_active FROM users WHERE id = ? AND is_active = 1',
        (user_id,),
    )
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_username(username):
    """Fetch an active user by username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, username, password_hash, is_active FROM users WHERE username = ? AND is_active = 1',
        (username,),
    )
    user = cursor.fetchone()
    conn.close()
    return user


def create_user(username, password_hash):
    """Create a new active user account."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def update_last_login(user_id):
    """Store the timestamp of the user's most recent successful login."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
        (user_id,),
    )
    conn.commit()
    conn.close()


def allowed_file(filename):
    """Check if the uploaded file is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_icon(filename):
    """Return the appropriate icon for a file based on its extension."""
    file_ext = filename.rsplit('.', 1)[1].lower()
    icon_map = {
        'pdf': 'pdf-icon.png',
        'txt': 'txt-icon.png',
        'png': 'image-icon.png',
        'jpg': 'image-icon.png',
        'jpeg': 'image-icon.png',
        'gif': 'image-icon.png',
    }
    return icon_map.get(file_ext, 'default-icon.png')


# Simple user class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username=None):
        self.id = str(id)
        self.username = username


# User loader
@login_manager.user_loader
def load_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return None
    return User(user['id'], user['username'])


def _get_user_credentials(user_id: int) -> list:
    """Return all stored WebAuthn credentials for a user as a list of dicts."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT credential_id, public_key, sign_count, transports, name"
        " FROM webauthn_credentials WHERE user_id = ?",
        (user_id,)
    ).fetchall()
    conn.close()
    return [
        {
            "credential_id": row["credential_id"],
            "public_key":    row["public_key"],
            "sign_count":    row["sign_count"],
            "transports":    json.loads(row["transports"]) if row["transports"] else [],
            "name":          row["name"],
        }
        for row in rows
    ]


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html', title="Secure Cloud Storage")
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = get_user_by_username(username)
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            login_user(User(user['id'], user['username']))
            update_last_login(user['id'])
            return redirect(url_for('index'))

        flash("Invalid credentials", "danger")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'GET':
        return redirect(url_for('index'))

    if 'file' not in request.files:
        flash("No file part in the request!", "danger")
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash("No file selected for uploading!", "warning")
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Encrypt the file before saving it
        encrypted_file = cipher_suite.encrypt(file.read())
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'wb') as f:
            f.write(encrypted_file)

        flash(
            f"File '{filename}' uploaded and encrypted successfully!", "success")
        return redirect(url_for('files'))
    else:
        flash("Invalid file type! Only txt, pdf, png, jpg, jpeg, and gif are allowed.", "danger")
        return redirect(url_for('index'))


@app.route('/files')
@login_required
def files():
    try:
        file_list = os.listdir(app.config['UPLOAD_FOLDER'])
        return render_template('files.html', files=file_list, get_icon=get_icon, title="Uploaded Files")
    except Exception as e:
        flash(f"Error retrieving files: {str(e)}", "danger")
        return redirect(url_for('index'))


@app.route('/download/<filename>')
@login_required
def download(filename):
    try:
        safe_filename = secure_filename(filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

        # Decrypt the file before sending
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)

        # Send the decrypted file to the user
        response = send_from_directory(
            app.config['UPLOAD_FOLDER'], safe_filename, as_attachment=True)
        response.data = decrypted_data
        return response
    except FileNotFoundError:
        flash("File not found!", "warning")
        return redirect(url_for('files'))
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "danger")
        return redirect(url_for('files'))


@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    try:
        safe_filename = secure_filename(filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

        if os.path.exists(file_path):
            os.remove(file_path)
            flash(f"File '{safe_filename}' deleted successfully!", "success")
        else:
            flash(f"File '{safe_filename}' not found!", "warning")

        return redirect(url_for('files'))
    except Exception as e:
        flash(f"Error deleting file: {str(e)}", "danger")
        return redirect(url_for('files'))


@app.route('/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    """Issue a WebAuthn registration challenge for the current logged-in user."""
    user_id = int(current_user.id)
    username = current_user.username

    existing = _get_user_credentials(user_id)

    exclude_credentials = [
        PublicKeyCredentialDescriptor(
            id=row["credential_id"],
            transports=[AuthenticatorTransport(t) for t in row["transports"]],
        )
        for row in existing
    ]

    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user_id).encode('utf-8'),
        user_name=username,
        user_display_name=username,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        hints=["client-device", "security-key"],
    )

    session['webauthn_reg_challenge'] = base64.b64encode(
        options.challenge).decode()

    return webauthn.options_to_json(options), 200, {'Content-Type': 'application/json'}


@app.route('/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    """Verify the authenticator's attestation response and persist the credential."""
    challenge_b64 = session.pop('webauthn_reg_challenge', None)
    if not challenge_b64:
        return jsonify({'error': 'No pending registration challenge'}), 400

    user_id = int(current_user.id)
    body = request.get_json(silent=True) or {}
    cred_name = body.get('name', 'My passkey')[:64]

    try:
        verification = webauthn.verify_registration_response(
            credential=webauthn.parse_registration_credential_json(
                body.get('credential', {})),
            expected_challenge=base64.b64decode(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
        )
    except WebAuthnException as exc:
        app.logger.warning("WebAuthn registration failed: %s", exc)
        return jsonify({'error': str(exc)}), 400

    transports_json = json.dumps(
        [t.value for t in (verification.credential_transports or [])]
    )

    conn = get_db_connection()
    try:
        conn.execute(
            """INSERT INTO webauthn_credentials
               (user_id, credential_id, public_key, sign_count, aaguid, transports, name)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                verification.credential_id,
                verification.credential_public_key,
                verification.sign_count,
                str(verification.aaguid),
                transports_json,
                cred_name,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({'status': 'ok', 'name': cred_name})


@app.route('/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    """Issue a WebAuthn authentication challenge for the named user."""
    body = request.get_json(silent=True) or {}
    username = (body.get('username') or '').strip()

    conn = get_db_connection()
    user = conn.execute(
        'SELECT id FROM users WHERE username = ? AND is_active = 1', (
            username,)
    ).fetchone()
    conn.close()

    allow_credentials = []
    if user:
        existing = _get_user_credentials(user['id'])
        allow_credentials = [
            PublicKeyCredentialDescriptor(
                id=row["credential_id"],
                transports=[AuthenticatorTransport(
                    t) for t in row["transports"]],
            )
            for row in existing
        ]
        session['webauthn_login_user_id'] = user['id']

    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    # Always set a fresh challenge — even for unknown users (prevents user enumeration)
    session['webauthn_login_challenge'] = base64.b64encode(
        options.challenge).decode()

    return webauthn.options_to_json(options), 200, {'Content-Type': 'application/json'}


@app.route('/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    """Verify the signed assertion and establish a Flask session."""
    challenge_b64 = session.pop('webauthn_login_challenge', None)
    user_id = session.pop('webauthn_login_user_id', None)

    if not challenge_b64 or not user_id:
        return jsonify({'error': 'No pending login challenge'}), 400

    body = request.get_json(silent=True) or {}

    conn = get_db_connection()
    username_row = conn.execute(
        'SELECT username FROM users WHERE id = ? AND is_active = 1', (user_id,)
    ).fetchone()

    raw_id_b64 = body.get('credential', {}).get('rawId', '')
    try:
        raw_id_bytes = base64.urlsafe_b64decode(raw_id_b64 + '==')
    except Exception:
        conn.close()
        return jsonify({'error': 'Invalid credential ID encoding'}), 400

    cred_row = conn.execute(
        """SELECT credential_id, public_key, sign_count
           FROM webauthn_credentials
           WHERE user_id = ? AND credential_id = ?""",
        (user_id, raw_id_bytes),
    ).fetchone()
    conn.close()

    if not cred_row or not username_row:
        return jsonify({'error': 'Credential not found'}), 400

    try:
        verification = webauthn.verify_authentication_response(
            credential=webauthn.parse_authentication_credential_json(
                body.get('credential', {})
            ),
            expected_challenge=base64.b64decode(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=cred_row['public_key'],
            credential_current_sign_count=cred_row['sign_count'],
            require_user_verification=False,
        )
    except WebAuthnException as exc:
        app.logger.warning("WebAuthn authentication failed: %s", exc)
        return jsonify({'error': str(exc)}), 400

    conn = get_db_connection()
    conn.execute(
        'UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?',
        (verification.new_sign_count, cred_row['credential_id']),
    )
    conn.commit()
    conn.close()

    login_user(User(user_id, username_row['username']))
    update_last_login(user_id)

    return jsonify({'status': 'ok', 'redirect': url_for('files')})


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', title="Page Not Found"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html', title="Internal Server Error"), 500


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        if not username or not password:
            flash("Username and password are required!", "danger")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()).decode()

        if not create_user(username, hashed_password):
            flash("Username already exists!", "danger")
            return redirect(url_for('signup'))

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html', title="Sign Up")


init_db()
migrate_users_from_txt()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
