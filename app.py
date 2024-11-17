import os
import random
import string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import hashlib

# Flask app initialization
app = Flask(__name__)

# Configure the Flask app
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['JWT_SECRET_KEY'] = 'jwtsecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'pptx', 'docx', 'xlsx'}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'

# Initialize extensions
jwt_manager = JWTManager(app)
mail = Mail(app)

# In-memory "databases"
users_db = {}  # email -> user data (password, role)
files_db = {}  # file_id -> file data (file_name, uploaded_by)

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_email_verification_link(email):
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    return f'http://127.0.0.1:5000/verify/{token}', token  # Return URL and token

def send_email_verification(email, token):
    verification_url = f'http://127.0.0.1:5000/verify/{token}'
    msg = Message("Email Verification", sender="your-email@gmail.com", recipients=[email])
    msg.body = f"Click this link to verify your email: {verification_url}"
    mail.send(msg)

# Routes

# User signup (Client user only)
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if email in users_db:
        return jsonify({"message": "User already exists"}), 400

    encrypted_password = hashlib.sha256(password.encode()).hexdigest()
    users_db[email] = {"password": encrypted_password, "role": "client", "verified": False}

    # Simulate email verification
    verification_token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    users_db[email]["verification_token"] = verification_token

    send_email_verification(email, verification_token)
    return jsonify({"message": "Signup successful. Check your email to verify your account."}), 200

# Email verification route
@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    # Simulate email verification
    for email, user_data in users_db.items():
        if user_data["verification_token"] == token:
            users_db[email]["verified"] = True
            return jsonify({"message": "Email verified successfully!"}), 200
    return jsonify({"message": "Invalid or expired verification token."}), 400

# User login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    encrypted_password = hashlib.sha256(password.encode()).hexdigest()
    user = users_db.get(email)

    if not user or user["password"] != encrypted_password:
        return jsonify({"message": "Invalid credentials"}), 401

    if not user["verified"]:
        return jsonify({"message": "Please verify your email first."}), 400

    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token), 200

# Upload file (Only Ops user)
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = get_jwt_identity()
    user = users_db.get(current_user)

    if user["role"] != "ops":
        return jsonify({"message": "Only Ops users can upload files."}), 403

    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return jsonify({"message": "Invalid file type. Only .pptx, .docx, .xlsx are allowed."}), 400

    filename = secure_filename(file.filename)
    file_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # Unique file ID
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    files_db[file_id] = {"file_name": filename, "uploaded_by": current_user}
    return jsonify({"message": "File uploaded successfully", "file_id": file_id}), 200

# Download file (Client user)
@app.route('/download/<file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    current_user = get_jwt_identity()
    user = users_db.get(current_user)

    if user["role"] != "client":
        return jsonify({"message": "Only Client users can download files."}), 403

    file_data = files_db.get(file_id)
    if not file_data:
        return jsonify({"message": "File not found."}), 404

    return jsonify({"message": f"Downloading {file_data['file_name']}."}), 200

# Main entry point
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)

