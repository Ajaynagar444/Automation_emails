from flask import Flask, render_template, request, redirect, flash, url_for, session, Response
from datetime import timedelta
from flask import make_response
import os
import pandas as pd
import smtplib
import ssl
from email.message import EmailMessage
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from dotenv import load_dotenv
import re
import logging
import json

# Setup logging
logging.basicConfig(level=logging.DEBUG, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
MYSQL_USER = os.getenv('MYSQL_USER')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
MYSQL_PORT = os.getenv('MYSQL_PORT', '3306')
MYSQL_DB = os.getenv('MYSQL_DB')

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key_here')
app.permanent_session_lifetime = timedelta(minutes=30)  # Session timeout

# Setup upload folder and allowed extensions
UPLOAD_FOLDER = 'Uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB file size limit
ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'xls'}  # Support CSV and Excel files

# MySQL connection string
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+mysqlconnector://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)  # Phone number required

# UploadedFile model
class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    mimetype = db.Column(db.String(128), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Optional: track uploader
    uploaded_at = db.Column(db.DateTime, default=db.func.now())
    data_json = db.Column(db.Text, nullable=True)  # JSON representation of file data

# Create DB if not exists
with app.app_context():
    db.create_all()

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_email(name, to_email, subject, body, from_email):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    personalized_body = body.replace("{name}", name)
    msg.set_content(personalized_body)
    return msg

def send_welcome_emails(file_path, smtp_server, smtp_port, subject, body, email_address, email_password):
    try:
        logger.debug(f"Processing file: {file_path}")
        
        # Read file with pandas
        try:
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
            elif file_path.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file_path)
            else:
                raise ValueError("Unsupported file format")
        except Exception as file_error:
            logger.error(f"Failed to read file: {file_path}, error: {file_error}")
            raise ValueError(f"Failed to read file: {file_error}")

        # Validate required columns
        if df.empty:
            raise ValueError("File is empty or contains no valid data")
            
        available_columns = set(col.lower() for col in df.columns)
        required_columns = {'name', 'email'}
        
        if not required_columns.issubset(available_columns):
            missing = required_columns - available_columns
            logger.error(f"Missing required columns: {', '.join(missing)}")
            raise ValueError(f"Missing required columns: {', '.join(missing)}. Available columns: {', '.join(available_columns)}")

        try:
            smtp_port_int = int(smtp_port)
        except Exception as port_error:
            logger.error(f"SMTP port is not a valid integer: {smtp_port}")
            raise ValueError(f"SMTP port is not a valid integer: {smtp_port}")

        context = ssl.create_default_context()
        emails_sent = 0
        failed_emails = 0
        
        try:
            with smtplib.SMTP_SSL(smtp_server, smtp_port_int, context=context) as server:
                logger.debug(f"Logging in to SMTP server: {smtp_server}:{smtp_port}")
                try:
                    server.login(email_address, email_password)
                    logger.info("SMTP authentication successful")
                except smtplib.SMTPAuthenticationError as auth_error:
                    logger.error(f"SMTP authentication failed: {auth_error}")
                    raise smtplib.SMTPAuthenticationError(auth_error.smtp_code, auth_error.smtp_error)
                except Exception as login_error:
                    logger.error(f"SMTP login failed: {login_error}")
                    raise login_error
                
                # Process each row in the DataFrame
                for index, row in df.iterrows():
                    name = str(row.get('name', '') or row.get('Name', '')).strip()
                    email = str(row.get('email', '') or row.get('Email', '')).strip()
                    
                    if not name or not email or email.lower() == 'nan':
                        logger.warning(f"Skipping row {index + 1}: missing name or email: name='{name}', email='{email}'")
                        failed_emails += 1
                        continue
                    
                    msg = create_email(name, email, subject, body, email_address)
                    try:
                        server.send_message(msg)
                        logger.info(f"✅ Email sent to {name} <{email}>")
                        emails_sent += 1
                    except Exception as send_error:
                        logger.error(f"❌ Failed to send email to {email}: {send_error}")
                        failed_emails += 1
                        continue  # Continue to next email on failure
            
            return {
                'success': True,
                'emails_sent': emails_sent,
                'failed_emails': failed_emails,
                'total_processed': emails_sent + failed_emails
            }
            
        except smtplib.SMTPException as smtp_error:
            logger.error(f"SMTP error: {smtp_error}")
            raise smtp_error
        except Exception as smtp_general_error:
            logger.error(f"SMTP connection or sending error: {smtp_general_error}")
            raise smtp_general_error
            
    except Exception as e:
        logger.error(f"Error in send_welcome_emails: {str(e)}")
        raise e

# Validate phone number (10-12 digits, optional + country code)
def validate_phone(phone):
    pattern = r'^\+?\d{10,12}$'
    return bool(re.match(pattern, phone))

# ----------------- USER AUTH ROUTES -------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone')

        if not email or not password or not phone:
            flash('Email, password, and phone number are required.', 'error')
            logger.debug("Registration failed: Missing required fields")
            return redirect(url_for('register'))

        # Validate phone number
        if not validate_phone(phone):
            flash('Phone number must be 10-12 digits (optional + country code).', 'error')
            logger.debug(f"Registration failed: Invalid phone number {phone}")
            return redirect(url_for('register'))

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered.', 'error')
            logger.debug(f"Registration failed: Email {email} already registered")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password, phone=phone)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        logger.info(f"User registered: {email}")
        return redirect(url_for('login'))
    
    response = make_response(render_template('register.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash('Email and password are required.', 'error')
            logger.debug("Login failed: Missing email or password")
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password.', 'error')
            logger.debug(f"Login failed: Invalid credentials for {email}")
            return redirect(url_for('login'))

        session['user_id'] = user.id
        session.permanent = True  # Enable session timeout
        logger.info(f"User logged in: {email}")
        flash('Logged in successfully!', 'success')
        return redirect(url_for('index'))
    
    response = make_response(render_template('login.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Only remove user_id, keep flash messages
    flash('Logged out successfully.', 'info')
    logger.info("User logged out")
    return redirect(url_for('login'))

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logger.warning("Unauthorized access attempt to protected route")
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------- MAIN PAGE -------------------

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        smtp_server = request.form.get('smtp_server')
        smtp_port = request.form.get('smtp_port')
        email_address = request.form.get('email_address')
        email_password = request.form.get('email_password')
        subject = request.form.get('subject')
        body = request.form.get('message')
        file = request.files.get('csv_file')

        logger.debug(f"Received POST request with: smtp_server={smtp_server}, smtp_port={smtp_port}, email_address={email_address}, subject={subject}, file={file.filename if file else 'None'}")

        # Validate all required fields
        if not all([smtp_server, smtp_port, email_address, email_password, subject, body, file]):
            logger.error("Missing required fields")
            flash('⚠️ All fields are required.', 'error')
            return redirect(url_for('index'))

        # Validate file
        if not file or not allowed_file(file.filename):
            logger.error("Invalid or missing file")
            flash('❌ Please upload a valid CSV, XLSX, or XLS file.', 'error')
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        file_data = file.read()  # Read file content as bytes
        mimetype = file.mimetype
        file.seek(0)  # Reset pointer after reading bytes

        # Parse file content to list of dicts
        try:
            if filename.lower().endswith('.csv'):
                df = pd.read_csv(file)
            elif filename.lower().endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file)
            else:
                df = None
        except Exception as e:
            df = None
            logger.error(f"Failed to parse uploaded file for JSON preview: {e}")

        data_json = None
        if df is not None:
            data_json = df.to_json(orient='records')  # List of dicts as JSON

        # Save file to DB (now with data_json)
        uploaded_file = UploadedFile(
            filename=filename,
            data=file_data,
            mimetype=mimetype,
            uploaded_by=session.get('user_id'),
            data_json=data_json
        )
        db.session.add(uploaded_file)
        db.session.commit()
        logger.info(f"File {filename} saved to database.")

        # Save file to disk for processing (if needed)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'wb') as f:
            f.write(file_data)
        logger.debug(f"File saved: {filepath}")
        
        try:
            # Send emails and get results
            result = send_welcome_emails(filepath, smtp_server, smtp_port, subject, body, email_address, email_password)
            
            # Set appropriate flash message based on results
            if result['emails_sent'] > 0:
                if result['failed_emails'] > 0:
                    flash(f'✅ {result["emails_sent"]} emails sent successfully! ⚠️ {result["failed_emails"]} failed.', 'warning')
                else:
                    flash(f'🎉 Success! {result["emails_sent"]} emails sent successfully!', 'success')
                logger.info(f"Email campaign completed: {result['emails_sent']} sent, {result['failed_emails']} failed")
            else:
                flash('⚠️ No valid emails were sent. Check your file for valid name and email entries.', 'warning')
                logger.warning("No emails were sent")
            
        except ValueError as ve:
            logger.error(f"Invalid file structure: {str(ve)}")
            flash(f'❌ Invalid file structure: {str(ve)}', 'error')
        except smtplib.SMTPAuthenticationError as sae:
            logger.error(f"SMTP authentication failed: {str(sae)}")
            flash('❌ Authentication failed. Check your email and app password.', 'error')
        except smtplib.SMTPException as se:
            logger.error(f"SMTP error: {str(se)}")
            flash(f'❌ SMTP error: {str(se)}', 'error')
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            flash(f'❌ Error processing file or sending emails: {str(e)}', 'error')
        finally:
            # Clean up the uploaded file
            if os.path.exists(filepath):
                logger.debug(f"Cleaning up file: {filepath}")
                os.remove(filepath)
        
        # Redirect to show the flash message
        return redirect(url_for('index'))

    # GET request - show the form
    logger.debug("Rendering index.html")
    response = make_response(render_template('index.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    uploaded_file = UploadedFile.query.get_or_404(file_id)
    return Response(
        uploaded_file.data,
        mimetype=uploaded_file.mimetype,
        headers={"Content-Disposition": f"attachment;filename={uploaded_file.filename}"}
    )

@app.route('/file/<int:file_id>')
@login_required
def view_file(file_id):
    uploaded_file = UploadedFile.query.get_or_404(file_id)
    data = []
    columns = []
    if uploaded_file.data_json:
        try:
            data = json.loads(uploaded_file.data_json)
            if data and isinstance(data, list):
                columns = list(data[0].keys())
        except Exception as e:
            logger.error(f"Failed to load JSON data for file {file_id}: {e}")
    return render_template('view_file.html', filename=uploaded_file.filename, columns=columns, data=data)

@app.route('/files')
@login_required
def list_files():
    files = UploadedFile.query.order_by(UploadedFile.uploaded_at.desc()).all()
    return render_template('list_files.html', files=files)

if __name__ == '__main__':
    app.run(debug=True)
