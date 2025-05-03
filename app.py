from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import random, string, os
from pymongo import MongoClient
import re

load_dotenv()

client = MongoClient("mongodb+srv://saadislion:krE4oIA2Ht9cFSDI@authcluster.ujfzwo4.mongodb.net/AccessGuard?retryWrites=true&w=majority")
print(client.server_info()) 

app = Flask(__name__)
app.secret_key = os.urandom(24)

# MongoDB Config
app.config["MONGO_URI"] = os.getenv("MONGO_URI")

mongo = PyMongo(app)
users_collection = mongo.db.users

# Mail Config
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
mail = Mail(app)

# Email validation function
def is_valid_email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False
    trusted_domains = ['@gmail.com', '@yahoo.com', '@hotmail.com']
    return any(email.lower().endswith(domain) for domain in trusted_domains)

# Password validation function
def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (e.g., !@#$%^&*)."
    return True, "Password is strong."

# ========== Routes ==========

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        form_data = request.form.to_dict()
        username = form_data['username']
        email = form_data['email']
        
        # Validate email format and domain
        if not is_valid_email(email):
            flash("Please enter a valid email from Gmail, Yahoo, or Hotmail.", "error")
            return render_template('signup.html', form_data=form_data)

        # Check for existing username
        existing_username = users_collection.find_one({'username': username})
        if existing_username:
            flash("Username already taken. Please choose a different one.", "error")
            return render_template('signup.html', form_data=form_data)

        # Check for existing email
        existing_email = users_collection.find_one({'email': email})
        if existing_email:
            flash("Email already registered.", "error")
            return render_template('signup.html', form_data=form_data)

        password = form_data['password']
        confirm_password = form_data['confirm_password']
        
        # Validate password strength
        is_strong, message = is_strong_password(password)
        if not is_strong:
            flash(message, "error")
            return render_template('signup.html', form_data=form_data)

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return render_template('signup.html', form_data=form_data)

        role = form_data['role'].lower()
        # Validate role
        if role not in ['user', 'admin']:
            flash("Invalid role selected. Please choose either user or admin.", "error")
            return render_template('signup.html', form_data=form_data)

        user = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password),
            'role': role,
            'verified': False,
            'otp': ''.join(random.choices(string.digits, k=6))
        }
        users_collection.insert_one(user)
        send_otp(user['email'], user['otp'])
        session['email'] = user['email']
        session['from_forgot'] = False
        flash("Registration successful! Please verify your email.", "success")
        return redirect(url_for('verify_otp'))
    return render_template('signup.html', form_data={})

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']
    user = users_collection.find_one({'email': email})
    if not user:
        return redirect(url_for('signup'))

    if request.method == 'POST':
        if request.form['otp'] == user['otp']:
            users_collection.update_one({'_id': user['_id']}, {'$set': {'verified': True, 'otp': ''}})
            from_forgot = session.get('from_forgot', False)
            if from_forgot:
                flash("OTP verified! Please reset your password.", "success")
                return redirect(url_for('reset_password'))
            else:
                flash("Email verified successfully! You can now login.", "success")
                session.pop('email', None)
                session.pop('from_forgot', None)
                return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Please try again.", "error")
    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']  # Can be username or email
        # Validate email if identifier looks like an email
        if '@' in identifier and not is_valid_email(identifier):
            flash("Please enter a valid email from Gmail, Yahoo, or Hotmail.", "error")
            return redirect(url_for('login'))
        
        user = users_collection.find_one({'$or': [{'username': identifier}, {'email': identifier}]})
        if user and check_password_hash(user['password'], request.form['password']):
            if not user.get('verified', False):
                flash("Please verify your email first.", "warning")
                session['email'] = user['email']
                session['from_forgot'] = False
                return redirect(url_for('verify_otp'))

            session['user_id'] = str(user['_id'])
            session['role'] = user['role']
            flash("Login successful! Welcome back!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username/email or password. Please try again.", "error")
    return render_template('login.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        # Validate email format and domain
        if not is_valid_email(email):
            flash("Please enter a valid email from Gmail, Yahoo, or Hotmail.", "error")
            return redirect(url_for('forgot'))

        user = users_collection.find_one({'email': email})
        if user:
            otp = ''.join(random.choices(string.digits, k=6))
            users_collection.update_one({'_id': user['_id']}, {'$set': {'otp': otp}})
            send_otp(email, otp)
            session['email'] = email
            session['from_forgot'] = True
            flash("OTP sent to your email. Please verify to reset password.", "success")
            return redirect(url_for('verify_otp'))
        flash("Email not found.", "error")
    return render_template('forgot.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'email' not in session or not session.get('from_forgot', False):
        return redirect(url_for('login'))

    email = session['email']
    user = users_collection.find_one({'email': email})
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        form_data = request.form.to_dict()
        new_password = form_data['password']
        confirm_password = form_data['confirm_password']
        
        # Validate password strength
        is_strong, message = is_strong_password(new_password)
        if not is_strong:
            flash(message, "error")
            return render_template('reset.html', form_data=form_data)

        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return render_template('reset.html', form_data=form_data)

        hashed_password = generate_password_hash(new_password)
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'password': hashed_password, 'otp': ''}}
        )
        flash("Password reset successfully! Please login with your new password.", "success")
        session.pop('email', None)
        session.pop('from_forgot', None)
        return redirect(url_for('login'))

    return render_template('reset.html', form_data={})

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    role = session.get('role')
    if role == 'admin':
        return render_template('dashboard/admin.html')
    elif role == 'user':
        return render_template('dashboard/user.html')
    else:
        return "Unauthorized", 403

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))

# ========== Utility ==========

def send_otp(to, otp):
    msg = Message("OTP Code for AccessGuard", sender=app.config["MAIL_USERNAME"], recipients=[to])
    msg.body = f"Hi Dear User, Your OTP is: {otp}"
    mail.send(msg)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))