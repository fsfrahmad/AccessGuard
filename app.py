from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import random, string, os
from pymongo import MongoClient

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

# ========== Routes ==========

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        existing = users_collection.find_one({'email': email})
        if existing:
            flash("Email already registered.", "error")
            return redirect(url_for('signup'))

        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('signup'))

        user = {
            'username': request.form['username'],
            'email': email,
            'password': generate_password_hash(password),
            'role': request.form['role'].lower(),
            'verified': False,
            'otp': ''.join(random.choices(string.digits, k=6))
        }
        users_collection.insert_one(user)
        send_otp(user['email'], user['otp'])
        session['email'] = user['email']
        session['from_forgot'] = False
        flash("Registration successful! Please verify your email.", "success")
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')

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
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('reset_password'))

        hashed_password = generate_password_hash(new_password)
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'password': hashed_password, 'otp': ''}}
        )
        flash("Password reset successfully! Please login with your new password.", "success")
        session.pop('email', None)
        session.pop('from_forgot', None)
        return redirect(url_for('login'))

    return render_template('reset.html')

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
    msg = Message("Hi Dear User, Your OTP Code for AccessGuard is:", sender=app.config["MAIL_USERNAME"], recipients=[to])
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))