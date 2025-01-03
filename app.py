from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import re

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
mail = Mail(app)

serializer = URLSafeTimedSerializer(app.secret_key)

limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

otp_store = {}

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/send-token', methods=['POST'])
@limiter.limit("5 per minute")
def send_token():
    email = request.form.get('email')
    if not email or not is_valid_email(email):
        flash("Invalid email address.")
        return redirect(url_for('home'))

    token = serializer.dumps(email, salt='email-confirm')
    link = url_for('login', token=token, _external=True)

    otp = pyotp.random_base32()
    otp_store[email] = {"otp": otp, "expires_at": datetime.now() + timedelta(minutes=5)}

    msg = Message("Your Login Link and OTP", sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"Click this link to log in: {link}\nYour OTP is: {otp} (expires in 5 minutes)."
    mail.send(msg)

    flash("Login link and OTP sent to your email!")
    return redirect(url_for('home'))

@app.route('/login/<token>')
def login(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=600)
        session['user'] = email
        return redirect(url_for('otp_page'))
    except:
        flash("Invalid or expired token.")
        return redirect(url_for('home'))

@app.route('/otp', methods=['GET'])
def otp_page():
    email = session.get('user')
    if not email:
        flash("Session expired. Please log in again.")
        return redirect(url_for('home'))
    return render_template('otp.html')

@app.route('/validate-otp', methods=['POST'])
def validate_otp():
    email = session.get('user')
    user_otp = request.form.get('otp')
    if not email or email not in otp_store:
        flash("Session expired. Please log in again.")
        return redirect(url_for('home'))
    stored_otp = otp_store[email]
    if stored_otp["otp"] == user_otp and datetime.now() < stored_otp["expires_at"]:
        flash("MFA successful!")
        return render_template('success.html', email=email)
    else:
        flash("Invalid or expired OTP.")
        return render_template('otp.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
