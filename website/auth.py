import os
from dotenv import load_dotenv
from flask import Blueprint, render_template, request, flash, session, redirect, url_for
from flask_mail import Message
from email_validator import validate_email, EmailNotValidError
import re
from website import db, mail
from website.models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
import random

load_dotenv()

auth = Blueprint("auth", __name__)

def is_valid_email(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def generate_otp():
    # Generate a random 6-digit OTP
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    msg = Message("Login OTP Verification", recipients=[email])
    msg.body = f"Your OTP for login is: {otp}"
    mail.send(msg)

@auth.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('views.home'))

    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                if user.is_active:
                    otp_code = generate_otp()
                    send_otp_email(email, otp_code)
                    session['otp_code'] = otp_code
                    session['email'] = email
                    return redirect(url_for('auth.verify_otp'))
                else:
                    flash("Account is not activated. Please check your email.", category="warning")
            else:
                flash("Incorrect password, try again", category='error')
        else:
            flash("Email does not exist", category="error")

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('otp_code', None)
    session.pop('email', None)
    return redirect(url_for("auth.login"))


@auth.route('/verify-otp', methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")
        email = session.get("email")
        if entered_otp == session.get("otp_code"):
            session.pop("otp_code")
            session.pop("email")
            flash("OTP verification successful. You are now logged in.", "success")
            login_user(User.query.filter_by(email=email).first())  # Log in the user
            return redirect(url_for("views.home"))  # Redirect to the home page
        else:
            flash("Invalid OTP. Please try again.", "error")
            return redirect(url_for("auth.verify_otp"))

    # Add a default return statement for GET requests
    return render_template("verify_otp.html")


@auth.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not check_password_hash(current_user.password, current_password):
            flash("Current password is incorrect", "error")
            return redirect(url_for("auth.change_password"))

        if new_password != confirm_password:
            flash("New password and confirm password do not match", "error")
            return redirect(url_for("auth.change_password"))

        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        flash("Password changed successfully", "success")
        return redirect(url_for("views.home"))

    return render_template("change_password.html")

from flask import Blueprint, render_template, redirect, request, session, flash
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash


from flask import redirect, request, session, flash
from flask_login import current_user
from functools import wraps

# Function to lock the screen
def lock_screen():
    session['screen_locked'] = True

# Function to unlock the screen
def unlock_screen():
    session.pop('screen_locked', None)

# Decorator to check if the screen is locked
def screen_locked_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('screen_locked'):
            flash('Please unlock the screen to access any page.', 'warning')
            return redirect('/lock-screen')
        return f(*args, **kwargs)
    return decorated_function

@auth.before_request
def before_request():
    if current_user.is_authenticated:
        if request.endpoint not in ['auth.lock_screen_route', 'auth.unlock_screen_route'] and session.get('screen_locked'):
            return redirect('/lock-screen')

@auth.route('/')
@screen_locked_required  # Apply the decorator here
@login_required
def home():
    return render_template("home.html")

@auth.route('/lock-screen')
@login_required
def lock_screen_route():
    lock_screen()  # Lock the screen
    return render_template("lock_screen.html")

@auth.route('/unlock-screen', methods=['POST'])
@login_required
def unlock_screen_route():
    password = request.form['password']
    if current_user and check_password_hash(current_user.password, password):
        unlock_screen()  # Unlock the screen
        flash('Screen unlocked successfully.', 'success')
    else:
        flash('Incorrect password. Please try again.', 'error')
    return redirect('/')

# Your other routes and functions go here...



@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if current_user.is_authenticated:
        return redirect(url_for('views.home'))

    if request.method == "POST":
        user_type = int(request.form.get('usertype'))
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash("Email already exists.", category="error")
        elif not email or not first_name or not password1 or not password2:
            flash("Please fill out all fields", category="error")
        elif len(email) < 4:
            flash("Email must be greater than 4 characters", category="error")
        elif not is_valid_email(email):
            flash("Email provided is not valid", category="error")
        elif len(first_name) < 2:
            flash("First name must be greater than 2 characters", category="error")
        elif password1 != password2:
            flash("Passwords don't match.", category="error")
        elif len(password1) < 8:
            flash("Password must be at least 8 characters", category="error")
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password1):
            flash("Password must have at least one special character", category="error")
        elif not re.search(r'\d', password1):
            flash("Password must have at least one digit", category="error")
        else:
            new_user = User(email=email, first_name=first_name, role_id=user_type,
                            password=generate_password_hash(password1, method="pbkdf2:sha256"), is_active=False)
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully! Please check your email to activate your account.', 'success')
            return redirect(url_for('auth.login'))

    return render_template("sign_up.html", user=current_user)
