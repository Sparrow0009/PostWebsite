import pyotp
from flask_qrcode import QRcode
from flask import  Blueprint, render_template, flash, redirect, url_for, session
from flask.cli import pass_script_info
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from wtforms.validators import equal_to, EqualTo
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, limiter, load_user
from markupsafe import Markup
from flask_login import login_user, logout_user, current_user, login_required

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')

@accounts_bp.route('/registration', methods = ['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        flash("You are already logged in", category = "info")
        return redirect(url_for('posts.posts'))
    mfa_key = pyotp.random_base32()

    form = RegistrationForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)
        new_user = User(email = form.email.data,
                        firstname = form.firstname.data,
                        lastname = form.lastname.data,
                        phone = form.phone.data,
                        password = form.password.data,
                        mfa_key = mfa_key)
        db.session.add(new_user)
        db.session.commit()

        uri = str(pyotp.totp.TOTP(new_user.mfa_key).provisioning_uri(new_user.email, "Sparsh's Post app"))
        flash('You have not yet enabled Multi-Factor Authentication. Please enable first to login')
        return render_template('accounts/setup_mfa.html', secret=new_user.mfa_key, qr_uri = uri)

    return render_template('accounts/registration.html', form = form)


@accounts_bp.route('/login', methods = ['GET', 'POST'])
@limiter.limit('20 per minute', error_message= 'Too Many Requests')
def login():

    if current_user.is_authenticated:
        flash("You are already logged in", category = "info")
        return redirect(url_for('posts.posts'))

    # checks if the session exists, if not, creates one and sets value to 0.
    global remaining_attempts
    show_form = True
    if not session.get("key"):
        session["key"] = 0
    form = LoginForm()
    if form.validate_on_submit():

        # queries the email from the database from the email gathered from the form
        user = User.query.filter_by(email=form.email.data).first()
        # if the user's email does not exist in the database or the user's password does not match
        if user and user.check_password(form.password.data):
            if pyotp.TOTP(user.mfa_key).verify(form.pin.data):
                if not user.mfa_enabled:
                    user.mfa_enabled = True
                    db.session.commit()

                login_user(user)
                session["key"] = 0
                flash("Login Successful", category='success')
                return redirect(url_for('posts.posts'))

            elif not user.mfa_enabled:
                flash("Multi Factor Authentication has not been enabled, please enable it to log in.", category='danger')
                uri = str(pyotp.totp.TOTP(user.mfa_key).provisioning_uri(user.email, "Sparsh's post app"))
                return render_template('accounts/setup_mfa.html', secret = user.mfa_key, qr_uri = uri)
            flash("Incorrect Pin, please try again", category='danger')
        flash("Incorrect Email or Password, please try again", category='danger')
        session["key"] += 1
        remaining_attempts = 3 - session["key"]

    if session["key"] >= 3:
        flash(Markup('Login failed, maximum authentication attempts exceeded.'), category = "danger")
        show_form = False
    elif 0 < session["key"] < 3:
        flash("Login Failed, you have {} attempts remaining".format(remaining_attempts), category='danger')
        show_form = True
    return render_template('accounts/login.html', form = form, show_form = show_form)


@accounts_bp.route('/reset_attempts', methods=['GET'])
@login_required
def reset_attempts():
    session["key"] = 0
    flash("Your account has been unlocked, Please try logging in again now.", category = 'success')
    return redirect(url_for('accounts.login'))


@accounts_bp.route('/logout', methods=['GET','POST'])
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash("You have been successfully logged out.", category='success')
    return redirect(url_for('index'))

@login_required
@accounts_bp.route('/account')
@login_required
def account():
    if current_user.is_authenticated:
        return render_template('accounts/account.html')
    else:
        return render_template('accounts/account.html', user=None)