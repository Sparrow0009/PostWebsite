import pyotp
from flask import  Blueprint, render_template, flash, redirect, url_for, session
from flask.cli import pass_script_info
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from wtforms.validators import equal_to, EqualTo
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, limiter
from markupsafe import Markup

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')

@accounts_bp.route('/registration', methods = ['GET', 'POST'])
def registration():
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
        flash('You have not yet enabled Multi-Factor Authentication. Please enable first to login')
       # flash('Account Created', category='success')
        return render_template('accounts/setup_mfa.html', secret = new_user.mfa_key)
        #return redirect(url_for('accounts.login'))

    return render_template('accounts/registration.html', form = form)


@accounts_bp.route('/login', methods = ['GET', 'POST'])
@limiter.limit('20 per minute', error_message= 'Too Many Requests')
def login():
    # checks if the session exists, if not, creates one and sets value to 0.
    if not session.get("key"):
        session["key"] = 0
    form = LoginForm()
    if form.validate_on_submit():

        # queries the email from the database from the email gathered from the form
        user = User.query.filter_by(email=form.email.data).first()
        session["key"] += 1
        if session["key"] >= 3:
            flash(Markup('Login failed, maximum authentication attempts exceeded <a href = "/login"> Unlock Account</a>'), category = "danger")
            return render_template('accounts/login.html')
        # if the user's email does not exist in the database or the user's password does not match
        if not user or not user.check_password(form.password.data) or not pyotp.TOTP(user.mfa_key).verify(form.pin.data):
            remaining_attempts = 3 - session["key"]
            flash("Login Failed, you have {} attempts remaining".format(remaining_attempts),category = 'danger')
            return redirect(url_for('accounts.login'))

        if not user.mfa_enabled:
            user.mfa_enabled = True
            db.session.commit()

        session["key"] = 0
        flash("Login Successful", category = 'success')
        return redirect(url_for('posts.posts'))
    return render_template('accounts/login.html', form = form)

@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')