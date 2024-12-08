import pyotp
from flask import Flask, url_for, flash, redirect, abort, render_template
from flask_limiter import Limiter
from flask_limiter.contrib.util import get_remote_address_cloudflare
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import  SQLAlchemy
from flask_migrate import Migrate, current
from sqlalchemy import MetaData
from datetime import datetime
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets
from flask_qrcode import QRcode
from flask_login import LoginManager, current_user
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms.validators import EqualTo

app = Flask(__name__)

qrcode = QRcode(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'accounts.login'
login_manager.login_message = 'Please Log in first you donut!'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = secrets.token_hex(16)

#DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///csc2031blog.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#CAPTCHA CONFIGURATION
app.config['RECAPTCHA_PUBLIC_KEY'] ='6LcaBV4qAAAAABbnBqXTymeD_jLjJfiXGOu8Wu82'
app.config['RECAPTCHA_PRIVATE_KEY'] ='6LcaBV4qAAAAAEZUnlbcLE0ypUMrxuLj6wsH1P6O'


metadata = MetaData(
    naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
    }
)

db = SQLAlchemy(app, metadata = metadata)
migrate = Migrate(app, db)

# DATABASE TABLES
class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    created = db.Column(db.DateTime, nullable=False)
    title = db.Column(db.Text, nullable=False)
    body = db.Column(db.Text, nullable=False)
    user = db.relationship("User", back_populates="posts")
    def __init__(self, userid, title, body):
        self.userid = userid
        self.created = datetime.now()
        self.title = title
        self.body = body

    def update(self,title,body):
        self.created = datetime.now()
        self.title = title
        self.body = body
        db.session.commit()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)

    #User authentication information
    email = db.Column(db.String(100), nullable = False, unique = True)
    password = db.Column(db.String(100), nullable = False,)

    #User information
    firstname = db.Column(db.String(100), nullable = False)
    lastname = db.Column(db.String(100), nullable = False)
    phone = db.Column(db.String(100), nullable = False)
    posts = db.relationship("Post", order_by = Post.id, back_populates = 'user')
    log = db.relationship("Log", uselist=False, back_populates="user")

    #MFA information
    mfa_key = db.Column(db.String(32), nullable = False, default=pyotp.random_base32)
    mfa_enabled = db.Column(db.Boolean, default = False)
    active = db.Column(db.Boolean, nullable = False, default = True)
    role = db.Column(db.String(32), nullable = False, default = 'end_user')

    def __init__(self, email, firstname, lastname, phone, password, mfa_key=None):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.mfa_key = pyotp.random_base32()
        self.mfa_enabled = False
        self.role = 'end_user'

    @property
    def is_active(self):
        return self.active

    def get_id(self):
        return str(self.id)

    def check_password(self,password):
        return self.password == password
    def generate_log(self):
        new_log = Log(userid = self.id, registration = datetime.now())
        db.session.add(new_log)
        db.session.commit()


class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer,primary_key = True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    registration = db.Column(db.DateTime, nullable = False)
    latest_login  = db.Column(db.DateTime, nullable = True)
    previous_login = db.Column(db.DateTime, nullable = True)
    latest_IP = db.Column(db.String(100), nullable = True)
    previous_IP = db.Column(db.String(100), nullable = True)
    user = db.relationship("User", back_populates = 'log')

    def __init__(self, userid, registration):
        self.userid = userid
        self.registration = registration


# DATABASE ADMINISTRATOR
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')

class PostView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'
    def inaccissible_callback(self, name, **kwargs):
        if current_user.is_authenticated:
            abort(403)
        flash("Access denied: Administrator Access Required.", category='danger')
        return redirect(url_for('accounts.login'))

    column_display_pk = True   # optional, but I like to see the IDs in the list
    column_hide_backrefs = False
    column_list = ('id','userid', 'created', 'title', 'body', 'user')
    #can_create = False
    #can_edit = False
    #can_delete = False

class UserView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'
    def inaccissible_callback(self, name, **kwargs):
        if current_user.is_authenticated:
            abort(403)
        flash("Access denied: Administrator Access Required.", category='danger')
        return redirect(url_for('accounts.login'))

    column_display_pk = True  # optional, but I like to see the IDs in the list
    column_hide_backrefs = False
    column_list = ('id', 'email', 'password', 'firstname', 'lastname', 'phone', 'posts', 'mfa_key', 'mfa_enabled', 'role')
    #can_create = False
    #can_edit = False
    #x`can_delete = False

class LogView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'
    def inaccissible_callback(self, name, **kwargs):
        if current_user.is_authenticated:
            abort(403)
        flash("Access denied: Administrator Access Required.", category='danger')
        return redirect(url_for('accounts.login'))
    column_display_pk = True  # optional, but I like to see the IDs in the list
    column_hide_backrefs = False
    column_list = ('id','userid','registration','latest_login','previous_login','latest_IP','previous_IP','user')
    can_create = False
    can_edit = False
    can_delete = False


admin = Admin(app, name = 'DB Admin', template_mode= 'bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name = 'Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))
admin.add_view(LogView(Log, db.session))

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=['500 per day'])

from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp

app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True

