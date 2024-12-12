from flask import Blueprint, render_template
from flask_login import login_required
from accounts.views import roles_required
from config import User

security_bp = Blueprint('security', __name__, template_folder= 'templates')


@security_bp.route('/security')
@login_required
@roles_required('sec_admin')
def security():
    logs = []
    with open('security.log', 'r') as file:
        logs = file.readlines()[-10:]
    users = User.query.all()
    return render_template('security/security.html', users = users, logs = logs)