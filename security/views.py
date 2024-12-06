from tempfile import template

from flask import Blueprint, render_template
from flask_login import login_required

from accounts.views import roles_required

security_bp = Blueprint('security', __name__, template_folder= 'templates')

@login_required
@security_bp.route('/security')
@roles_required('sec_admin')
def security():
    return render_template('security/security.html')