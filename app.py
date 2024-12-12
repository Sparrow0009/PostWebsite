import re
from config import app
from flask import render_template, request


@app.route('/')
def index():
    return render_template('home/index.html')

@app.errorhandler(429)
def error_page(e):
    return render_template('errors/error.html', message = str(e))

@app.errorhandler(400)
def bad_request_error(error):
    return render_template('errors/400.html'), 400

@app.errorhandler(404)
def page_not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('errors/500.html'), 500

@app.errorhandler(501)
def not_implemented_error(error):
    return render_template('errors/501.html'), 501


conditions = {
    "SQL Injection": re.compile(r"(union|select|insert|drop|alter|;|`|')", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|<iframe>|%3Cscript%3E|%3Ciframe%3E)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.|%2e%2e%2f|%2e%2e/)", re.IGNORECASE),
}

@app.before_request
def waf_protection():
    for attack_type, attack_pattern in conditions.items():
        if attack_pattern.search(request.path) or attack_pattern.search(request.query_string.decode()):
            return render_template('errors/attack.html', attack_type=attack_type)

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))