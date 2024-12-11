from flask_limiter import RateLimitExceeded
from rich.markup import render

from config import app, limiter
from flask import render_template

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

if __name__ == '__main__':
    app.run()