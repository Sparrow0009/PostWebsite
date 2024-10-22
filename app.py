from flask_limiter import RateLimitExceeded

from config import app, limiter
from flask import render_template

@app.route('/')
def index():
    return render_template('home/index.html')

@app.errorhandler(429)
def error_page(e):
    return render_template('errors/error.html', message = str(e))

if __name__ == '__main__':
    app.run()