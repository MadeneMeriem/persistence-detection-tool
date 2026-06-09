import os
import sys

from flask import Flask
try:
    from flask_cors import CORS
except ImportError:
    CORS = lambda app: None

try:
    from .api import api_bp
except (ImportError, SystemError):
    sys.path.insert(0, os.path.dirname(__file__))
    from api import api_bp

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

app = Flask(
    __name__,
    static_folder=FRONTEND_DIR,
    static_url_path="",
    template_folder=FRONTEND_DIR,
)
CORS(app)
app.register_blueprint(api_bp, url_prefix="/api")


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.errorhandler(404)
def not_found(error):
    return app.send_static_file("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
