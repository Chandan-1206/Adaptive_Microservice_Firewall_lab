# victim_app/app.py
from flask import Flask, request
import time

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    real_ip = request.headers.get("X-Real-IP") or request.remote_addr
    time.sleep(0.05)
    return f"Hello from VICTIM app! Client IP: {real_ip}"

@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
