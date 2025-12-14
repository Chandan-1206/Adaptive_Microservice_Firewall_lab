from flask import Flask, request
import time

app = Flask(__name__)

@app.route("/")
def index():
    # Simulate some work
    time.sleep(0.05)
    return f"Hello from VICTIM app! Your IP (from proxy): {request.headers.get('X-Real-IP', 'unknown')}"

@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
