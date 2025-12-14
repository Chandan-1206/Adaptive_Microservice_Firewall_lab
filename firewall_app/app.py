# firewall_app/app.py
import time
from flask import Flask, request, Response, render_template, jsonify
import requests
from urllib.parse import unquote_plus
from signatures import contains_sqli

app = Flask(__name__)

VICTIM_URL = "http://victim_app:8000"

TRAFFIC_STATS = {}
WINDOW_SECONDS = 10
THRESHOLD = 50
BLOCK_DURATION = 60

TOTAL_ALLOWED = 0
TOTAL_BLOCKED = 0


def is_blocked(ip):
    now = time.time()
    info = TRAFFIC_STATS.get(ip)

    if not info:
        return False

    if info["blocked"]:
        if now - info["blocked_at"] < BLOCK_DURATION:
            return True
        info["blocked"] = False
        info["blocked_at"] = None

    return False


def update_stats(ip, allowed, reason=None):
    global TOTAL_ALLOWED, TOTAL_BLOCKED
    now = time.time()

    info = TRAFFIC_STATS.get(ip, {
        "count": 0,
        "first_seen": now,
        "blocked": False,
        "blocked_at": None,
        "total_allowed_requests": 0,
        "total_blocked_requests": 0,
        "last_reason": None
    })

    if allowed:
        info["total_allowed_requests"] += 1
        TOTAL_ALLOWED += 1
    else:
        info["total_blocked_requests"] += 1
        info["last_reason"] = reason
        TOTAL_BLOCKED += 1

    TRAFFIC_STATS[ip] = info


@app.before_request
def firewall_logic():
    if request.path.startswith("/dashboard") or request.path.startswith("/api"):
        return

    ip = request.remote_addr or "unknown"
    now = time.time()

    raw_payload = (
        (request.query_string.decode() if request.query_string else "") +
        (request.get_data(as_text=True) or "") +
        (" ".join([f"{k}:{v}" for k, v in request.headers.items()]))
    )

    payload = unquote_plus(raw_payload)


    if contains_sqli(payload):
        update_stats(ip, False, "SQL_INJECTION_SIGNATURE")
        return Response("BLOCKED - SQL INJECTION DETECTED", status=403)

    info = TRAFFIC_STATS.get(ip, {
        "count": 0,
        "first_seen": now,
        "blocked": False,
        "blocked_at": None,
        "total_allowed_requests": 0,
        "total_blocked_requests": 0,
        "last_reason": None
    })

    if is_blocked(ip):
        update_stats(ip, False, "TEMPORARY_BAN")
        return Response("BLOCKED BY FIREWALL", status=403)

    if now - info["first_seen"] > WINDOW_SECONDS:
        info["count"] = 0
        info["first_seen"] = now

    info["count"] += 1

    if info["count"] > THRESHOLD:
        info["blocked"] = True
        info["blocked_at"] = now
        TRAFFIC_STATS[ip] = info
        update_stats(ip, False, "RATE_LIMIT_EXCEEDED")
        return Response("BLOCKED - RATE LIMIT EXCEEDED", status=403)

    TRAFFIC_STATS[ip] = info
    update_stats(ip, True)


@app.route("/")
def proxy_to_victim():
    try:
        r = requests.get(VICTIM_URL)
        return r.text
    except Exception as e:
        return f"Error contacting victim: {e}", 500


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats")
def stats():
    data = []
    for ip, info in TRAFFIC_STATS.items():
        data.append({
            "ip": ip,
            "current_window_count": info["count"],
            "blocked": info["blocked"],
            "total_allowed_requests": info["total_allowed_requests"],
            "total_blocked_requests": info["total_blocked_requests"],
            "last_reason": info["last_reason"]
        })

    return jsonify({
        "ips": data,
        "totals": {
            "allowed": TOTAL_ALLOWED,
            "blocked": TOTAL_BLOCKED
        }
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
