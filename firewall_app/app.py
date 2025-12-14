import time
from flask import Flask, request, Response, render_template, jsonify
import requests

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
        else:
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

    info = TRAFFIC_STATS.get(ip, {
        "count": 0,
        "first_seen": now,
        "blocked": False,
        "blocked_at": None,
        "total_allowed_requests": 0,
        "total_blocked_requests": 0,
        "last_reason": None
    })

    # Check if blocked
    if is_blocked(ip):
        update_stats(ip, False, "Temporary ban")
        return Response("BLOCKED BY FIREWALL", status=403)

    # Sliding window check
    if now - info["first_seen"] > WINDOW_SECONDS:
        info["count"] = 0
        info["first_seen"] = now

    info["count"] += 1

    if info["count"] > THRESHOLD:
        info["blocked"] = True
        info["blocked_at"] = now
        TRAFFIC_STATS[ip] = info
        update_stats(ip, False, "Rate limit exceeded")
        return Response("BLOCKED - RATE LIMIT EXCEEDED", status=403)

    TRAFFIC_STATS[ip] = info
    update_stats(ip, True)


# ✅ REAL TRAFFIC ROUTE (MONITORED)
@app.route("/")
def proxy_to_victim():
    try:
        response = requests.get(VICTIM_URL)
        return response.text
    except Exception as e:
        return f"Error contacting victim: {e}", 500


# ✅ DASHBOARD (NOT MONITORED)
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ✅ STATS API (NOT MONITORED)
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
