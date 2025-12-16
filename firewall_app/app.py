import time
from flask import Flask, request, Response, render_template, jsonify
import requests
from urllib.parse import unquote_plus

from signatures import contains_sqli, contains_xss

app = Flask(__name__)

VICTIM_URL = "http://victim_app:8000"

WINDOW_SECONDS = 10
BLOCK_DURATION = 60

BASE_ALLOW = 30
BASE_THROTTLE = 60
BASE_BLOCK = 90

THROTTLE_DELAY = 0.4
THREAT_DECAY = 0.01

SAFE_ORIGIN = "http://localhost:8080"
CSRF_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

TRAFFIC_STATS = {}

# ✅ NEW: attack history log
ATTACK_EVENTS = []
MAX_EVENTS = 300

TOTAL_ALLOWED = 0
TOTAL_BLOCKED = 0


def default_ip_state(now):
    return {
        "count": 0,
        "first_seen": now,
        "blocked": False,
        "blocked_at": None,
        "total_allowed_requests": 0,
        "total_blocked_requests": 0,
        "last_reason": None,
        "threat_score": 0.0,
        "last_activity": now
    }


# ✅ NEW: explicit attack logger
def log_attack(ip, attack_type, action):
    ATTACK_EVENTS.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "attack_type": attack_type,
        "action": action
    })
    if len(ATTACK_EVENTS) > MAX_EVENTS:
        ATTACK_EVENTS.pop(0)


def is_blocked(ip):
    info = TRAFFIC_STATS.get(ip)
    if not info or not info["blocked"]:
        return False

    if time.time() - info["blocked_at"] < BLOCK_DURATION:
        return True

    info["blocked"] = False
    info["blocked_at"] = None
    return False


def decay_threat(info):
    elapsed = time.time() - info["last_activity"]
    info["threat_score"] = max(0.0, info["threat_score"] - elapsed * THREAT_DECAY)
    info["last_activity"] = time.time()


def thresholds(info):
    penalty = int(info["threat_score"] * 10)
    allow = max(10, BASE_ALLOW - penalty)
    throttle = max(20, BASE_THROTTLE - penalty)
    block = max(30, BASE_BLOCK - penalty)
    return allow, throttle, block


def csrf_suspected(req):
    if req.method not in CSRF_METHODS:
        return False

    origin = req.headers.get("Origin")
    referer = req.headers.get("Referer")

    if not origin and not referer:
        return True

    if origin and not origin.startswith(SAFE_ORIGIN):
        return True

    return False


def update_stats(ip, allowed, reason=None):
    global TOTAL_ALLOWED, TOTAL_BLOCKED

    info = TRAFFIC_STATS[ip]
    info["last_reason"] = reason

    if allowed:
        info["total_allowed_requests"] += 1
        TOTAL_ALLOWED += 1
    else:
        info["total_blocked_requests"] += 1
        TOTAL_BLOCKED += 1


@app.before_request
def firewall_logic():
    if request.path.startswith("/dashboard") or request.path.startswith("/api"):
        return

    ip = request.remote_addr or "unknown"
    now = time.time()

    info = TRAFFIC_STATS.get(ip, default_ip_state(now))

    raw_payload = (
        (request.query_string.decode() if request.query_string else "") +
        (request.get_data(as_text=True) or "") +
        " ".join([f"{k}:{v}" for k, v in request.headers.items()])
    )

    payload = unquote_plus(raw_payload)

    # -------- SQL Injection --------
    if contains_sqli(payload):
        info["threat_score"] += 2.0
        TRAFFIC_STATS[ip] = info
        update_stats(ip, False, "SQL_INJECTION")
        log_attack(ip, "SQL Injection", "Blocked")
        return Response("BLOCKED - SQL INJECTION", status=403)

    # -------- XSS --------
    if contains_xss(payload):
        info["threat_score"] += 1.5
        TRAFFIC_STATS[ip] = info
        update_stats(ip, False, "XSS_ATTACK")
        log_attack(ip, "XSS", "Blocked")
        return Response("BLOCKED - XSS", status=403)

    # -------- CSRF --------
    if csrf_suspected(request):
        info["threat_score"] += 1.0
        TRAFFIC_STATS[ip] = info

        if info["threat_score"] > 2.5:
            update_stats(ip, False, "CSRF_BLOCK")
            log_attack(ip, "CSRF", "Blocked")
            return Response("BLOCKED - CSRF", status=403)

        update_stats(ip, True, "CSRF_SUSPECTED")
        log_attack(ip, "CSRF", "ALLOWED")

    # -------- Existing block --------
    if is_blocked(ip):
        TRAFFIC_STATS[ip] = info
        update_stats(ip, False, "TEMP_BAN")
        return Response("BLOCKED", status=403)

    # -------- Rate logic --------
    if now - info["first_seen"] > WINDOW_SECONDS:
        info["count"] = 0
        info["first_seen"] = now

    decay_threat(info)
    allow_t, throttle_t, block_t = thresholds(info)

    info["count"] += 1

    if info["count"] > block_t:
        info["blocked"] = True
        info["blocked_at"] = now
        info["threat_score"] += 1.5
        TRAFFIC_STATS[ip] = info
        update_stats(ip, False, "RATE_LIMIT_BLOCK")
        log_attack(ip, "Abnormal Traffic", "Blocked")
        return Response("BLOCKED - RATE LIMIT", status=403)

    if info["count"] > throttle_t:
        time.sleep(THROTTLE_DELAY)
        info["threat_score"] += 0.2
        TRAFFIC_STATS[ip] = info
        update_stats(ip, True, "THROTTLED")
        log_attack(ip, "Abnormal Traffic", "Throttled")
        return

    TRAFFIC_STATS[ip] = info
    update_stats(ip, True, "NORMAL")


@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy_to_victim():
    r = requests.request(
        method=request.method,
        url=VICTIM_URL,
        headers={"X-Real-IP": request.remote_addr},
        data=request.get_data(),
        params=request.args
    )
    return r.text, r.status_code


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats")
def stats():
    return jsonify({
        "ips": [
            {
                "ip": ip,
                "current_window_count": info["count"],
                "blocked": info["blocked"],
                "total_allowed_requests": info["total_allowed_requests"],
                "total_blocked_requests": info["total_blocked_requests"],
                "last_reason": info["last_reason"],
                "threat_score": round(info["threat_score"], 2)
            }
            for ip, info in TRAFFIC_STATS.items()
        ],
        "events": ATTACK_EVENTS,   # ✅ HISTORY HERE
        "totals": {
            "allowed": TOTAL_ALLOWED,
            "blocked": TOTAL_BLOCKED
        }
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
