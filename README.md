# 🛡 Adaptive Microservice Firewall Lab  
**Ethical Hacking • Docker • Python • Layer-7 WAF Simulation**

A complete **attack–defense cybersecurity lab** that simulates real-world web attacks and enforces an **adaptive Layer-7 firewall** using Python and Docker.  
The project demonstrates **DoS mitigation, SQLi/XSS/CSRF detection, adaptive rate limiting, threat scoring, and historical attack logging**, visualized through a real-time security dashboard.

---

##  Project Overview

This lab recreates a realistic microservice environment with:

- **Firewall (Reverse Proxy / WAF)** inspecting all inbound traffic  
- **Victim Flask Application** protected behind the firewall  
- **Attacker Container** generating high-volume malicious traffic  
- **Live Security Dashboard** for monitoring attacks & defenses  

The firewall adapts dynamically based on **traffic history and threat score**, escalating actions from **allow → throttle → block**.

---

##  Security Capabilities

- **Layer-7 DoS Protection** (HTTP Flood / Refresh Flood)
- **Adaptive Rate Limiting** with threat-score based thresholds
- **SQL Injection Detection** (regex signature based)
- **XSS Detection** (script, JS, DOM-based patterns)
- **CSRF Heuristics** (Origin / Referer validation)
- **Temporary IP Banning** with decay & recovery
- **Attack History Logging** (timeline of events)
- **Real-Time Visualization Dashboard**

---

##  System Architecture

Browser ──▶ Firewall (8080) ──▶ Victim App (8000)
│
├── Traffic Inspection (SQLi / XSS / CSRF)
├── Adaptive Rate Limiter
├── Threat Score Engine
└── Live Dashboard (/dashboard)

Attacker Container ──▶ Firewall (HTTP Flood)

---

##  Directory Structure

Adaptive_Microservice_Firewall_lab
├── attacker/
│   ├── attack.py
│   ├── Dockerfile
│   └── fire/
├── firewall_app/
│   ├── templates/
│   │   ├── dashboard.html
│   │   └── index.html
│   ├── app.py
│   ├── Dockerfile
│   └── signatures.py
├── Output/ [...]
├── victim_app/
│   ├── app.py
│   └── Dockerfile
├── .gitignore
├── desktop.ini
├── docker-compose.yml
├── README.md
└── requirements.txt

---

##  Project Screenshots

| Stage | Screenshot |
|-----|-----------|
| Docker Build | ![](Output/Output1-Building%20containers.png) |
| Containers Running | ![](Output/Output2-Starting%20containers.png) |
| Victim App (No Firewall) | ![](Output/Output3-VictimApp%20with%20no%20firewall%20(Port-8000,IP-172.18.0.3).png) |
| Victim App (With Firewall) | ![](Output/Output4-VictimApp%20with%20firewall(Port-8080,IP-172.18.0.1).png) |
| Normal Traffic | ![](Output/Output5-No%20attack.png) |
| DoS HTTP Flood | ![](Output/Output6-%20Attack%20using%20hhtp%20flooding%28Dos%20attack%29.png) |
| Attacker IP Blocked | ![](Output/Output7-%20Attack%20container%20IP-172.18.0.4%20gets%20blocked.png) |
| Brute Refresh Flood | ![](Output/Output8-%20BruteForce%20attack%28Refresh%20flood%29%20on%20VictimApp%20IP%20also%20blocked.png) |

---

##  How to Run

### 1️⃣ Build Containers
```bash
docker compose build
```
### 2️⃣ Start Firewall & Victim
```bash
docker compose up -d
```
### 3️⃣ Verify
```bash
docker ps
```
##  Access Points

Firewall Proxy: http://localhost:8080
Security Dashboard: http://localhost:8080/dashboard

### Dashboard updates every 2 seconds and shows:
Allowed vs Blocked traffic
Per-IP enforcement
Threat scores
Attack history timeline

##  Launch Attack (Manual)
```bash
docker compose --profile manual run --rm attacker
```
### Expected result:
Initial requests allowed
Throttling begins
IP blocked (403)
Dashboard flags active threats

##  Firewall Decision Logic
| Condition        | Action          |
| ---------------- | --------------- |
| Low traffic      | Allow           |
| Suspicious burst | Throttle        |
| Sustained abuse  | Block IP        |
| SQLi / XSS       | Instant block   |
| Repeated CSRF    | Escalated block |

Threat score decays over time, allowing recovery for legitimate clients.

##  Useful Commands
```bash
docker compose down
docker logs -f firewall_app
docker logs -f victim_app
docker system prune -f
```

##  Learning Outcomes

-> Practical DoS & WAF internals
-> Reverse proxy firewall design
-> Adaptive security based on traffic history
-> Docker microservice networking
-> Real-time cyber attack visualization
-> Interview-ready cybersecurity project
