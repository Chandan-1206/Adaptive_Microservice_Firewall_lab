# 🔥 Ethical Hacking Firewall Simulation (Docker + Python)

A complete ethical hacking mini-project demonstrating:

- DoS-style attack simulation  
- Python-based firewall with IP rate limiting  
- Real-time traffic monitoring dashboard  
- Docker-based microservice architecture  
- Attacker container executed manually  

---

# 📸 **Project Screenshots (Outputs)**

### **Output 1 – Building Containers**
![Output1-Building Containers](Output/Output1-Building%20containers.png)

### **Output 2 – Starting Containers**
![Output2-Starting Containers](Output/Output2-Starting%20containers.png)

### **Output 3 – VictimApp With No Firewall (Port 8000, IP 172.18.0.3)**
![Output3-No Firewall](Output/Output3-VictimApp%20with%20no%20firewall%20(Port-8000,IP-172.18.0.3).png)

### **Output 4 – VictimApp With Firewall (Port 8080, IP 172.18.0.1)**
![Output4-With Firewall](Output/Output4-VictimApp%20with%20firewall(Port-8080,IP-172.18.0.1).png)

### **Output 5 – No Attack (Normal Behavior)**
![Output5-No Attack](Output/Output5-No%20attack.png)

### **Output 6 – DoS Attack Using HTTP Flooding**
![Output6-Dos Attack]![Output6](Output/Output6-%20Attack%20using%20hhtp%20flooding%28Dos%20attack%29.png)


### **Output 7 – Attacker Container IP Gets Blocked**
![Output7-IP Blocked]![Output7](Output/Output7-%20Attack%20container%20IP-172.18.0.4%20gets%20blocked.png)


### **Output 8 – Brute Force Refresh Flood Attack (VictimApp IP Also Gets Blocked)**
![Output8-Brute force]![Output8](Output/Output8-%20BruteForce%20attack%28Refresh%20flood%29%20on%20VictimApp%20IP%20also%20blocked.png)


---

## 🚀 Project Overview

This project simulates a **real-world attack and defense scenario**:

1. A **Firewall container** monitors and forwards requests.
2. A **Victim Flask app** sits behind the firewall.
3. An **Attacker container** sends 1000 fast requests.
4. Firewall analyzes traffic and:
   - Allows first few requests
   - Blocks abusive IPs (403)
   - Visualizes results on dashboard

Dashboard URL:  
👉 **http://localhost:8080/dashboard**

---

## 📁 Directory Structure

```
docker-firewall-lab/
├── docker-compose.yml
├── firewall_app/
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   └── templates/
│       └── dashboard.html
├── victim_app/
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
└── attacker/
    ├── Dockerfile
    ├── attack.py
    └── requirements.txt
```

---

## 🧩 Architecture

```
Browser ──> Firewall (8080) ──> Victim Server (8000)
                │
                └──> Dashboard (Traffic Monitoring)

Attacker Container ──> Firewall (Flood Requests)
```

Firewall calculates:

- Requests per IP  
- Allowed vs Blocked  
- Temporary banning  
- Live stats  

---

## ⚙️ How to Run the Project

### **1. Build all containers**
```bash
docker compose build
```

### **2. Start firewall + victim**
```bash
docker compose up -d
```

### **3. Check running containers**
```bash
docker ps
```

You should see:

- `firewall_app`
- `victim_app`

---

## 🖥️ Access Dashboard

Open:

👉 **http://localhost:8080/dashboard**

The dashboard shows:

- Pie chart: Allowed vs Blocked
- Bar chart: Per-IP stats
- Table: IP → Count, Allowed, Blocked, Status

Dashboard refreshes every 2 seconds.

---

## 🔎 Test Normal Traffic

Open:

👉 **http://localhost:8080/**

Refresh a few times.

You will see your IP in dashboard as:

```
ACTIVE
Allowed: few
Blocked: 0
```

---

## 🔥 Run Attacker (Manual Trigger)

### Attack with self-deleting container
```bash
docker compose --profile manual run --rm attacker
```

### Attack but keep container for logs
```bash
docker compose --profile manual run attacker
```

You will see:

```
[ATTACKER] Total requests: 1000
200: 50
403: 950
```

Dashboard marks attacker IP as **BLOCKED**.

---

## 📜 View Logs

### Firewall logs
```bash
docker logs -f firewall_app
```

### Victim logs
```bash
docker logs -f victim_app
```

### Attacker logs (if container kept)
```bash
docker ps -a
docker logs -f <attacker-container-name>
```

---

## 🧹 Cleanup & Docker Maintenance Commands

#### Stop & remove containers
```bash
docker compose down
```

#### Remove all unused containers, networks, images
```bash
docker system prune -f
```

#### Remove unused networks
```bash
docker network prune -f
```

#### Remove specific container
```bash
docker rm -f <container>
```

---

## 🛠 Useful Docker Commands

Enter a container shell:
```bash
docker exec -it firewall_app sh
```

Show last 100 log lines:
```bash
docker logs --tail 100 firewall_app
```

Restart services:
```bash
docker compose restart
```

---

## 📌 Expected Behavior Summary

| Scenario | Result |
|----------|---------|
Normal browsing | IP = ACTIVE |
Repeat refresh | Eventually BLOCKED |
Run attacker | 950+ 403 blocks |
Dashboard open | Real time stats |

---

## 🎯 What You Learn

- How DoS attacks work  
- How firewalls mitigate floods  
- Docker microservice networking  
- Flask-based reverse proxy logic  
- Visualizing cyber attacks  
- Ethical hacking simulation  

---

## 🏁 Conclusion

This project is a complete **Attack + Defense Lab** suitable for:

- PBL submissions  
- Cybersecurity demonstrations  
- Ethical hacking learning  
- Portfolio showcase  
- Interviews  
