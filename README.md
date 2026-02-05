# Sentinel Shield – Advanced Intrusion Detection & Web Protection System:

Sentinel Shield is an academic cybersecurity project that simulates how a real-world **Intrusion Detection System (IDS)** and **Web Application Firewall (WAF)** work.  
It inspects incoming HTTP requests, detects common web attacks, logs suspicious activity, and generates alerts.


## Project Objectives

• Understand how malicious web requests look in real traffic  
• Detect common attacks using rule-based logic  
• Monitor abusive behavior using rate limiting  
• Log and analyze security events  
• Simulate the detection → decision → logging → alerting workflow  


## Attacks Detected

✔ SQL Injection (SQLi)  
✔ Cross-Site Scripting (XSS)  
✔ Local File Inclusion (LFI)  
✔ Command Injection (basic patterns)  
✔ Brute-force / abusive traffic via rate limiting  


## How the System Works

1. A user sends an HTTP request  
2. Sentinel Shield inspects the request (URL, parameters, headers)  
3. The detection engine matches known attack patterns  
4. IP behavior is monitored (rate limiting)  
5. If malicious or abusive:
   - The request is blocked or flagged
   - The event is logged
   - An alert is generated

Think of Sentinel Shield as a **security guard for your web application**.
-----------------------------------------------------------------------------------------------------------------------------

User Request

↓
Web App (Flask)

↓
Sentinel Shield Engine

├── Request Inspection

├── Rule-Based Detection

├── Behavior Monitoring (Rate Limiting)

├── Logging & Alerts

↓
Logs / Dashboard / Reports

-----------------------------------------------------------------------------------------------------------------------------

# 🛠 STEP 1 — Environment Setup (Do This First)

### 1️⃣ Install Python

Check:

```bash
python --version
```

If not installed, install from python.org

---

### 2️⃣ Create Project Folder

```bash
mkdir sentinel-shield
cd sentinel-shield
```

---

### 3️⃣ Create Virtual Environment (Good Practice)

```bash
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate  # Linux/Mac
```

---

### 4️⃣ Install Flask

```bash
pip install flask
```

---

### 5️⃣ Create Files

Create these files:

```
sentinel-shield/
├── app.py
├── detector.py
├── rate_limiter.py
├── logger.py
├── dashboard.py
├── rules.json
├── logs/
│   └── security.log
├── templates/
│   └── dashboard.html
└── requirements.txt
```

---

# 🧠 STEP 2 — Detection Rules (rules.json)

```json
{
  "SQLi": ["(?i)union\\s+select", "(?i)or\\s+1=1", "(?i)drop\\s+table"],
  "XSS": ["<script>", "onerror=", "onload="],
  "LFI": ["\\.\\./", "/etc/passwd"],
  "CMDi": [";\\s*ls", ";\\s*whoami"]
}
```

---

# 🔍 STEP 3 — Detection Engine (detector.py)

```python
import re, json

with open("rules.json") as f:
    RULES = json.load(f)

def detect_attack(data):
    for attack, patterns in RULES.items():
        for pattern in patterns:
            if re.search(pattern, data):
                return attack
    return None
```

---

# 🚦 STEP 4 — Rate Limiting (rate_limiter.py)

```python
import time
from collections import defaultdict

REQUEST_LOG = defaultdict(list)
LIMIT = 10
WINDOW = 60

def is_abusive(ip):
    now = time.time()
    REQUEST_LOG[ip] = [t for t in REQUEST_LOG[ip] if now - t < WINDOW]
    REQUEST_LOG[ip].append(now)
    return len(REQUEST_LOG[ip]) > LIMIT
```

---

# 📝 STEP 5 — Logging (logger.py)

```python
import logging

logging.basicConfig(filename="logs/security.log", level=logging.INFO)

def log_event(ip, attack):
    logging.info(f"IP: {ip} | Attack: {attack}")
```

---

# 🌐 STEP 6 — Flask App (app.py)

```python
from flask import Flask, request, abort
from detector import detect_attack
from rate_limiter import is_abusive
from logger import log_event

app = Flask(__name__)

@app.before_request
def inspect():
    ip = request.remote_addr
    data = request.full_path + str(request.data)

    if is_abusive(ip):
        log_event(ip, "RateLimit")
        abort(429)

    attack = detect_attack(data)
    if attack:
        log_event(ip, attack)
        abort(403)

@app.route("/")
def home():
    return "Sentinel Shield Active"

if __name__ == "__main__":
    app.run(debug=True)
```

---

# 📊 STEP 7 — Dashboard (dashboard.py + HTML)

```python
from collections import Counter

def get_summary():
    counts = Counter()
    with open("logs/security.log") as f:
        for line in f:
            if "Attack" in line:
                attack = line.split("Attack:")[1].strip()
                counts[attack] += 1
    return counts
```

HTML template in `templates/dashboard.html`:

```html
<h2>Sentinel Shield Dashboard</h2>
<ul>
{% for k,v in summary.items() %}
<li>{{k}} : {{v}}</li>
{% endfor %}
</ul>
```

---

# ▶ STEP 8 — Run the Project

```bash
python app.py
```

Open:
👉 [http://127.0.0.1:5000](http://127.0.0.1:5000)

Test with:

```
http://127.0.0.1:5000/?q=<script>alert(1)</script>
```







## Project Structure

📁Sentinel-Shield/
│
├── app.py
├── dashboard.py
├── detector.py
├── logger.py
├── rate_limiter.py
├── rules.json
│
📁├── logs/
│ └── security_logs
│
📁├── templates/
│ └── dashboard.html
│
├── README.md
└── requirements.txt


