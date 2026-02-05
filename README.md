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

```python --version```

If not installed, install from python.org

### 2️⃣ Create Project Folder

```
mkdir sentinel-shield
cd sentinel-shield
```

### 3️⃣ Create Virtual Environment (Good Practice)

```
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate  # Linux/Mac
```

### 4️⃣ Install Flask

```
pip install flask
```

### 5️⃣ Create Files

Create these files:

```
📁Sentinel-Shield/
│
├── app.py  # Main Flask application
├── dashboard.py  # Simple dashboard view
├── detector.py  # Detection logic
├── logger.py  # Logging & alerting
├── rate_limiter.py  # IP behavior tracking
├── rules.json  # Attack signatures and patterns
│
📁├── logs/
│ └── security_logs
│
📁├── templates/
│ └── dashboard.html
│
├── README.md
└── requirements.txt
```

# STEP 2 — Detection Rules (rules.json)

```
{
  "XSS": [
    "<script>",
    "onerror",
    "onload",
    "alert\\("
  ],
  "SQL Injection": [
    "select .* from",
    "union select",
    "or 1=1",
    "' or '1'='1"
  ]
}

```

# STEP 3 — Detection Engine (detector.py)

```
import re
import json
from logger import log_event

with open("rules.json") as f:
    RULES = json.load(f)

def inspect_request(req):
    data = req.query_string.decode().lower()

    print("[+] Raw Data:", data)

    for attack, patterns in RULES.items():
        for pattern in patterns:
            if re.search(pattern, data):
                ip = req.remote_addr
                print(f"[!] Attack detected: {attack} from {ip}")
                log_event(ip, attack)
```

# STEP 4 — Rate Limiting (rate_limiter.py)

```
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

# STEP 5 — Logging (logger.py)

```
import logging
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "security.log")

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("sentinel")
logger.setLevel(logging.INFO)

handler = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter("%(asctime)s | IP=%(message)s")
handler.setFormatter(formatter)

if not logger.handlers:
    logger.addHandler(handler)

def log_event(ip, attack):
    logger.info(f"{ip} | ATTACK={attack}")
```

# STEP 6 — Flask App (app.py)

```
from flask import Flask, request
from detector import inspect_request

app = Flask(__name__)

@app.before_request
def before():
    inspect_request(request)

@app.route("/")
def home():
    return "Sentinel Shield Active"

if __name__ == "__main__":
    app.run(debug=True)
```

# STEP 7 — Dashboard (dashboard.py + HTML)

```
from collections import Counter

def get_summary():
    counts = Counter()
    try:
        with open("logs/security.log") as f:
            for line in f:
                if "Attack:" in line:
                    attack = line.split("Attack:")[1].strip()
                    counts[attack] += 1
    except FileNotFoundError:
        pass
    return counts
```

HTML template in `templates/dashboard.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Sentinel Shield Dashboard</title>
</head>
<body>
    <h2>Sentinel Shield – Security Dashboard</h2>
    <p>Attack Summary:</p>
    <ul>
        {% for k, v in summary.items() %}
        <li><strong>{{ k }}</strong> : {{ v }}</li>
        {% endfor %}
    </ul>
</body>
</html>
```

# ▶ STEP 8 — Run the Project

```
python app.py
```

Server will start at:
👉 http://127.0.0.1:5000

Test with:
```
http://127.0.0.1:5000/?q=<script>alert(1)</script>
```

## Testing the System

### Normal Request

```
curl "http://127.0.0.1:5000/?q=hello"
```

### SQL Injection Test

```
curl "http://127.0.0.1:5000/?q=' OR 1=1 --"
```

### XSS Test

```
curl "http://127.0.0.1:5000/?q=<script>alert(1)</script>"
```

### LFI Test

```
curl "http://127.0.0.1:5000/?q=../../etc/passwd"
```
-----------------------------------------------------------------------------------------------------------------------------

## Logs & Output

All detected events are stored in:

```
logs/security_logs
```

Each entry contains:
• Timestamp
• Source IP
• Detected attack type
• Action taken

These logs simulate what a SOC analyst would review.

-----------------------------------------------------------------------------------------------------------------------------

## Testing Strategy

✔ Send normal requests → should be allowed
✔ Send attack payloads → should be blocked
✔ Send repeated requests → rate limited
✔ Review logs → verify detection accuracy

## 📌 Conclusion

Sentinel Shield bridges the gap between **theory and real-world cybersecurity practice**.
It shows how attacks are detected, logged, and analyzed — the same workflow used in real security operations.






