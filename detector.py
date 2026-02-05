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
