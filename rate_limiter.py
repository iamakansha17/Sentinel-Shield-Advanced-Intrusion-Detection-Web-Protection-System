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
