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
