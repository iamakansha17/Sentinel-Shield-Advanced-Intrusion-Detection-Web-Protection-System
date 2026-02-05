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
