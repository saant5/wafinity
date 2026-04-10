import csv
import random

normal_payloads = [
    "id=1",
    "name=apple",
    "search=book",
    "product=laptop",
    "page=home",
    "category=electronics",
    "sort=asc",
    "user=guest",
    "view=products",
    "query=flowers",
]

attack_payloads = [
    "' OR 1=1 --",
    "admin' --",
    "' OR 'a'='a",
    "1 OR 1=1",
    "UNION SELECT username,password FROM users",
    "DROP TABLE users",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "; ls",
    "; cat /etc/passwd",
    "| whoami",
    "&& shutdown -h now",
]

rows = []

for _ in range(500):
    rows.append((random.choice(normal_payloads), 0))

for _ in range(500):
    rows.append((random.choice(attack_payloads), 1))

random.shuffle(rows)

with open("dataset.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["payload", "label"])
    writer.writerows(rows)

print("Dataset generated with", len(rows), "samples")