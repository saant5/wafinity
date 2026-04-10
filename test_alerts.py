# test_alerts.py
# Run this BEFORE starting gateway.py to verify your alerts work.
# Place this in your project root folder.
# Usage: python test_alerts.py

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from alerts.alerts import send_block_alert

# Fake BLOCK event — same structure as real gateway events
test_event = {
    "event_id":       "EVT-TEST-001",
    "time":           "2026-03-13 12:00:00",
    "ip":             "192.168.1.99",
    "path":           "/login",
    "method":         "POST",
    "decision":       "BLOCK",
    "threats":        ["SQL_INJECTION"],
    "severity":       "CRITICAL",
    "final_score":    95,
    "risk_score":     88,
    "ai_score":       95,
    "payload_preview": "' OR 1=1 -- username=admin",
    "source":         "test_script",
}

print("Sending test alerts...")
print("  → Email to:", os.getenv("ALERT_EMAIL_TO", "check alerts/alerts.py"))
print("  → SMS  to:", os.getenv("TWILIO_TO_NUMBER", "check alerts/alerts.py"))

send_block_alert(test_event)

import time
time.sleep(4)   # wait for background threads to finish
print("\nDone. Check your email and phone!")