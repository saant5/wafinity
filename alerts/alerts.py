import os
import smtplib
from email.mime.text import MIMEText

try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

EMAIL_SENDER = os.environ.get("ALERT_EMAIL_SENDER", "")
EMAIL_PASSWORD = os.environ.get("ALERT_EMAIL_PASSWORD", "")
EMAIL_RECEIVER = os.environ.get("ALERT_EMAIL_RECEIVER", "")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM = os.environ.get("TWILIO_FROM", "")
TWILIO_TO = os.environ.get("TWILIO_TO", "")


def send_email_alert(subject: str, body: str):
    if not (EMAIL_SENDER and EMAIL_PASSWORD and EMAIL_RECEIVER):
        print("[ALERT] Email config missing; skipping email alert.")
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print("[ALERT] Email alert sent.")
    except Exception as e:
        print(f"[ALERT ERROR] Email send failed: {e}")


def send_sms_alert(message: str):
    if not TwilioClient:
        print("[ALERT] Twilio library not installed; skipping SMS alert.")
        return

    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM and TWILIO_TO):
        print("[ALERT] Twilio config missing; skipping SMS alert.")
        return

    try:
        client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=message,
            from_=TWILIO_FROM,
            to=TWILIO_TO,
        )
        print("[ALERT] SMS alert sent.")
    except Exception as e:
        print(f"[ALERT ERROR] SMS send failed: {e}")


def send_block_alert(event: dict):
    ip = event.get("ip", "unknown")
    path = event.get("path", "")
    decision = event.get("decision", "")
    threats = ", ".join(event.get("threats", []))
    score = event.get("final_score", 0)

    subject = f"WAF Alert: {decision} {threats}"
    body = (
        f"Blocked Event\n"
        f"IP: {ip}\n"
        f"Path: {path}\n"
        f"Decision: {decision}\n"
        f"Threats: {threats}\n"
        f"Score: {score}\n"
    )

    send_email_alert(subject, body)
    send_sms_alert(body)