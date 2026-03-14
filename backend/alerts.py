import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST       = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT", 587))
SMTP_USER       = os.getenv("SMTP_USER", "")
SMTP_PASS       = os.getenv("SMTP_PASS", "")
ALERT_RECIPIENT = os.getenv("ALERT_RECIPIENT", "")


def send_high_severity_alert(indicator: dict):
    """
    Sends an email alert when a high/critical severity indicator is submitted.
    Silently fails if SMTP is not configured (non-critical path).
    """
    if not SMTP_USER or not SMTP_PASS or not ALERT_RECIPIENT:
        print("[ALERT] SMTP not configured — skipping email.")
        return

    subject = f"[DTISP ALERT] {indicator['severity'].upper()} Threat: {indicator['indicator_type'].upper()}"

    body = f"""
    <html><body>
    <h2 style="color:red;">⚠️ High Severity Threat Indicator Detected</h2>
    <table border="1" cellpadding="6" cellspacing="0">
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Type</td><td>{indicator['indicator_type']}</td></tr>
        <tr><td>Value</td><td>{indicator['indicator_value']}</td></tr>
        <tr><td>Category</td><td>{indicator['threat_category']}</td></tr>
        <tr><td>Severity</td><td>{indicator['severity']}</td></tr>
        <tr><td>Reporter</td><td>{indicator['reporter_id']}</td></tr>
        <tr><td>Description</td><td>{indicator['description']}</td></tr>
        <tr><td>Hash</td><td><code>{indicator['data_hash']}</code></td></tr>
    </table>
    <p>Verify this indicator at: <a href="http://localhost:8000">DTISP Dashboard</a></p>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_USER
    msg["To"]      = ALERT_RECIPIENT
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_RECIPIENT, msg.as_string())
        print(f"[ALERT] Email sent for {indicator['indicator_value']}")
    except Exception as e:
        print(f"[ALERT] Failed to send email: {e}")