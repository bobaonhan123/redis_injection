import hashlib
import hmac
import json
import os
import subprocess
from datetime import datetime, timezone

from email_validator import EmailNotValidError, validate_email
from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "mail_jobs")
JOB_HMAC_SECRET = os.getenv("JOB_HMAC_SECRET", "change_me")


def enqueue_job(job_payload: str) -> None:
    subprocess.run(
        [
            "redis-cli",
            "-h",
            REDIS_HOST,
            "-p",
            REDIS_PORT,
            "LPUSH",
            REDIS_QUEUE_KEY,
            job_payload,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def normalize_email(raw_email: str) -> str:
    validated = validate_email(raw_email, check_deliverability=False)
    return validated.normalized


def sign_payload(payload: dict) -> str:
    message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(JOB_HMAC_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/schedule", methods=["POST"])
def schedule_report():
    email = request.form.get("admin_email", "").strip()

    try:
        safe_email = normalize_email(email)
    except EmailNotValidError:
        return redirect(url_for("home", status="invalid_email"))

    payload = {
        "email": safe_email,
        "report_type": "daily_summary",
        "source": "web_form",
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    envelope = {
        "payload": payload,
        "signature": sign_payload(payload),
    }

    try:
        enqueue_job(json.dumps(envelope, separators=(",", ":"), sort_keys=True))
    except subprocess.CalledProcessError:
        return redirect(url_for("home", status="queue_error"))

    return redirect(url_for("home", status="queued", email=safe_email))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
