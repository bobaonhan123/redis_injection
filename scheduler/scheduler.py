import hashlib
import hmac
import json
import os
import subprocess
import time
from datetime import datetime, timezone

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "mail_jobs")
JOB_HMAC_SECRET = os.getenv("JOB_HMAC_SECRET", "change_me")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
INTERVAL_SECONDS = int(os.getenv("INTERVAL_SECONDS", "30"))


def sign_payload(payload: dict) -> str:
    message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(JOB_HMAC_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()


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


def run() -> None:
    while True:
        payload = {
            "email": ADMIN_EMAIL,
            "report_type": "daily_summary",
            "source": "scheduler",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
        envelope = {
            "payload": payload,
            "signature": sign_payload(payload),
        }

        enqueue_job(json.dumps(envelope, separators=(",", ":"), sort_keys=True))
        print(f"[scheduler] queued daily report for {ADMIN_EMAIL}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    run()
