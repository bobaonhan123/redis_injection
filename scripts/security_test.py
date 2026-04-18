import hashlib
import hmac
import json
import os
import subprocess
import time
from datetime import datetime, timezone

import requests

BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "mail_jobs")
JOB_HMAC_SECRET = os.getenv("JOB_HMAC_SECRET", "supersecret_lab_key")


def redis_cmd(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "redis", "redis-cli", *args],
        check=True,
        capture_output=True,
        text=True,
    )


def sign_payload(payload: dict) -> str:
    message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(JOB_HMAC_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()


def push_raw_job(envelope: dict) -> None:
    raw = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    redis_cmd("LPUSH", REDIS_QUEUE_KEY, raw)


def queue_depth() -> int:
    result = redis_cmd("LLEN", REDIS_QUEUE_KEY)
    return int(result.stdout.strip())


def test_web_invalid_email() -> None:
    response = requests.post(
        f"{BASE_URL}/schedule",
        data={"admin_email": "admin@example.com; FLUSHALL"},
        allow_redirects=False,
        timeout=5,
    )
    print("[test] invalid email blocked:", response.status_code in {302, 303})


def test_signed_job_acceptance() -> None:
    payload = {
        "email": "safe-admin@example.com",
        "report_type": "daily_summary",
        "source": "security_test",
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    envelope = {"payload": payload, "signature": sign_payload(payload)}
    push_raw_job(envelope)
    print("[test] pushed valid signed job")


def test_tampered_job_rejected() -> None:
    payload = {
        "email": "attacker@example.com",
        "report_type": "daily_summary",
        "source": "tampered_test",
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    envelope = {"payload": payload, "signature": "bad-signature"}
    push_raw_job(envelope)
    print("[test] pushed tampered job")


def main() -> None:
    print("[test] queue depth before:", queue_depth())
    test_web_invalid_email()
    test_signed_job_acceptance()
    test_tampered_job_rejected()
    time.sleep(2)
    print("[test] queue depth after:", queue_depth())
    print("[test] Check worker logs and MailHog UI for final verification")


if __name__ == "__main__":
    main()
