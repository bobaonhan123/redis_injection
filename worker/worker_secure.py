import hashlib
import hmac
import json
import os
import time

import redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "mail_jobs_secure")
JOB_HMAC_SECRET = os.getenv("JOB_HMAC_SECRET", "change_me")


def verify_signature(payload: dict, signature: str) -> bool:
    message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    expected = hmac.new(JOB_HMAC_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def run() -> None:
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
    print(f"[secure-worker] Listening on queue: {REDIS_QUEUE_KEY}")

    while True:
        result = client.brpop(REDIS_QUEUE_KEY, timeout=5)
        if not result:
            continue

        _, raw_job = result

        try:
            job_text = raw_job.decode("utf-8")
        except UnicodeDecodeError:
            print("[secure-worker] Dropped non-UTF8 job")
            continue

        try:
            envelope = json.loads(job_text)
            payload = envelope["payload"]
            signature = envelope["signature"]
        except (json.JSONDecodeError, KeyError, TypeError):
            print("[secure-worker] Dropped invalid JSON job")
            continue

        if not isinstance(payload, dict) or not isinstance(signature, str):
            print("[secure-worker] Dropped malformed envelope")
            continue

        if not verify_signature(payload, signature):
            print("[secure-worker] Dropped job with invalid signature")
            continue

        email = payload.get("email")
        if not isinstance(email, str) or "@" not in email:
            print("[secure-worker] Dropped signed job with invalid email")
            continue

        print(f"[secure-worker] Accepted signed job for {email}")
        time.sleep(0.1)


if __name__ == "__main__":
    run()
