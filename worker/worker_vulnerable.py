import os
import pickle
import time

import redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "mail_jobs_vuln")


def run() -> None:
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
    print(f"[vuln-worker] Listening on queue: {REDIS_QUEUE_KEY}")

    while True:
        result = client.brpop(REDIS_QUEUE_KEY, timeout=5)
        if not result:
            continue

        _, raw_job = result
        try:
            # Intentionally vulnerable: attacker-controlled pickle data can execute code.
            job = pickle.loads(raw_job)
            print(f"[vuln-worker] Processed object type={type(job).__name__} value={job}")
        except Exception as exc:
            print(f"[vuln-worker] Failed to deserialize job: {exc}")
            time.sleep(0.5)


if __name__ == "__main__":
    run()
