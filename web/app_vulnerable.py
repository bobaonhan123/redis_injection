import socket
import urllib.parse

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)


def send_raw_tcp(host: str, port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)

        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if len(chunks) >= 4:
                break

    return b"".join(chunks)


@app.route("/", methods=["GET"])
def home():
    if request.args.get("format") == "json":
        return jsonify(
            {
                "service": "web-vulnerable-ssrf",
                "note": "For lab only. This endpoint intentionally allows SSRF via gopher.",
                "usage": "/fetch?url=gopher://redis:6379/_<urlencoded_resp_payload>",
            }
        )

    return render_template("index_vulnerable.html")


@app.route("/fetch", methods=["GET"])
def fetch_url():
    target_url = request.args.get("url", "").strip()
    if not target_url:
        return jsonify({"ok": False, "error": "Missing url query parameter"}), 400

    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme.lower() != "gopher":
        return jsonify({"ok": False, "error": "Only gopher URLs are accepted in this lab"}), 400

    host = parsed.hostname
    port = parsed.port or 70
    path = parsed.path or ""

    if not host:
        return jsonify({"ok": False, "error": "Invalid host"}), 400

    if not path.startswith("/_"):
        return jsonify({"ok": False, "error": "Gopher payload must start with /_"}), 400

    raw_payload = urllib.parse.unquote_to_bytes(path[2:])

    try:
        response = send_raw_tcp(host=host, port=port, payload=raw_payload)
    except OSError as exc:
        return jsonify({"ok": False, "error": f"Network failure: {exc}"}), 502

    return jsonify(
        {
            "ok": True,
            "target": f"{host}:{port}",
            "bytes_sent": len(raw_payload),
            "reply_preview": response[:120].decode("utf-8", errors="replace"),
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
