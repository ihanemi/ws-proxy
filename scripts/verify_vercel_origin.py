"""Seven direct synthetic HTTPS controls; no Worker, proxy, token or retry."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import time

BODY_BYTES = 180000
ID_HEADER = "X-WSVPN-Diagnostic-ID"


def evaluate(report, wire, identifier):
    """Validate synthetic data without retaining it in the report."""
    split = wire.find(b"\r\n\r\n")
    body = b""
    common = False
    if split >= 0:
        if split > 32768:
            return False
        lines = wire[:split].decode("ascii", "strict").split("\r\n")
        status = re.fullmatch(r"HTTP/1\.[01] (\d{3})(?: .*)?", lines[0])
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            name = name.lower()
            if name in headers:
                return False
            headers[name] = value.strip()
        report["http_status"] = int(status[1]) if status else None
        body = wire[split + 4:]
        report["body_bytes"] = len(body)
        report["echo_id_matches"] = headers.get(ID_HEADER.lower()) == identifier
        cache = headers.get("x-vercel-cache", "").upper()
        report["cache_state"] = cache if cache in ("HIT", "MISS", "BYPASS", "STALE", "PRERENDER", "REVALIDATED") else "absent_or_other"
        report["cache_no_store"] = "no-store" in headers.get("cache-control", "").lower()
        report["cache_age_zero_or_absent"] = headers.get("age", "0") == "0"
        report["identity_encoding"] = headers.get("content-encoding", "identity").lower() == "identity"
        report["declared_length_matches"] = headers.get("content-length") == str(BODY_BYTES)
        report["transfer_encoding_present"] = "transfer-encoding" in headers
        common = (report["http_status"] == 200 and report["echo_id_matches"]
                  and report["cache_no_store"] and report["cache_age_zero_or_absent"]
                  and report["identity_encoding"] and report["declared_length_matches"]
                  and not report["transfer_encoding_present"] and cache not in ("HIT", "STALE", "PRERENDER")
                  and body == b"A" * len(body))
        received = 0
        for event in report["reads"]:
            received += event["bytes"]
            if received > split + 4:
                report["first_body_ms"] = event["elapsed_ms"]
                break
    report["http_bytes"] = len(wire)
    if not report["tls_verified"]:
        return False
    wait_ms = report["elapsed_ms"] - report.get("request_sent_ms", report["elapsed_ms"])
    if report["mode"] == "ok":
        return common and len(body) == BODY_BYTES
    if not 9000 <= wait_ms <= 12500:
        return False
    if report["mode"] == "stall-response":
        return len(wire) == 0
    return (common and len(body) == 1024 and report.get("first_body_ms") is not None
            and report["elapsed_ms"] - report["first_body_ms"] >= 5000)


def run_case(host, address, identifier, mode, *, context=None, port=443):
    started = time.monotonic()
    deadline = started + 12
    report = {"id": identifier, "mode": mode, "passed": False, "tls_verified": False,
              "body_bytes": 0, "http_status": None, "reads": []}
    wire = bytearray()
    phase = "connect"
    sock = None

    def elapsed():
        return round((time.monotonic() - started) * 1000, 3)

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError()
        return value

    try:
        if context is None:
            # Unlike create_default_context(), this does not honor SSLKEYLOGFILE.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_default_certs()
        sock = socket.create_connection((address, port), timeout=remaining())
        phase = "tls"
        sock.settimeout(remaining())
        sock = context.wrap_socket(sock, server_hostname=host, suppress_ragged_eofs=False)
        report["tls_verified"] = True
        cert = sock.getpeercert()
        report["tls"] = {"version": sock.version(), "peer_ip": sock.getpeername()[0],
                         "certificate_sha256": hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest(),
                         "issuer": cert.get("issuer"), "san": cert.get("subjectAltName"),
                         "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter")}
        phase = "request"
        sock.settimeout(remaining())
        sock.sendall((f"GET /_wsvpn_diag/{mode} HTTP/1.1\r\nHost: {host}\r\n"
                      f"{ID_HEADER}: {identifier}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii"))
        report["request_sent_ms"] = elapsed()
        phase = "response"
        while True:
            sock.settimeout(remaining())
            data = sock.recv(16384)
            if not data:
                report["end"] = "eof"
                break
            wire.extend(data)
            if len(report["reads"]) < 64:
                report["reads"].append({"elapsed_ms": elapsed(), "bytes": len(data)})
            if len(wire) > BODY_BYTES + 32768:
                raise ValueError("Response limit")
            split = wire.find(b"\r\n\r\n")
            if mode == "ok" and split >= 0 and len(wire) >= split + 4 + BODY_BYTES:
                report["end"] = "complete_body"
                break
    except (OSError, ValueError) as error:
        report["end"] = type(error).__name__  # Never a raw exception/message/header/payload.
    finally:
        if sock is not None:
            sock.close()
    report["phase_at_end"] = phase
    report["elapsed_ms"] = elapsed()
    try:
        report["passed"] = phase == "response" and evaluate(report, wire, identifier)
    except (ValueError, UnicodeError):
        report["validation_error"] = "malformed_http"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--experiment", required=True, type=Path)
    parser.add_argument("--cloudflare-ranges", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.vercel\.app", args.host):
        parser.error("Only the exact reviewed Vercel origin hostname is allowed")
    address = ipaddress.ip_address(args.ip)
    ranges = json.loads(args.cloudflare_ranges.read_text(encoding="utf-8-sig"))["result"]
    networks = [ipaddress.ip_network(value) for key in ("ipv4_cidrs", "ipv6_cidrs") for value in ranges[key]]
    if not networks or not address.is_global or address.is_multicast or any(address in net for net in networks):
        parser.error("Destination must be a reviewed public non-Cloudflare address")
    config = json.loads(args.experiment.read_text(encoding="utf-8-sig"))
    identifiers = config["ids"]
    now = time.time() * 1000
    if (len(identifiers) != 7 or len(set(identifiers)) != 7
            or any(not re.fullmatch(r"[0-9a-f]{32}", value) for value in identifiers)
            or not config["not_before_ms"] <= now < config["expires_ms"] - 90000):
        parser.error("Need seven fresh IDs and at least 90 seconds before origin expiry")
    if args.output.exists():
        parser.error("Refusing to overwrite evidence")
    results = [run_case(args.host, args.ip, identifiers[i], mode) for i, mode in enumerate(
        ("ok", "ok", "ok", "stall-response", "stall-body"))]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results.extend(pool.map(lambda identifier: run_case(args.host, args.ip, identifier, "ok"), identifiers[5:]))
    report = {"kind": "independent-origin-only-no-worker", "host": args.host, "ip": args.ip, "port": 443,
              "requests": results, "all_client_controls_passed": all(case["passed"] for case in results),
              "origin_logs_correlation_required": True, "workers_reachability_tested": False}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps({"requests": len(results), "passed": sum(case["passed"] for case in results),
                      "output": str(args.output), "workers_used": False}))
    return 0 if report["all_client_controls_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
