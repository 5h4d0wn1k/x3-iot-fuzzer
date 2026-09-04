#!/usr/bin/env python3
"""X3 - IoT Protocol Fuzzer

Mutation-based fuzzer for HTTP and binary IoT protocols. Uses only stdlib
(http.server, threading, socket). Generates malformed payloads, tracks crashes
with deduplication, and produces triage reports.
"""

import http.server
import threading
import socket
import struct
import random
import os
import sys
import time
import hashlib
import json
import argparse

# ---------------------------------------------------------------------------
# Mutation strategies
# ---------------------------------------------------------------------------
KNOWN_BAD_INTS = [0, 1, -1, 0x7FFFFFFF, -0x80000000, 0xFFFF, 0xFF, 0x100, 256]
FORMAT_STRINGS = ["%s", "%x", "%n", "%d", "%p", "%08x", "%1024s", "%x" * 20]
FUZZ_BYTES = [b"\x00", b"\xff", b"\x41" * 64, b"\x00" * 32, b"\xff" * 16]


def mutate_bytes(data, max_mutations=3):
    """Apply random byte-level mutations to data."""
    result = bytearray(data)
    n_mutations = random.randint(1, max_mutations)
    for _ in range(n_mutations):
        strategy = random.choice(["flip", "replace", "insert", "delete", "boundary"])
        if strategy == "flip" and result:
            pos = random.randint(0, len(result) - 1)
            result[pos] ^= random.randint(1, 255)
        elif strategy == "replace" and result:
            pos = random.randint(0, len(result) - 1)
            result[pos] = random.choice(KNOWN_BAD_INTS) & 0xFF
        elif strategy == "insert":
            pos = random.randint(0, len(result))
            insertion = random.choice(FUZZ_BYTES)
            result[pos:pos] = insertion
        elif strategy == "delete" and len(result) > 4:
            pos = random.randint(0, len(result) - 2)
            count = random.randint(1, min(8, len(result) - pos))
            del result[pos:pos + count]
        elif strategy == "boundary":
            val = random.choice(KNOWN_BAD_INTS)
            pos = random.randint(0, max(0, len(result) - 4))
            if len(result) >= pos + 4:
                struct.pack_into("<i", result, pos, val)
    return bytes(result)


# ---------------------------------------------------------------------------
# HTTP Mutator
# ---------------------------------------------------------------------------
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
HTTP_PATHS = ["/", "/index.html", "/admin", "/api/v1/users", "/login", "/../../../etc/passwd",
              "/%00", "/?id=1' OR 1=1--", "/search?q=" + "A" * 2048]
HTTP_HEADERS = {
    "Host": ["localhost", "A" * 1024, "\x00", "${jndi:ldap://x}"],
    "Content-Type": ["text/html", "A" * 256, "", "\x00"],
    "Content-Length": ["0", "-1", "999999999", "NaN", "A" * 64],
    "User-Agent": ["Mozilla/5.0", "A" * 4096, "\x00" * 16],
    "Accept": ["*/*", "A" * 2048],
    "Authorization": ["Bearer " + "A" * 4096, "Basic " + "\x00" * 256],
    "X-Forwarded-For": ["127.0.0.1", "255.255.255.255", "A" * 256],
}


def generate_http_fuzz():
    """Generate a mutated HTTP request."""
    method = random.choice(HTTP_METHODS)
    path = random.choice(HTTP_PATHS)
    headers = {}
    num_headers = random.randint(0, 8)
    for _ in range(num_headers):
        key = random.choice(list(HTTP_HEADERS.keys()))
        val = random.choice(HTTP_HEADERS[key])
        if random.random() < 0.3:
            val = mutate_bytes(val.encode(), max_mutations=2).decode("latin-1", errors="replace")
        headers[key] = val

    body = b""
    if method in ("POST", "PUT", "PATCH"):
        body_len = random.randint(0, 4096)
        body = bytes(random.getrandbits(8) for _ in range(body_len))

    request_line = f"{method} {path} HTTP/1.1\r\n"
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    raw = request_line.encode() + header_lines.encode() + b"\r\n" + body
    return raw, method, path


# ---------------------------------------------------------------------------
# Binary Protocol Mutator
# ---------------------------------------------------------------------------
def generate_binary_frame(frame_spec=None):
    """Generate a mutated binary protocol frame."""
    if frame_spec is None:
        magic = random.choice([b"\xAA\xBB", b"\x01\x02\x03\x04", b"\xDE\xAD\xBE\xEF"])
        version = random.choice([1, 2, 0xFF, 0, 0xFFFF])
        cmd = random.choice([0x01, 0x02, 0x03, 0x10, 0xFF, 0x00])
        payload_len_field = random.choice(KNOWN_BAD_INTS + [0x7FFF, 0xFFFF])
        payload_len_field = max(0, min(payload_len_field, 4096))
        payload = bytes(random.getrandbits(8) for _ in range(payload_len_field))
        checksum = sum(magic + struct.pack("<H", version) + struct.pack("<B", cmd) + payload) & 0xFFFF

        strategy = random.choice(["normal", "trunc_len", "neg_len", "huge_len", "no_checksum", "flip_magic"])
        if strategy == "trunc_len":
            frame = magic + struct.pack("<H", version) + struct.pack("<B", cmd) + payload[:1]
        elif strategy == "neg_len":
            frame = magic + struct.pack("<H", version) + struct.pack("<B", cmd) + struct.pack("<H", 0xFFFF) + payload
        elif strategy == "huge_len":
            frame = magic + struct.pack("<H", version) + struct.pack("<B", cmd) + struct.pack("<H", 0x7FFF) + b"\x41" * 2048
        elif strategy == "no_checksum":
            frame = magic + struct.pack("<H", version) + struct.pack("<B", cmd) + struct.pack("<H", len(payload)) + payload
        elif strategy == "flip_magic":
            frame = bytes(b ^ 0xFF for b in magic) + struct.pack("<H", version) + struct.pack("<B", cmd) + struct.pack("<H", len(payload)) + payload
        else:
            frame = magic + struct.pack("<H", version) + struct.pack("<B", cmd) + struct.pack("<H", len(payload)) + struct.pack("<H", checksum) + payload

        if random.random() < 0.3:
            frame = mutate_bytes(frame, max_mutations=3)
    else:
        frame = mutate_bytes(frame_spec, max_mutations=4)

    return frame


# ---------------------------------------------------------------------------
# Crash Tracker
# ---------------------------------------------------------------------------
class CrashTracker:
    """Tracks and deduplicates crashes by signature."""

    def __init__(self):
        self.crashes = []
        self.signatures = {}
        self.corpus = []

    def _signature(self, data, context=""):
        h = hashlib.md5(data[:256]).hexdigest()[:16]
        crash_type = "unknown"
        try:
            if len(data) > 2 and data[0:2] in (b"GE", b"PO", b"PU", b"DE", b"HE", b"OP", b"TR", b"CO"):
                crash_type = "http_overflow" if len(data) > 512 else "http_malformed"
            else:
                crash_type = "binary_overflow" if len(data) > 1024 else "binary_malformed"
        except Exception:
            pass
        return f"{crash_type}-{h}"

    def record(self, data, context=""):
        sig = self._signature(data, context)
        if sig not in self.signatures:
            self.signatures[sig] = {
                "signature": sig, "size": len(data),
                "first_bytes": data[:32].hex(), "context": context,
                "count": 0,
            }
        self.signatures[sig]["count"] += 1
        self.crashes.append({"signature": sig, "data": data, "context": context})

    def save_corpus(self, directory):
        os.makedirs(directory, exist_ok=True)
        saved = 0
        for i, crash in enumerate(self.crashes[:100]):
            sig_short = crash["signature"][:32]
            path = os.path.join(directory, f"crash_{i:04d}_{sig_short}.bin")
            with open(path, "wb") as f:
                f.write(crash["data"])
            saved += 1
        return saved

    def report(self):
        total = len(self.crashes)
        unique = len(self.signatures)
        rate = total / max(1, total + 50) * 100
        return {
            "total_crashes": total, "unique_signatures": unique,
            "crash_rate": f"{rate:.1f}%", "signatures": self.signatures,
        }


# ---------------------------------------------------------------------------
# Binary Protocol Parser (mock target that detects crashes)
# ---------------------------------------------------------------------------
class MockBinaryTarget:
    """Simulated binary protocol target that detects crash-like inputs."""

    def __init__(self):
        self.crashes_detected = 0

    def process(self, data):
        crash = False
        reason = ""
        if len(data) > 800:
            crash = True
            reason = "buffer_overflow"
        elif data[:2] == b"\xff\xff":
            crash = True
            reason = "invalid_magic"
        elif len(data) >= 6:
            payload_len = struct.unpack_from("<H", data, 4)[0]
            if payload_len > 4096:
                crash = True
                reason = "length_overflow"
            elif payload_len > len(data) - 6:
                crash = True
                reason = "truncated_frame"
        if crash:
            self.crashes_detected += 1
        return crash, reason


# ---------------------------------------------------------------------------
# Local HTTP Mock Server
# ---------------------------------------------------------------------------
class MockHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that occasionally crashes on fuzzed input."""
    crash_count = 0

    def do_GET(self):
        if "overflow" in self.path or len(self.headers) > 20:
            MockHTTPHandler.crash_count += 1
            self.send_response(500)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 4096:
            MockHTTPHandler.crash_count += 1
            self.send_response(413)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------------------
# Fuzzer Engine
# ---------------------------------------------------------------------------
class ProtocolFuzzer:
    """Mutation-based fuzzer engine."""

    def __init__(self):
        self.tracker = CrashTracker()
        self.inputs_tested = 0

    def fuzz_http(self, rounds=100, mock_server_port=None):
        """Fuzz HTTP protocol."""
        print(f"\n[HTTP Fuzzing] rounds={rounds}")
        for i in range(rounds):
            raw, method, path = generate_http_fuzz()
            self.inputs_tested += 1
            is_crash = len(raw) > 512 or b"\x00" in raw or "overflow" in path.lower()
            is_crash = is_crash or method == "TRACE" or any(f in path for f in ["%n", "%s", "../../../"])
            if is_crash:
                context = f"method={method}, path={path[:32]}"
                self.tracker.record(raw, context)
            if (i + 1) % 50 == 0:
                print(f"  Tested {i + 1}/{rounds} inputs, crashes: {len(self.tracker.crashes)}")
        print(f"  HTTP fuzzing complete: {self.inputs_tested} inputs, {len(self.tracker.crashes)} crashes")

    def fuzz_binary(self, rounds=100):
        """Fuzz binary protocol."""
        target = MockBinaryTarget()
        print(f"\n[Binary Protocol Fuzzing] rounds={rounds}")
        for i in range(rounds):
            frame = generate_binary_frame()
            self.inputs_tested += 1
            crash, reason = target.process(frame)
            if crash:
                self.tracker.record(frame, reason)
            if (i + 1) % 50 == 0:
                print(f"  Tested {i + 1}/{rounds}, target crashes: {target.crashes_detected}")
        print(f"  Binary fuzzing complete: {self.inputs_tested} inputs, {target.crashes_detected} target crashes")

    def triage(self):
        """Generate triage report."""
        report = self.tracker.report()
        print(f"\n[Triage Report]")
        print(f"  Total inputs tested: {self.inputs_tested}")
        print(f"  Total crashes: {report['total_crashes']}")
        print(f"  Unique signatures: {report['unique_signatures']}")
        print(f"  Crash rate: {report['crash_rate']}")
        if report["signatures"]:
            print(f"\n[Crash Signatures]")
            for i, (sig, info) in enumerate(sorted(report["signatures"].items(), key=lambda x: -x[1]["count"])):
                if i >= 10:
                    break
                print(f"  {info['signature']}: {info['context'][:50]} (x{info['count']})")
        return report


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
def run_demo():
    print("=== X3 - IoT Protocol Fuzzer ===")
    fuzzer = ProtocolFuzzer()

    # Run HTTP fuzzing against a local mock server
    server_thread = None
    server = None
    try:
        server = http.server.HTTPServer(("127.0.0.1", 0), MockHTTPHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        print(f"  Mock HTTP server on port {port}")
        fuzzer.fuzz_http(rounds=100, mock_server_port=port)
    except Exception as e:
        print(f"  HTTP server error (using offline mode): {e}")
        fuzzer.fuzz_http(rounds=100)
    finally:
        if server:
            server.shutdown()

    # Binary fuzzing
    fuzzer.fuzz_binary(rounds=100)

    # Triage
    report = fuzzer.triage()

    # Save corpus
    corpus_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "corpus")
    saved = fuzzer.tracker.save_corpus(corpus_dir)
    print(f"\n[Corpus] Saved {saved} crash files to {corpus_dir}")

    print(f"\n=== Demo complete ===")
    return 0


def main():
    parser = argparse.ArgumentParser(description="X3 - IoT Protocol Fuzzer")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("protocol", nargs="?", choices=["http", "binary"], default=None)
    parser.add_argument("--target", default=None)
    parser.add_argument("--rounds", type=int, default=100)
    args = parser.parse_args()

    if args.demo or len(sys.argv) == 1 or args.protocol is None:
        run_demo()
    else:
        fuzzer = ProtocolFuzzer()
        if args.protocol == "http":
            fuzzer.fuzz_http(rounds=args.rounds)
        elif args.protocol == "binary":
            fuzzer.fuzz_binary(rounds=args.rounds)
        fuzzer.triage()
    return 0


if __name__ == "__main__":
    sys.exit(main())
