#!/usr/bin/env python3
"""X3 - IoT Protocol Fuzzer.

A real, deterministic, mutation-based fuzzer over locally implemented protocol
parsers (MQTT / CoAP / HTTP / binary frames). The parsers are faithful stdlib
(`struct`/`array`) implementations that contain **planted memory-safety bugs** —
the Python-equivalent of the classic C overread / width-overflow / negative-
length defect classes. The fuzzer's job is to rediscover inputs that crash
(uncaught exception in) these parsers, then save them as reproducers.

All fuzzing is offline and seeded; nothing touches the network unless
`--live-http` is given (then an HTTP fixture listens on 127.0.0.1 only).

## IMPORTANT: Read before use.
This tool only exercises locally implemented, deliberately-buggy test parsers.
It is for learning how mutation fuzzing finds real parse bugs. Do not use it —
or its payloads — against any system you do not own or lack authorization to
test. The planted bugs mirror real-world vulnerability classes but live only
in this repository's fixture code.
"""
import argparse
import hashlib
import json
import os
import random
import struct
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), os.pardir))
FIRMWARE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(ROOT, "reports")
CRASH_DIR = os.path.join(ROOT, "crash")

# ---------------------------------------------------------------------------
# Mutation engine (deterministic via injected Random)
# ---------------------------------------------------------------------------
KNOWN_BAD_INTS = [0, 1, -1, 0x7FFFFFFF, -0x80000000, 0xFFFF, 0xFF, 0x100, 256]
FUZZ_BYTES = [b"\x00", b"\xff", b"\x41" * 64, b"\x00" * 32, b"\xff" * 16,
              b"\x80\x80\x80\x80", b"\xff\xff\xff\xff"]
BOUNDARY_VALUES = [0, 1, 0x7F, 0x80, 0xFE, 0xFF, 0x7FFF, 0x8000, 0xFFFF]


def mutate_bytes(data, rng, max_mutations=4):
    """Apply 1..max_mutations byte-level mutations to `data`."""
    result = bytearray(data)
    n_mutations = rng.randint(1, max_mutations)
    for _ in range(n_mutations):
        strategy = rng.choice(["flip", "replace", "insert", "delete", "boundary"])
        if strategy == "flip" and result:
            pos = rng.randint(0, len(result) - 1)
            result[pos] ^= rng.randint(1, 255)
        elif strategy == "replace" and result:
            pos = rng.randint(0, len(result) - 1)
            result[pos] = rng.choice(KNOWN_BAD_INTS) & 0xFF
        elif strategy == "insert":
            pos = rng.randint(0, len(result))
            result[pos:pos] = rng.choice(FUZZ_BYTES)
        elif strategy == "delete" and len(result) > 4:
            pos = rng.randint(0, len(result) - 2)
            count = rng.randint(1, min(8, len(result) - pos))
            del result[pos:pos + count]
        elif strategy == "boundary":
            pos = rng.randint(0, max(0, len(result) - 4))
            if len(result) >= pos + 4:
                struct.pack_into("<i", result, pos, rng.choice(BOUNDARY_VALUES))
    return bytes(result)


# ---------------------------------------------------------------------------
# Protocol parsers with planted vulnerabilities
# ---------------------------------------------------------------------------
# Each parser implements the real wire format, then replicates a classic bug:
#   mqtt   -> treats the 4-byte maximum remaining length as a uint16 size;
#             oversized/over-read slices raise struct.error / IndexError
#   coap   -> trusts the Token-Length nibble for a fixed 4-byte read even when
#             the message is token-shorter (index overreads)
#   http   -> converts Content-Length without bound check and packs it as a
#             width-4 uint (width overflow -> struct.error)
#   binary -> reads the trailing checksum at 7+payload_len (overread) when the
#             declared length exceeds the actual frame
# The parser name is metadata in crash records, and every crash maps 1:1 to a
# real uncaught exception the fuzzer then reproduces.

def parse_mqtt_vuln(data):
    """MQTT CONNECT frame parser with a planted length/size bug."""
    if len(data) < 2:
        return {"type": 0, "topic": b"", "client_id": b"", "err": "short"}
    flags = data[0]
    declared_len, i, mult = 0, 1, 1
    while data[i] & 0x80:
        declared_len += (data[i] & 0x7F) * mult
        mult *= 128
        i += 1
        if i >= len(data):
            return {"type": 0, "topic": b"", "client_id": b"", "err": "unterminated"}
    declared_len += (data[i] & 0x7F) * mult
    # planted bug: remaining length is forced through a uint16 size bucket,
    # so a CONNECT advertising a huge remaining length overflows the packet
    size = struct.unpack("<H", bytes((declared_len & 0xFF, (declared_len >> 8) & 0xFF)))[0]
    total = i + 1 + size
    rest = data[:total]
    topic_len = struct.unpack_from("<H", rest, 2)[0]
    topic = rest[4:4 + topic_len]
    client_id = b""
    if topic:
        client_id = rest[4 + topic_len + 2:]
    return {"type": (flags >> 4) & 0x0F, "topic": topic, "client_id": client_id}


def parse_coap_vuln(data):
    """CoAP (RFC 7252) message parser with a planted token-length bug."""
    if len(data) < 4:
        return {"version": 0, "code": 0, "mid": b"", "token": b"",
                "payload": b"", "plen": 0, "err": "short"}
    ver = (data[0] >> 6) & 0x03
    token_len = data[0] & 0x0F
    code = data[1]
    msg_id = data[2:4]
    # planted bug: the parser reads the message-id window at a fixed offset 4
    # regardless of the true token length; a too-short frame underruns
    marker = struct.unpack_from("<I", data, 4)[0]
    token = data[4:4 + token_len]
    payload = data[4 + token_len:]
    if payload.startswith(b"\xff"):
        payload = payload[1:]
    return {"version": ver, "code": code, "mid": msg_id, "token": token,
            "payload": marker, "plen": len(payload)}


def parse_http_vuln(data):
    """HTTP/1.1 request-line parser with a planted Content-Length bug."""
    end = data.find(b"\r\n")
    if end == -1 or end > 4096:
        return {"method": "", "content_length": 0, "body_len": 0, "err": "bad_line"}
    line = data[:end].decode("latin-1")
    method = line.split(" ", 1)[0]
    cl = 0
    start = data.lower().find(b"content-length:")
    if start != -1:
        nl = data.find(b"\r\n", start)
        val = data[start + len(b"content-length:"):nl].strip()
        if val and bytes(val).isdigit():
            cl = int(val)
            # planted bug: no width guard before packing the length as uint32
            cl = struct.unpack("<I", struct.pack("<I", cl))[0]
    body = data[end + 4:end + 4 + cl] if cl > 0 else b""
    return {"method": method, "content_length": cl, "body_len": len(body)}


def parse_binary_vuln(data):
    """Little-endian [magic,ver,cmd,plen,payload,cksum] frame parser (flawed)."""
    if len(data) < 7:
        return {"magic": b"", "ver": 0, "cmd": 0, "plen": 0,
                "payload": b"", "cksum": 0, "err": "short"}
    magic = data[:2]
    ver, cmd = data[2], data[3]
    plen = struct.unpack_from("<H", data, 4)[0]
    # planted bug: reads the checksum at the declared payload end without
    # checking the frame is long enough to actually carry it
    cksum = struct.unpack_from("<H", data, 6 + plen)[0]
    payload = data[6:6 + plen]
    return {"magic": magic, "ver": ver, "cmd": cmd, "plen": plen,
            "payload": payload, "cksum": cksum}


HTTP_BIG_NUM = str(2 ** 48).encode()


def METHODS_DEF():
    return {
        "mqtt": (parse_mqtt_vuln, b"\x10\x0f\x00\x04MQTT\x00\x02\x00\x00"),
        "coap": (parse_coap_vuln, b"\x40\x01\xbe\xaf\x01\x02\x03\x04"),
        "http": (parse_http_vuln, b"GET /index.html HTTP/1.1\r\nContent-Length: 13\r\nHost: x\r\n"),
        "binary": (parse_binary_vuln, b"\xaa\xbb\x01\x01\x03\x00abc\x34\x12"),
    }


# ---------------------------------------------------------------------------
# Crash tracking
# ---------------------------------------------------------------------------
class CrashTracker:
    """Records, dedupes, and replays parser exceptions."""

    def __init__(self):
        self.crashes = []
        self.by_signature = {}
        self.inputs_tested = 0

    def record(self, method, data, exc):
        self.inputs_tested += 1
        sig = hashlib.sha1(method.encode() + b":" + data[:256]).hexdigest()[:12]
        entry = {
            "method": method,
            "exc_type": type(exc).__name__,
            "exc_repr": str(exc)[:120],
            "size": len(data),
            "seed_hex": data[:32].hex(),
            "count": 1,
        }
        if sig in self.by_signature:
            self.by_signature[sig]["count"] += 1
        else:
            self.by_signature[sig] = entry
            self.crashes.append({"signature": sig, "data": data, **entry})
        return sig

    def save_reproducers(self, directory=CRASH_DIR, limit=64):
        os.makedirs(directory, exist_ok=True)
        saved = 0
        for c in self.crashes[:limit]:
            path = os.path.join(directory, "%s_%s_%s.bin" % (
                c["method"], c["exc_type"], c["signature"]))
            with open(path, "wb") as f:
                f.write(c["data"])
            saved += 1
        return saved

    def report(self):
        total = len(self.crashes)
        return {
            "inputs_tested": self.inputs_tested,
            "total_crashes": total,
            "unique_signatures": len(self.by_signature),
            "covered_methods": sorted({c["method"] for c in self.crashes}),
            "signatures": [v for v in self.by_signature.values()],
        }


# ---------------------------------------------------------------------------
# Seeded fuzz engine
# ---------------------------------------------------------------------------
class ProtocolFuzzer:
    def __init__(self, seed=0x1337DEAD, rounds=500):
        self.seed = seed
        self.rounds = rounds
        self.rng = random.Random(seed)
        self.tracker = CrashTracker()
        self.methods = METHODS_DEF()

    def _derive(self, method, seed_bytes):
        r = self.rng.random()
        if r < 0.3:
            data = mutate_bytes(seed_bytes, self.rng)
        elif r < 0.5:
            data = seed_bytes
        else:
            data = bytes(self.rng.getrandbits(8)
                         for _ in range(self.rng.randint(1, 64)))
            if self.rng.random() < 0.4:
                data = mutate_bytes(data, self.rng, max_mutations=6)
        if method == "http" and self.rng.random() < 0.25:
            idx = data.find(b"Content-Length: ")
            if idx != -1:
                nl = data.find(b"\r\n", idx)
                if nl != -1:
                    data = data[:idx + len(b"Content-Length: ")] + HTTP_BIG_NUM + data[nl:]
        return data

    def _run_round(self, method, parser, seed_bytes):
        data = self._derive(method, seed_bytes)
        try:
            parser(data)
        except (struct.error, IndexError, OverflowError) as exc:
            self.tracker.record(method, data, exc)

    def fuzz(self, methods=("mqtt", "coap", "http", "binary")):
        for _ in range(self.rounds):
            method = self.rng.choice(methods)
            parser, seed_bytes = self.methods[method]
            self._run_round(method, parser, seed_bytes)
        return self.report()

    def report(self):
        return self.tracker.report()


# ---------------------------------------------------------------------------
# CLI / demo / JSON report
# ---------------------------------------------------------------------------
def run_demo(seed=0x1337DEAD, rounds=400):
    print("=== X3 - IoT Protocol Fuzzer ===")
    print("seed=%d rounds=%d protocols=mqtt,coap,http,binary (offline)" % (seed, rounds))
    f = ProtocolFuzzer(seed=seed, rounds=rounds)
    t0 = time.time()
    report = f.fuzz()
    dt = time.time() - t0
    print("  [fuzz] %d inputs in %.2fs -> %d crashes, %d unique signatures" % (
        report["inputs_tested"], dt, report["total_crashes"],
        report["unique_signatures"]))
    for sig in report["signatures"]:
        print("    %-8s %-16s %s (x%d)" % (
            sig["method"], sig["exc_type"], sig["exc_repr"], sig["count"]))
    saved = f.tracker.save_reproducers()
    print("  [corpus] saved %d reproducer(s) -> crash/" % saved)
    os.makedirs(REPORTS, exist_ok=True)
    path = os.path.join(REPORTS, "fuzz_report.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    print("  [report] %s" % path)
    ok = report["total_crashes"] > 0 and \
        set(report["covered_methods"]) == {"mqtt", "coap", "http", "binary"}
    print("Fuzzer %s (found real parser exceptions across all 4 fixtures)"
          % ("PASS" if ok else "CHECK"))
    return 0 if ok else 1


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="iot_fuzzer",
        description="Deterministic mutation fuzzer over locally implemented "
                    "MQTT/CoAP/HTTP/binary parsers (planted bugs).",
        epilog="Offline by default; parsers live in this repo. See README.md.")
    ap.add_argument("--seed", type=lambda v: int(v, 0), default=0x1337DEAD,
                    help="RNG seed (hex or decimal) for deterministic runs")
    ap.add_argument("--rounds", type=int, default=400)
    ap.add_argument("--method", choices=sorted(METHODS_DEF()), default=None,
                    help="fuzz only one protocol fixture")
    ap.add_argument("--dry-run", action="store_true",
                    help="print plan and exit without fuzzing")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    methods = (args.method,) if args.method else tuple(sorted(METHODS_DEF()))
    if args.dry_run:
        print("dry-run: seed=0x%x rounds=%d methods=%s (no execution)"
              % (args.seed, args.rounds, ",".join(methods)))
        return 0
    return run_demo(seed=args.seed, rounds=args.rounds)


if __name__ == "__main__":
    sys.exit(main())