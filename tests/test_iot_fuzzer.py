#!/usr/bin/env python3
"""Deterministic offline tests for the X3 IoT protocol fuzzer."""
import collections
import json
import os
import random
import struct
import subprocess
import sys
import unittest

FIRMWARE = os.path.join(os.path.dirname(__file__), os.pardir, "firmware")
ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
if FIRMWARE not in sys.path:
    sys.path.insert(0, FIRMWARE)

import iot_fuzzer as fz  # noqa: E402


class TestMutation(unittest.TestCase):
    def test_deterministic(self):
        a = fz.mutate_bytes(b"abcdefghij", random.Random(7))
        b = fz.mutate_bytes(b"abcdefghij", random.Random(7))
        self.assertEqual(a, b)

    def test_seeded(self):
        vocab = set()
        for s in range(5):
            vocab.add(fz.mutate_bytes(b"GET /x HTTP/1.1", random.Random(s)))
        self.assertTrue(any(v != b"GET /x HTTP/1.1" for v in vocab))


class TestParsersBenign(unittest.TestCase):
    def test_all_seeds_parse(self):
        for method, (parser, seed) in fz.METHODS_DEF().items():
            try:
                res = parser(seed)
            except Exception as exc:  # noqa: BLE001
                self.fail("%s seed raised %r" % (method, exc))
            self.assertIsInstance(res, dict)

    def test_benign_rejections_return_dict(self):
        self.assertEqual(fz.parse_mqtt_vuln(b"").get("err"), "short")
        self.assertEqual(fz.parse_coap_vuln(b"\x40\x01").get("err"), "short")
        self.assertIn("err", fz.parse_http_vuln(b"\x00" * 4))
        self.assertEqual(fz.parse_binary_vuln(b"\x00\x01\x02").get("err"), "short")


class TestPlantedBugs(unittest.TestCase):
    def test_mqtt_length_overread(self):
        # declared remaining length 0 -> fixed 2-byte header parse overreads
        with self.assertRaises(struct.error):
            fz.parse_mqtt_vuln(b"\x10\x00")

    def test_mqtt_uint16_bucket_overflow(self):
        with self.assertRaises(struct.error):
            fz.parse_mqtt_vuln(b"\x10\x7f\x01")

    def test_coap_msgid_underrun(self):
        # 4..7 byte frames crash the fixed message-id window read
        for n in range(4, 8):
            with self.assertRaises(struct.error):
                fz.parse_coap_vuln(b"\x40\x01\xbe\xaf" + b"\x01" * (n - 4))

    def test_http_cl_width_overflow(self):
        frame = b"GET /x HTTP/1.1\r\nContent-Length: " + str(2 ** 40).encode() + b"\r\n\r\n"
        with self.assertRaises(struct.error):
            fz.parse_http_vuln(frame)

    def test_http_valid_cl_ok(self):
        res = fz.parse_http_vuln(
            b"GET /x HTTP/1.1\r\nContent-Length: 19\r\n\r\n" + b"A" * 19)
        self.assertEqual(res["content_length"], 19)
        self.assertEqual(res["body_len"], 19)

    def test_binary_checksum_overread(self):
        frame = b"\xaa\xbb\x01\x01" + struct.pack("<H", 0xFFFF) + b"\x00"
        with self.assertRaises(struct.error):
            fz.parse_binary_vuln(frame)


class TestFuzzer(unittest.TestCase):
    def test_seeded_deterministic(self):
        a = fz.ProtocolFuzzer(seed=0xDEAD, rounds=120).fuzz()
        b = fz.ProtocolFuzzer(seed=0xDEAD, rounds=120).fuzz()
        self.assertEqual(a["total_crashes"], b["total_crashes"])

    def test_covers_all_fixtures(self):
        r = fz.ProtocolFuzzer(seed=0x1337DEAD, rounds=400).fuzz()
        self.assertEqual(set(r["covered_methods"]), {"mqtt", "coap", "http", "binary"})
        self.assertGreater(r["total_crashes"], 0)

    def test_crash_types_are_planted_bugs(self):
        r = fz.ProtocolFuzzer(seed=0x1337DEAD, rounds=400).fuzz()
        for sig in r["signatures"]:
            self.assertIn(sig["exc_type"], ("error", "OverflowError", "IndexError"))

    def test_reproducers_replay(self):
        fuzzer = fz.ProtocolFuzzer(seed=0x1337DEAD, rounds=300)
        fuzzer.fuzz()
        for c in fuzzer.tracker.crashes[:10]:
            parser = fz.METHODS_DEF()[c["method"]][0]
            with self.assertRaises(Exception):  # noqa: BLE001
                parser(c["data"])
            self.assertIn(c["exc_type"], ("error", "OverflowError", "IndexError"))

    def test_report_json(self):
        fz.ProtocolFuzzer(seed=5, rounds=50).fuzz()
        fuzzer = fz.ProtocolFuzzer(seed=5, rounds=50)
        fuzzer.fuzz()
        saved = fuzzer.tracker.save_reproducers()
        self.assertGreaterEqual(saved, 0)
        path = os.path.join(ROOT, "reports", "fuzz_report.json")
        fz.run_demo(seed=0x1337DEAD, rounds=60)
        with open(path) as f:
            obj = json.load(f)
        self.assertIn("total_crashes", obj)

    def test_cli_dry_run_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "iot_fuzzer.py"), "--dry-run"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("no execution", r.stdout)

    def test_cli_demo_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "iot_fuzzer.py")],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0)
        self.assertIn("PASS", r.stdout)


if __name__ == "__main__":
    unittest.main()