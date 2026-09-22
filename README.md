> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# X3 — IoT Protocol Fuzzer (iot_fuzzer)

[![License](https://img.shields.io/github/license/5h4d0wn1k/x3-iot-fuzzer)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/x3-iot-fuzzer)](https://github.com/5h4d0wn1k/x3-iot-fuzzer/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/x3-iot-fuzzer)](https://github.com/5h4d0wn1k/x3-iot-fuzzer/commits/master)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/x3-iot-fuzzer)](https://github.com/5h4d0wn1k/x3-iot-fuzzer/issues)

**X3** is a deterministic, mutation-based protocol fuzzer for embedded and IoT
protocols — MQTT, CoAP, HTTP, and custom binary frames. It generates
malformed-input packets, feeds them to locally implemented wire-format parsers,
and tracks, deduplicates, and triages crashes.

## Why X3?

Negative testing of parsers is how embedded and IoT firmware fails first. X3
gives security educators and researchers a self-contained lab: a real mutation
engine over faithful MQTT/CoAP/HTTP/binary wire formats, with classic
vulnerability classes (oversized remaining-length, token-length overread,
`Content-Length` width overflow, checksum overread) planted so the fuzzer
proves its detection. Fully offline and deterministic, it is safe for
classroom and authorized IoT security testing without touching a live device.

## Features

- **Protocol-aware mutation engine** — byte flips, inserts, deletes, boundary
  values, and known-bad integers for MQTT, CoAP, HTTP, and binary frames.
- **Faithful parser fixtures** — `parse_mqtt_vuln`, `parse_coap_vuln`,
  `parse_http_vuln`, `parse_binary_vuln` in `firmware/iot_fuzzer.py`.
- **Crash tracking & dedup** — crash signatures, unique-signature counting, and
  reproducer extraction (`CrashTracker.record`, `save_reproducers`).
- **Structured triage reports** — JSON report with per-method crash counts and
  signatures, written to `reports/fuzz_report.json`.
- **Deterministic fuzzing** — seeded RNG (`--seed`) for reproducible runs.
- **Offline by default** — all parsers live in the repo; no live targets.

## Quickstart

### Prerequisites

- Python 3.8+

### Run the fuzzer demo

```bash
git clone https://github.com/5h4d0wn1k/x3-iot-fuzzer
cd x3-iot-fuzzer
python firmware/iot_fuzzer.py
```

### Options

```bash
python firmware/iot_fuzzer.py --rounds 400          # iterations per seed
python firmware/iot_fuzzer.py --method mqtt         # fuzz only one protocol
python firmware/iot_fuzzer.py --seed 0x1337DEAD     # deterministic seed
python firmware/iot_fuzzer.py --dry-run             # print plan, don't run
```

Outputs go to `crash/` (reproducers) and `reports/fuzz_report.json` (triage).

## Tests

```bash
python -m pytest tests/test_iot_fuzzer.py
```

## Project Structure

- `firmware/iot_fuzzer.py` — Mutation engine, protocol parsers, crash tracker,
  triage report writer, and CLI.
- `crash/` — Saved reproducer inputs from the last run.
- `reports/` — `fuzz_report.json` triage output.
- `tests/` — `test_iot_fuzzer.py` test suite.

## Documentation

- [ETHICS.md](ETHICS.md) — Educational purpose and authorized use only.
- [SCOPE.md](SCOPE.md) — Authorized scope of research.
- [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md),
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Contributing

Contributions for educational and authorized-testing research are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT License — see [LICENSE](LICENSE) for details.

> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**