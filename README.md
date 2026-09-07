# X3 — IoT Protocol Fuzzer — iot_fuzzer

Mutation-based protocol fuzzer for HTTP and binary IoT protocols with crash tracking and triage.

## Overview

This project implements a mutation-style fuzzer for network protocols:
- Generates malformed HTTP requests with mutated headers, methods, and body content
- Generates mutated binary protocol frames with fuzzed length fields, magic bytes, and payloads
- Tracks crash count with deduplication via unique crash signatures
- Auto-saves crash corpus to disk for later analysis
- Produces a structured triage report with crash categories and statistics
- Uses a callback-based target interface for flexible target integration
- Demo includes a local mock HTTP server for safe offline testing

## Features

- **HTTP fuzzing**: Method, header, body, URL, content-length mutations
- **Binary frame fuzzing**: Magic byte, length field, payload, checksum mutations
- **Mutation strategies**: Bit flip, byte replacement, boundary values, format string, truncation
- **Crash dedup**: Signature-based crash grouping to avoid duplicate reports
- **Corpus management**: Auto-save interesting inputs and crashes
- **Triage report**: Summary statistics, crash categories, reproduction steps

## Installation

```bash
# No external dependencies required — Python 3.8+ standard library only
python3 firmware/iot_fuzzer.py --demo
```

## Usage

```bash
python3 firmware/iot_fuzzer.py                          # offline demo (exit 0)
python3 firmware/iot_fuzzer.py --seed 0x1337DEAD --rounds 400
python3 firmware/iot_fuzzer.py --method mqtt            # fuzz only one fixture
python3 firmware/iot_fuzzer.py --dry-run                # print plan, no execution
```

The fuzzer exercises the locally implemented, deliberately-buggy MQTT / CoAP /
HTTP / binary parsers in `firmware/iot_fuzzer.py`, records and dedupes the
crashes (uncaught `struct.error` / `IndexError` / `OverflowError`), saves
reproducers to `crash/`, and writes `reports/fuzz_report.json`.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. `python3 firmware/iot_fuzzer.py` — fuzzer finds real parser exceptions across
   all 4 planted-bug fixtures (mqtt, coap, http, binary); prints `PASS`, exit 0.
2. Re-run with the same seed → byte-identical crash set (deterministic).
3. Inspect `crash/` — each reproducer `.bin` re-raises the original exception when
   fed back to its parser.
4. `python3 -m unittest discover -s tests` — 17 deterministic assertions covering
   mutation determinism, planted-bug triggers, crash dedup, reproducer replay, CLI.

## Metrics

- Mutation engine: flip / replace / insert / delete / boundary over seed frames,
  deterministic under an injected `random.Random`
- 4 real protocol fixtures with planted memory-safety bug classes (overread,
  width overflow, index underrun)
- Crash dedup by SHA-1 signature; reproducers saved to `crash/` (gitignored)
- JSON triage report in `reports/fuzz_report.json` (gitignored)
- 17 unittest assertions, all offline/deterministic

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before fuzzing any target
- Fuzzing network services can cause denial of service and data corruption
- This tool should ONLY be used on systems you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Denial of Service laws**: Intentional disruption of service is illegal under federal and state law
- **State Laws**: Many states have additional computer crime and network abuse statutes
- **GDPR/CCPA**: Fuzzing may cause unintended data exposure subject to privacy regulations

### Acceptable Use
- Fuzzing your own software and services for bug discovery
- Authorized penetration testing with written scope that includes fuzzing
- Academic research in controlled lab environments
- Security education and training on isolated test infrastructure

### Prohibited Use
- Fuzzing third-party services without explicit authorization
- Denial-of-service attacks against any system
- Fuzzing production systems without change management approval
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software. Fuzzing may cause instability in target systems.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept
4. Include crash reproduction steps in your report

## License

MIT
