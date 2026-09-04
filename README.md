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
python3 firmware/iot_fuzzer.py --demo
python3 firmware/iot_fuzzer.py http --target http://localhost:8080 --rounds 1000
python3 firmware/iot_fuzzer.py binary --target localhost:9999 --rounds 500
```

## Example Output

```
=== X3 - IoT Protocol Fuzzer ===

[HTTP Fuzzing Round]
  Target: http://localhost:8080
  Mutations generated: 200
  Crashes found: 3
  Unique signatures: 3
  Corpus saved: 12 files

[Binary Protocol Fuzzing Round]
  Target: localhost:9999
  Mutations generated: 200
  Crashes found: 2
  Unique signatures: 2

[Triage Report]
  Total inputs: 400
  Total crashes: 5
  Unique crashes: 5
  Crash rate: 1.25%
  Top crash category: Buffer overflow (3 crashes)

[Crash Signatures]
  SIG-001: HTTP header overflow (method: PUT, field: Content-Length)
  SIG-002: HTTP null byte in URI
  SIG-003: HTTP negative content-length
  SIG-004: Binary frame length overflow
  SIG-005: Binary frame truncated mid-payload
```

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
