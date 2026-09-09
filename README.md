# Telegent

Telegent measures packet-level response latency for streaming LLM HTTP requests.
It uses `tshark` and a TLS key log to identify `/responses` and
`/chat/completions` POST requests without depending on Codex internals.

## Requirements

- Python 3.10 or newer
- `tshark` on `PATH`
- A TLS key log that can decrypt the capture

## Usage

Install the package in a virtual environment:

```bash
python -m pip install ./telegent
```

Analyze one or more capture/key-log pairs:

```bash
telegent analyze \
  --input capture/deepseek/official_03.pcap sslkey/deepseek/sslkeys.key \
  --input capture/deepseek/openrouter_01.pcap sslkey/deepseek/sslkeys.key \
  --output timings.csv
```

The CSV contains the request-completion, response-header, and first-response-data
frame numbers and timestamps, together with these measurements:

- request completion to final HTTP 200 response headers
- request completion to first response body data
- final HTTP 200 response headers to first response body data

For HTTP/1.1, Telegent verifies the decrypted status using Wireshark's parsed
`http.response.code` field. For HTTP/2, it correlates frames by TCP stream and
HTTP/2 stream ID. SNI is included only as debugging metadata and does not affect
classification or timing.

## Library API

```python
from pathlib import Path

from telegent import TsharkAnalyzer

transactions = TsharkAnalyzer().analyze_capture(
    Path("capture.pcap"),
    Path("sslkeys.key"),
)

for transaction in transactions:
    print(transaction.request_to_response_headers_ms())
```

The default request classifier is `telegent.is_llm_request`. Supply another
callable to `TsharkAnalyzer(request_classifier=...)` when an API uses different
endpoint paths.
