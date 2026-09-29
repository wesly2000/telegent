# Telegent

Telegent captures and measures packet-level response latency for streaming LLM
HTTP requests. It uses `tshark` and a TLS key log to identify `/responses` and
`/chat/completions` POST requests without depending on Codex internals.

## Requirements

- Python 3.10 or newer
- `tshark` on `PATH`
- A TLS key log that can decrypt the capture
- Bash for automated capture workloads

## Usage

Install the package in a virtual environment:

```bash
python -m pip install ./telegent
```

Copy `.env.example` to `.env`, set the local paths and provider API keys, then
capture a configured model/provider pair:

```bash
telegent capture deepseek openrouter
```

To wait after each completed response before sending the next prompt from the
prompt file, set an interval in seconds:

```bash
telegent capture deepseek openrouter --request-interval-seconds 5
```

The interval can also be configured as `TELEGENT_REQUEST_INTERVAL_SECONDS` in
`.env`. It defaults to zero and applies only between prompts, never before the
first prompt or after the last. Packet capture remains active during the wait.

Pass a positive repetition count to collect multiple captures sequentially with
the same resolved configuration:

```bash
telegent capture deepseek openrouter 5
```

To capture every provider in a model's `config.toml`, omit the provider and
specify the number of rounds:

```bash
telegent capture deepseek 5
```

Each round captures every provider once, sequentially, in `config.toml` order.
`telegent capture deepseek` captures one round. All providers are validated
before the first capture. For a background run from the directory containing
`.env`:

```bash
nohup /home/lxyu/aitraffic/bin/telegent capture deepseek 5 \
  > telegent-capture.log 2>&1 &
```

Each successful repetition receives its own provider-specific capture ID. If a
repetition fails, Telegent stops immediately, preserves earlier successful
captures, and returns a nonzero status.

Telegent validates `codex-third-party/deepseek/config.toml`, the selected
`openrouter.config.toml` profile, its API-key environment variable, and every
executable before reserving a provider-specific capture ID. Use `--dry-run` to
show the resolved paths and commands without reserving an ID or starting a
process:

```bash
telegent capture deepseek openrouter --dry-run
```

Configuration is resolved in this order: command-line overrides, process
environment, `.env` in the working directory (or `--env-file`), then defaults.
Run `telegent capture --help` for the complete set of overrides. Successful
captures contain a pcap, an append-only model TLS key log, and a run directory
with `capture.json`, `capture.log`, and the sequence output under `agent/`.
Failed captures remove their reserved artifacts, make the ID reusable, and keep
a diagnostic log under the model's `failures/` directory.

### Endpoint testing

Test the configured provider URLs, API keys, and model IDs without running
Codex or tshark:

```bash
telegent test deepseek
telegent test deepseek --provider openrouter
telegent test deepseek --dry-run
```

The command reads every `[model_providers.<provider>]` entry from the model's
`config.toml` and its matching `<provider>.config.toml` profile. It sends one
direct Responses API request containing `Hi` per provider and requires a
completed response. The output reports each provider separately and exits
nonzero if any provider fails or lacks credentials. `--dry-run` shows the URL,
model ID, and API-key variable name without sending requests or printing keys.
Failures include bounded response-status, incomplete-reason, and error-code
details when available, but never the response body or API key.
Use `--env-file`, `--codex-config-root`, or `--timeout-seconds` to override the
normal dotenv/configuration lookup and the default 60-second request timeout.

Telegent includes `codex-sequence.sh` and the manual `codex-deepseek.sh`,
`codex-glm.sh`, `codex-grok.sh`, `codex-minimax.sh`, and `codex-openai.sh`
launchers under `src/telegent/scripts`. The launchers have no machine-specific
paths. They load these values from the process environment or `.env`, with
existing process variables taking precedence:

- `TELEGENT_CODEX_CONFIG_ROOT`
- `TELEGENT_CAPTURE_ROOT`
- `TELEGENT_CODEX_BINARY`
- `TELEGENT_REQUEST_INTERVAL_SECONDS`

Set `TELEGENT_ENV_FILE` in the process environment to select another dotenv
file. The dotenv file is parsed by `python-dotenv`; it is not sourced as shell
code. For manual sequence runs, `TELEGENT_MODEL_PROVIDER` can replace the
provider argument, and `TELEGENT_PROMPTS_FILE` can select a newline-delimited
prompt file instead of the bundled two-prompt test sequence.

For example:

```bash
# From the repository working directory:
telegent/src/telegent/scripts/codex-deepseek.sh exec -p openrouter

TELEGENT_MODEL_PROVIDER=openrouter \
  telegent/src/telegent/scripts/codex-sequence.sh
```

### Analysis

Analyze one or more capture/key-log pairs:

```bash
telegent analyze \
  --input capture/deepseek/official_03.pcap sslkey/deepseek/sslkeys.key \
  --input capture/deepseek/openrouter_01.pcap sslkey/deepseek/sslkeys.key \
  --output timings.csv
```

Analyze every `.pcap` directly inside one capture directory:

```bash
telegent analyze \
  --capture-dir test-capture/chat/deepseek \
  --analysis-dir test-analysis/chat/deepseek
```

Batch analysis uses `sslkeys.key` from the capture directory and writes one CSV
per capture to the analysis directory's `timing/` subdirectory. Each CSV keeps
the capture's base name, such as `openrouter_01.pcap` becoming
`timing/openrouter_01.csv`. Captures whose destination CSV already exists are
skipped without overwriting the existing result.

The CSV contains the request-completion, response-header, and first-response-data
frame numbers and timestamps, together with these measurements:

- request completion to final HTTP 200 response headers
- request completion to first response body data
- final HTTP 200 response headers to first response body data
- first response body data to the first SSE event whose top-level JSON `type`
  contains `delta`

For HTTP/1.1, Telegent verifies the decrypted status using Wireshark's parsed
`http.response.code` field. For HTTP/2, it correlates frames by TCP stream and
HTTP/2 stream ID and reassembles SSE events across DATA frames. The streaming
token metric currently supports HTTP/2; its CSV value is blank for HTTP/1.1.
SNI is included only as debugging metadata and does not affect classification
or timing.

## Library API

```python
from pathlib import Path

from telegent import CaptureRunner, CaptureSettings, TsharkAnalyzer

capture = CaptureRunner(CaptureSettings.resolve()).collect("deepseek", "openrouter")

transactions = TsharkAnalyzer().analyze_capture(
    capture.pcap_path,
    capture.ssl_keylog_path,
)

for transaction in transactions:
    print(transaction.request_to_response_headers_ms())
```

The default request classifier is `telegent.is_llm_request`. Supply another
callable to `TsharkAnalyzer(request_classifier=...)` when an API uses different
endpoint paths.
