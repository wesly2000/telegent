# Telegent

Telegent captures and measures packet-level response latency for streaming LLM
HTTP requests. It uses `tshark` and a TLS key log to identify `/responses` and
`/chat/completions` POST requests without depending on Codex internals.

## Requirements

- Python 3.10 or newer
- `tshark` on `PATH`
- A TLS key log that can decrypt the capture
- Bash for automated capture workloads

## Automated capture

Install the package in a virtual environment:

```bash
python -m pip install ./telegent
```

For development, install the package in editable mode so changes in the source
tree are immediately available in the virtual environment:

```bash
python -m pip install --editable ./telegent
```

When running the command from inside the `telegent` repository, use
`python -m pip install --editable .` instead.

Copy `.env.example` to `.env`, set the local paths and provider API keys, then
select the agent explicitly when capturing a configured model/provider pair:

```bash
telegent capture --agent codex deepseek openrouter
telegent capture --agent opencode deepseek official
```

`TELEGENT_AGENT_BINARY` must point to the matching executable. In particular,
OpenCode traffic is decryptable only when this is the OpenCode executable built
with the customized Bun runtime. `TELEGENT_AGENT_CONFIG_ROOT` is shared as a
root name, but the configuration below each model is agent-native.

### Codex configuration

Codex retains its existing layout:

```text
agent-config/deepseek/
├── config.toml
├── models.json                 # optional
└── openrouter.config.toml
```

`config.toml` defines `[model_providers.<provider>]`; the matching
`<provider>.config.toml` selects the provider and model. If `models.json`
exists, Telegent supplies it to Codex as `model_catalog_json` on every turn.

### OpenCode configuration

OpenCode uses one complete native config per logical provider. Use exactly one
of these extensions for each provider:

```text
agent-config/deepseek/
├── official.opencode.jsonc
└── openrouter.opencode.json
```

Every file must contain a top-level `model` in `provider/model` form. JSONC is
supported, including comments and trailing commas. The rest of the object is
passed to OpenCode without translating it into Codex settings, so it may define
providers, model options, agents, and instructions. For example:

```jsonc
{
  "model": "deepseek/deepseek-chat",
  "provider": {
    "deepseek": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://api.deepseek.com/v1",
        "apiKey": "{env:DEEPSEEK_API_KEY}"
      },
      "models": {
        "deepseek-chat": { "name": "DeepSeek Chat" }
      }
    }
  }
}
```

Use `@ai-sdk/openai-compatible` for Chat Completions-compatible providers and
`@ai-sdk/openai` when the provider supports OpenAI's Responses API. Telegent
validates every `{env:NAME}` reference before capture and rewrites relative
`{file:path}` references relative to the selected config file. It passes the
normalized object through `OPENCODE_CONFIG_CONTENT`, disables project config,
model refreshes, updates and compaction, and creates capture-local XDG config,
data, state and cache directories. Relative local-plugin paths are anchored to
the selected config file before it is passed inline. It does not change `HOME`.

### Capture controls

To wait after each completed response before sending the next prompt from the
prompt file, set an interval in seconds:

```bash
telegent capture --agent opencode deepseek official \
  --request-interval-seconds 5
```

The interval can also be configured as `TELEGENT_REQUEST_INTERVAL_SECONDS` in
`.env`. It defaults to zero and applies only between prompts, never before the
first prompt or after the last. Packet capture remains active during the wait.

Pass a positive repetition count to collect multiple captures sequentially with
the same resolved configuration:

```bash
telegent capture --agent opencode deepseek official 5
```

To capture every provider, omit the provider and specify the number of rounds:

```bash
telegent capture --agent opencode deepseek 5
```

Codex uses `config.toml` provider order. OpenCode discovers
`*.opencode.json[c]` files in lexical provider order. Each round captures every
provider once and all providers are validated before the first capture. For a
background run from the directory containing `.env`:

```bash
nohup /home/lxyu/aitraffic/bin/telegent capture \
  --agent opencode deepseek 5 \
  > telegent-capture.log 2>&1 &
```

Each successful repetition receives its own provider-specific capture ID. If a
capture fails, Telegent stops its workload and tshark processes, records a
diagnostic log, and continues with the remaining providers or repetitions. The
command preserves successful captures and returns a nonzero status after the
schedule finishes if any capture failed. User interruption still stops the
schedule immediately.

Use `--dry-run` to validate configs, credentials and executables and show the
resolved paths and commands without reserving an ID or starting a process:

```bash
telegent capture --agent opencode deepseek official --dry-run
```

Configuration is resolved in this order: command-line overrides, process
environment, `.env` in the working directory (or `--env-file`), then defaults.
Run `telegent capture --help` for the complete set of overrides. Successful
captures contain a pcap, an append-only model TLS key log, and a run directory
with `capture.json`, `capture.log`, and the sequence output under `agent/`.
Failed captures remove their reserved artifacts, make the ID reusable, and keep
a diagnostic log under the model's `failures/` directory.

### Agent testing

Test every provider configured for one model through the selected agent, without
starting tshark:

```bash
telegent test --agent codex deepseek
telegent test --agent opencode deepseek
telegent test --agent codex deepseek --provider openrouter
telegent test --agent opencode deepseek --dry-run
```

The command launches the actual Codex or OpenCode binary with a minimal `Hi`
prompt for each provider configured under the requested model. It therefore
tests the agent, its native configuration, the selected provider/model, and
connectivity together. Providers are tested independently and reported
separately; one failure does not prevent later providers from running. API keys
and agent response bodies are never printed. `--provider` limits the run to one
provider, while `--dry-run` validates and displays targets without starting the
agent. Use `--env-file`, `--agent-config-root`, `--agent-binary`, or
`--timeout-seconds` to override normal lookup.

Telegent includes `codex-sequence.sh`, `opencode-sequence.sh`, and the manual `codex-deepseek.sh`,
`codex-glm.sh`, `codex-grok.sh`, `codex-minimax.sh`, and `codex-openai.sh`
launchers under `src/telegent/scripts`. The launchers have no machine-specific
paths. They load these values from the process environment or `.env`, with
existing process variables taking precedence:

- `TELEGENT_AGENT_CONFIG_ROOT`
- `TELEGENT_CAPTURE_ROOT`
- `TELEGENT_AGENT_BINARY`
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

Timing analysis remains the default. Analyze one or more capture/key-log pairs:

```bash
telegent analyze \
  --input capture/deepseek/official_03.pcap sslkey/deepseek/sslkeys.key \
  --input capture/deepseek/openrouter_01.pcap sslkey/deepseek/sslkeys.key \
  --output timings.csv
```

Use `--sse` to write one row per delta event in a complete SSE response:

```bash
telegent analyze --sse \
  --input telegent-capture/chat/minimax/official_01.pcap \
          telegent-capture/chat/minimax/sslkeys.key \
  --output minimax-sse.csv
```

Batch analysis recursively mirrors a capture tree below a feature directory:

```bash
telegent analyze --sse \
  --capture-dir telegent-capture \
  --analysis-dir telegent-analysis
```

For every discovered `.pcap`, batch analysis uses `sslkeys.key` from that
capture's directory. It writes one CSV beneath `timing/` or `sse/` and retains
the path relative to the capture root. For example,
`telegent-capture/chat/minimax/official_01.pcap` becomes
`telegent-analysis/sse/chat/minimax/official_01.csv`. Captures whose
mode-specific destination already exists are skipped without overwriting it.

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

SSE analysis accepts successful `text/event-stream` responses using HTTP/1.1
or HTTP/2. It emits only events whose top-level JSON `type` contains `delta`.
`event_size_bytes` is the exact UTF-8 size from the event's first field through
its terminating blank line, including field names, spaces, and original line
endings. Comment-only blocks such as `: keepalive` are ignored.

Delta rows are staged until Telegent observes `data: [DONE]`, a
`response.completed` event, or a clean HTTP response end with no partial SSE
block. If none of those completion conditions is present, all rows for that
response are discarded. HTTP/2 DATA payloads are read from their original
frame bytes, so tshark's generated reassembled-body fields cannot duplicate
events.

### Metrics database

Telegent can compute a scalar metric from a numeric analysis CSV column and
upsert it into a persistent wide CSV database. Configure both paths in `.env`:

```dotenv
TELEGENT_ANALYSIS_ROOT=/absolute/path/to/telegent-analysis/timing
TELEGENT_METRICS_DB=/absolute/path/to/telegent-analysis/database.db
```

Then run one operation:

```bash
telegent metric \
  --input /absolute/path/to/telegent-analysis/timing/chat/deepseek/official_01.csv \
  --column request_to_response_headers_ms \
  --operator p95
```

To apply the same operator and column to every `.csv` below an analysis root:

```bash
telegent metric \
  --root /absolute/path/to/telegent-analysis/timing \
  --column request_to_response_headers_ms \
  --operator p95
```

The scan is recursive and deterministic. Files without a `.csv` suffix are
ignored, so the CSV-formatted `database.db` is not treated as an input.
For SSE statistics, configure or pass `telegent-analysis/sse` as the root and
use `event_size_bytes` as the source column, for example:

```bash
telegent metric \
  --root /absolute/path/to/telegent-analysis/sse \
  --column event_size_bytes \
  --operator mean
```

The built-in operators are `mean`, `std`, `p50`, and `p95`. Database rows use
the input path relative to `TELEGENT_ANALYSIS_ROOT`, and metric columns use
`operator__column` names:

```csv
source_id,mean__request_to_response_headers_ms,p95__request_to_response_headers_ms
chat/deepseek/official_01.csv,123.4,180.2
chat/glm/official_01.csv,NaN,205.1
```

New rows and columns are appended, uncomputed cells contain literal `NaN`, and
recomputing a metric always replaces its existing cell. See the
[metrics database design](database.md) for the complete naming, computation,
validation, and update rules.

## Library API

```python
from pathlib import Path

from telegent import CaptureRunner, CaptureSettings, TsharkAnalyzer

settings = CaptureSettings.resolve({"agent": "opencode"})
capture = CaptureRunner(settings).collect("deepseek", "official")

transactions = TsharkAnalyzer().analyze_capture(
    capture.pcap_path,
    capture.ssl_keylog_path,
)

delta_sizes = TsharkAnalyzer().analyze_sse_capture(
    capture.pcap_path,
    capture.ssl_keylog_path,
)

for transaction in transactions:
    print(transaction.request_to_response_headers_ms())
```

The metric workflow is also reusable from Python:

```python
from telegent import Mean, MetricProcessor, MetricSettings

settings = MetricSettings.resolve()
result = MetricProcessor(settings).process_file(
    settings.analysis_root / "chat/deepseek/official_01.csv",
    "request_to_response_headers_ms",
    Mean(),
)
print(result.metric_key, result.value)
```

The default request classifier is `telegent.is_llm_request`. Supply another
callable to `TsharkAnalyzer(request_classifier=...)` when an API uses different
endpoint paths.
