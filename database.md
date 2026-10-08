# Metrics database design

Telegent stores computed statistics in a wide CSV table. Each row identifies
one analysis CSV, each metric column identifies one operator/source-column
pair, and each cell contains the latest result for that combination.

This database is intended for a single writer. It is human-readable and easy
to load with standard CSV and dataframe tools; it is not a transactional or
concurrent database.

## Configuration

Two settings are required, either in the process environment or a dotenv file:

```dotenv
TELEGENT_ANALYSIS_ROOT=/absolute/path/to/telegent-analysis/timing
TELEGENT_METRICS_DB=/absolute/path/to/telegent-analysis/database.db
```

`TELEGENT_ANALYSIS_ROOT` anchors portable source identifiers.
`TELEGENT_METRICS_DB` is the CSV database to create or update. Telegent creates
its parent directories when necessary. Its suffix does not determine its
format: `database.db` is still CSV text, not SQLite. The `.db` suffix keeps it
out of recursive `*.csv` input scans. Read it with CSV tooling, for example
`pandas.read_csv("database.db")`, rather than `pandas.read_sql`.

Use a feature-level analysis root because timing and SSE CSVs have different
schemas: `telegent-analysis/timing` for timing columns, or
`telegent-analysis/sse` for `event_size_bytes`.

## Table schema

The first column is always `source_id`. Every remaining column is a metric:

```csv
source_id,mean__request_to_response_headers_ms,p95__request_to_response_headers_ms
chat/deepseek/official_01.csv,123.4,180.2
chat/glm/official_01.csv,NaN,205.1
```

The database has these invariants:

- `source_id` is the first column and is unique for every row.
- Header names are unique.
- Every row has exactly the same number of fields as the header.
- A computed value is a finite floating-point number or the literal `NaN`.
- `NaN` means that the source/metric combination has no computed finite value.

The database contains values only. It does not currently record computation
timestamps, input hashes, or other provenance metadata.

## Source ID naming

The row name is the resolved input path relative to the resolved
`TELEGENT_ANALYSIS_ROOT`, written with `/` separators and retaining the `.csv`
suffix:

```text
Absolute input:
  /srv/telegent-analysis/timing/chat/deepseek/official_01.csv

Configured root:
  /srv/telegent-analysis/timing

Stored source_id:
  chat/deepseek/official_01.csv
```

This convention provides three useful properties:

- It avoids collisions between identical basenames in different directories,
  such as the DeepSeek and GLM `official_01.csv` files.
- It preserves useful hierarchy without turning each directory level into a
  separate database grouping or table.
- It does not expose the machine-specific absolute path above the configured
  analysis root.

Inputs outside the configured root are rejected. Symbolic links are resolved
before this check, so a link inside the root cannot identify a file outside it.
Moving or renaming an input changes its `source_id` and therefore creates a new
row; Telegent does not automatically delete the old row.

## Metric column naming

A metric column name has this form:

```text
<operator>__<source-column>
```

The double underscore makes the operator/source-column boundary visually
distinct even when the source column itself contains underscores. Examples:

```text
mean__request_to_response_headers_ms
std__request_to_first_response_data_ms
p50__response_headers_to_first_response_data_ms
p95__first_response_data_to_first_streaming_token_ms
```

Operator names are the lowercase operator class names. The built-in mappings
are:

| Class | Operator name | Meaning |
| --- | --- | --- |
| `Mean` | `mean` | Arithmetic mean |
| `Std` | `std` | Sample standard deviation |
| `P50` | `p50` | Nearest-rank 50th percentile |
| `P95` | `p95` | Nearest-rank 95th percentile |

## Input and result rules

The requested source column is read from a UTF-8 `.csv` file. Telegent ignores
blank, NaN, infinite, and nonnumeric cells. Operators receive only the
remaining finite numbers.

An operator returns NaN when it cannot produce a finite result. In particular:

- Every operator returns NaN when no finite input values remain.
- `Std` returns NaN when fewer than two finite values remain.
- `P50` and `P95` use NumPy's nearest-rank-compatible percentile method.

The stored number uses Python's floating-point representation. Non-finite
results are always serialized as the exact text `NaN`.

## Batch discovery

The `metric` command accepts either one `--input` file or a `--root` directory.
With `--root`, that path becomes the configured analysis root for the
invocation. Telegent recursively finds lowercase `*.csv` files and processes
them in source-ID order. Other suffixes, including `.db`, are ignored.

The configured metrics database is explicitly excluded even if it has a
`.csv` suffix. An empty scan is an error. Batch execution reuses the same
single-file processor for every source and is fail-fast: if a discovered CSV
does not contain the requested column, processing stops and reports the error.
Results written for earlier files remain committed.

## Update rules

Each operation updates exactly one logical cell identified by:

```text
(source_id, operator__source-column)
```

Updates follow these rules:

1. If the database does not exist, Telegent creates it with `source_id` and the
   requested metric column.
2. If the metric column does not exist, Telegent appends it and fills that
   column with `NaN` for every existing row.
3. If the source row does not exist, Telegent appends it and fills all metric
   cells in the new row with `NaN`.
4. Telegent replaces the target cell with the newly computed result.
5. Existing row and column order is preserved; new rows and columns are
   appended in first-seen order.

Replacement is unconditional. A new finite result replaces either a finite
value or NaN, and a new NaN result likewise replaces either an old finite value
or NaN. No “write only if missing” or “keep the best value” rule is applied.

For example, starting with:

```csv
source_id,mean__latency_ms
chat/deepseek/official_01.csv,100.0
```

Computing `p95` for a new GLM source produces:

```csv
source_id,mean__latency_ms,p95__latency_ms
chat/deepseek/official_01.csv,100.0,NaN
chat/glm/official_01.csv,NaN,180.0
```

Recomputing `mean__latency_ms` for the DeepSeek source replaces `100.0` in
place without changing any other cell.

## Validation and write safety

Before updating an existing database, Telegent verifies its structural
invariants: the `source_id` header, unique headers, equal row widths, nonempty
source IDs, and unique source IDs. Invalid input CSVs, missing source columns,
invalid database structure, and inputs outside the analysis root fail without
updating the database.

For a successful update, Telegent writes the complete new table to a temporary
file in the database directory, flushes it, and atomically replaces the old
database. This prevents readers from observing a partially written CSV after a
normal process or write failure. There is no inter-process lock, so callers
must ensure that only one process updates the database at a time.
