"""Command-line interface for Telegent."""

import argparse
import csv
import math
import re
import statistics
import sys
from collections.abc import Iterable
from pathlib import Path

from .analyzer import TelegentError, TsharkAnalyzer
from .collector import CaptureResult, CaptureRunner, CaptureSettings
from .collector.validation import validate_all_targets
from .errors import CaptureError
from .metrics import Mean, MetricProcessor, MetricSettings, P50, P95, Std
from .models import FramePoint, HttpTransaction, SseEventSize
from .probe import EndpointProbe, ProbeSettings

_CSV_FIELDS = (
    "capture_path",
    "sni",
    "http_version",
    "tcp_stream",
    "http2_stream_id",
    "request_method",
    "request_path",
    "response_status",
    "request_end_frame",
    "request_end_time_epoch",
    "response_headers_frame",
    "response_headers_time_epoch",
    "first_response_data_frame",
    "first_response_data_time_epoch",
    "request_to_response_headers_ms",
    "request_to_first_response_data_ms",
    "response_headers_to_first_response_data_ms",
    "diagnostics",
    "first_response_data_to_first_streaming_token_ms",
)

_SSE_CSV_FIELDS = (
    "capture_path",
    "sni",
    "http_version",
    "tcp_stream",
    "http2_stream_id",
    "request_method",
    "request_path",
    "response_status",
    "delta_index",
    "event_type",
    "event_size_bytes",
)

_METRIC_OPERATORS = {
    operator.name: operator for operator in (Mean(), Std(), P50(), P95())
}


def main(argv: list[str] | None = None) -> int:
    """Run the Telegent command-line interface."""

    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "capture":
        return _capture(args, parser)
    if args.command == "test":
        return _test(args)
    if args.command == "metric":
        return _metric(args, parser)

    return _analyze(args, parser)


def _analyze(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.capture_dir is not None and args.output is not None:
        parser.error("--capture-dir must be used with --analysis-dir")
    if args.inputs is not None and args.analysis_dir is not None:
        parser.error("--input must be used with --output")

    analyzer = TsharkAnalyzer()
    try:
        if args.capture_dir is not None:
            return _analyze_directory(
                analyzer,
                args.capture_dir,
                args.analysis_dir,
                args.analysis_mode,
            )

        if args.analysis_mode == "timing":
            transactions: list[HttpTransaction] = []
            for pcap, keylog in args.inputs:
                transactions.extend(analyzer.analyze_capture(pcap, keylog))
            _write_csv(args.output, transactions)
            _print_summary(transactions)
        elif args.analysis_mode == "sse":
            measurements: list[SseEventSize] = []
            for pcap, keylog in args.inputs:
                measurements.extend(analyzer.analyze_sse_capture(pcap, keylog))
            _write_sse_csv(args.output, measurements)
            _print_sse_summary(measurements)
        else:
            raise NotImplementedError(args.analysis_mode)
    except (OSError, TelegentError) as error:
        parser.error(str(error))

    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="telegent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze TLS-decryptable pcaps")
    analysis_modes = analyze.add_mutually_exclusive_group()
    analysis_modes.add_argument(
        "--timing",
        dest="analysis_mode",
        action="store_const",
        const="timing",
        help="write transaction timing measurements (default)",
    )
    analysis_modes.add_argument(
        "--sse",
        dest="analysis_mode",
        action="store_const",
        const="sse",
        help="write complete-response SSE delta event sizes",
    )
    analyze.set_defaults(analysis_mode="timing")
    analysis_inputs = analyze.add_mutually_exclusive_group(required=True)
    analysis_inputs.add_argument(
        "--input",
        dest="inputs",
        action="append",
        nargs=2,
        metavar=("PCAP", "KEYLOG"),
        type=Path,
        help="capture and corresponding TLS key log; may be repeated",
    )
    analysis_inputs.add_argument(
        "--capture-dir",
        type=Path,
        help="capture tree containing pcaps with neighboring sslkeys.key files",
    )
    analysis_outputs = analyze.add_mutually_exclusive_group(required=True)
    analysis_outputs.add_argument(
        "--output",
        type=Path,
        help="destination CSV file",
    )
    analysis_outputs.add_argument(
        "--analysis-dir",
        type=Path,
        help="root for recursively mirrored results under timing/ or sse/",
    )
    capture = subparsers.add_parser(
        "capture", help="run a coding-agent sequence while capturing its traffic"
    )
    capture.add_argument("--agent", choices=("codex", "opencode"), required=True)
    capture.add_argument("model", help="agent configuration directory name")
    capture.add_argument(
        "provider",
        nargs="?",
        help="provider name, or N to capture all configured providers",
    )
    capture.add_argument(
        "repetitions",
        nargs="?",
        type=_positive_integer,
        metavar="N",
        help="number of capture rounds (default: 1)",
    )
    capture.add_argument(
        "--env-file", type=Path, help="dotenv file (default: .env in working directory)"
    )
    capture.add_argument("--capture-root", type=Path)
    capture.add_argument("--agent-config-root", type=Path)
    capture.add_argument("--sequence-script", type=Path)
    capture.add_argument("--agent-binary", type=Path)
    capture.add_argument("--capture-interface", "--interface")
    capture.add_argument("--capture-filter", "--filter")
    capture.add_argument("--tail-seconds", type=float)
    capture.add_argument(
        "--request-interval-seconds",
        type=float,
        help="delay between completed prompts (default: 0)",
    )
    capture.add_argument(
        "--capture-start-timeout-seconds", "--start-timeout-seconds", type=float
    )
    capture.add_argument("--tshark-binary", type=Path)
    capture.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print resolved paths and commands without starting processes",
    )
    probe = subparsers.add_parser(
        "test", help="test configured model providers through an agent"
    )
    probe.add_argument("--agent", choices=("codex", "opencode"), required=True)
    probe.add_argument("model", help="agent configuration directory name")
    probe.add_argument("--provider", help="test only this provider (default: all)")
    probe.add_argument(
        "--env-file", type=Path, help="dotenv file (default: .env in working directory)"
    )
    probe.add_argument("--agent-config-root", type=Path)
    probe.add_argument("--agent-binary", type=Path)
    probe.add_argument(
        "--timeout-seconds", type=float, help="agent timeout (default: 60)"
    )
    probe.add_argument(
        "--dry-run", action="store_true", help="show targets without starting the agent"
    )
    metric = subparsers.add_parser(
        "metric", help="compute and store metrics from analysis CSV files"
    )
    metric_inputs = metric.add_mutually_exclusive_group(required=True)
    metric_inputs.add_argument("--input", type=Path, help="one analysis CSV file")
    metric_inputs.add_argument(
        "--root",
        type=Path,
        help="analysis root whose .csv files are processed recursively",
    )
    metric.add_argument("--column", required=True, help="numeric source column")
    metric.add_argument(
        "--operator",
        required=True,
        choices=tuple(_METRIC_OPERATORS),
        help="scalar operation to compute",
    )
    metric.add_argument(
        "--env-file", type=Path, help="dotenv file (default: .env in working directory)"
    )
    return parser


def _metric(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    overrides = {"env_file": args.env_file} if args.env_file is not None else {}
    if args.root is not None:
        overrides["analysis_root"] = args.root
    try:
        settings = MetricSettings.resolve(overrides)
        processor = MetricProcessor(settings)
        operator = _METRIC_OPERATORS[args.operator]
        if args.root is not None:
            results = processor.process_directory(args.column, operator)
        else:
            results = [processor.process_file(args.input, args.column, operator)]
    except TelegentError as error:
        parser.error(str(error))

    if args.root is None:
        result = results[0]
        value = "NaN" if not math.isfinite(result.value) else repr(result.value)
        print(f"source: {result.source_id}")
        print(f"metric: {result.metric_key}")
        print(f"value: {value}")
        print(f"database: {result.database_path}")
    else:
        for result in results:
            value = "NaN" if not math.isfinite(result.value) else repr(result.value)
            print(f"computed {result.metric_key} for {result.source_id}: {value}")
        print(f"metric batch complete: {len(results)} file(s)")
        print(f"database: {settings.database_path}")
    return 0


def _test(args: argparse.Namespace) -> int:
    overrides = {
        name: getattr(args, name)
        for name in (
            "agent",
            "env_file",
            "agent_config_root",
            "agent_binary",
            "timeout_seconds",
        )
        if getattr(args, name) is not None
    }
    try:
        settings = ProbeSettings.resolve(overrides)
        results = EndpointProbe(settings).run(
            args.model, args.provider, dry_run=args.dry_run
        )
    except TelegentError as error:
        print(f"telegent: error: {error}", file=sys.stderr)
        return 1
    if args.dry_run:
        print(f"agent: {settings.agent}")
        print(f"config root: {settings.agent_config_root}")
        print(f"dotenv file: {settings.env_file or '<not loaded>'}")
    for result in results:
        elapsed = f" ({result.elapsed_ms:.0f} ms)" if result.elapsed_ms is not None else ""
        print(f"{result.status} {result.provider}: {result.detail}{elapsed}")
    if args.dry_run:
        print(f"dry run: {len(results)} provider(s); no agents started")
    else:
        passed = sum(result.status == "PASS" for result in results)
        print(f"agent test complete: {passed}/{len(results)} passed")
    return 0 if all(result.status in ("PASS", "READY") for result in results) else 1


def _capture(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    provider = args.provider
    repetitions = args.repetitions or 1
    if provider is not None and re.fullmatch(r"[+-]?[0-9]+", provider):
        if args.repetitions is not None:
            parser.error("specify either a provider and N, or N alone")
        try:
            repetitions = _positive_integer(provider)
        except argparse.ArgumentTypeError as error:
            parser.error(str(error))
        provider = None

    names = (
        "agent",
        "env_file",
        "capture_root",
        "agent_config_root",
        "sequence_script",
        "agent_binary",
        "capture_interface",
        "capture_filter",
        "tail_seconds",
        "request_interval_seconds",
        "capture_start_timeout_seconds",
        "tshark_binary",
    )
    overrides = {name: getattr(args, name) for name in names if getattr(args, name) is not None}
    active_capture: tuple[int, str] | None = None
    try:
        runner = CaptureRunner(CaptureSettings.resolve(overrides))
        providers = (
            [provider]
            if provider is not None
            else [target.provider for target in validate_all_targets(runner.settings, args.model)]
        )
        if args.dry_run:
            for selected_provider in providers:
                print(runner.dry_run(args.model, selected_provider))
            print(f"providers: {', '.join(providers)}")
            print(f"repetitions: {repetitions}")
            return 0
        if provider is None:
            print(
                f"capturing {len(providers)} provider(s) for {repetitions} round(s)",
                flush=True,
            )
        for repetition in range(1, repetitions + 1):
            for selected_provider in providers:
                active_capture = repetition, selected_provider
                result = runner.collect(args.model, selected_provider)
                _print_capture_result(
                    result, repetition, repetitions, all_providers=provider is None
                )
                sys.stdout.flush()
    except TelegentError as error:
        if active_capture is not None and provider is None:
            round_number, failed_provider = active_capture
            print(
                f"capture failed in round {round_number}/{repetitions}: {failed_provider}",
                file=sys.stderr,
            )
        print(f"telegent: error: {error}", file=sys.stderr)
        if isinstance(error, CaptureError) and error.failure_log_path is not None:
            print(f"failure log: {error.failure_log_path}", file=sys.stderr)
        return 130 if isinstance(error, CaptureError) and error.interrupted else 1
    except KeyboardInterrupt:
        print("telegent: capture interrupted", file=sys.stderr)
        return 130

    return 0


def _print_capture_result(
    result: CaptureResult,
    repetition: int,
    repetitions: int,
    *,
    all_providers: bool = False,
) -> None:
    prefix = "capture"
    if all_providers:
        prefix = f"capture round {repetition}/{repetitions}:"
    elif repetitions > 1:
        prefix = f"capture {repetition}/{repetitions}:"
    print(f"{prefix} {result.provider}_{result.capture_id:02d} complete")
    print(f"pcap: {result.pcap_path}")
    print(f"TLS key log: {result.ssl_keylog_path}")
    print(f"run artifacts: {result.run_directory}")


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _analyze_directory(
    analyzer: TsharkAnalyzer,
    capture_dir: Path,
    analysis_dir: Path,
    analysis_mode: str,
) -> int:
    if not capture_dir.is_dir():
        raise TelegentError(f"capture directory does not exist: {capture_dir}")

    pcaps = sorted(path for path in capture_dir.rglob("*.pcap") if path.is_file())
    if not pcaps:
        raise TelegentError(f"no .pcap files found in capture directory: {capture_dir}")

    analyzed = 0
    skipped = 0
    for pcap in pcaps:
        relative_output = pcap.relative_to(capture_dir).with_suffix(".csv")
        output = analysis_dir / analysis_mode / relative_output
        if output.is_file():
            print(f"skipped {pcap}: {output} already exists")
            skipped += 1
            continue

        keylog = pcap.parent / "sslkeys.key"
        if analysis_mode == "timing":
            transactions = analyzer.analyze_capture(pcap, keylog)
            _write_csv(output, transactions)
            _print_summary(transactions)
        elif analysis_mode == "sse":
            measurements = analyzer.analyze_sse_capture(pcap, keylog)
            _write_sse_csv(output, measurements)
            _print_sse_summary(measurements)
        else:
            raise NotImplementedError(analysis_mode)
        print(f"analyzed {pcap} -> {output}")
        analyzed += 1

    print(f"batch analysis complete: {analyzed} analyzed, {skipped} skipped")
    return 0


def _write_csv(path: Path, transactions: Iterable[HttpTransaction]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for transaction in transactions:
            writer.writerow(_csv_row(transaction))


def _write_sse_csv(path: Path, measurements: Iterable[SseEventSize]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=_SSE_CSV_FIELDS)
        writer.writeheader()
        for measurement in measurements:
            writer.writerow(_sse_csv_row(measurement))


def _sse_csv_row(measurement: SseEventSize) -> dict[str, object]:
    return {
        "capture_path": str(measurement.capture_path),
        "sni": measurement.sni or "",
        "http_version": measurement.http_version,
        "tcp_stream": measurement.tcp_stream,
        "http2_stream_id": measurement.http2_stream_id or "",
        "request_method": measurement.request.method,
        "request_path": measurement.request.path,
        "response_status": measurement.response_status,
        "delta_index": measurement.delta_index,
        "event_type": measurement.event_type or "",
        "event_size_bytes": measurement.event_size_bytes,
    }


def _csv_row(transaction: HttpTransaction) -> dict[str, object]:
    return {
        "capture_path": str(transaction.capture_path),
        "sni": transaction.sni or "",
        "http_version": transaction.http_version,
        "tcp_stream": transaction.tcp_stream,
        "http2_stream_id": transaction.http2_stream_id or "",
        "request_method": transaction.request.method,
        "request_path": transaction.request.path,
        "response_status": transaction.response_status or "",
        "request_end_frame": _frame_number(transaction.request_end),
        "request_end_time_epoch": _timestamp(transaction.request_end),
        "response_headers_frame": _frame_number(transaction.response_headers),
        "response_headers_time_epoch": _timestamp(transaction.response_headers),
        "first_response_data_frame": _frame_number(transaction.first_response_data),
        "first_response_data_time_epoch": _timestamp(transaction.first_response_data),
        "request_to_response_headers_ms": _number(
            transaction.request_to_response_headers_ms()
        ),
        "request_to_first_response_data_ms": _number(
            transaction.request_to_first_response_data_ms()
        ),
        "response_headers_to_first_response_data_ms": _number(
            transaction.response_headers_to_first_response_data_ms()
        ),
        "diagnostics": ";".join(transaction.diagnostics),
        "first_response_data_to_first_streaming_token_ms": _number(
            transaction.first_response_data_to_first_streaming_token_ms()
        ),
    }


def _print_summary(transactions: list[HttpTransaction]) -> None:
    by_capture: dict[Path, list[HttpTransaction]] = {}
    for transaction in transactions:
        by_capture.setdefault(transaction.capture_path, []).append(transaction)

    for capture, capture_transactions in by_capture.items():
        complete = sum(
            not transaction.diagnostics for transaction in capture_transactions
        )
        failed = sum(
            transaction.response_status is not None
            and transaction.response_status != 200
            for transaction in capture_transactions
        )
        incomplete = len(capture_transactions) - complete - failed
        print(
            f"{capture}: {len(capture_transactions)} transactions "
            f"({complete} complete, {failed} failed, {incomplete} incomplete)"
        )
        metrics = (
            ("request->headers", HttpTransaction.request_to_response_headers_ms),
            ("request->data", HttpTransaction.request_to_first_response_data_ms),
            (
                "headers->data",
                HttpTransaction.response_headers_to_first_response_data_ms,
            ),
            (
                "data->token",
                HttpTransaction.first_response_data_to_first_streaming_token_ms,
            ),
        )
        for label, measurement in metrics:
            values = [
                value
                for transaction in capture_transactions
                if (value := measurement(transaction)) is not None
            ]
            if values:
                print(
                    f"  {label}: median={statistics.median(values):.3f} ms, "
                    f"p95={_percentile_95(values):.3f} ms"
                )


def _print_sse_summary(measurements: list[SseEventSize]) -> None:
    by_capture: dict[Path, list[SseEventSize]] = {}
    for measurement in measurements:
        by_capture.setdefault(measurement.capture_path, []).append(measurement)
    for capture, capture_measurements in by_capture.items():
        stream_ids = {
            (measurement.tcp_stream, measurement.http2_stream_id)
            for measurement in capture_measurements
        }
        print(
            f"{capture}: {len(capture_measurements)} SSE delta events "
            f"from {len(stream_ids)} complete responses"
        )


def _percentile_95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def _frame_number(point: FramePoint | None) -> int | str:
    return point.frame_number if point else ""


def _timestamp(point: FramePoint | None) -> str:
    return str(point.timestamp_epoch) if point else ""


def _number(value: float | None) -> str:
    return f"{value:.6f}" if value is not None else ""


if __name__ == "__main__":
    sys.exit(main())
