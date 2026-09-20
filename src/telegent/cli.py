"""Command-line interface for Telegent."""

import argparse
import csv
import math
import statistics
import sys
from collections.abc import Iterable
from pathlib import Path

from .analyzer import TelegentError, TsharkAnalyzer
from .collector import CaptureResult, CaptureRunner, CaptureSettings
from .errors import CaptureError
from .models import FramePoint, HttpTransaction
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
)


def main(argv: list[str] | None = None) -> int:
    """Run the Telegent command-line interface."""

    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "capture":
        return _capture(args)
    if args.command == "test":
        return _test(args)

    return _analyze(args, parser)


def _analyze(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.capture_dir is not None and args.output is not None:
        parser.error("--capture-dir must be used with --analysis-dir")
    if args.inputs is not None and args.analysis_dir is not None:
        parser.error("--input must be used with --output")

    analyzer = TsharkAnalyzer()
    try:
        if args.capture_dir is not None:
            return _analyze_directory(analyzer, args.capture_dir, args.analysis_dir)

        transactions: list[HttpTransaction] = []
        for pcap, keylog in args.inputs:
            transactions.extend(analyzer.analyze_capture(pcap, keylog))
        _write_csv(args.output, transactions)
    except (OSError, TelegentError) as error:
        parser.error(str(error))

    _print_summary(transactions)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="telegent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze TLS-decryptable pcaps")
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
        help="directory containing pcaps and sslkeys.key for batch analysis",
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
        help="root directory for batch results; CSV files are written under timing/",
    )
    capture = subparsers.add_parser(
        "capture", help="run a Codex sequence while capturing its network traffic"
    )
    capture.add_argument("model", help="Codex configuration directory name")
    capture.add_argument("provider", help="Codex profile and model provider name")
    capture.add_argument(
        "repetitions",
        nargs="?",
        default=1,
        type=_positive_integer,
        metavar="N",
        help="number of sequential captures to collect (default: 1)",
    )
    capture.add_argument(
        "--env-file", type=Path, help="dotenv file (default: .env in working directory)"
    )
    capture.add_argument("--capture-root", type=Path)
    capture.add_argument("--codex-config-root", type=Path)
    capture.add_argument("--sequence-script", type=Path)
    capture.add_argument("--codex-binary", type=Path)
    capture.add_argument("--capture-interface", "--interface")
    capture.add_argument("--capture-filter", "--filter")
    capture.add_argument("--tail-seconds", type=float)
    capture.add_argument(
        "--capture-start-timeout-seconds", "--start-timeout-seconds", type=float
    )
    capture.add_argument("--tshark-binary", type=Path)
    capture.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print resolved paths and commands without starting processes",
    )
    probe = subparsers.add_parser("test", help="test configured model provider endpoints")
    probe.add_argument("model", help="Codex configuration directory name")
    probe.add_argument("--provider", help="test only this provider (default: all)")
    probe.add_argument(
        "--env-file", type=Path, help="dotenv file (default: .env in working directory)"
    )
    probe.add_argument("--codex-config-root", type=Path)
    probe.add_argument(
        "--timeout-seconds", type=float, help="request timeout (default: 60)"
    )
    probe.add_argument(
        "--dry-run", action="store_true", help="show targets without sending requests"
    )
    return parser


def _test(args: argparse.Namespace) -> int:
    overrides = {
        name: getattr(args, name)
        for name in ("env_file", "codex_config_root", "timeout_seconds")
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
        print(f"config root: {settings.codex_config_root}")
        print(f"dotenv file: {settings.env_file or '<not loaded>'}")
    for result in results:
        elapsed = f" ({result.elapsed_ms:.0f} ms)" if result.elapsed_ms is not None else ""
        print(f"{result.status} {result.provider}: {result.detail}{elapsed}")
    if args.dry_run:
        print(f"dry run: {len(results)} provider(s); no requests sent")
    else:
        passed = sum(result.status == "PASS" for result in results)
        print(f"endpoint test complete: {passed}/{len(results)} passed")
    return 0 if all(result.status in ("PASS", "READY") for result in results) else 1


def _capture(args: argparse.Namespace) -> int:
    names = (
        "env_file",
        "capture_root",
        "codex_config_root",
        "sequence_script",
        "codex_binary",
        "capture_interface",
        "capture_filter",
        "tail_seconds",
        "capture_start_timeout_seconds",
        "tshark_binary",
    )
    overrides = {name: getattr(args, name) for name in names if getattr(args, name) is not None}
    try:
        runner = CaptureRunner(CaptureSettings.resolve(overrides))
        if args.dry_run:
            print(runner.dry_run(args.model, args.provider))
            print(f"repetitions: {args.repetitions}")
            return 0
        for repetition in range(1, args.repetitions + 1):
            result = runner.collect(args.model, args.provider)
            _print_capture_result(result, repetition, args.repetitions)
    except CaptureError as error:
        print(f"telegent: error: {error}", file=sys.stderr)
        if error.failure_log_path is not None:
            print(f"failure log: {error.failure_log_path}", file=sys.stderr)
        return 130 if error.interrupted else 1

    return 0


def _print_capture_result(
    result: CaptureResult, repetition: int, repetitions: int
) -> None:
    prefix = "capture"
    if repetitions > 1:
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
    analyzer: TsharkAnalyzer, capture_dir: Path, analysis_dir: Path
) -> int:
    if not capture_dir.is_dir():
        raise TelegentError(f"capture directory does not exist: {capture_dir}")

    pcaps = sorted(
        path
        for path in capture_dir.iterdir()
        if path.is_file() and path.suffix == ".pcap"
    )
    if not pcaps:
        raise TelegentError(f"no .pcap files found in capture directory: {capture_dir}")

    keylog = capture_dir / "sslkeys.key"
    timing_dir = analysis_dir / "timing"
    analyzed = 0
    skipped = 0
    for pcap in pcaps:
        output = timing_dir / f"{pcap.stem}.csv"
        if output.is_file():
            print(f"skipped {pcap}: {output} already exists")
            skipped += 1
            continue

        transactions = analyzer.analyze_capture(pcap, keylog)
        _write_csv(output, transactions)
        print(f"analyzed {pcap} -> {output}")
        _print_summary(transactions)
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
