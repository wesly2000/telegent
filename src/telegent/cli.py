"""Command-line interface for Telegent."""

import argparse
import csv
import math
import statistics
import sys
from collections.abc import Iterable
from pathlib import Path

from .analyzer import TelegentError, TsharkAnalyzer
from .models import FramePoint, HttpTransaction

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
    analyzer = TsharkAnalyzer()
    transactions: list[HttpTransaction] = []
    try:
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
    analyze.add_argument(
        "--input",
        dest="inputs",
        action="append",
        nargs=2,
        required=True,
        metavar=("PCAP", "KEYLOG"),
        type=Path,
        help="capture and corresponding TLS key log; may be repeated",
    )
    analyze.add_argument(
        "--output",
        required=True,
        type=Path,
        help="destination CSV file",
    )
    return parser


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
