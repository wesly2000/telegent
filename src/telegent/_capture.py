"""Low-level tshark field extraction."""

import csv
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

from .errors import TelegentError
from .models import FramePoint

COMMON_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "tls.handshake.extensions_server_name",
    "http2.streamid",
    "http2.type",
    "http2.length",
    "http2.flags",
    "http2.headers.method",
    "http2.headers.path",
    "http2.headers.status",
    "http.request.method",
    "http.request.uri",
)

HTTP2_DATA_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "http2.streamid",
    "http2.type",
    "http2.length",
    "http2.flags",
    "http2.data.data",
)

HTTP1_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "http.request.method",
    "http.request.uri",
    "http.response.code",
    "http.request_in",
    "http.response_in",
    "http.file_data",
)


@dataclass(frozen=True)
class Packet:
    frame: FramePoint
    tcp_stream: int
    endpoint: tuple[str, str]
    values: dict[str, str]


@dataclass(frozen=True)
class Http2Frame:
    stream_id: int
    frame_type: int
    length: int
    flags: int


class TsharkRunner:
    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or shutil.which("tshark") or ""

    def fields(
        self,
        pcap_path: Path,
        keylog_path: Path,
        fields: Sequence[str],
        display_filter: str,
        preferences: Sequence[str] = (),
    ) -> list[dict[str, str]]:
        """Run tshark and return selected packet fields."""

        return list(
            self.iter_fields(
                pcap_path,
                keylog_path,
                fields,
                display_filter,
                preferences,
            )
        )

    def iter_fields(
        self,
        pcap_path: Path,
        keylog_path: Path,
        fields: Sequence[str],
        display_filter: str,
        preferences: Sequence[str] = (),
    ) -> Iterable[dict[str, str]]:
        """Yield selected tshark fields without buffering its complete output."""

        if not self.executable:
            raise TelegentError("tshark was not found on PATH")

        command = [
            self.executable,
            "-n",
            "-r",
            str(pcap_path),
            "-o",
            f"tls.keylog_file:{keylog_path}",
        ]
        for preference in preferences:
            command.extend(("-o", preference))
        command.extend(
            (
                "-Y",
                display_filter,
                "-T",
                "fields",
                "-E",
                "header=y",
                "-E",
                "separator=/t",
                "-E",
                "quote=d",
                "-E",
                "occurrence=a",
                "-E",
                "aggregator=,",
            )
        )
        for field in fields:
            command.extend(("-e", field))

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if process.stdout is None or process.stderr is None:
            process.kill()
            raise TelegentError("failed to open tshark output streams")

        previous_field_limit = csv.field_size_limit()
        try:
            csv.field_size_limit(sys.maxsize)
            yield from csv.DictReader(process.stdout, delimiter="\t")
            detail = process.stderr.read().strip()
            returncode = process.wait()
        finally:
            csv.field_size_limit(previous_field_limit)
            process.stdout.close()
            process.stderr.close()
            if process.poll() is None:
                process.kill()
                process.wait()
        if returncode != 0:
            detail = detail or "unknown tshark error"
            raise TelegentError(f"tshark failed for {pcap_path}: {detail}")


def packets(rows: Iterable[dict[str, str]]) -> Iterable[Packet]:
    """Convert tshark rows into typed packet records, skipping incomplete rows."""

    for row in rows:
        try:
            point = FramePoint(
                frame_number=int(row["frame.number"]),
                timestamp_epoch=Decimal(row["frame.time_epoch"]),
            )
            tcp_stream = int(row["tcp.stream"])
        except (KeyError, ValueError, InvalidOperation):
            continue
        address = row.get("ip.src") or row.get("ipv6.src") or ""
        endpoint = (address, row.get("tcp.srcport", ""))
        yield Packet(point, tcp_stream, endpoint, row)


def collect_sni(packet_records: Iterable[Packet]) -> dict[int, str]:
    """Map each TCP stream to the first SNI observed in its ClientHello."""

    result = {}
    for packet in packet_records:
        names = split_values(
            packet.values.get("tls.handshake.extensions_server_name", "")
        )
        if names:
            result.setdefault(packet.tcp_stream, names[0])
    return result


def http2_frames(packet: Packet) -> list[Http2Frame]:
    """Return HTTP/2 frame descriptors in their packet order."""

    # Tshark emits one row per captured network frame and joins repeated field
    # occurrences with commas. For example, one network frame containing a
    # WINDOW_UPDATE followed by HEADERS might produce:
    #
    #   http2.streamid = "0,1"
    #   http2.type     = "8,1"
    #   http2.length   = "4,37"
    #   http2.flags    = "0x00,0x04"
    #
    # Aligning the values by index reconstructs the HTTP/2 frame descriptors:
    #
    #   Http2Frame(stream_id=0, frame_type=8, length=4, flags=0)
    #   Http2Frame(stream_id=1, frame_type=1, length=37, flags=4)
    stream_ids = split_values(packet.values.get("http2.streamid", ""))
    frame_types = split_values(packet.values.get("http2.type", ""))
    lengths = split_values(packet.values.get("http2.length", ""))
    flags = split_values(packet.values.get("http2.flags", ""))
    count = min(len(stream_ids), len(frame_types))
    return [
        Http2Frame(
            stream_id=int(stream_ids[index]),
            frame_type=int(frame_types[index]),
            length=int(lengths[index]) if index < len(lengths) else 0,
            flags=int(flags[index], 0) if index < len(flags) else 0,
        )
        for index in range(count)
    ]


def http2_data_fragments(packet: Packet) -> list[tuple[int, bytes]]:
    """Return original positive-length DATA payloads, excluding body duplicates."""

    payloads = split_values(packet.values.get("http2.data.data", ""))
    payload_index = 0
    fragments = []
    for frame in http2_frames(packet):
        if frame.frame_type != 0 or frame.length <= 0:
            continue
        if payload_index >= len(payloads):
            break
        payload = payloads[payload_index]
        payload_index += 1
        try:
            fragments.append((frame.stream_id, bytes.fromhex(payload)))
        except ValueError:
            continue
    return fragments


def split_values(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


def optional_int(value: str) -> int | None:
    try:
        return int(value.split(",", 1)[0])
    except ValueError:
        return None
