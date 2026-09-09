"""Low-level tshark field extraction."""

import csv
import io
import shutil
import subprocess
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
    "http2.flags",
    "http2.headers.method",
    "http2.headers.path",
    "http2.headers.status",
    "http.request.method",
    "http.request.uri",
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
        """Run tshark and return selected packet fields without payload content."""

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

        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or "unknown tshark error"
            raise TelegentError(f"tshark failed for {pcap_path}: {detail}")
        return list(csv.DictReader(io.StringIO(result.stdout), delimiter="\t"))


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

    stream_ids = split_values(packet.values.get("http2.streamid", ""))
    frame_types = split_values(packet.values.get("http2.type", ""))
    flags = split_values(packet.values.get("http2.flags", ""))
    count = min(len(stream_ids), len(frame_types))
    return [
        Http2Frame(
            stream_id=int(stream_ids[index]),
            frame_type=int(frame_types[index]),
            flags=int(flags[index], 0) if index < len(flags) else 0,
        )
        for index in range(count)
    ]


def split_values(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


def optional_int(value: str) -> int | None:
    try:
        return int(value.split(",", 1)[0])
    except ValueError:
        return None
