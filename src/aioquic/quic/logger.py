import json
import os
import time
from collections import deque
from collections.abc import Iterable
from typing import Any

from ..h3.events import Headers
from .packet import (
    QuicErrorCode,
    QuicFrameType,
    QuicPacketType,
    QuicStreamFrame,
    QuicTransportParameters,
)

PACKET_TYPE_NAMES = {
    QuicPacketType.INITIAL: "initial",
    QuicPacketType.HANDSHAKE: "handshake",
    QuicPacketType.ZERO_RTT: "0RTT",
    QuicPacketType.ONE_RTT: "1RTT",
    QuicPacketType.RETRY: "retry",
    QuicPacketType.VERSION_NEGOTIATION: "version_negotiation",
}
QLOG_FILE_SCHEMA = "urn:ietf:params:qlog:file:contained"
QLOG_SERIALIZATION_FORMAT = "application/qlog+json"


def hexdump(data: bytes) -> str:
    return data.hex()


class QuicLoggerTrace:
    """
    A QUIC event trace.

    Events are logged in the format defined by qlog.

    See:
    - https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-14
    - https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events-13
    - https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-h3-events-13
    """

    def __init__(self, *, is_client: bool, odcid: bytes) -> None:
        self._odcid = odcid
        self._events: deque[dict[str, Any]] = deque()
        self._vantage_point = {
            "name": "aioquic",
            "type": "client" if is_client else "server",
        }

    # QUIC

    def encode_ack_frame(self, *, ranges: Iterable[range], delay: float) -> dict:
        return {
            "ack_delay": self.encode_time(delay),
            "acked_ranges": [[x.start, x.stop - 1] for x in ranges],
            "frame_type": "ack",
        }

    def encode_application_error(self, error_code: int) -> dict:
        # The QUIC layer does not know the application's error names.
        return {"error": "unknown", "error_code": error_code}

    def encode_connection_close_frame(
        self, *, error_code: int, frame_type: int | None, reason_phrase: str
    ) -> dict:
        attrs: dict[str, Any] = {
            "frame_type": "connection_close",
            "reason": reason_phrase,
        }
        if frame_type is None:
            attrs["error_space"] = "application"
            attrs.update(self.encode_application_error(error_code))
        else:
            attrs["error_space"] = "transport"
            attrs.update(self.encode_transport_error(error_code))
            attrs["trigger_frame_type"] = frame_type

        return attrs

    def encode_connection_limit_frame(self, *, frame_type: int, maximum: int) -> dict:
        if frame_type == QuicFrameType.MAX_DATA:
            return {"frame_type": "max_data", "maximum": maximum}
        else:
            return {
                "frame_type": "max_streams",
                "maximum": maximum,
                "stream_type": "unidirectional"
                if frame_type == QuicFrameType.MAX_STREAMS_UNI
                else "bidirectional",
            }

    def encode_crypto_frame(self, frame: QuicStreamFrame) -> dict:
        # The frame's Length field goes in raw.length (quic-events section 8.13.7).
        return {
            "frame_type": "crypto",
            "offset": frame.offset,
            "raw": {"length": len(frame.data)},
        }

    def encode_data_blocked_frame(self, limit: int) -> dict:
        return {"frame_type": "data_blocked", "limit": limit}

    def encode_datagram_frame(self, length: int) -> dict:
        return {"frame_type": "datagram", "raw": {"length": length}}

    def encode_handshake_done_frame(self) -> dict:
        return {"frame_type": "handshake_done"}

    def encode_max_stream_data_frame(self, *, maximum: int, stream_id: int) -> dict:
        return {
            "frame_type": "max_stream_data",
            "maximum": maximum,
            "stream_id": stream_id,
        }

    def encode_new_connection_id_frame(
        self,
        *,
        connection_id: bytes,
        retire_prior_to: int,
        sequence_number: int,
        stateless_reset_token: bytes,
    ) -> dict:
        return {
            "connection_id": hexdump(connection_id),
            "frame_type": "new_connection_id",
            "retire_prior_to": retire_prior_to,
            "sequence_number": sequence_number,
            "stateless_reset_token": hexdump(stateless_reset_token),
        }

    def encode_new_token_frame(self, token: bytes) -> dict:
        return {
            "frame_type": "new_token",
            "token": {"raw": {"data": hexdump(token), "length": len(token)}},
        }

    def encode_padding_frame(self, length: int) -> dict:
        # A single frame stands for all the padding bytes in the packet
        # (quic-events section 8.13.1).
        return {"frame_type": "padding", "raw": {"payload_length": length}}

    def encode_path_challenge_frame(self, data: bytes) -> dict:
        return {"data": hexdump(data), "frame_type": "path_challenge"}

    def encode_path_response_frame(self, data: bytes) -> dict:
        return {"data": hexdump(data), "frame_type": "path_response"}

    def encode_ping_frame(self) -> dict:
        return {"frame_type": "ping"}

    def encode_reset_stream_frame(
        self,
        *,
        error_code: int,
        final_size: int,
        stream_id: int,
        reliable_size: int | None = None,
    ) -> dict:
        data: dict = {
            "final_size": final_size,
            "frame_type": "reset_stream",
            "stream_id": stream_id,
            **self.encode_application_error(error_code),
        }
        if reliable_size is not None:
            data["frame_type"] = "reset_stream_at"
            data["reliable_size"] = reliable_size
        return data

    def encode_retire_connection_id_frame(self, sequence_number: int) -> dict:
        return {
            "frame_type": "retire_connection_id",
            "sequence_number": sequence_number,
        }

    def encode_stream_data_blocked_frame(self, *, limit: int, stream_id: int) -> dict:
        return {
            "frame_type": "stream_data_blocked",
            "limit": limit,
            "stream_id": stream_id,
        }

    def encode_stop_sending_frame(self, *, error_code: int, stream_id: int) -> dict:
        return {
            "frame_type": "stop_sending",
            "stream_id": stream_id,
            **self.encode_application_error(error_code),
        }

    def encode_stream_frame(self, *, frame: QuicStreamFrame, stream_id: int) -> dict:
        # The frame's Length field goes in raw.length (quic-events section 8.13.9).
        return {
            "fin": frame.fin,
            "frame_type": "stream",
            "offset": frame.offset,
            "raw": {"length": len(frame.data)},
            "stream_id": stream_id,
        }

    def encode_streams_blocked_frame(
        self, *, is_unidirectional: bool, limit: int
    ) -> dict:
        return {
            "frame_type": "streams_blocked",
            "limit": limit,
            "stream_type": "unidirectional" if is_unidirectional else "bidirectional",
        }

    def encode_time(self, seconds: float) -> float:
        """
        Convert a time to milliseconds.
        """
        return seconds * 1000

    def encode_transport_error(self, error_code: int) -> dict:
        if 0x100 <= error_code <= 0x1FF:
            return {"error": f"crypto_error_0x{error_code:x}"}
        elif error_code <= QuicErrorCode.NO_VIABLE_PATH:
            return {"error": QuicErrorCode(error_code).name.lower()}
        else:
            return {"error": "unknown", "error_code": error_code}

    def encode_transport_parameters(
        self, *, initiator: str, parameters: QuicTransportParameters
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"initiator": initiator}
        for param_name, param_value in parameters.__dict__.items():
            if param_name == "quantum_readiness":
                # qlog has no field for this reserved parameter (RFC 9000 section
                # 18.1).
                if param_value is not None:
                    data["unknown_parameters"] = [
                        {"id": 0x0C37, "value": hexdump(param_value)}
                    ]
            elif isinstance(param_value, bool):
                data[param_name] = param_value
            elif isinstance(param_value, bytes):
                data[param_name] = hexdump(param_value)
            elif isinstance(param_value, int):
                data[param_name] = param_value
        return data

    def encode_version_information(
        self,
        *,
        chosen_version: int | None,
        client_versions: list[int],
        server_versions: list[int] | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "client_versions": [f"{version:08x}" for version in client_versions]
        }
        if server_versions is not None:
            data["server_versions"] = [f"{version:08x}" for version in server_versions]
        if chosen_version is not None:
            data["chosen_version"] = f"{chosen_version:08x}"
        return data

    def packet_type(self, packet_type: QuicPacketType) -> str:
        return PACKET_TYPE_NAMES[packet_type]

    # HTTP/3

    def encode_http3_data_frame(self, *, length: int, stream_id: int) -> dict:
        return {
            "frame": {"frame_type": "data", "raw": {"payload_length": length}},
            "stream_id": stream_id,
        }

    def encode_http3_headers_frame(
        self, *, length: int, headers: Headers, stream_id: int
    ) -> dict:
        return {
            "frame": {
                "frame_type": "headers",
                "headers": self._encode_http3_headers(headers),
                "raw": {"payload_length": length},
            },
            "stream_id": stream_id,
        }

    def _encode_http3_headers(self, headers: Headers) -> list[dict]:
        fields = []
        for name, value in headers:
            field = {}
            for key, data in (("name", name), ("value", value)):
                # Bytes which are not text are logged as hex instead
                # (h3-events section 4.2.2).
                try:
                    field[key] = data.decode("utf8")
                except UnicodeDecodeError:
                    field[f"{key}_bytes"] = hexdump(data)
            fields.append(field)
        return fields

    # CORE

    def log_event(self, *, name: str, data: dict) -> None:
        self._events.append(
            {
                "data": data,
                "name": name,
                "time": self.encode_time(time.time()),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Return the trace as a dictionary which can be written as JSON.
        """
        return {
            "common_fields": {
                "group_id": hexdump(self._odcid),
                "reference_time": {
                    "clock_type": "system",
                    "epoch": "1970-01-01T00:00:00.000Z",
                },
            },
            "event_schemas": [
                "urn:ietf:params:qlog:events:quic-13",
                "urn:ietf:params:qlog:events:http3-13",
            ],
            "events": list(self._events),
            "vantage_point": self._vantage_point,
        }


class QuicLogger:
    """
    A QUIC event logger which stores traces in memory.
    """

    def __init__(self) -> None:
        self._traces: list[QuicLoggerTrace] = []

    def start_trace(self, is_client: bool, odcid: bytes) -> QuicLoggerTrace:
        trace = QuicLoggerTrace(is_client=is_client, odcid=odcid)
        self._traces.append(trace)
        return trace

    def end_trace(self, trace: QuicLoggerTrace) -> None:
        if trace not in self._traces:
            raise ValueError("QuicLoggerTrace does not belong to QuicLogger")

    def to_dict(self) -> dict[str, Any]:
        """
        Return the traces as a dictionary which can be written as JSON.
        """
        return {
            "file_schema": QLOG_FILE_SCHEMA,
            "serialization_format": QLOG_SERIALIZATION_FORMAT,
            "traces": [trace.to_dict() for trace in self._traces],
        }


class QuicFileLogger(QuicLogger):
    """
    A QUIC event logger which writes one trace per file.
    """

    def __init__(self, path: str) -> None:
        if not os.path.isdir(path):
            raise ValueError(f"QUIC log output directory '{path}' does not exist")
        self.path = path
        super().__init__()

    def end_trace(self, trace: QuicLoggerTrace) -> None:
        trace_dict = trace.to_dict()
        trace_path = os.path.join(
            self.path, trace_dict["common_fields"]["group_id"] + ".qlog"
        )
        with open(trace_path, "w") as logger_fp:
            json.dump(
                {
                    "file_schema": QLOG_FILE_SCHEMA,
                    "serialization_format": QLOG_SERIALIZATION_FORMAT,
                    "traces": [trace_dict],
                },
                logger_fp,
            )
        self._traces.remove(trace)
