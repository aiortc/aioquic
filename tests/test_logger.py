import json
import os
import tempfile

from aioquic.quic.logger import QuicFileLogger, QuicLogger
from aioquic.quic.packet import (
    QuicFrameType,
    QuicProtocolVersion,
    QuicTransportParameters,
)

from .utils import TestCase

SINGLE_TRACE = {
    "file_schema": "urn:ietf:params:qlog:file:contained",
    "serialization_format": "application/qlog+json",
    "traces": [
        {
            "common_fields": {
                "group_id": "0000000000000000",
                "reference_time": {
                    "clock_type": "system",
                    "epoch": "1970-01-01T00:00:00.000Z",
                },
            },
            "event_schemas": [
                "urn:ietf:params:qlog:events:quic-13",
                "urn:ietf:params:qlog:events:http3-13",
            ],
            "events": [],
            "vantage_point": {"name": "aioquic", "type": "client"},
        }
    ],
}


class QuicLoggerTest(TestCase):
    def test_empty(self) -> None:
        logger = QuicLogger()
        self.assertEqual(
            logger.to_dict(),
            {
                "file_schema": "urn:ietf:params:qlog:file:contained",
                "serialization_format": "application/qlog+json",
                "traces": [],
            },
        )

    def test_encode_connection_close_frame(self) -> None:
        trace = QuicLogger().start_trace(is_client=True, odcid=bytes(8))
        for error_code, frame_type, expected in (
            (
                0x10C,
                None,
                {"error_space": "application", "error": "unknown", "error_code": 0x10C},
            ),
            (
                0x1,
                QuicFrameType.STREAM_BASE,
                {
                    "error_space": "transport",
                    "error": "internal_error",
                    "trigger_frame_type": QuicFrameType.STREAM_BASE,
                },
            ),
            (
                0x10C,
                QuicFrameType.CRYPTO,
                {
                    "error_space": "transport",
                    "error": "crypto_error_0x10c",
                    "trigger_frame_type": QuicFrameType.CRYPTO,
                },
            ),
            (
                0x11,
                QuicFrameType.PADDING,
                {
                    "error_space": "transport",
                    "error": "unknown",
                    "error_code": 0x11,
                    "trigger_frame_type": QuicFrameType.PADDING,
                },
            ),
        ):
            with self.subTest(error_code=error_code, frame_type=frame_type):
                self.assertEqual(
                    trace.encode_connection_close_frame(
                        error_code=error_code,
                        frame_type=frame_type,
                        reason_phrase="bye",
                    ),
                    {"frame_type": "connection_close", "reason": "bye", **expected},
                )

    def test_encode_http3_headers_frame(self) -> None:
        """
        Field names and values which are not valid UTF-8 are logged as hex
        (h3-events section 4.2.2).
        """
        trace = QuicLogger().start_trace(is_client=True, odcid=bytes(8))
        self.assertEqual(
            trace.encode_http3_headers_frame(
                length=10,
                headers=[(b":status", b"200"), (b"x-foo", b"\xff"), (b"\xfe", b"bar")],
                stream_id=0,
            ),
            {
                "frame": {
                    "frame_type": "headers",
                    "headers": [
                        {"name": ":status", "value": "200"},
                        {"name": "x-foo", "value_bytes": "ff"},
                        {"name_bytes": "fe", "value": "bar"},
                    ],
                    "raw": {"payload_length": 10},
                },
                "stream_id": 0,
            },
        )

    def test_encode_transport_parameters(self) -> None:
        trace = QuicLogger().start_trace(is_client=True, odcid=bytes(8))
        self.assertEqual(
            trace.encode_transport_parameters(
                initiator="local",
                parameters=QuicTransportParameters(
                    initial_source_connection_id=b"\x01\x02",
                    max_idle_timeout=60000,
                    quantum_readiness=b"\x00\xff",
                ),
            ),
            {
                "disable_active_migration": False,
                "initial_source_connection_id": "0102",
                "initiator": "local",
                "max_idle_timeout": 60000,
                "unknown_parameters": [{"id": 0x0C37, "value": "00ff"}],
            },
        )

    def test_encode_version_information(self) -> None:
        trace = QuicLogger().start_trace(is_client=True, odcid=bytes(8))
        self.assertEqual(
            trace.encode_version_information(
                chosen_version=None,
                client_versions=[QuicProtocolVersion.VERSION_1],
                server_versions=[0x1A2A3A4A],
            ),
            {"client_versions": ["00000001"], "server_versions": ["1a2a3a4a"]},
        )

    def test_end_trace_unknown(self) -> None:
        logger = QuicLogger()
        trace = QuicLogger().start_trace(is_client=True, odcid=bytes(8))
        with self.assertRaisesMessage(
            ValueError, "QuicLoggerTrace does not belong to QuicLogger"
        ):
            logger.end_trace(trace)

    def test_single_trace(self) -> None:
        logger = QuicLogger()
        trace = logger.start_trace(is_client=True, odcid=bytes(8))
        logger.end_trace(trace)
        self.assertEqual(logger.to_dict(), SINGLE_TRACE)


class QuicFileLoggerTest(TestCase):
    def test_invalid_path(self) -> None:
        with self.assertRaisesMessage(
            ValueError,
            "QUIC log output directory 'this_path_should_not_exist' does not exist",
        ):
            QuicFileLogger("this_path_should_not_exist")

    def test_single_trace(self) -> None:
        with tempfile.TemporaryDirectory() as dirpath:
            logger = QuicFileLogger(dirpath)
            trace = logger.start_trace(is_client=True, odcid=bytes(8))
            logger.end_trace(trace)

            filepath = os.path.join(dirpath, "0000000000000000.qlog")
            self.assertTrue(os.path.exists(filepath))

            with open(filepath) as fp:
                data = json.load(fp)
            self.assertEqual(data, SINGLE_TRACE)
