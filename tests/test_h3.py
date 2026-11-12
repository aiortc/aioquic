import contextlib
import copy
from typing import Any

from aioquic.buffer import UINT_VAR_MAX, Buffer, encode_uint_var
from aioquic.h3.connection import (
    H3_ALPN,
    MAX_FIELD_SECTION_SIZE,
    MAX_SETTINGS_SIZE,
    ErrorCode,
    FrameType,
    H3Connection,
    HeadersState,
    MessageError,
    Setting,
    SettingsError,
    StreamType,
    encode_frame,
    encode_settings,
    is_interim_response,
    parse_settings,
    validate_request_headers,
    validate_response_headers,
    validate_trailers,
)
from aioquic.h3.events import (
    DataReceived,
    GoAwayReceived,
    H3Event,
    Headers,
    HeadersReceived,
)
from aioquic.h3.exceptions import (
    H3Error,
    InvalidStreamIdError,
    InvalidStreamStateError,
    InvalidStreamTypeError,
    NoAvailablePushIDError,
)
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    QuicEvent,
    StopSendingReceived,
    StreamDataReceived,
    StreamReset,
)

from .test_connection import client_and_server, transfer
from .utils import TestCase

DUMMY_SETTINGS: dict[int, int] = {
    Setting.QPACK_MAX_TABLE_CAPACITY: 4096,
    Setting.QPACK_BLOCKED_STREAMS: 16,
    Setting.DUMMY: 1,
}
QUIC_CONFIGURATION_OPTIONS = {"alpn_protocols": H3_ALPN}


def closed(quic: QuicConnection) -> tuple[int, str] | None:
    """
    Return the error code and reason phrase `quic` was closed with, if any.
    """
    event = quic._close_event
    if event is None:
        return None
    return (event.error_code, event.reason_phrase)


def h3_client_and_server(
    options: dict[str, Any] = QUIC_CONFIGURATION_OPTIONS,
) -> contextlib.AbstractContextManager[tuple[QuicConnection, QuicConnection]]:
    return client_and_server(
        client_options=options,
        server_options=options,
    )


def h3_transfer(
    quic_sender: QuicConnection, h3_receiver: H3Connection, split: bool = False
) -> list[H3Event]:
    """
    Transfer data from `quic_sender` and return the receiver's H3 events.

    With `split`, stream data is handed to the receiver one byte at a time, which
    exercises H3Connection with frames split at every possible point.
    """
    quic_receiver = h3_receiver._quic
    transfer(quic_sender, quic_receiver)

    # process QUIC events
    http_events = []
    for quic_event in drain_events(quic_receiver):
        if split and isinstance(quic_event, StreamDataReceived):
            events: list[QuicEvent] = [
                StreamDataReceived(
                    data=bytes([c]), end_stream=False, stream_id=quic_event.stream_id
                )
                for c in quic_event.data
            ]
            if quic_event.end_stream:
                events.append(
                    StreamDataReceived(
                        data=b"", end_stream=True, stream_id=quic_event.stream_id
                    )
                )
        else:
            events = [quic_event]
        for event in events:
            http_events.extend(h3_receiver.handle_event(event))
    return http_events


def drain_events(quic: QuicConnection) -> list[QuicEvent]:
    events = []
    event = quic.next_event()
    while event is not None:
        events.append(event)
        event = quic.next_event()
    return events


def qpack_decoder_bytes_sent(quic: QuicConnection) -> int:
    """
    Return how many bytes of QPACK decoder instructions `quic` has sent,
    according to its qlog.
    """
    logger = quic.configuration.quic_logger
    assert logger is not None
    events = logger.to_dict()["traces"][0]["events"]
    [stream_id] = [
        event["data"]["stream_id"]
        for event in events
        if event["name"] == "http3:stream_type_set"
        and event["data"]["initiator"] == "local"
        and event["data"]["stream_type"] == "qpack_decode"
    ]
    end = max(
        (
            frame["offset"] + frame["raw"]["length"]
            for event in events
            if event["name"] == "quic:packet_sent"
            for frame in event["data"]["frames"]
            if frame["frame_type"] == "stream" and frame["stream_id"] == stream_id
        ),
        default=0,
    )
    # The stream starts with its type, a single byte.
    return max(end - 1, 0)


def send_goaway(h3: H3Connection, frame_data: bytes) -> None:
    """
    Send a GOAWAY frame on the control stream of `h3`, which cannot send one.
    """
    assert h3._local_control_stream_id is not None
    h3._quic.send_stream_data(
        h3._local_control_stream_id, encode_frame(FrameType.GOAWAY, frame_data)
    )


class H3ConnectionTest(TestCase):
    maxDiff = None

    def _make_request(self, h3_client: H3Connection, h3_server: H3Connection) -> None:
        quic_client = h3_client._quic
        quic_server = h3_server._quic

        # send request
        stream_id = quic_client.get_next_available_stream_id()
        h3_client.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
                (b"x-foo", b"client"),
            ],
        )
        h3_client.send_data(stream_id=stream_id, data=b"", end_stream=True)

        # receive request
        events = h3_transfer(quic_client, h3_server)
        self.assertEqual(
            events,
            [
                HeadersReceived(
                    headers=[
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/"),
                        (b"x-foo", b"client"),
                    ],
                    stream_id=stream_id,
                    stream_ended=False,
                ),
                DataReceived(data=b"", stream_id=stream_id, stream_ended=True),
            ],
        )

        # send response
        h3_server.send_headers(
            stream_id=stream_id,
            headers=[
                (b":status", b"200"),
                (b"content-type", b"text/html; charset=utf-8"),
                (b"x-foo", b"server"),
            ],
        )
        h3_server.send_data(
            stream_id=stream_id,
            data=b"<html><body>hello</body></html>",
            end_stream=True,
        )

        # receive response
        events = h3_transfer(quic_server, h3_client)
        self.assertEqual(
            events,
            [
                HeadersReceived(
                    headers=[
                        (b":status", b"200"),
                        (b"content-type", b"text/html; charset=utf-8"),
                        (b"x-foo", b"server"),
                    ],
                    stream_id=stream_id,
                    stream_ended=False,
                ),
                DataReceived(
                    data=b"<html><body>hello</body></html>",
                    stream_id=stream_id,
                    stream_ended=True,
                ),
            ],
        )

    def _send_request_headers(
        self, h3_client: H3Connection, h3_server: H3Connection
    ) -> int:
        quic_client = h3_client._quic

        stream_id = quic_client.get_next_available_stream_id()
        h3_client.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ],
        )
        h3_transfer(quic_client, h3_server)
        self.assertIn(stream_id, h3_server._stream)
        return stream_id

    def test_enable_webtransport_positional(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            with self.assertWarns(DeprecationWarning) as cm:
                h3_client = H3Connection(quic_client, True)  # type: ignore[call-arg]
            self.assertEqual(
                str(cm.warning),
                "Passing enable_webtransport as a positional argument is "
                "deprecated, pass it as a keyword argument instead",
            )
            self.assertEqual(cm.filename, __file__)
            assert h3_client.sent_settings is not None
            self.assertEqual(h3_client.sent_settings[Setting.ENABLE_WEBTRANSPORT], 1)

    def test_enable_webtransport_positional_and_keyword(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            with self.assertRaisesMessage(
                TypeError,
                "H3Connection.__init__() takes 2 positional arguments but 3 "
                "positional arguments (and 1 keyword-only argument) were given",
            ):
                H3Connection(
                    quic_client,
                    True,  # type: ignore[misc]
                    enable_webtransport=False,
                )

    def test_handle_control_frame_cancel_push(self) -> None:
        """
        No push ID can be cancelled, as servers never push and clients never
        send MAX_PUSH_ID, see RFC 9114 section 7.2.3.
        """
        for is_client in (True, False):
            with (
                self.subTest(is_client=is_client),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                quic = quic_client if is_client else quic_server
                h3 = H3Connection(quic)

                h3.handle_event(
                    StreamDataReceived(
                        stream_id=3 if is_client else 2,
                        data=encode_uint_var(StreamType.CONTROL)
                        + encode_frame(
                            FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
                        )
                        + encode_frame(FrameType.CANCEL_PUSH, encode_uint_var(0)),
                        end_stream=False,
                    )
                )
                self.assertEqual(
                    closed(quic),
                    (ErrorCode.H3_ID_ERROR, "Server push is not supported"),
                )

    def test_handle_control_frame_goaway(self) -> None:
        """
        A client reports the stream ID of a GOAWAY frame, while a server only
        checks the push ID, as it never pushes. Later GOAWAY frames may keep or
        lower the ID, but not raise it, see RFC 9114 section 5.2.
        """
        for is_client, goaway_ids, expected_events in [
            (True, [8], [GoAwayReceived(stream_id=8)]),
            (
                True,
                [8, 8, 4],
                [
                    GoAwayReceived(stream_id=8),
                    GoAwayReceived(stream_id=8),
                    GoAwayReceived(stream_id=4),
                ],
            ),
            (False, [3], []),
            (False, [3, 3, 1], []),
        ]:
            with (
                self.subTest(is_client=is_client, goaway_ids=goaway_ids),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)
                h3_server = H3Connection(quic_server)
                h3_receiver, h3_sender = (
                    (h3_client, h3_server) if is_client else (h3_server, h3_client)
                )

                for goaway_id in goaway_ids:
                    send_goaway(h3_sender, encode_uint_var(goaway_id))
                events = h3_transfer(h3_sender._quic, h3_receiver)
                self.assertIsNone(closed(h3_receiver._quic))
                self.assertEqual(events, expected_events)

    def test_handle_control_frame_goaway_fragmented(self) -> None:
        """
        A GOAWAY frame received one byte at a time is reported once complete.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            send_goaway(h3_server, encode_uint_var(1024))
            events = h3_transfer(quic_server, h3_client, split=True)
            self.assertIsNone(closed(quic_client))
            self.assertEqual(events, [GoAwayReceived(stream_id=1024)])

    def test_handle_control_frame_goaway_invalid_id(self) -> None:
        """
        A client must reject a GOAWAY frame which does not carry a
        client-initiated bidirectional stream ID, see RFC 9114 section 7.2.6.

        A GOAWAY frame must not raise the ID of a previous one, see RFC 9114
        section 5.2.
        """
        for is_client, goaway_ids, reason_phrase in [
            (
                True,
                [5],
                "GOAWAY does not carry a client-initiated bidirectional stream ID",
            ),
            (True, [4, 8], "GOAWAY increased the ID of a previous GOAWAY"),
            (False, [1, 3], "GOAWAY increased the ID of a previous GOAWAY"),
        ]:
            with (
                self.subTest(is_client=is_client, goaway_ids=goaway_ids),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)
                h3_server = H3Connection(quic_server)
                h3_receiver, h3_sender = (
                    (h3_client, h3_server) if is_client else (h3_server, h3_client)
                )

                for goaway_id in goaway_ids:
                    send_goaway(h3_sender, encode_uint_var(goaway_id))
                h3_transfer(h3_sender._quic, h3_receiver)
                self.assertEqual(
                    closed(h3_receiver._quic), (ErrorCode.H3_ID_ERROR, reason_phrase)
                )

    def test_handle_control_frame_goaway_malformed(self) -> None:
        """
        A GOAWAY frame which is empty or has trailing data must be rejected.
        """
        for frame_data, reason_phrase in [
            (b"", "Could not parse GOAWAY frame"),
            (b"\x04\x00", "GOAWAY frame has trailing data"),
        ]:
            with (
                self.subTest(frame_data=frame_data),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)
                h3_server = H3Connection(quic_server)

                send_goaway(h3_server, frame_data)
                h3_transfer(quic_server, h3_client)
                self.assertEqual(
                    closed(quic_client), (ErrorCode.H3_FRAME_ERROR, reason_phrase)
                )

    def test_handle_control_frame_goaway_too_long(self) -> None:
        """
        A GOAWAY frame carries a single variable-length integer, so one which
        is longer than 8 bytes is rejected from its header alone, see RFC 9114
        sections 7.1 and 7.2.6.
        """
        for frame_size, data, expected_closed, expected_events in [
            (
                8,
                encode_frame(FrameType.GOAWAY, encode_uint_var(2**30)),
                None,
                [GoAwayReceived(stream_id=2**30)],
            ),
            (
                9,
                encode_uint_var(FrameType.GOAWAY) + encode_uint_var(9),
                (ErrorCode.H3_FRAME_ERROR, "GOAWAY frame has trailing data"),
                [],
            ),
        ]:
            with (
                self.subTest(frame_size=frame_size),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)

                events = h3_client.handle_event(
                    StreamDataReceived(
                        stream_id=3,
                        data=encode_uint_var(StreamType.CONTROL)
                        + encode_frame(
                            FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
                        )
                        + data,
                        end_stream=False,
                    )
                )
                self.assertEqual(closed(quic_client), expected_closed)
                self.assertEqual(events, expected_events)

    def test_handle_control_frame_headers(self) -> None:
        """
        We should not receive HEADERS on the control stream.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)
            self.assertIsNotNone(h3_server.sent_settings)
            self.assertIsNone(h3_server.received_settings)

            # receive SETTINGS
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_server))
            self.assertIsNotNone(h3_server.sent_settings)
            self.assertEqual(h3_server.received_settings, DUMMY_SETTINGS)

            # receive unexpected HEADERS
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_frame(FrameType.HEADERS, b""),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (ErrorCode.H3_FRAME_UNEXPECTED, "Invalid frame type on control stream"),
            )

    def test_handle_control_frame_reserved(self) -> None:
        """
        Frame types reserved from HTTP/2 must be rejected on the control stream,
        see RFC 9114 section 7.2.8.
        """
        for frame_type in [0x2, 0x6, 0x8, 0x9]:
            with (
                self.subTest(frame_type=frame_type),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_server = H3Connection(quic_server)

                h3_server.handle_event(
                    StreamDataReceived(
                        stream_id=2,
                        data=encode_uint_var(StreamType.CONTROL)
                        + encode_frame(
                            FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
                        )
                        + encode_frame(frame_type, b""),
                        end_stream=False,
                    )
                )
                self.assertEqual(
                    closed(quic_server),
                    (
                        ErrorCode.H3_FRAME_UNEXPECTED,
                        "Invalid frame type on control stream",
                    ),
                )

    def test_handle_control_frame_unknown(self) -> None:
        """
        Unknown frame types must be ignored on the control stream, including
        DUPLICATE_PUSH which only existed in drafts, see RFC 9114 section 9.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS))
                    + encode_frame(0xE, encode_uint_var(0))
                    + encode_frame(0x21, b"unknown")
                    + encode_frame(FrameType.MAX_PUSH_ID, encode_uint_var(5)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_server))
            self.assertEqual(h3_server._max_push_id, 5)

    def test_handle_control_frame_settings_fragmented(self) -> None:
        """
        We should handle SETTINGS received one byte at a time.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            data = encode_uint_var(StreamType.CONTROL) + encode_frame(
                FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
            )
            for c in data:
                self.assertIsNone(h3_server.received_settings)
                h3_server.handle_event(
                    StreamDataReceived(stream_id=2, data=bytes([c]), end_stream=False)
                )
            self.assertIsNone(closed(quic_server))
            self.assertEqual(h3_server.received_settings, DUMMY_SETTINGS)

    def test_handle_control_frame_settings_qpack_maximum(self) -> None:
        """
        The QPACK settings can take any value, and the encoder may use less
        than the peer allows (RFC 9204 section 3.2.3).
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            settings = copy.copy(DUMMY_SETTINGS)
            settings[Setting.QPACK_MAX_TABLE_CAPACITY] = UINT_VAR_MAX
            settings[Setting.QPACK_BLOCKED_STREAMS] = UINT_VAR_MAX
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(settings)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_server))
            self.assertEqual(h3_server.received_settings, settings)

    def test_handle_control_frame_settings_too_large(self) -> None:
        """
        A SETTINGS frame of up to 4 KiB is accepted, a larger one is rejected
        from its header alone.
        """
        # 1365 unknown settings, one with a 2-byte value, make 4096 bytes.
        settings = {0x40 + i: 0 for i in range(1364)} | {0x40 + 1364: 0x40}
        payload = encode_settings(settings)
        self.assertEqual(len(payload), MAX_SETTINGS_SIZE)

        for frame_size, data, expected_closed, expected_settings in [
            (4096, encode_frame(FrameType.SETTINGS, payload), None, settings),
            (
                4097,
                encode_uint_var(FrameType.SETTINGS) + encode_uint_var(4097),
                (ErrorCode.H3_EXCESSIVE_LOAD, "SETTINGS frame is too large"),
                None,
            ),
        ]:
            with (
                self.subTest(frame_size=frame_size),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_server = H3Connection(quic_server)

                h3_server.handle_event(
                    StreamDataReceived(
                        stream_id=2,
                        data=encode_uint_var(StreamType.CONTROL) + data,
                        end_stream=False,
                    )
                )
                self.assertEqual(closed(quic_server), expected_closed)
                self.assertEqual(h3_server.received_settings, expected_settings)

    def test_handle_control_frame_settings_truncated(self) -> None:
        """
        We should reject a SETTINGS frame which ends in the middle of a setting.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, b"\x01"),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (ErrorCode.H3_FRAME_ERROR, "Could not parse SETTINGS frame"),
            )

    def test_handle_control_frame_unknown_before_settings(self) -> None:
        """
        An unknown frame does not satisfy the requirement for SETTINGS to be
        the first frame on the control stream, see RFC 9114 section 9.

        The error must be detected from the frame header alone.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_uint_var(0x21)
                    + encode_uint_var(1000000),
                    end_stream=False,
                )
            )
            self.assertEqual(closed(quic_server), (ErrorCode.H3_MISSING_SETTINGS, ""))

    def test_handle_control_frame_unknown_fragmented(self) -> None:
        """
        The payload of unknown frames must be discarded as it is received,
        see RFC 9114 section 7.2.8 and section 9.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive SETTINGS
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_server))

            # receive unknown frames, the last byte of the second one is withheld
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_frame(0x21, b"")
                    + encode_uint_var(0x40)
                    + encode_uint_var(10000),
                    end_stream=False,
                )
            )
            for i in range(9):
                h3_server.handle_event(
                    StreamDataReceived(stream_id=2, data=b"x" * 1111, end_stream=False)
                )
                self.assertIsNone(closed(quic_server))
                self.assertEqual(h3_server._stream[2].buffer, b"")
                self.assertEqual(
                    h3_server._stream[2].frame_size, 10000 - 1111 * (i + 1)
                )

            # receive the last byte and MAX_PUSH_ID
            self.assertIsNone(h3_server._max_push_id)
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=b"x" + encode_frame(FrameType.MAX_PUSH_ID, encode_uint_var(5)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_server))
            self.assertEqual(h3_server._max_push_id, 5)

    def test_handle_control_frame_wrong_frame_type_header_only(self) -> None:
        """
        Frames which are not allowed on the control stream must be rejected
        from the frame header alone, without buffering their payload.
        """
        for is_client, frame_type, reason in [
            (False, FrameType.DATA, "Invalid frame type on control stream"),
            (False, FrameType.HEADERS, "Invalid frame type on control stream"),
            (False, FrameType.PUSH_PROMISE, "Invalid frame type on control stream"),
            (False, 0x2, "Invalid frame type on control stream"),
            (False, 0x6, "Invalid frame type on control stream"),
            (False, 0x8, "Invalid frame type on control stream"),
            (False, 0x9, "Invalid frame type on control stream"),
            (False, FrameType.SETTINGS, "SETTINGS have already been received"),
            (True, FrameType.MAX_PUSH_ID, "Servers must not send MAX_PUSH_ID"),
        ]:
            with (
                self.subTest(is_client=is_client, frame_type=frame_type),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                quic = quic_client if is_client else quic_server
                h3 = H3Connection(quic)
                stream_id = 3 if is_client else 2

                # receive SETTINGS
                h3.handle_event(
                    StreamDataReceived(
                        stream_id=stream_id,
                        data=encode_uint_var(StreamType.CONTROL)
                        + encode_frame(
                            FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
                        ),
                        end_stream=False,
                    )
                )
                self.assertIsNone(closed(quic))

                # receive frame header only
                h3.handle_event(
                    StreamDataReceived(
                        stream_id=stream_id,
                        data=encode_uint_var(frame_type) + encode_uint_var(1000000),
                        end_stream=False,
                    )
                )
                self.assertEqual(closed(quic), (ErrorCode.H3_FRAME_UNEXPECTED, reason))

    def test_handle_control_frame_max_push_id_from_client_before_settings(self) -> None:
        """
        A server should not receive MAX_PUSH_ID before SETTINGS.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive unexpected MAX_PUSH_ID
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.MAX_PUSH_ID, b""),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (ErrorCode.H3_MISSING_SETTINGS, ""),
            )

    def test_handle_control_frame_max_push_id_from_server(self) -> None:
        """
        A client should not receive MAX_PUSH_ID on the control stream.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            # receive SETTINGS
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=3,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_client))

            # receive unexpected MAX_PUSH_ID
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=3,
                    data=encode_frame(FrameType.MAX_PUSH_ID, b""),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_client),
                (ErrorCode.H3_FRAME_UNEXPECTED, "Servers must not send MAX_PUSH_ID"),
            )

    def test_handle_control_frame_max_push_id_malformed(self) -> None:
        """
        A server should reject a MAX_PUSH_ID frame which is empty or has
        trailing data.
        """
        for frame_data, reason_phrase in [
            (b"", "Could not parse MAX_PUSH_ID frame"),
            (b"\x05\x00", "MAX_PUSH_ID frame has trailing data"),
        ]:
            with (
                self.subTest(frame_data=frame_data),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_server = H3Connection(quic_server)

                h3_server.handle_event(
                    StreamDataReceived(
                        stream_id=2,
                        data=encode_uint_var(StreamType.CONTROL)
                        + encode_frame(
                            FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
                        )
                        + encode_frame(FrameType.MAX_PUSH_ID, frame_data),
                        end_stream=False,
                    )
                )
                self.assertEqual(
                    closed(quic_server), (ErrorCode.H3_FRAME_ERROR, reason_phrase)
                )

    def test_handle_control_frame_max_push_id_reduced(self) -> None:
        """
        A server must reject a MAX_PUSH_ID frame which reduces the maximum
        push ID, see RFC 9114 section 7.2.7.
        """
        for max_push_id, expected_closed, expected_max_push_id in [
            (7, (ErrorCode.H3_ID_ERROR, "MAX_PUSH_ID reduced the maximum push ID"), 8),
            (8, None, 8),
            (9, None, 9),
        ]:
            with (
                self.subTest(max_push_id=max_push_id),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_server = H3Connection(quic_server)

                h3_server.handle_event(
                    StreamDataReceived(
                        stream_id=2,
                        data=encode_uint_var(StreamType.CONTROL)
                        + encode_frame(
                            FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
                        )
                        + encode_frame(FrameType.MAX_PUSH_ID, encode_uint_var(8))
                        + encode_frame(
                            FrameType.MAX_PUSH_ID, encode_uint_var(max_push_id)
                        ),
                        end_stream=False,
                    )
                )
                self.assertEqual(closed(quic_server), expected_closed)
                self.assertEqual(h3_server._max_push_id, expected_max_push_id)

    def test_handle_control_frame_max_push_id_too_long(self) -> None:
        """
        A MAX_PUSH_ID frame carries a single variable-length integer, so one
        which is longer than 8 bytes is rejected from its header alone, see
        RFC 9114 sections 7.1 and 7.2.7.
        """
        for frame_size, data, expected_closed, expected_max_push_id in [
            (
                8,
                encode_frame(FrameType.MAX_PUSH_ID, encode_uint_var(2**30)),
                None,
                2**30,
            ),
            (
                9,
                encode_uint_var(FrameType.MAX_PUSH_ID) + encode_uint_var(9),
                (ErrorCode.H3_FRAME_ERROR, "MAX_PUSH_ID frame has trailing data"),
                None,
            ),
        ]:
            with (
                self.subTest(frame_size=frame_size),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_server = H3Connection(quic_server)

                h3_server.handle_event(
                    StreamDataReceived(
                        stream_id=2,
                        data=encode_uint_var(StreamType.CONTROL)
                        + encode_frame(
                            FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
                        )
                        + data,
                        end_stream=False,
                    )
                )
                self.assertEqual(closed(quic_server), expected_closed)
                self.assertEqual(h3_server._max_push_id, expected_max_push_id)

    def test_handle_control_settings_twice(self) -> None:
        """
        We should not receive HEADERS on the control stream.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive SETTINGS
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_server))

            # receive unexpected SETTINGS
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_frame(
                        FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
                    ),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (ErrorCode.H3_FRAME_UNEXPECTED, "SETTINGS have already been received"),
            )

    def test_handle_control_stream_close(self) -> None:
        """
        Closing the control stream is not allowed.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            # receive SETTINGS
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=3,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_client))

            # receive unexpected FIN
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=3,
                    data=b"",
                    end_stream=True,
                )
            )
            self.assertEqual(
                closed(quic_client),
                (
                    ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                    "Closing control stream is not allowed",
                ),
            )

    def test_handle_control_stream_duplicate(self) -> None:
        """
        We must only receive a single control stream.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive a first control stream
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL),
                    end_stream=False,
                )
            )

            # receive a second control stream
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=6,
                    data=encode_uint_var(StreamType.CONTROL),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_STREAM_CREATION_ERROR,
                    "Only one control stream is allowed",
                ),
            )

    def test_handle_control_stream_reset(self) -> None:
        """
        Resetting the control stream is not allowed.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            # Receive SETTINGS.
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=3,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_client))

            # Receive unexpected RESET_STREAM.
            h3_client.handle_event(StreamReset(error_code=0, stream_id=3))
            self.assertEqual(
                closed(quic_client),
                (
                    ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                    "Resetting a critical stream is not allowed",
                ),
            )

    def test_handle_control_stream_stop_sending(self) -> None:
        """
        Asking us to stop sending on our control stream is not allowed.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            # Receive unexpected STOP_SENDING.
            h3_client.handle_event(
                StopSendingReceived(
                    error_code=0, stream_id=h3_client._local_control_stream_id
                )
            )
            self.assertEqual(
                closed(quic_client),
                (
                    ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                    "Stopping a critical stream is not allowed",
                ),
            )

    def test_handle_push_stream_from_client(self) -> None:
        """
        A server must reject a push stream, see RFC 9114 section 6.2.2.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.PUSH),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_STREAM_CREATION_ERROR,
                    "Clients must not open push streams",
                ),
            )

    def test_handle_push_stream_from_server(self) -> None:
        """
        A client must reject a push stream, as it never sends MAX_PUSH_ID, see
        RFC 9114 section 4.6.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=15,
                    data=encode_uint_var(StreamType.PUSH),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_client),
                (ErrorCode.H3_ID_ERROR, "Server push is not supported"),
            )

    def test_handle_qpack_decoder_duplicate(self) -> None:
        """
        We must only receive a single QPACK decoder stream.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            # receive a first decoder stream
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=11,
                    data=encode_uint_var(StreamType.QPACK_DECODER),
                    end_stream=False,
                )
            )

            # receive a second decoder stream
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=15,
                    data=encode_uint_var(StreamType.QPACK_DECODER),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_client),
                (
                    ErrorCode.H3_STREAM_CREATION_ERROR,
                    "Only one QPACK decoder stream is allowed",
                ),
            )

    def test_handle_qpack_decoder_stream_error(self) -> None:
        """
        Receiving garbage on the QPACK decoder stream triggers an exception.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=11,
                    data=encode_uint_var(StreamType.QPACK_DECODER) + b"\x00",
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_client), (ErrorCode.QPACK_DECODER_STREAM_ERROR, "")
            )

    def test_handle_qpack_encoder_duplicate(self) -> None:
        """
        We must only receive a single QPACK encoder stream.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            # receive a first encoder stream
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=11,
                    data=encode_uint_var(StreamType.QPACK_ENCODER),
                    end_stream=False,
                )
            )

            # receive a second encoder stream
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=15,
                    data=encode_uint_var(StreamType.QPACK_ENCODER),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_client),
                (
                    ErrorCode.H3_STREAM_CREATION_ERROR,
                    "Only one QPACK encoder stream is allowed",
                ),
            )

    def test_handle_qpack_encoder_stream_error(self) -> None:
        """
        Receiving garbage on the QPACK encoder stream triggers an exception.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=7,
                    data=encode_uint_var(StreamType.QPACK_ENCODER) + b"\x00",
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_client), (ErrorCode.QPACK_ENCODER_STREAM_ERROR, "")
            )

    def test_handle_qpack_encoder_stream_reset(self) -> None:
        """
        Resetting the QPACK encoder stream is not allowed.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=7,
                    data=encode_uint_var(StreamType.QPACK_ENCODER),
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_client))

            # Receive unexpected RESET_STREAM.
            h3_client.handle_event(StreamReset(error_code=0, stream_id=7))
            self.assertEqual(
                closed(quic_client),
                (
                    ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                    "Resetting a critical stream is not allowed",
                ),
            )

    def test_handle_qpack_encoder_stream_table_capacity(self) -> None:
        """
        We advertise no dynamic table, so the peer's encoder cannot set its
        capacity above zero, see RFC 9204 section 4.3.1.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            # Set Dynamic Table Capacity to 0.
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=7,
                    data=encode_uint_var(StreamType.QPACK_ENCODER) + b"\x20",
                    end_stream=False,
                )
            )
            self.assertIsNone(closed(quic_client))

            # Set Dynamic Table Capacity to 32.
            h3_client.handle_event(
                StreamDataReceived(stream_id=7, data=b"\x3f\x01", end_stream=False)
            )
            self.assertEqual(
                closed(quic_client), (ErrorCode.QPACK_ENCODER_STREAM_ERROR, "")
            )

    def test_handle_request_frame_bad_headers(self) -> None:
        """
        We should not receive HEADERS which cannot be decoded.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=encode_frame(FrameType.HEADERS, b""),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server), (ErrorCode.QPACK_DECOMPRESSION_FAILED, "")
            )

    def test_handle_request_frame_data_before_headers(self) -> None:
        """
        We should not receive DATA before receiving headers.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=encode_frame(FrameType.DATA, b""),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_FRAME_UNEXPECTED,
                    "DATA frame is not allowed in this state",
                ),
            )

    def test_handle_request_frame_headers_after_trailers(self) -> None:
        """
        We should not receive HEADERS after receiving trailers.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
            )
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[(b"x-some-trailer", b"foo")],
                end_stream=True,
            )
            h3_transfer(quic_client, h3_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=encode_frame(FrameType.HEADERS, b""),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_FRAME_UNEXPECTED,
                    "HEADERS frame is not allowed in this state",
                ),
            )

    def test_handle_request_frame_headers_too_large(self) -> None:
        """
        A HEADERS frame larger than the maximum field section size plus a margin
        is rejected from its header alone, by a client as by a server, see
        RFC 9114 section 10.5.1.
        """
        for is_client in (False, True):
            for frame_size, expected_closed in [
                (MAX_FIELD_SECTION_SIZE * 3 // 2, None),
                (
                    MAX_FIELD_SECTION_SIZE * 3 // 2 + 1,
                    (ErrorCode.H3_EXCESSIVE_LOAD, "HEADERS frame is too large"),
                ),
            ]:
                with (
                    self.subTest(is_client=is_client, frame_size=frame_size),
                    h3_client_and_server() as (quic_client, quic_server),
                ):
                    quic = quic_client if is_client else quic_server
                    h3 = H3Connection(quic)

                    events = h3.handle_event(
                        StreamDataReceived(
                            stream_id=0,
                            data=encode_uint_var(FrameType.HEADERS)
                            + encode_uint_var(frame_size),
                            end_stream=False,
                        )
                    )
                    self.assertEqual(events, [])
                    self.assertEqual(closed(quic), expected_closed)

    def test_handle_request_frame_interim_response_at_end(self) -> None:
        """
        A response stream cannot end after an interim response, whether or not
        the end of stream comes with the HEADERS frame, see RFC 9114 section 4.1.
        """
        for fin_with_headers in (True, False):
            with (
                self.subTest(fin_with_headers=fin_with_headers),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)
                h3_server = H3Connection(quic_server)

                # Send the request.
                stream_id = quic_client.get_next_available_stream_id()
                h3_client.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/"),
                    ],
                    end_stream=True,
                )
                h3_transfer(quic_client, h3_server)

                # Send an interim response, then end the stream.
                h3_server.send_headers(
                    stream_id=stream_id, headers=[(b":status", b"103")]
                )
                if not fin_with_headers:
                    h3_transfer(quic_server, h3_client)
                quic_server.send_stream_data(stream_id, b"", end_stream=True)
                h3_transfer(quic_server, h3_client)
                self.assertEqual(
                    closed(quic_client),
                    (
                        ErrorCode.H3_MESSAGE_ERROR,
                        "Interim response cannot end the stream",
                    ),
                )

    def test_handle_request_frame_interim_response_content_length(self) -> None:
        """
        The content-length of an interim response does not apply to the final
        response, as interim responses have no content (RFC 9110 section 6.4.1).
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # Send the request.
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
                end_stream=True,
            )
            h3_transfer(quic_client, h3_server)

            # Send an interim response with a content-length, then the response.
            h3_server.send_headers(
                stream_id=stream_id,
                headers=[(b":status", b"103"), (b"content-length", b"5")],
            )
            h3_server.send_headers(stream_id=stream_id, headers=[(b":status", b"200")])
            h3_server.send_data(
                stream_id=stream_id, data=b"hello world", end_stream=True
            )
            h3_transfer(quic_server, h3_client)
            self.assertIsNone(closed(quic_client))

    def test_handle_request_frame_push_promise_from_client(self) -> None:
        """
        A server should not receive PUSH_PROMISE on a request stream.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=encode_frame(FrameType.PUSH_PROMISE, b""),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (ErrorCode.H3_FRAME_UNEXPECTED, "Clients must not send PUSH_PROMISE"),
            )

    def test_handle_request_frame_push_promise_from_server(self) -> None:
        """
        A client must reject a PUSH_PROMISE, as it never sends MAX_PUSH_ID, see
        RFC 9114 section 7.2.5. It is rejected from the frame header alone.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            events = h3_client.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=encode_uint_var(FrameType.PUSH_PROMISE)
                    + encode_uint_var(1000000),
                    end_stream=False,
                )
            )
            self.assertEqual(events, [])
            self.assertEqual(
                closed(quic_client),
                (ErrorCode.H3_ID_ERROR, "Server push is not supported"),
            )

    def test_handle_request_frame_wrong_frame_type(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=encode_frame(FrameType.SETTINGS, b""),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (ErrorCode.H3_FRAME_UNEXPECTED, "Invalid frame type on request stream"),
            )

    def test_handle_request_frame_reserved(self) -> None:
        """
        Frame types reserved from HTTP/2 must be rejected on a request stream,
        see RFC 9114 section 7.2.8.
        """
        for frame_type in [0x2, 0x6, 0x8, 0x9]:
            with (
                self.subTest(frame_type=frame_type),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_server = H3Connection(quic_server)

                h3_server.handle_event(
                    StreamDataReceived(
                        stream_id=0,
                        data=encode_frame(frame_type, b""),
                        end_stream=False,
                    )
                )
                self.assertEqual(
                    closed(quic_server),
                    (
                        ErrorCode.H3_FRAME_UNEXPECTED,
                        "Invalid frame type on request stream",
                    ),
                )

    def test_handle_request_frame_unknown_duplicate_push(self) -> None:
        """
        DUPLICATE_PUSH only existed in drafts, it is now an unknown frame type
        which must be ignored, see RFC 9114 section 9.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            events = h3_server.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=encode_frame(0xE, encode_uint_var(0)),
                    end_stream=False,
                )
            )
            self.assertEqual(events, [])
            self.assertIsNone(closed(quic_server))

    def test_handle_request_frame_wrong_frame_type_header_only(self) -> None:
        """
        Frames which are not allowed on a request stream must be rejected from
        the frame header alone, without buffering their payload.
        """
        for is_client, frame_type, reason in [
            (False, FrameType.CANCEL_PUSH, "Invalid frame type on request stream"),
            (False, FrameType.SETTINGS, "Invalid frame type on request stream"),
            (False, FrameType.PUSH_PROMISE, "Clients must not send PUSH_PROMISE"),
            (False, FrameType.GOAWAY, "Invalid frame type on request stream"),
            (False, FrameType.MAX_PUSH_ID, "Invalid frame type on request stream"),
            (False, 0x2, "Invalid frame type on request stream"),
            (False, 0x6, "Invalid frame type on request stream"),
            (False, 0x8, "Invalid frame type on request stream"),
            (False, 0x9, "Invalid frame type on request stream"),
            (True, FrameType.SETTINGS, "Invalid frame type on request stream"),
        ]:
            with (
                self.subTest(is_client=is_client, frame_type=frame_type),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                quic = quic_client if is_client else quic_server
                h3 = H3Connection(quic)

                h3.handle_event(
                    StreamDataReceived(
                        stream_id=0,
                        data=encode_uint_var(frame_type) + encode_uint_var(1000000),
                        end_stream=False,
                    )
                )
                self.assertEqual(closed(quic), (ErrorCode.H3_FRAME_UNEXPECTED, reason))

    def test_handle_request_frame_truncated(self) -> None:
        """
        A frame truncated by the end of the stream must be rejected, see
        RFC 9114 section 7.1.
        """
        headers = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/"),
            (b"content-length", b"5"),
        ]
        cases = {
            "frame header": encode_frame(FrameType.DATA, b"hello")[:1],
            "DATA": encode_frame(FrameType.DATA, b"hello")[:-2],
            "HEADERS": encode_frame(FrameType.HEADERS, b"\x00\x00\x40\x41")[:-1],
            "unknown": encode_frame(0x21, b"grease")[:-1],
        }
        for name, truncated_data in cases.items():
            for split in [False, True]:
                with (
                    self.subTest(frame=name, split=split),
                    h3_client_and_server() as (quic_client, quic_server),
                ):
                    h3_client = H3Connection(quic_client)
                    h3_server = H3Connection(quic_server)

                    stream_id = quic_client.get_next_available_stream_id()
                    h3_client.send_headers(stream_id=stream_id, headers=headers)
                    quic_client.send_stream_data(
                        stream_id, truncated_data, end_stream=not split
                    )

                    # Receive the stream end with the truncated frame, or after it.
                    if split:
                        h3_transfer(quic_client, h3_server)
                        self.assertIsNone(closed(quic_server))
                        quic_client.send_stream_data(stream_id, b"", end_stream=True)
                    events = h3_transfer(quic_client, h3_server)
                    self.assertEqual(events, [])
                    self.assertEqual(
                        closed(quic_server),
                        (
                            ErrorCode.H3_FRAME_ERROR,
                            "Frame is truncated by the end of the stream",
                        ),
                    )

    def test_handle_request_frame_unknown(self) -> None:
        """
        Unknown frames must be ignored, see RFC 9114 section 7.2.8 and
        section 9.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # send request headers
            stream_id = quic_client.get_next_available_stream_id()
            headers = [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ]
            quic_client.send_stream_data(stream_id, encode_frame(0x21, b""))
            h3_client.send_headers(stream_id=stream_id, headers=headers)

            # receive unknown frames around the HEADERS and DATA frames
            quic_client.send_stream_data(
                stream_id,
                encode_frame(0x40, b"unknown")
                + encode_frame(FrameType.DATA, b"hello")
                + encode_frame(0x5F, b"x" * 1000)
                + encode_frame(FrameType.DATA, b"world"),
                end_stream=True,
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertIsNone(closed(quic_server))
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=headers, stream_id=stream_id, stream_ended=False
                    ),
                    DataReceived(
                        data=b"hello", stream_id=stream_id, stream_ended=False
                    ),
                    DataReceived(data=b"world", stream_id=stream_id, stream_ended=True),
                ],
            )

    def test_handle_request_frame_unknown_at_end(self) -> None:
        """
        Unknown frames can be the last frame on a request stream, see
        RFC 9114 section 4.1.
        """
        headers = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/"),
            (b"content-length", b"5"),
        ]
        trailers = [(b"x-some-trailer", b"foo")]

        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # send request with trailers
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(stream_id=stream_id, headers=headers)
            h3_client.send_data(stream_id=stream_id, data=b"hello", end_stream=False)

            # receive an unknown frame after the body
            quic_client.send_stream_data(
                stream_id, encode_frame(0x21, b"grease"), end_stream=True
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertIsNone(closed(quic_server))
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=headers, stream_id=stream_id, stream_ended=False
                    ),
                    DataReceived(
                        data=b"hello", stream_id=stream_id, stream_ended=False
                    ),
                    DataReceived(data=b"", stream_id=stream_id, stream_ended=True),
                ],
            )

            # receive an unknown frame after the trailers
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(stream_id=stream_id, headers=headers)
            h3_client.send_data(stream_id=stream_id, data=b"hello", end_stream=False)
            h3_client.send_headers(stream_id=stream_id, headers=trailers)
            quic_client.send_stream_data(
                stream_id, encode_frame(0x21, b"grease"), end_stream=True
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertIsNone(closed(quic_server))
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=headers, stream_id=stream_id, stream_ended=False
                    ),
                    DataReceived(
                        data=b"hello", stream_id=stream_id, stream_ended=False
                    ),
                    HeadersReceived(
                        headers=trailers, stream_id=stream_id, stream_ended=False
                    ),
                    DataReceived(data=b"", stream_id=stream_id, stream_ended=True),
                ],
            )

    def test_handle_request_frame_unknown_at_end_content_length_mismatch(self) -> None:
        """
        The content-length must be checked when a request stream ends with
        an unknown frame.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # send request
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                    (b"content-length", b"20"),
                ],
            )
            h3_client.send_data(stream_id=stream_id, data=b"hello", end_stream=False)

            # receive an unknown frame after the body
            quic_client.send_stream_data(
                stream_id, encode_frame(0x21, b"grease"), end_stream=True
            )
            h3_transfer(quic_client, h3_server)
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_MESSAGE_ERROR,
                    "content-length does not match data size",
                ),
            )

    def test_handle_request_frame_unknown_fragmented(self) -> None:
        """
        The payload of unknown frames must be discarded as it is received,
        see RFC 9114 section 7.2.8 and section 9.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # send request headers
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(len(events), 1)
            self.assertIsInstance(events[0], HeadersReceived)

            # receive an unknown frame, the last byte is withheld
            events = h3_server.handle_event(
                StreamDataReceived(
                    stream_id=stream_id,
                    data=encode_uint_var(0x21) + encode_uint_var(10000),
                    end_stream=False,
                )
            )
            self.assertEqual(events, [])
            for i in range(9):
                events = h3_server.handle_event(
                    StreamDataReceived(
                        stream_id=stream_id, data=b"x" * 1111, end_stream=False
                    )
                )
                self.assertEqual(events, [])
                self.assertIsNone(closed(quic_server))
                self.assertEqual(h3_server._stream[stream_id].buffer, b"")
                self.assertEqual(
                    h3_server._stream[stream_id].frame_size, 10000 - 1111 * (i + 1)
                )

            # receive the last byte and DATA
            events = h3_server.handle_event(
                StreamDataReceived(
                    stream_id=stream_id,
                    data=b"x" + encode_frame(FrameType.DATA, b"hello"),
                    end_stream=True,
                )
            )
            self.assertIsNone(closed(quic_server))
            self.assertEqual(
                events,
                [DataReceived(data=b"hello", stream_id=stream_id, stream_ended=True)],
            )

    def test_max_push_id_not_sent(self) -> None:
        """
        A client never sends MAX_PUSH_ID, so servers cannot push, see RFC 9114
        section 4.6.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertTrue(h3_server._settings_received)
            self.assertIsNone(h3_server._max_push_id)

    def test_request(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # make first request
            self._make_request(h3_client, h3_server)

            # make second request
            self._make_request(h3_client, h3_server)

            # make third request
            self._make_request(h3_client, h3_server)

    def test_request_headers_only(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # send request
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"HEAD"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                    (b"x-foo", b"client"),
                ],
                end_stream=True,
            )

            # receive request
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[
                            (b":method", b"HEAD"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/"),
                            (b"x-foo", b"client"),
                        ],
                        stream_id=stream_id,
                        stream_ended=True,
                    )
                ],
            )

            # send response
            h3_server.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"x-foo", b"server"),
                ],
                end_stream=True,
            )

            # receive response
            events = h3_transfer(quic_server, h3_client)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[
                            (b":status", b"200"),
                            (b"content-type", b"text/html; charset=utf-8"),
                            (b"x-foo", b"server"),
                        ],
                        stream_id=stream_id,
                        stream_ended=True,
                    )
                ],
            )

    def test_request_field_section_too_large(self) -> None:
        """
        A field section is limited to the maximum field section size once
        decoded, which is advertised in SETTINGS_MAX_FIELD_SECTION_SIZE, see
        RFC 9114 section 4.2.2. A larger one closes the connection.
        """
        request = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/"),
        ]
        response = [(b":status", b"200")]

        def field_section(headers: Headers, size: int) -> Headers:
            # Pad the headers with a field to reach `size` bytes once decoded.
            used = sum(len(name) + len(value) + 32 for name, value in headers)
            return headers + [(b"x-big", b"a" * (size - used - len(b"x-big") - 32))]

        for is_client, size, expected_closed in [
            (False, MAX_FIELD_SECTION_SIZE, None),
            (
                False,
                MAX_FIELD_SECTION_SIZE + 1,
                (ErrorCode.H3_EXCESSIVE_LOAD, "Field section is too large"),
            ),
            (True, MAX_FIELD_SECTION_SIZE, None),
            (
                True,
                MAX_FIELD_SECTION_SIZE + 1,
                (ErrorCode.H3_EXCESSIVE_LOAD, "Field section is too large"),
            ),
        ]:
            with (
                self.subTest(is_client=is_client, size=size),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)
                h3_server = H3Connection(quic_server)
                h3_receiver, h3_sender = (
                    (h3_client, h3_server) if is_client else (h3_server, h3_client)
                )

                # The peer advertises its limit.
                h3_transfer(quic_client, h3_server)
                h3_transfer(quic_server, h3_client)
                assert h3_receiver.received_settings is not None
                self.assertEqual(
                    h3_receiver.received_settings[Setting.MAX_FIELD_SECTION_SIZE],
                    MAX_FIELD_SECTION_SIZE,
                )

                stream_id = quic_client.get_next_available_stream_id()
                if is_client:
                    h3_client.send_headers(stream_id, request)
                    h3_transfer(quic_client, h3_server)
                    headers = field_section(response, size)
                else:
                    headers = field_section(request, size)
                h3_sender.send_headers(stream_id, headers, end_stream=True)

                # The field section takes several round trips.
                for _ in range(20):
                    events = h3_transfer(h3_sender._quic, h3_receiver)
                    if events or closed(h3_receiver._quic) is not None:
                        break
                    transfer(h3_receiver._quic, h3_sender._quic)

                # A refused field section never reaches the application.
                if expected_closed is None:
                    self.assertEqual(
                        events,
                        [
                            HeadersReceived(
                                headers=headers, stream_id=stream_id, stream_ended=True
                            )
                        ],
                    )
                else:
                    self.assertEqual(events, [])
                self.assertEqual(closed(h3_receiver._quic), expected_closed)

    def test_request_fragmented_frame(self) -> None:
        """
        Frames and stream headers received one byte at a time are reassembled,
        and the payload of DATA frames is passed on as each byte arrives.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # send request
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                    (b"x-foo", b"client"),
                ],
            )
            h3_client.send_data(stream_id=stream_id, data=b"hello", end_stream=True)

            # receive request
            events = h3_transfer(quic_client, h3_server, split=True)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/"),
                            (b"x-foo", b"client"),
                        ],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    DataReceived(data=b"h", stream_id=0, stream_ended=False),
                    DataReceived(data=b"e", stream_id=0, stream_ended=False),
                    DataReceived(data=b"l", stream_id=0, stream_ended=False),
                    DataReceived(data=b"l", stream_id=0, stream_ended=False),
                    DataReceived(data=b"o", stream_id=0, stream_ended=False),
                    DataReceived(data=b"", stream_id=0, stream_ended=True),
                ],
            )

            # send response
            h3_server.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"text/html; charset=utf-8"),
                ],
                end_stream=False,
            )
            h3_server.send_data(stream_id=stream_id, data=b"html", end_stream=True)

            # receive response
            events = h3_transfer(quic_server, h3_client, split=True)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[
                            (b":status", b"200"),
                            (b"content-type", b"text/html; charset=utf-8"),
                        ],
                        stream_id=0,
                        stream_ended=False,
                    ),
                    DataReceived(data=b"h", stream_id=0, stream_ended=False),
                    DataReceived(data=b"t", stream_id=0, stream_ended=False),
                    DataReceived(data=b"m", stream_id=0, stream_ended=False),
                    DataReceived(data=b"l", stream_id=0, stream_ended=False),
                    DataReceived(data=b"", stream_id=0, stream_ended=True),
                ],
            )

    def test_send_after_quic_reset(self) -> None:
        """
        Once the application resets a stream through QUIC, H3 reports that it
        can no longer send on it, and the failed attempts change no state.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            stream_id = self._send_request_headers(h3_client, h3_server)

            quic_client.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)

            # Neither the trailers nor the data count as sent.
            for _ in range(2):
                with self.assertRaisesMessage(
                    InvalidStreamStateError,
                    "Cannot send after the stream was reset",
                ):
                    h3_client.send_headers(
                        stream_id=stream_id,
                        headers=[(b"x-foo", b"bar")],
                        end_stream=True,
                    )
                with self.assertRaisesMessage(
                    InvalidStreamStateError,
                    "Cannot send after the stream was reset",
                ):
                    h3_client.send_data(
                        stream_id=stream_id, data=b"hello", end_stream=True
                    )
            stream = h3_client._stream[stream_id]
            self.assertEqual(stream.headers_send_state, HeadersState.AFTER_HEADERS)
            self.assertFalse(stream.sending_ended)

    def test_send_after_stop_sending(self) -> None:
        """
        We should not send on a stream once the peer asked us to stop sending,
        while the request body is still being received.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            stream_id = self._send_request_headers(h3_client, h3_server)

            # The client asks the server to stop sending.
            quic_client.stop_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertIn(stream_id, h3_server._stream)

            # The server can no longer send headers or data.
            with self.assertRaisesMessage(
                InvalidStreamStateError, "Cannot send after the stream was ended"
            ):
                h3_server.send_headers(
                    stream_id=stream_id, headers=[(b":status", b"200")]
                )
            with self.assertRaisesMessage(
                InvalidStreamStateError, "Cannot send after the stream was ended"
            ):
                h3_server.send_data(stream_id=stream_id, data=b"hello", end_stream=True)

    def test_send_data_after_trailers(self) -> None:
        """
        We should not send DATA after trailers.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
            )
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[(b"x-some-trailer", b"foo")],
                end_stream=False,
            )
            with self.assertRaisesMessage(
                InvalidStreamStateError, "Cannot send data after the trailers"
            ):
                h3_client.send_data(
                    stream_id=stream_id, data=b"hello", end_stream=False
                )

    def test_send_data_before_headers(self) -> None:
        """
        We should not send DATA before headers.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            stream_id = quic_client.get_next_available_stream_id()
            with self.assertRaisesMessage(
                InvalidStreamStateError, "Cannot send data before the headers"
            ):
                h3_client.send_data(
                    stream_id=stream_id, data=b"hello", end_stream=False
                )
            self.assertNotIn(stream_id, h3_client._stream)

    def test_send_headers_after_trailers(self) -> None:
        """
        We should not send HEADERS after trailers.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
            )
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[(b"x-some-trailer", b"foo")],
                end_stream=False,
            )
            with self.assertRaisesMessage(
                InvalidStreamStateError, "Cannot send headers after the trailers"
            ):
                h3_client.send_headers(
                    stream_id=stream_id,
                    headers=[(b"x-other-trailer", b"foo")],
                    end_stream=False,
                )

    def test_send_headers_encoder_stream_stopped(self) -> None:
        """
        Once the peer stops our QPACK encoder stream, which it must not do (RFC
        9204 section 4.2), headers cannot be sent, whether or not the H3 layer
        has handled the STOP_SENDING yet.
        """
        for handled in (False, True):
            with (
                self.subTest(handled=handled),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)
                h3_server = H3Connection(quic_server)
                h3_transfer(quic_server, h3_client)
                stream_id = self._send_request_headers(h3_client, h3_server)

                quic_client.stop_stream(
                    h3_server._local_encoder_stream_id, ErrorCode.H3_NO_ERROR
                )
                if handled:
                    h3_transfer(quic_client, h3_server)
                    self.assertEqual(
                        closed(quic_server),
                        (
                            ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                            "Stopping a critical stream is not allowed",
                        ),
                    )
                else:
                    transfer(quic_client, quic_server)

                with self.assertRaisesMessage(
                    H3Error,
                    "Cannot send headers once the QPACK encoder stream was stopped",
                ):
                    h3_server.send_headers(
                        stream_id=stream_id, headers=[(b":status", b"200")]
                    )
                self.assertEqual(
                    h3_server._stream[stream_id].headers_send_state,
                    HeadersState.INITIAL,
                )

    def test_send_headers_interim_end_stream(self) -> None:
        """
        We should not end the stream with an interim response.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            stream_id = self._send_request_headers(h3_client, h3_server)

            with self.assertRaisesMessage(
                InvalidStreamStateError,
                "Cannot end the stream with an interim response",
            ):
                h3_server.send_headers(
                    stream_id=stream_id,
                    headers=[(b":status", b"103")],
                    end_stream=True,
                )

            # The final response can still be sent.
            h3_server.send_headers(
                stream_id=stream_id, headers=[(b":status", b"200")], end_stream=True
            )

    def test_send_headers_on_finished_stream(self) -> None:
        """
        A client cannot send headers again on a request stream which has ended
        on both sides, and the failed attempt leaves no state behind.
        """
        # QUIC refuses the data either after the FIN or, once the stream is
        # acknowledged, because it was discarded.
        for round_trips, quic_message in [
            (0, "Cannot send data after FIN"),
            (1, "Cannot send data on a finished stream"),
        ]:
            with (
                self.subTest(round_trips=round_trips),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)
                h3_server = H3Connection(quic_server)

                # The request and the response both end the stream.
                stream_id = quic_client.get_next_available_stream_id()
                request = [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ]
                h3_client.send_headers(
                    stream_id=stream_id, headers=request, end_stream=True
                )
                h3_transfer(quic_client, h3_server)
                h3_server.send_headers(
                    stream_id=stream_id,
                    headers=[(b":status", b"200")],
                    end_stream=True,
                )
                h3_transfer(quic_server, h3_client)
                self.assertNotIn(stream_id, h3_client._stream)

                for _ in range(round_trips):
                    h3_transfer(quic_client, h3_server)
                    h3_transfer(quic_server, h3_client)

                with self.assertRaisesMessage(
                    InvalidStreamStateError, "Cannot send after the stream was ended"
                ) as cm:
                    h3_client.send_headers(stream_id=stream_id, headers=request)
                self.assertEqual(str(cm.exception.__cause__), quic_message)
                self.assertNotIn(stream_id, h3_client._stream)

    def test_send_headers_on_unopened_stream(self) -> None:
        """
        A server cannot respond on a request stream the client has not opened,
        and the failed attempt leaves no state behind.
        """
        for end_stream in (False, True):
            with (
                self.subTest(end_stream=end_stream),
                h3_client_and_server() as (quic_client, quic_server),
            ):
                h3_client = H3Connection(quic_client)
                h3_server = H3Connection(quic_server)

                stream_id = quic_client.get_next_available_stream_id()
                with self.assertRaisesMessage(
                    InvalidStreamStateError,
                    "Cannot send on a stream the peer has not opened",
                ):
                    h3_server.send_headers(
                        stream_id=stream_id,
                        headers=[(b":status", b"200")],
                        end_stream=end_stream,
                    )
                self.assertNotIn(stream_id, h3_server._stream)

                # Once the client opens the stream, the server responds normally.
                self._send_request_headers(h3_client, h3_server)
                h3_server.send_headers(
                    stream_id=stream_id, headers=[(b":status", b"200")]
                )
                h3_server.send_data(stream_id=stream_id, data=b"hello", end_stream=True)
                self.assertEqual(
                    h3_transfer(quic_server, h3_client),
                    [
                        HeadersReceived(
                            headers=[(b":status", b"200")],
                            stream_id=stream_id,
                            stream_ended=False,
                        ),
                        DataReceived(
                            data=b"hello", stream_id=stream_id, stream_ended=True
                        ),
                    ],
                )

    def test_send_on_critical_stream(self) -> None:
        """
        We should not send HTTP messages on our control or QPACK streams, which
        would make the peer close the connection.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            h3_transfer(quic_server, h3_client)

            for stream_id in (
                h3_server._local_control_stream_id,
                h3_server._local_decoder_stream_id,
                h3_server._local_encoder_stream_id,
            ):
                assert stream_id is not None
                with self.subTest(stream_id=stream_id):
                    with self.assertRaisesMessage(
                        InvalidStreamTypeError,
                        "Headers and data can only be sent on request streams",
                    ):
                        h3_server.send_headers(
                            stream_id=stream_id, headers=[(b":status", b"200")]
                        )
                    with self.assertRaisesMessage(
                        InvalidStreamTypeError,
                        "Headers and data can only be sent on request streams",
                    ):
                        h3_server.send_data(
                            stream_id=stream_id, data=b"hello", end_stream=True
                        )
                    self.assertNotIn(stream_id, h3_server._stream)

            # Nothing was sent, so the client keeps the connection open.
            self.assertEqual(h3_transfer(quic_server, h3_client), [])
            self.assertIsNone(closed(quic_client))

    def test_send_on_non_request_stream(self) -> None:
        """
        We should only send HTTP messages on request streams, not on a client's
        unidirectional streams nor on a server's bidirectional streams.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            h3_transfer(quic_client, h3_server)
            h3_transfer(quic_server, h3_client)

            for h3, stream_id in (
                (h3_client, quic_client.get_next_available_stream_id(True)),
                (h3_server, quic_server.get_next_available_stream_id()),
            ):
                with self.subTest(stream_id=stream_id):
                    with self.assertRaisesMessage(
                        InvalidStreamTypeError,
                        "Headers and data can only be sent on request streams",
                    ):
                        h3.send_headers(
                            stream_id=stream_id, headers=[(b"x-foo", b"bar")]
                        )
                    with self.assertRaisesMessage(
                        InvalidStreamTypeError,
                        "Headers and data can only be sent on request streams",
                    ):
                        h3.send_data(
                            stream_id=stream_id, data=b"hello", end_stream=True
                        )
                    self.assertNotIn(stream_id, h3._stream)

            # Nothing was sent, so neither side closes the connection.
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertEqual(h3_transfer(quic_server, h3_client), [])
            self.assertIsNone(closed(quic_client))
            self.assertIsNone(closed(quic_server))

    def test_send_on_out_of_range_stream(self) -> None:
        """
        Stream IDs outside 0 to 2^62 - 1 are refused (RFC 9000 section 2.1),
        before any state is created for them.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            for stream_id in (-4, UINT_VAR_MAX + 1):
                with self.subTest(stream_id=stream_id):
                    with self.assertRaisesMessage(
                        InvalidStreamIdError, "Stream ID must be between 0 and 2^62 - 1"
                    ):
                        h3_client.send_headers(
                            stream_id=stream_id,
                            headers=[
                                (b":method", b"GET"),
                                (b":scheme", b"https"),
                                (b":authority", b"localhost"),
                                (b":path", b"/"),
                            ],
                        )
                    with self.assertRaisesMessage(
                        InvalidStreamIdError, "Stream ID must be between 0 and 2^62 - 1"
                    ):
                        h3_client.send_data(
                            stream_id=stream_id, data=b"hello", end_stream=True
                        )
                    self.assertNotIn(stream_id, h3_client._stream)

            # Nothing was sent, so the server keeps the connection open.
            h3_transfer(quic_client, h3_server)
            self.assertIsNone(closed(quic_server))

    def test_send_on_peer_unidirectional_stream(self) -> None:
        """
        We should not send on the peer's unidirectional streams, whether or not
        they have state, nor create state for them.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            h3_transfer(quic_client, h3_server)

            # The client's control stream has state, the other stream does not.
            control_stream_id = 2
            unknown_stream_id = 14
            self.assertIn(control_stream_id, h3_server._stream)
            self.assertNotIn(unknown_stream_id, h3_server._stream)

            for stream_id in (control_stream_id, unknown_stream_id):
                with self.subTest(stream_id=stream_id):
                    with self.assertRaisesMessage(
                        InvalidStreamTypeError,
                        "Cannot send on the peer's unidirectional streams",
                    ):
                        h3_server.send_headers(
                            stream_id=stream_id, headers=[(b":status", b"200")]
                        )
                    with self.assertRaisesMessage(
                        InvalidStreamTypeError,
                        "Cannot send on the peer's unidirectional streams",
                    ):
                        h3_server.send_data(
                            stream_id=stream_id, data=b"hello", end_stream=True
                        )
            self.assertNotIn(unknown_stream_id, h3_server._stream)

    def test_send_push_promise(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)
            with (
                self.assertWarns(DeprecationWarning) as cm,
                self.assertRaises(NoAvailablePushIDError),
            ):
                h3_server.send_push_promise(stream_id=0, headers=[])
            self.assertEqual(
                str(cm.warning),
                "send_push_promise() is deprecated and will be removed, as server "
                "push is no longer supported",
            )
            self.assertEqual(cm.filename, __file__)

    def test_dynamic_table_reference_refused(self) -> None:
        """
        We advertise no dynamic table and that no stream may be blocked, so a
        header block which references dynamic table entries is a connection
        error, see RFC 9204 sections 2.1.2 and 4.5.1.1.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            h3_transfer(quic_client, h3_server)
            assert h3_server.received_settings is not None
            self.assertEqual(
                h3_server.received_settings[Setting.QPACK_MAX_TABLE_CAPACITY], 0
            )
            self.assertEqual(
                h3_server.received_settings[Setting.QPACK_BLOCKED_STREAMS], 0
            )

            # A Required Insert Count which is not zero, then a reference to a
            # dynamic table entry.
            stream_id = quic_client.get_next_available_stream_id()
            quic_client.send_stream_data(
                stream_id,
                encode_frame(FrameType.HEADERS, b"\x02\x00\x80"),
                end_stream=True,
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertEqual(
                closed(quic_server), (ErrorCode.QPACK_DECOMPRESSION_FAILED, "")
            )

    def test_uni_stream_grease(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            quic_client.send_stream_data(
                14,
                b"\xff\xff\xff\xff\xff\xff\xff\xfeGREASE is the word",
                end_stream=True,
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])

            # the stream is no longer tracked
            self.assertNotIn(14, h3_server._stream)

    def test_uni_stream_reset(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            for _ in range(10):
                # Open a stream of a reserved type, then reset it.
                stream_id = quic_client.get_next_available_stream_id(
                    is_unidirectional=True
                )
                quic_client.send_stream_data(stream_id, b"\x21")
                self.assertEqual(h3_transfer(quic_client, h3_server), [])
                self.assertIn(stream_id, h3_server._stream)

                quic_client.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
                self.assertEqual(h3_transfer(quic_client, h3_server), [])
                self.assertNotIn(stream_id, h3_server._stream)

            # No Stream Cancellation is sent for unidirectional streams.
            transfer(quic_server, quic_client)
            self.assertEqual(qpack_decoder_bytes_sent(quic_server), 0)

    def test_request_with_interim_responses(self) -> None:
        """
        A server can send interim responses before the final response, see
        RFC 9114 section 4.1.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # Send the request.
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
                end_stream=True,
            )
            h3_transfer(quic_client, h3_server)

            # Send interim responses, then the response.
            h3_server.send_headers(stream_id=stream_id, headers=[(b":status", b"100")])
            h3_server.send_headers(
                stream_id=stream_id,
                headers=[(b":status", b"103"), (b"link", b"</style.css>; rel=preload")],
            )
            h3_server.send_headers(stream_id=stream_id, headers=[(b":status", b"200")])
            h3_server.send_data(stream_id=stream_id, data=b"hello", end_stream=True)

            # Receive interim responses, then the response.
            events = h3_transfer(quic_server, h3_client)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[(b":status", b"100")],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    HeadersReceived(
                        headers=[
                            (b":status", b"103"),
                            (b"link", b"</style.css>; rel=preload"),
                        ],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    HeadersReceived(
                        headers=[(b":status", b"200")],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    DataReceived(
                        data=b"hello",
                        stream_id=stream_id,
                        stream_ended=True,
                    ),
                ],
            )

    def test_request_with_trailers(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # send request with trailers
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
                end_stream=False,
            )
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[(b"x-some-trailer", b"foo")],
                end_stream=True,
            )

            # receive request
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/"),
                        ],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    HeadersReceived(
                        headers=[(b"x-some-trailer", b"foo")],
                        stream_id=stream_id,
                        stream_ended=True,
                    ),
                ],
            )

            # send response
            h3_server.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"text/html; charset=utf-8"),
                ],
                end_stream=False,
            )
            h3_server.send_data(
                stream_id=stream_id,
                data=b"<html><body>hello</body></html>",
                end_stream=False,
            )
            h3_server.send_headers(
                stream_id=stream_id,
                headers=[(b"x-some-trailer", b"bar")],
                end_stream=True,
            )

            # receive response
            events = h3_transfer(quic_server, h3_client)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[
                            (b":status", b"200"),
                            (b"content-type", b"text/html; charset=utf-8"),
                        ],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    DataReceived(
                        data=b"<html><body>hello</body></html>",
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    HeadersReceived(
                        headers=[(b"x-some-trailer", b"bar")],
                        stream_id=stream_id,
                        stream_ended=True,
                    ),
                ],
            )

    def test_uni_stream_type(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # unknown stream type 9
            stream_id = quic_client.get_next_available_stream_id(is_unidirectional=True)
            self.assertEqual(stream_id, 2)
            quic_client.send_stream_data(stream_id, b"\x09")
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertEqual(list(h3_server._stream.keys()), [2])
            self.assertEqual(h3_server._stream[2].buffer, b"")
            self.assertEqual(h3_server._stream[2].stream_type, 9)

            # unknown stream type 64, one byte at a time
            stream_id = quic_client.get_next_available_stream_id(is_unidirectional=True)
            self.assertEqual(stream_id, 6)

            quic_client.send_stream_data(stream_id, b"\x40")
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertEqual(list(h3_server._stream.keys()), [2, 6])
            self.assertEqual(h3_server._stream[2].buffer, b"")
            self.assertEqual(h3_server._stream[2].stream_type, 9)
            self.assertEqual(h3_server._stream[6].buffer, b"\x40")
            self.assertEqual(h3_server._stream[6].stream_type, None)

            quic_client.send_stream_data(stream_id, b"\x40")
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertEqual(list(h3_server._stream.keys()), [2, 6])
            self.assertEqual(h3_server._stream[2].buffer, b"")
            self.assertEqual(h3_server._stream[2].stream_type, 9)
            self.assertEqual(h3_server._stream[6].buffer, b"")
            self.assertEqual(h3_server._stream[6].stream_type, 64)

            # unknown stream types are logged by value
            logger = quic_server.configuration.quic_logger
            assert logger is not None
            self.assertEqual(
                [
                    event["data"]
                    for event in logger.to_dict()["traces"][0]["events"]
                    if event["name"] == "http3:stream_type_set"
                ],
                [
                    {"initiator": "local", "stream_id": 3, "stream_type": "control"},
                    {
                        "initiator": "local",
                        "stream_id": 7,
                        "stream_type": "qpack_encode",
                    },
                    {
                        "initiator": "local",
                        "stream_id": 11,
                        "stream_type": "qpack_decode",
                    },
                    {
                        "initiator": "remote",
                        "stream_id": 2,
                        "stream_type": "unknown",
                        "stream_type_bytes": 9,
                    },
                    {
                        "initiator": "remote",
                        "stream_id": 6,
                        "stream_type": "unknown",
                        "stream_type_bytes": 64,
                    },
                ],
            )

    def test_validate_settings_h3_datagram_invalid_value(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive SETTINGS with an invalid H3_DATAGRAM value
            settings = copy.copy(DUMMY_SETTINGS)
            settings[Setting.H3_DATAGRAM] = 2
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(settings)),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_SETTINGS_ERROR,
                    "H3_DATAGRAM setting must be 0 or 1",
                ),
            )

    def test_validate_settings_enable_connect_protocol_invalid_value(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive SETTINGS with an invalid ENABLE_CONNECT_PROTOCOL value
            settings = copy.copy(DUMMY_SETTINGS)
            settings[Setting.ENABLE_CONNECT_PROTOCOL] = 2
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(settings)),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_SETTINGS_ERROR,
                    "ENABLE_CONNECT_PROTOCOL setting must be 0 or 1",
                ),
            )

    def test_validate_settings_enable_webtransport_invalid_value(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive SETTINGS with an invalid ENABLE_WEBTRANSPORT value
            settings = copy.copy(DUMMY_SETTINGS)
            settings[Setting.ENABLE_WEBTRANSPORT] = 2
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(settings)),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_SETTINGS_ERROR,
                    "ENABLE_WEBTRANSPORT setting must be 0 or 1",
                ),
            )

    def test_validate_settings_enable_webtransport_without_h3_datagram(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive SETTINGS requesting WebTransport, but DATAGRAM was not offered
            settings = copy.copy(DUMMY_SETTINGS)
            settings[Setting.ENABLE_WEBTRANSPORT] = 1
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=2,
                    data=encode_uint_var(StreamType.CONTROL)
                    + encode_frame(FrameType.SETTINGS, encode_settings(settings)),
                    end_stream=False,
                )
            )
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_SETTINGS_ERROR,
                    "ENABLE_WEBTRANSPORT requires H3_DATAGRAM",
                ),
            )

    def _content_length_template(
        self,
        content_length: bytes | None,
        data: bytes,
        end_at: str,
        expected_closed: tuple[int, str] | None,
    ) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            end_stream = False

            stream_id = quic_client.get_next_available_stream_id()
            if end_at == "headers":
                end_stream = True
            # Headers
            headers = [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ]
            if content_length is not None:
                headers.append((b"content-length", content_length))
            h3_client.send_headers(
                stream_id=stream_id,
                headers=headers,
                end_stream=end_stream,
            )
            if not end_stream:
                # Data
                if end_at == "data":
                    end_stream = True
                h3_client.send_data(
                    stream_id=stream_id, data=data, end_stream=end_stream
                )
            if not end_stream:
                # Trailers
                assert end_at == "trailers"
                h3_client.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b"x-foo", b"hi"),
                    ],
                    end_stream=True,
                )
            # Deliver the request byte by byte, so that data is still received
            # after an invalid content-length closed the connection.
            h3_transfer(quic_client, h3_server, split=True)
            self.assertEqual(closed(quic_server), expected_closed)

    def test_content_length_not_specified_is_ok(self) -> None:
        """
        If a content-length is specified and OK, all is good.
        """
        self._content_length_template(None, b"hello world", "data", None)

    def test_content_length_is_ok(self) -> None:
        """
        If a content-length is specified and OK, all is good.
        """
        self._content_length_template(b"11", b"hello world", "data", None)

    def test_content_length_that_is_not_an_int_rejected(self) -> None:
        """
        A content-length that doesn't parse as an integer is bad.
        """
        self._content_length_template(
            b"1bogus1",
            b"hello world",
            "data",
            (
                ErrorCode(ErrorCode.H3_MESSAGE_ERROR),
                "content-length is not a non-negative integer",
            ),
        )

    def test_content_length_that_is_negative_is_rejected(self) -> None:
        """
        A content-length that doesn't parse as an integer is bad.
        """
        self._content_length_template(
            b"-1",
            b"hello world",
            "data",
            (
                ErrorCode(ErrorCode.H3_MESSAGE_ERROR),
                "content-length is not a non-negative integer",
            ),
        )

    def test_content_length_does_not_match_data_length(self) -> None:
        """
        If a content-length is specified and wrong when data ends the stream,
        we must close.
        """
        self._content_length_template(
            b"20",
            b"hello world",
            "data",
            (
                ErrorCode(ErrorCode.H3_MESSAGE_ERROR),
                "content-length does not match data size",
            ),
        )

    def test_content_length_does_not_match_when_headers_end_stream(self) -> None:
        """
        If a content-length is specified and wrong, we must reject it.
        """
        self._content_length_template(
            b"20",
            b"",
            "headers",
            (
                ErrorCode(ErrorCode.H3_MESSAGE_ERROR),
                "content-length does not match data size",
            ),
        )

    def test_content_length_does_not_match_when_trailers_end_stream(self) -> None:
        """
        If a content-length is specified and wrong, we must reject it.
        """
        self._content_length_template(
            b"20",
            b"hello world",
            "trailers",
            (
                ErrorCode(ErrorCode.H3_MESSAGE_ERROR),
                "content-length does not match data size",
            ),
        )

    def test_streams_are_closed_after_requests(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            for _ in range(6):
                self._make_request(h3_client, h3_server)

            # Only 3 streams should be opened: Control, QPACK encoder and QPACK decoder
            self.assertEqual(len(h3_client._stream), 3)
            self.assertEqual(len(h3_server._stream), 3)

    def test_streams_are_closed_after_end_without_headers(self) -> None:
        """
        A request stream which ends before its HEADERS frame is received is
        aborted with H3_REQUEST_INCOMPLETE, see RFC 9114 section 4.1.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # The client ends a request stream without sending HEADERS.
            stream_id = quic_client.get_next_available_stream_id()
            quic_client.send_stream_data(stream_id, b"", end_stream=True)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertNotIn(stream_id, h3_server._stream)

            # The server aborts its response, which closes the QUIC stream.
            transfer(quic_server, quic_client)
            self.assertIn(
                StreamReset(
                    error_code=ErrorCode.H3_REQUEST_INCOMPLETE, stream_id=stream_id
                ),
                drain_events(quic_client),
            )
            transfer(quic_client, quic_server)
            self.assertEqual(transfer(quic_server, quic_client), 0)
            self.assertNotIn(stream_id, quic_server._streams)

            # The client ends a request stream after an unknown frame.
            stream_id = quic_client.get_next_available_stream_id()
            quic_client.send_stream_data(
                stream_id, encode_frame(0x21, b"grease"), end_stream=True
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertNotIn(stream_id, h3_server._stream)

            # The server aborts its response, which closes the QUIC stream.
            transfer(quic_server, quic_client)
            self.assertIn(
                StreamReset(
                    error_code=ErrorCode.H3_REQUEST_INCOMPLETE, stream_id=stream_id
                ),
                drain_events(quic_client),
            )
            transfer(quic_client, quic_server)
            self.assertEqual(transfer(quic_server, quic_client), 0)
            self.assertNotIn(stream_id, quic_server._streams)

    def test_streams_are_closed_after_reset(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            stream_id = self._send_request_headers(h3_client, h3_server)

            # The client resets the request.
            quic_client.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])

            # No Stream Cancellation is sent, as there is no dynamic table (RFC
            # 9204 section 4.4.2).
            transfer(quic_server, quic_client)
            self.assertEqual(qpack_decoder_bytes_sent(quic_server), 0)

            # The stream is kept until the server finishes sending.
            self.assertIn(stream_id, h3_server._stream)
            h3_server.send_headers(
                stream_id=stream_id, headers=[(b":status", b"200")], end_stream=True
            )
            self.assertNotIn(stream_id, h3_server._stream)

    def test_streams_are_closed_after_reset_and_stop_sending(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            stream_id = self._send_request_headers(h3_client, h3_server)

            # The client resets the request and asks the server to stop sending.
            quic_client.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            quic_client.stop_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertNotIn(stream_id, h3_server._stream)

    def test_streams_are_closed_after_reset_before_headers(self) -> None:
        """
        A request stream which is reset before its HEADERS frame is received is
        aborted with H3_REQUEST_INCOMPLETE, see RFC 9114 section 4.1.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # The client opens a request stream, then resets it.
            stream_id = quic_client.get_next_available_stream_id()
            quic_client.send_stream_data(stream_id, b"")
            quic_client.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertNotIn(stream_id, h3_server._stream)

            # The server aborts its response, which closes the QUIC stream.
            transfer(quic_server, quic_client)
            self.assertIn(
                StreamReset(
                    error_code=ErrorCode.H3_REQUEST_INCOMPLETE, stream_id=stream_id
                ),
                drain_events(quic_client),
            )
            transfer(quic_client, quic_server)
            self.assertEqual(transfer(quic_server, quic_client), 0)
            self.assertNotIn(stream_id, quic_server._streams)

    def test_streams_are_closed_after_reset_during_headers(self) -> None:
        """
        A request stream which is reset while its HEADERS frame is only partly
        received is aborted with H3_REQUEST_INCOMPLETE, see RFC 9114 section 4.1.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # The client sends the start of a HEADERS frame, then resets the stream.
            stream_id = quic_client.get_next_available_stream_id()
            quic_client.send_stream_data(
                stream_id, encode_uint_var(FrameType.HEADERS) + encode_uint_var(10)
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertIn(stream_id, h3_server._stream)
            quic_client.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertNotIn(stream_id, h3_server._stream)

            # The server aborts its response, which closes the QUIC stream.
            transfer(quic_server, quic_client)
            self.assertIn(
                StreamReset(
                    error_code=ErrorCode.H3_REQUEST_INCOMPLETE, stream_id=stream_id
                ),
                drain_events(quic_client),
            )
            transfer(quic_client, quic_server)
            self.assertEqual(transfer(quic_server, quic_client), 0)
            self.assertNotIn(stream_id, quic_server._streams)

    def test_streams_are_closed_after_stop_sending(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            stream_id = self._send_request_headers(h3_client, h3_server)

            # The client finishes the request.
            h3_client.send_data(stream_id=stream_id, data=b"", end_stream=True)
            h3_transfer(quic_client, h3_server)
            self.assertIn(stream_id, h3_server._stream)

            # The client asks the server to stop sending the response.
            quic_client.stop_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertNotIn(stream_id, h3_server._stream)

    def test_streams_are_not_closed_prematurely(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # No streams opened
            self.assertEqual(len(h3_client._stream), 0)
            self.assertEqual(len(h3_server._stream), 0)

            # Send request
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                    (b"x-foo", b"client"),
                ],
            )

            # The request stream was opened
            self.assertEqual(len(h3_client._stream), 1)

            h3_client.send_data(stream_id=stream_id, data=b"p1ng", end_stream=False)
            # Still the same stream
            self.assertEqual(len(h3_client._stream), 1)

            h3_client.send_data(stream_id=stream_id, data=b"", end_stream=True)
            # Still the same stream because server didn't end the stream yet
            self.assertEqual(len(h3_client._stream), 1)

            h3_transfer(h3_client._quic, h3_server)

            self.assertEqual(len(h3_client._stream), 1)
            # Server has 4 streams: Control, QPACK encoder, QPACK decoder and
            # the request stream
            self.assertEqual(len(h3_server._stream), 4)

            h3_server.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"x-foo", b"server"),
                ],
            )
            h3_transfer(h3_server._quic, h3_client)
            h3_transfer(h3_client._quic, h3_server)

            # Now both have 4 streams still open
            self.assertEqual(len(h3_server._stream), 4)
            self.assertEqual(len(h3_client._stream), 4)

            h3_server.send_data(
                stream_id=stream_id,
                data=b"p0ng",
                end_stream=False,
            )
            h3_transfer(h3_server._quic, h3_client)
            h3_transfer(h3_client._quic, h3_server)

            # All streams are still open
            self.assertEqual(len(h3_server._stream), 4)
            self.assertEqual(len(h3_client._stream), 4)

            h3_server.send_data(
                stream_id=stream_id,
                data=b"",
                end_stream=True,
            )
            h3_transfer(h3_server._quic, h3_client)
            h3_transfer(h3_client._quic, h3_server)
            # Request streams are closed. The Control and QPACK remain open to
            # the end of connection
            self.assertEqual(len(h3_client._stream), 3)
            self.assertEqual(len(h3_server._stream), 3)

    def test_double_sending_stream_closing(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                    (b"x-foo", b"client"),
                ],
                end_stream=True,
            )

            # Nothing can be sent once the stream was ended, whether or not the send
            # would end it again.
            for end_stream in (False, True):
                with self.assertRaisesMessage(
                    InvalidStreamStateError, "Cannot send after the stream was ended"
                ):
                    h3_client.send_data(stream_id, b"data", end_stream=end_stream)
                with self.assertRaisesMessage(
                    InvalidStreamStateError, "Cannot send after the stream was ended"
                ):
                    h3_client.send_headers(
                        stream_id, [(b"x-trailer", b"late")], end_stream=end_stream
                    )

            # The refused headers did not count as trailers.
            self.assertEqual(
                h3_client._stream[stream_id].headers_send_state,
                HeadersState.AFTER_HEADERS,
            )


class H3ParserTest(TestCase):
    def test_is_interim_response(self) -> None:
        self.assertTrue(is_interim_response([(b":status", b"100")]))
        self.assertTrue(is_interim_response([(b":status", b"103"), (b"link", b"")]))
        self.assertFalse(is_interim_response([(b":status", b"200")]))

        # Headers without a status, such as trailers, are not a response.
        self.assertFalse(is_interim_response([(b"x-foo", b"bar")]))

    def test_parse_settings_duplicate_identifier(self) -> None:
        buf = Buffer(capacity=1024)
        buf.push_uint_var(1)
        buf.push_uint_var(123)
        buf.push_uint_var(1)
        buf.push_uint_var(456)

        with self.assertRaises(SettingsError) as cm:
            parse_settings(buf.data)
        self.assertEqual(
            cm.exception.reason_phrase, "Setting identifier 0x1 is included twice"
        )

    def test_parse_settings_reserved_identifier(self) -> None:
        buf = Buffer(capacity=1024)
        buf.push_uint_var(0)
        buf.push_uint_var(123)

        with self.assertRaises(SettingsError) as cm:
            parse_settings(buf.data)
        self.assertEqual(
            cm.exception.reason_phrase, "Setting identifier 0x0 is reserved"
        )

    def test_validate_request_headers(self) -> None:
        # OK
        validate_request_headers(
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":authority", b"localhost"),
            ]
        )
        validate_request_headers(
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":authority", b"localhost"),
                (b"x-foo", b"bar"),
            ]
        )

        # uppercase header
        with self.assertRaises(MessageError) as cm:
            validate_request_headers([(b"X-Foo", b"foo")])
        self.assertEqual(
            cm.exception.reason_phrase, "Header b'X-Foo' contains invalid characters"
        )

        # header with too small a value
        with self.assertRaises(MessageError) as cm:
            validate_request_headers([(b"x-\x00foo", b"foo")])
        self.assertEqual(
            cm.exception.reason_phrase,
            "Header b'x-\\x00foo' contains invalid characters",
        )

        # header with too big a value
        with self.assertRaises(MessageError) as cm:
            validate_request_headers([(b"x-\x7ffoo", b"foo")])
        self.assertEqual(
            cm.exception.reason_phrase,
            "Header b'x-\\x7ffoo' contains invalid characters",
        )

        # header with non-initial colon
        with self.assertRaises(MessageError) as cm:
            validate_request_headers([(b"x-f:oo", b"foo")])
        self.assertEqual(
            cm.exception.reason_phrase, "Header b'x-f:oo' contains a non-initial colon"
        )

        # TE is allowed in a request, but only as trailers.
        for value in (b"trailers", b"Trailers"):
            with self.subTest(value=value):
                validate_request_headers(
                    [
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":path", b"/"),
                        (b":authority", b"localhost"),
                        (b"te", value),
                    ]
                )
        with self.assertRaises(MessageError) as cm:
            validate_request_headers([(b"te", b"bogus")])
        self.assertEqual(
            cm.exception.reason_phrase, "Header b'te' value is not trailers"
        )

        # Other connection-specific fields are forbidden.
        for name in (
            b"connection",
            b"keep-alive",
            b"proxy-connection",
            b"transfer-encoding",
            b"upgrade",
        ):
            with self.subTest(header=name):
                with self.assertRaises(MessageError) as cm:
                    validate_request_headers([(name, b"trailers")])
                self.assertEqual(
                    cm.exception.reason_phrase,
                    f"Header {name!r} is connection-specific",
                )

        # value with a forbidden NUL, LF, or CR:
        for prefix in [b"\x00", b"\x0a", b"\x0d"]:
            with self.assertRaises(MessageError) as cm:
                validate_request_headers([(b"x-foo", prefix + b"foo")])
            self.assertEqual(
                cm.exception.reason_phrase,
                "Header b'x-foo' value has forbidden characters",
            )

        # value with an initial TAB or SP:
        for prefix in [b"\x09", b"\x20"]:
            with self.assertRaises(MessageError) as cm:
                validate_request_headers([(b"x-foo", prefix + b"foo")])
            self.assertEqual(
                cm.exception.reason_phrase,
                "Header b'x-foo' value starts with whitespace",
            )

        # value with a final TAB or SP:
        for suffix in [b"\x09", b"\x20"]:
            with self.assertRaises(MessageError) as cm:
                validate_request_headers([(b"x-foo", b"foo" + suffix)])
            self.assertEqual(
                cm.exception.reason_phrase,
                "Header b'x-foo' value ends with whitespace",
            )

        # invalid pseudo-header
        with self.assertRaises(MessageError) as cm:
            validate_request_headers([(b":status", b"foo")])
        self.assertEqual(
            cm.exception.reason_phrase, "Pseudo-header b':status' is not valid"
        )

        # duplicate pseudo-header
        with self.assertRaises(MessageError) as cm:
            validate_request_headers(
                [
                    (b":method", b"GET"),
                    (b":method", b"POST"),
                ]
            )
        self.assertEqual(
            cm.exception.reason_phrase, "Pseudo-header b':method' is included twice"
        )

        # pseudo-header after regular headers
        with self.assertRaises(MessageError) as cm:
            validate_request_headers(
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                    (b"x-foo", b"bar"),
                    (b":authority", b"foo"),
                ]
            )
        self.assertEqual(
            cm.exception.reason_phrase,
            "Pseudo-header b':authority' is not allowed after regular headers",
        )

        # missing pseudo-headers
        with self.assertRaises(MessageError) as cm:
            validate_request_headers([(b":method", b"GET")])
        self.assertEqual(
            cm.exception.reason_phrase,
            "Pseudo-headers [b':authority'] are missing",
        )

        # empty :authority pseudo-header for http/https
        for scheme in [b"http", b"https"]:
            with self.assertRaises(MessageError) as cm:
                validate_request_headers(
                    [
                        (b":method", b"GET"),
                        (b":scheme", scheme),
                        (b":authority", b""),
                        (b":path", b"/"),
                    ]
                )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Pseudo-header b':authority' cannot be empty",
            )

        # empty :path pseudo-header for http/https
        for scheme in [b"http", b"https"]:
            with self.assertRaises(MessageError) as cm:
                validate_request_headers(
                    [
                        (b":method", b"GET"),
                        (b":scheme", scheme),
                        (b":authority", b"localhost"),
                        (b":path", b""),
                    ]
                )
            self.assertEqual(
                cm.exception.reason_phrase, "Pseudo-header b':path' cannot be empty"
            )

    def test_validate_response_headers(self) -> None:
        # OK
        validate_response_headers([(b":status", b"103")])
        validate_response_headers([(b":status", b"200")])
        validate_response_headers(
            [
                (b":status", b"200"),
                (b"x-foo", b"bar"),
            ]
        )

        # invalid pseudo-header
        with self.assertRaises(MessageError) as cm:
            validate_response_headers([(b":method", b"GET")])
        self.assertEqual(
            cm.exception.reason_phrase, "Pseudo-header b':method' is not valid"
        )

        # duplicate pseudo-header
        with self.assertRaises(MessageError) as cm:
            validate_response_headers(
                [
                    (b":status", b"200"),
                    (b":status", b"501"),
                ]
            )
        self.assertEqual(
            cm.exception.reason_phrase, "Pseudo-header b':status' is included twice"
        )

        # The status code is a three-digit integer.
        for status in (b"20", b"2000", b"+20", b"2_0", b"abc"):
            with self.subTest(status=status):
                with self.assertRaises(MessageError) as cm:
                    validate_response_headers([(b":status", status)])
                self.assertEqual(
                    cm.exception.reason_phrase,
                    f"Pseudo-header b':status' has invalid value {status!r}",
                )

        # 101 Switching Protocols is not supported.
        with self.assertRaises(MessageError) as cm:
            validate_response_headers([(b":status", b"101")])
        self.assertEqual(
            cm.exception.reason_phrase, "Pseudo-header b':status' cannot be 101"
        )

        # Connection-specific fields, including TE, are forbidden in responses.
        for name in (
            b"connection",
            b"keep-alive",
            b"proxy-connection",
            b"te",
            b"transfer-encoding",
            b"upgrade",
        ):
            with self.subTest(header=name):
                with self.assertRaises(MessageError) as cm:
                    validate_response_headers(
                        [(b":status", b"200"), (name, b"trailers")]
                    )
                self.assertEqual(
                    cm.exception.reason_phrase,
                    f"Header {name!r} is connection-specific",
                )

    def test_validate_trailers(self) -> None:
        # OK
        validate_trailers([(b"x-foo", b"bar")])

        # invalid pseudo-header
        with self.assertRaises(MessageError) as cm:
            validate_trailers([(b":status", b"foo")])
        self.assertEqual(
            cm.exception.reason_phrase, "Pseudo-header b':status' is not valid"
        )

        # pseudo-header after regular headers
        with self.assertRaises(MessageError) as cm:
            validate_trailers(
                [
                    (b"x-foo", b"bar"),
                    (b":authority", b"foo"),
                ]
            )
        self.assertEqual(
            cm.exception.reason_phrase,
            "Pseudo-header b':authority' is not allowed after regular headers",
        )

        # Connection-specific fields, including TE, are forbidden in trailers.
        for name in (
            b"connection",
            b"keep-alive",
            b"proxy-connection",
            b"te",
            b"transfer-encoding",
            b"upgrade",
        ):
            with self.subTest(header=name):
                with self.assertRaises(MessageError) as cm:
                    validate_trailers([(name, b"trailers")])
                self.assertEqual(
                    cm.exception.reason_phrase,
                    f"Header {name!r} is connection-specific",
                )
