import binascii
import contextlib
import copy
from unittest import TestCase

from aioquic.buffer import Buffer, encode_uint_var
from aioquic.h3.connection import (
    H3_ALPN,
    ErrorCode,
    FrameType,
    FrameUnexpected,
    H3Connection,
    MessageError,
    Setting,
    SettingsError,
    StreamType,
    encode_frame,
    encode_settings,
    parse_settings,
    validate_push_promise_headers,
    validate_request_headers,
    validate_response_headers,
    validate_trailers,
)
from aioquic.h3.events import DataReceived, HeadersReceived, PushPromiseReceived
from aioquic.h3.exceptions import InvalidStreamTypeError, NoAvailablePushIDError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StopSendingReceived, StreamDataReceived, StreamReset
from aioquic.quic.logger import QuicLogger

from .test_connection import client_and_server, transfer

DUMMY_SETTINGS = {
    Setting.QPACK_MAX_TABLE_CAPACITY: 4096,
    Setting.QPACK_BLOCKED_STREAMS: 16,
    Setting.DUMMY: 1,
}
QUIC_CONFIGURATION_OPTIONS = {"alpn_protocols": H3_ALPN}


def h3_client_and_server(options=QUIC_CONFIGURATION_OPTIONS):
    return client_and_server(
        client_options=options,
        server_options=options,
    )


@contextlib.contextmanager
def h3_fake_client_and_server(options=QUIC_CONFIGURATION_OPTIONS):
    quic_client = FakeQuicConnection(
        configuration=QuicConfiguration(is_client=True, **options)
    )
    quic_server = FakeQuicConnection(
        configuration=QuicConfiguration(is_client=False, **options)
    )

    # exchange transport parameters
    quic_client._remote_max_datagram_frame_size = (
        quic_server.configuration.max_datagram_frame_size
    )
    quic_server._remote_max_datagram_frame_size = (
        quic_client.configuration.max_datagram_frame_size
    )

    yield quic_client, quic_server


def h3_transfer(quic_sender, h3_receiver):
    quic_receiver = h3_receiver._quic
    if hasattr(quic_sender, "stream_queue"):
        quic_receiver._events.extend(quic_sender.stream_queue)
        quic_sender.stream_queue.clear()
    else:
        transfer(quic_sender, quic_receiver)

    # process QUIC events
    http_events = []
    event = quic_receiver.next_event()
    while event is not None:
        http_events.extend(h3_receiver.handle_event(event))
        event = quic_receiver.next_event()
    return http_events


class FakeQuicConnection:
    def __init__(self, configuration):
        self.closed = None
        self.configuration = configuration
        self.stream_queue = []
        self._events = []
        self._next_stream_bidi = 0 if configuration.is_client else 1
        self._next_stream_uni = 2 if configuration.is_client else 3
        self._quic_logger = QuicLogger().start_trace(
            is_client=configuration.is_client, odcid=b""
        )
        self._remote_max_datagram_frame_size = None

    def close(self, error_code, reason_phrase):
        self.closed = (error_code, reason_phrase)

    def get_next_available_stream_id(self, is_unidirectional=False):
        if is_unidirectional:
            stream_id = self._next_stream_uni
            self._next_stream_uni += 4
        else:
            stream_id = self._next_stream_bidi
            self._next_stream_bidi += 4
        return stream_id

    def next_event(self):
        try:
            return self._events.pop(0)
        except IndexError:
            return None

    def send_stream_data(self, stream_id, data, end_stream=False):
        # chop up data into individual bytes
        for c in data:
            self.stream_queue.append(
                StreamDataReceived(
                    data=bytes([c]), end_stream=False, stream_id=stream_id
                )
            )
        if end_stream:
            self.stream_queue.append(
                StreamDataReceived(data=b"", end_stream=end_stream, stream_id=stream_id)
            )


class H3ConnectionTest(TestCase):
    maxDiff = None

    def _make_request(self, h3_client, h3_server):
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

    def _send_request_headers(self, h3_client, h3_server):
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

    def test_handle_control_frame_headers(self):
        """
        We should not receive HEADERS on the control stream.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
        self.assertIsNone(quic_server.closed)
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
            quic_server.closed,
            (ErrorCode.H3_FRAME_UNEXPECTED, "Invalid frame type on control stream"),
        )

    def test_handle_control_frame_reserved(self):
        """
        Frame types reserved from HTTP/2 must be rejected on the control stream,
        see RFC 9114 section 7.2.8.
        """
        for frame_type in [0x2, 0x6, 0x8, 0x9]:
            with self.subTest(frame_type=frame_type):
                quic_server = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=False)
                )
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
                    quic_server.closed,
                    (
                        ErrorCode.H3_FRAME_UNEXPECTED,
                        "Invalid frame type on control stream",
                    ),
                )

    def test_handle_control_frame_unknown(self):
        """
        Unknown frame types must be ignored on the control stream, including
        DUPLICATE_PUSH which only existed in drafts, see RFC 9114 section 9.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
        self.assertIsNone(quic_server.closed)
        self.assertEqual(h3_server._max_push_id, 5)

    def test_handle_control_frame_settings_fragmented(self):
        """
        We should handle SETTINGS received one byte at a time.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        data = encode_uint_var(StreamType.CONTROL) + encode_frame(
            FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)
        )
        for c in data:
            self.assertIsNone(h3_server.received_settings)
            h3_server.handle_event(
                StreamDataReceived(stream_id=2, data=bytes([c]), end_stream=False)
            )
        self.assertIsNone(quic_server.closed)
        self.assertEqual(h3_server.received_settings, DUMMY_SETTINGS)

    def test_handle_control_frame_settings_truncated(self):
        """
        We should reject a SETTINGS frame which ends in the middle of a setting.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
            quic_server.closed,
            (ErrorCode.H3_FRAME_ERROR, "Could not parse SETTINGS frame"),
        )

    def test_handle_control_frame_unknown_before_settings(self):
        """
        An unknown frame does not satisfy the requirement for SETTINGS to be
        the first frame on the control stream, see RFC 9114 section 9.

        The error must be detected from the frame header alone.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
        self.assertEqual(quic_server.closed, (ErrorCode.H3_MISSING_SETTINGS, ""))

    def test_handle_control_frame_unknown_fragmented(self):
        """
        The payload of unknown frames must be discarded as it is received,
        see RFC 9114 section 7.2.8 and section 9.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
        self.assertIsNone(quic_server.closed)

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
            self.assertIsNone(quic_server.closed)
            self.assertEqual(h3_server._stream[2].buffer, b"")
            self.assertEqual(h3_server._stream[2].frame_size, 10000 - 1111 * (i + 1))

        # receive the last byte and MAX_PUSH_ID
        self.assertIsNone(h3_server._max_push_id)
        h3_server.handle_event(
            StreamDataReceived(
                stream_id=2,
                data=b"x" + encode_frame(FrameType.MAX_PUSH_ID, encode_uint_var(5)),
                end_stream=False,
            )
        )
        self.assertIsNone(quic_server.closed)
        self.assertEqual(h3_server._max_push_id, 5)

    def test_handle_control_frame_wrong_frame_type_header_only(self):
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
            with self.subTest(is_client=is_client, frame_type=frame_type):
                quic = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=is_client)
                )
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
                self.assertIsNone(quic.closed)

                # receive frame header only
                h3.handle_event(
                    StreamDataReceived(
                        stream_id=stream_id,
                        data=encode_uint_var(frame_type) + encode_uint_var(1000000),
                        end_stream=False,
                    )
                )
                self.assertEqual(quic.closed, (ErrorCode.H3_FRAME_UNEXPECTED, reason))

    def test_handle_control_frame_max_push_id_from_client_before_settings(self):
        """
        A server should not receive MAX_PUSH_ID before SETTINGS.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
            quic_server.closed,
            (ErrorCode.H3_MISSING_SETTINGS, ""),
        )

    def test_handle_control_frame_max_push_id_from_server(self):
        """
        A client should not receive MAX_PUSH_ID on the control stream.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
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
        self.assertIsNone(quic_client.closed)

        # receive unexpected MAX_PUSH_ID
        h3_client.handle_event(
            StreamDataReceived(
                stream_id=3,
                data=encode_frame(FrameType.MAX_PUSH_ID, b""),
                end_stream=False,
            )
        )
        self.assertEqual(
            quic_client.closed,
            (ErrorCode.H3_FRAME_UNEXPECTED, "Servers must not send MAX_PUSH_ID"),
        )

    def test_handle_control_frame_max_push_id_malformed(self):
        """
        A server should reject a MAX_PUSH_ID frame which is empty or has
        trailing data.
        """
        for frame_data, reason_phrase in [
            (b"", "Could not parse MAX_PUSH_ID frame"),
            (b"\x05\x00", "MAX_PUSH_ID frame has trailing data"),
        ]:
            with self.subTest(frame_data=frame_data):
                quic_server = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=False)
                )
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
                    quic_server.closed, (ErrorCode.H3_FRAME_ERROR, reason_phrase)
                )

    def test_handle_control_frame_max_push_id_reduced(self):
        """
        A server must reject a MAX_PUSH_ID frame which reduces the maximum
        push ID, see RFC 9114 section 7.2.7.
        """
        for max_push_id, expected_closed, expected_max_push_id in [
            (7, (ErrorCode.H3_ID_ERROR, "MAX_PUSH_ID reduced the maximum push ID"), 8),
            (8, None, 8),
            (9, None, 9),
        ]:
            with self.subTest(max_push_id=max_push_id):
                quic_server = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=False)
                )
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
                self.assertEqual(quic_server.closed, expected_closed)
                self.assertEqual(h3_server._max_push_id, expected_max_push_id)

    def test_handle_control_settings_twice(self):
        """
        We should not receive HEADERS on the control stream.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
        self.assertIsNone(quic_server.closed)

        # receive unexpected SETTINGS
        h3_server.handle_event(
            StreamDataReceived(
                stream_id=2,
                data=encode_frame(FrameType.SETTINGS, encode_settings(DUMMY_SETTINGS)),
                end_stream=False,
            )
        )
        self.assertEqual(
            quic_server.closed,
            (ErrorCode.H3_FRAME_UNEXPECTED, "SETTINGS have already been received"),
        )

    def test_handle_control_stream_close(self):
        """
        Closing the control stream is not allowed.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
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
        self.assertIsNone(quic_client.closed)

        # receive unexpected FIN
        h3_client.handle_event(
            StreamDataReceived(
                stream_id=3,
                data=b"",
                end_stream=True,
            )
        )
        self.assertEqual(
            quic_client.closed,
            (
                ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                "Closing control stream is not allowed",
            ),
        )

    def test_handle_control_stream_duplicate(self):
        """
        We must only receive a single control stream.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        # receive a first control stream
        h3_server.handle_event(
            StreamDataReceived(
                stream_id=2, data=encode_uint_var(StreamType.CONTROL), end_stream=False
            )
        )

        # receive a second control stream
        h3_server.handle_event(
            StreamDataReceived(
                stream_id=6, data=encode_uint_var(StreamType.CONTROL), end_stream=False
            )
        )
        self.assertEqual(
            quic_server.closed,
            (
                ErrorCode.H3_STREAM_CREATION_ERROR,
                "Only one control stream is allowed",
            ),
        )

    def test_handle_control_stream_reset(self):
        """
        Resetting the control stream is not allowed.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
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
        self.assertIsNone(quic_client.closed)

        # Receive unexpected RESET_STREAM.
        h3_client.handle_event(StreamReset(error_code=0, stream_id=3))
        self.assertEqual(
            quic_client.closed,
            (
                ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                "Resetting a critical stream is not allowed",
            ),
        )

    def test_handle_control_stream_stop_sending(self):
        """
        Asking us to stop sending on our control stream is not allowed.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        # Receive unexpected STOP_SENDING.
        h3_client.handle_event(
            StopSendingReceived(
                error_code=0, stream_id=h3_client._local_control_stream_id
            )
        )
        self.assertEqual(
            quic_client.closed,
            (
                ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                "Stopping a critical stream is not allowed",
            ),
        )

    def test_handle_push_frame_wrong_frame_type(self):
        """
        We should not received SETTINGS on a push stream.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        h3_client.handle_event(
            StreamDataReceived(
                stream_id=15,
                data=encode_uint_var(StreamType.PUSH)
                + encode_uint_var(0)  # push ID
                + encode_frame(FrameType.SETTINGS, b""),
                end_stream=False,
            )
        )
        self.assertEqual(
            quic_client.closed,
            (ErrorCode.H3_FRAME_UNEXPECTED, "Invalid frame type on push stream"),
        )

    def test_handle_push_frame_reserved(self):
        """
        Frame types reserved from HTTP/2 must be rejected on a push stream,
        see RFC 9114 section 7.2.8.
        """
        for frame_type in [0x2, 0x6, 0x8, 0x9]:
            with self.subTest(frame_type=frame_type):
                quic_client = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=True)
                )
                h3_client = H3Connection(quic_client)

                h3_client.handle_event(
                    StreamDataReceived(
                        stream_id=15,
                        data=encode_uint_var(StreamType.PUSH)
                        + encode_uint_var(0)  # push ID
                        + encode_frame(frame_type, b""),
                        end_stream=False,
                    )
                )
                self.assertEqual(
                    quic_client.closed,
                    (
                        ErrorCode.H3_FRAME_UNEXPECTED,
                        "Invalid frame type on push stream",
                    ),
                )

    def test_handle_push_frame_wrong_frame_type_header_only(self):
        """
        Frames which are not allowed on a push stream must be rejected from
        the frame header alone, without buffering their payload.
        """
        for frame_type in [
            FrameType.CANCEL_PUSH,
            FrameType.SETTINGS,
            FrameType.PUSH_PROMISE,
            FrameType.GOAWAY,
            FrameType.MAX_PUSH_ID,
            0x2,
            0x6,
            0x8,
            0x9,
        ]:
            with self.subTest(frame_type=frame_type):
                quic_client = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=True)
                )
                h3_client = H3Connection(quic_client)

                h3_client.handle_event(
                    StreamDataReceived(
                        stream_id=15,
                        data=encode_uint_var(StreamType.PUSH)
                        + encode_uint_var(0)  # push ID
                        + encode_uint_var(frame_type)
                        + encode_uint_var(1000000),
                        end_stream=False,
                    )
                )
                self.assertEqual(
                    quic_client.closed,
                    (
                        ErrorCode.H3_FRAME_UNEXPECTED,
                        "Invalid frame type on push stream",
                    ),
                )

    def test_handle_push_stream_from_client(self):
        """
        A server must reject a push stream, see RFC 9114 section 6.2.2.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        h3_server.handle_event(
            StreamDataReceived(
                stream_id=2,
                data=encode_uint_var(StreamType.PUSH),
                end_stream=False,
            )
        )
        self.assertEqual(
            quic_server.closed,
            (ErrorCode.H3_STREAM_CREATION_ERROR, "Clients must not open push streams"),
        )

    def test_handle_push_stream_push_id_exceeds_max(self):
        """
        A client must reject a push stream whose push ID exceeds the
        MAX_PUSH_ID it sent, see RFC 9114 section 4.6.
        """
        for push_id, expected_closed in [
            (8, None),
            (9, (ErrorCode.H3_ID_ERROR, "Push ID exceeds the maximum push ID")),
        ]:
            with self.subTest(push_id=push_id):
                quic_client = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=True)
                )
                h3_client = H3Connection(quic_client)

                h3_client.handle_event(
                    StreamDataReceived(
                        stream_id=15,
                        data=encode_uint_var(StreamType.PUSH)
                        + encode_uint_var(push_id),
                        end_stream=False,
                    )
                )
                self.assertEqual(quic_client.closed, expected_closed)

    def test_handle_qpack_decoder_duplicate(self):
        """
        We must only receive a single QPACK decoder stream.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
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
            quic_client.closed,
            (
                ErrorCode.H3_STREAM_CREATION_ERROR,
                "Only one QPACK decoder stream is allowed",
            ),
        )

    def test_handle_qpack_decoder_stream_error(self):
        """
        Receiving garbage on the QPACK decoder stream triggers an exception.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        h3_client.handle_event(
            StreamDataReceived(
                stream_id=11,
                data=encode_uint_var(StreamType.QPACK_DECODER) + b"\x00",
                end_stream=False,
            )
        )
        self.assertEqual(quic_client.closed, (ErrorCode.QPACK_DECODER_STREAM_ERROR, ""))

    def test_handle_qpack_encoder_duplicate(self):
        """
        We must only receive a single QPACK encoder stream.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
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
            quic_client.closed,
            (
                ErrorCode.H3_STREAM_CREATION_ERROR,
                "Only one QPACK encoder stream is allowed",
            ),
        )

    def test_handle_qpack_encoder_stream_error(self):
        """
        Receiving garbage on the QPACK encoder stream triggers an exception.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        h3_client.handle_event(
            StreamDataReceived(
                stream_id=7,
                data=encode_uint_var(StreamType.QPACK_ENCODER) + b"\x00",
                end_stream=False,
            )
        )
        self.assertEqual(quic_client.closed, (ErrorCode.QPACK_ENCODER_STREAM_ERROR, ""))

    def test_handle_qpack_encoder_stream_reset(self):
        """
        Resetting the QPACK encoder stream is not allowed.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        h3_client.handle_event(
            StreamDataReceived(
                stream_id=7,
                data=encode_uint_var(StreamType.QPACK_ENCODER),
                end_stream=False,
            )
        )
        self.assertIsNone(quic_client.closed)

        # Receive unexpected RESET_STREAM.
        h3_client.handle_event(StreamReset(error_code=0, stream_id=7))
        self.assertEqual(
            quic_client.closed,
            (
                ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                "Resetting a critical stream is not allowed",
            ),
        )

    def test_handle_request_frame_bad_headers(self):
        """
        We should not receive HEADERS which cannot be decoded.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        h3_server.handle_event(
            StreamDataReceived(
                stream_id=0, data=encode_frame(FrameType.HEADERS, b""), end_stream=False
            )
        )
        self.assertEqual(quic_server.closed, (ErrorCode.QPACK_DECOMPRESSION_FAILED, ""))

    def test_handle_request_frame_data_before_headers(self):
        """
        We should not receive DATA before receiving headers.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        h3_server.handle_event(
            StreamDataReceived(
                stream_id=0, data=encode_frame(FrameType.DATA, b""), end_stream=False
            )
        )
        self.assertEqual(
            quic_server.closed,
            (
                ErrorCode.H3_FRAME_UNEXPECTED,
                "DATA frame is not allowed in this state",
            ),
        )

    def test_handle_request_frame_headers_after_trailers(self):
        """
        We should not receive HEADERS after receiving trailers.
        """
        with h3_fake_client_and_server() as (quic_client, quic_server):
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
                quic_server.closed,
                (
                    ErrorCode.H3_FRAME_UNEXPECTED,
                    "HEADERS frame is not allowed in this state",
                ),
            )

    def test_handle_request_frame_push_promise_at_end(self):
        """
        PUSH_PROMISE can be the last frame on a request stream, see
        RFC 9114 section 4.1.
        """
        with h3_fake_client_and_server() as (quic_client, quic_server):
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
                ],
                end_stream=True,
            )
            h3_transfer(quic_client, h3_server)

            # send response followed by a push promise
            h3_server.send_headers(
                stream_id=stream_id,
                headers=[(b":status", b"200")],
                end_stream=False,
            )
            h3_server.send_data(stream_id=stream_id, data=b"hello", end_stream=False)
            push_headers = [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/app.css"),
            ]
            h3_server.send_push_promise(stream_id=stream_id, headers=push_headers)
            response_data = b"".join(
                e.data for e in quic_server.stream_queue if e.stream_id == stream_id
            )

            # receive response
            events = h3_client.handle_event(
                StreamDataReceived(
                    stream_id=stream_id, data=response_data, end_stream=True
                )
            )
            self.assertIsNone(quic_client.closed)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[(b":status", b"200")],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    DataReceived(
                        data=b"hello", stream_id=stream_id, stream_ended=False
                    ),
                    PushPromiseReceived(
                        headers=push_headers, push_id=0, stream_id=stream_id
                    ),
                    DataReceived(data=b"", stream_id=stream_id, stream_ended=True),
                ],
            )

    def test_handle_request_frame_push_promise_from_client(self):
        """
        A server should not receive PUSH_PROMISE on a request stream.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        h3_server.handle_event(
            StreamDataReceived(
                stream_id=0,
                data=encode_frame(FrameType.PUSH_PROMISE, b""),
                end_stream=False,
            )
        )
        self.assertEqual(
            quic_server.closed,
            (ErrorCode.H3_FRAME_UNEXPECTED, "Clients must not send PUSH_PROMISE"),
        )

    def test_handle_request_frame_push_promise_id_exceeds_max(self):
        """
        A client must reject a PUSH_PROMISE whose push ID exceeds the
        MAX_PUSH_ID it sent, see RFC 9114 section 7.2.5.
        """
        push_headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/app.css"),
        ]
        for push_id, expected_events, expected_closed in [
            (
                8,
                [PushPromiseReceived(headers=push_headers, push_id=8, stream_id=0)],
                None,
            ),
            (
                9,
                [],
                (ErrorCode.H3_ID_ERROR, "Push ID exceeds the maximum push ID"),
            ),
        ]:
            with self.subTest(push_id=push_id):
                quic_client = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=True)
                )
                h3_client = H3Connection(quic_client)

                events = h3_client.handle_event(
                    StreamDataReceived(
                        stream_id=0,
                        data=encode_frame(
                            FrameType.PUSH_PROMISE,
                            encode_uint_var(push_id)
                            + binascii.unhexlify(
                                "0000d1d75086a0e41d139d0951866075d6b9108f"
                            ),
                        ),
                        end_stream=False,
                    )
                )
                self.assertEqual(events, expected_events)
                self.assertEqual(quic_client.closed, expected_closed)

    def test_handle_request_frame_push_promise_truncated(self):
        """
        A client should reject a PUSH_PROMISE frame without a push ID.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        h3_client.handle_event(
            StreamDataReceived(
                stream_id=0,
                data=encode_frame(FrameType.PUSH_PROMISE, b""),
                end_stream=False,
            )
        )
        self.assertEqual(
            quic_client.closed,
            (ErrorCode.H3_FRAME_ERROR, "Could not parse PUSH_PROMISE frame"),
        )

    def test_handle_request_frame_wrong_frame_type(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        h3_server.handle_event(
            StreamDataReceived(
                stream_id=0,
                data=encode_frame(FrameType.SETTINGS, b""),
                end_stream=False,
            )
        )
        self.assertEqual(
            quic_server.closed,
            (ErrorCode.H3_FRAME_UNEXPECTED, "Invalid frame type on request stream"),
        )

    def test_handle_request_frame_reserved(self):
        """
        Frame types reserved from HTTP/2 must be rejected on a request stream,
        see RFC 9114 section 7.2.8.
        """
        for frame_type in [0x2, 0x6, 0x8, 0x9]:
            with self.subTest(frame_type=frame_type):
                quic_server = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=False)
                )
                h3_server = H3Connection(quic_server)

                h3_server.handle_event(
                    StreamDataReceived(
                        stream_id=0,
                        data=encode_frame(frame_type, b""),
                        end_stream=False,
                    )
                )
                self.assertEqual(
                    quic_server.closed,
                    (
                        ErrorCode.H3_FRAME_UNEXPECTED,
                        "Invalid frame type on request stream",
                    ),
                )

    def test_handle_request_frame_unknown_duplicate_push(self):
        """
        DUPLICATE_PUSH only existed in drafts, it is now an unknown frame type
        which must be ignored, see RFC 9114 section 9.
        """
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        events = h3_server.handle_event(
            StreamDataReceived(
                stream_id=0,
                data=encode_frame(0xE, encode_uint_var(0)),
                end_stream=False,
            )
        )
        self.assertEqual(events, [])
        self.assertIsNone(quic_server.closed)

    def test_handle_request_frame_wrong_frame_type_header_only(self):
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
            with self.subTest(is_client=is_client, frame_type=frame_type):
                quic = FakeQuicConnection(
                    configuration=QuicConfiguration(is_client=is_client)
                )
                h3 = H3Connection(quic)

                h3.handle_event(
                    StreamDataReceived(
                        stream_id=0,
                        data=encode_uint_var(frame_type) + encode_uint_var(1000000),
                        end_stream=False,
                    )
                )
                self.assertEqual(quic.closed, (ErrorCode.H3_FRAME_UNEXPECTED, reason))

    def test_handle_request_frame_truncated(self):
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
                    h3_fake_client_and_server() as (quic_client, quic_server),
                ):
                    h3_client = H3Connection(quic_client)
                    h3_server = H3Connection(quic_server)

                    stream_id = quic_client.get_next_available_stream_id()
                    h3_client.send_headers(stream_id=stream_id, headers=headers)
                    headers_data = b"".join(
                        e.data
                        for e in quic_client.stream_queue
                        if e.stream_id == stream_id
                    )

                    # Receive the stream end with the truncated frame, or after it.
                    if split:
                        h3_server.handle_event(
                            StreamDataReceived(
                                stream_id=stream_id,
                                data=headers_data + truncated_data,
                                end_stream=False,
                            )
                        )
                        self.assertIsNone(quic_server.closed)
                        events = h3_server.handle_event(
                            StreamDataReceived(
                                stream_id=stream_id, data=b"", end_stream=True
                            )
                        )
                    else:
                        events = h3_server.handle_event(
                            StreamDataReceived(
                                stream_id=stream_id,
                                data=headers_data + truncated_data,
                                end_stream=True,
                            )
                        )
                    self.assertEqual(events, [])
                    self.assertEqual(
                        quic_server.closed,
                        (
                            ErrorCode.H3_FRAME_ERROR,
                            "Frame is truncated by the end of the stream",
                        ),
                    )

    def test_handle_request_frame_unknown(self):
        """
        Unknown frames must be ignored, see RFC 9114 section 7.2.8 and
        section 9.
        """
        with h3_fake_client_and_server() as (quic_client, quic_server):
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
            h3_client.send_headers(stream_id=stream_id, headers=headers)
            headers_data = b"".join(
                e.data for e in quic_client.stream_queue if e.stream_id == stream_id
            )

            # receive unknown frames around the HEADERS and DATA frames
            events = h3_server.handle_event(
                StreamDataReceived(
                    stream_id=stream_id,
                    data=encode_frame(0x21, b"")
                    + headers_data
                    + encode_frame(0x40, b"unknown")
                    + encode_frame(FrameType.DATA, b"hello")
                    + encode_frame(0x5F, b"x" * 1000)
                    + encode_frame(FrameType.DATA, b"world"),
                    end_stream=True,
                )
            )
            self.assertIsNone(quic_server.closed)
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

    def test_handle_request_frame_unknown_at_end(self):
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

        with h3_fake_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # send request with trailers
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(stream_id=stream_id, headers=headers)
            h3_client.send_data(stream_id=stream_id, data=b"hello", end_stream=False)
            body_data = b"".join(
                e.data for e in quic_client.stream_queue if e.stream_id == stream_id
            )
            quic_client.stream_queue.clear()
            h3_client.send_headers(stream_id=stream_id, headers=trailers)
            trailers_data = b"".join(
                e.data for e in quic_client.stream_queue if e.stream_id == stream_id
            )

            # receive an unknown frame after the body
            events = h3_server.handle_event(
                StreamDataReceived(
                    stream_id=stream_id,
                    data=body_data + encode_frame(0x21, b"grease"),
                    end_stream=True,
                )
            )
            self.assertIsNone(quic_server.closed)
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
            events = h3_server.handle_event(
                StreamDataReceived(
                    stream_id=stream_id,
                    data=body_data + trailers_data + encode_frame(0x21, b"grease"),
                    end_stream=True,
                )
            )
            self.assertIsNone(quic_server.closed)
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

    def test_handle_request_frame_unknown_at_end_content_length_mismatch(self):
        """
        The content-length must be checked when a request stream ends with
        an unknown frame.
        """
        with h3_fake_client_and_server() as (quic_client, quic_server):
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
            body_data = b"".join(
                e.data for e in quic_client.stream_queue if e.stream_id == stream_id
            )

            # receive an unknown frame after the body
            h3_server.handle_event(
                StreamDataReceived(
                    stream_id=stream_id,
                    data=body_data + encode_frame(0x21, b"grease"),
                    end_stream=True,
                )
            )
            self.assertEqual(
                quic_server.closed,
                (
                    ErrorCode.H3_MESSAGE_ERROR,
                    "content-length does not match data size",
                ),
            )

    def test_handle_request_frame_unknown_fragmented(self):
        """
        The payload of unknown frames must be discarded as it is received,
        see RFC 9114 section 7.2.8 and section 9.
        """
        with h3_fake_client_and_server() as (quic_client, quic_server):
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
                self.assertIsNone(quic_server.closed)
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
            self.assertIsNone(quic_server.closed)
            self.assertEqual(
                events,
                [DataReceived(data=b"hello", stream_id=stream_id, stream_ended=True)],
            )

    def test_request(self):
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # make first request
            self._make_request(h3_client, h3_server)

            # make second request
            self._make_request(h3_client, h3_server)

            # make third request -> dynamic table
            self._make_request(h3_client, h3_server)

    def test_request_headers_only(self):
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

    def test_request_fragmented_frame(self):
        with h3_fake_client_and_server() as (quic_client, quic_server):
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
                    DataReceived(data=b"h", stream_id=0, stream_ended=False),
                    DataReceived(data=b"e", stream_id=0, stream_ended=False),
                    DataReceived(data=b"l", stream_id=0, stream_ended=False),
                    DataReceived(data=b"l", stream_id=0, stream_ended=False),
                    DataReceived(data=b"o", stream_id=0, stream_ended=False),
                    DataReceived(data=b"", stream_id=0, stream_ended=True),
                ],
            )

            # send push promise
            push_stream_id = h3_server.send_push_promise(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/app.txt"),
                ],
            )
            self.assertEqual(push_stream_id, 15)

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

            #  fulfill push promise
            h3_server.send_headers(
                stream_id=push_stream_id,
                headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
                end_stream=False,
            )
            h3_server.send_data(stream_id=push_stream_id, data=b"text", end_stream=True)

            # receive push promise / response
            events = h3_transfer(quic_server, h3_client)
            self.assertEqual(
                events,
                [
                    PushPromiseReceived(
                        headers=[
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/app.txt"),
                        ],
                        push_id=0,
                        stream_id=stream_id,
                    ),
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
                    HeadersReceived(
                        headers=[
                            (b":status", b"200"),
                            (b"content-type", b"text/plain"),
                        ],
                        stream_id=15,
                        stream_ended=False,
                        push_id=0,
                    ),
                    DataReceived(
                        data=b"t", stream_id=15, stream_ended=False, push_id=0
                    ),
                    DataReceived(
                        data=b"e", stream_id=15, stream_ended=False, push_id=0
                    ),
                    DataReceived(
                        data=b"x", stream_id=15, stream_ended=False, push_id=0
                    ),
                    DataReceived(
                        data=b"t", stream_id=15, stream_ended=False, push_id=0
                    ),
                    DataReceived(data=b"", stream_id=15, stream_ended=True, push_id=0),
                ],
            )

    def test_request_with_server_push(self):
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
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/"),
                        ],
                        stream_id=stream_id,
                        stream_ended=True,
                    )
                ],
            )

            # send push promises
            push_stream_id_css = h3_server.send_push_promise(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/app.css"),
                ],
            )
            self.assertEqual(push_stream_id_css, 15)

            push_stream_id_js = h3_server.send_push_promise(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/app.js"),
                ],
            )
            self.assertEqual(push_stream_id_js, 19)

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
                end_stream=True,
            )

            #  fulfill push promises
            h3_server.send_headers(
                stream_id=push_stream_id_css,
                headers=[(b":status", b"200"), (b"content-type", b"text/css")],
                end_stream=False,
            )
            h3_server.send_data(
                stream_id=push_stream_id_css,
                data=b"body { color: pink }",
                end_stream=True,
            )

            h3_server.send_headers(
                stream_id=push_stream_id_js,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"application/javascript"),
                ],
                end_stream=False,
            )
            h3_server.send_data(
                stream_id=push_stream_id_js, data=b"alert('howdee');", end_stream=True
            )

            # receive push promises, response and push responses

            events = h3_transfer(quic_server, h3_client)
            self.assertEqual(
                events,
                [
                    PushPromiseReceived(
                        headers=[
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/app.css"),
                        ],
                        push_id=0,
                        stream_id=stream_id,
                    ),
                    PushPromiseReceived(
                        headers=[
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/app.js"),
                        ],
                        push_id=1,
                        stream_id=stream_id,
                    ),
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
                        stream_ended=True,
                    ),
                    HeadersReceived(
                        headers=[(b":status", b"200"), (b"content-type", b"text/css")],
                        push_id=0,
                        stream_id=push_stream_id_css,
                        stream_ended=False,
                    ),
                    DataReceived(
                        data=b"body { color: pink }",
                        push_id=0,
                        stream_id=push_stream_id_css,
                        stream_ended=True,
                    ),
                    HeadersReceived(
                        headers=[
                            (b":status", b"200"),
                            (b"content-type", b"application/javascript"),
                        ],
                        push_id=1,
                        stream_id=push_stream_id_js,
                        stream_ended=False,
                    ),
                    DataReceived(
                        data=b"alert('howdee');",
                        push_id=1,
                        stream_id=push_stream_id_js,
                        stream_ended=True,
                    ),
                ],
            )

            # push streams are no longer tracked
            for push_stream_id in (push_stream_id_css, push_stream_id_js):
                self.assertNotIn(push_stream_id, h3_client._stream)
                self.assertNotIn(push_stream_id, h3_server._stream)

    def test_request_with_server_push_max_push_id(self):
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
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/"),
                        ],
                        stream_id=stream_id,
                        stream_ended=True,
                    )
                ],
            )

            # send push promise on a server-initiated stream
            with self.assertRaises(InvalidStreamTypeError):
                h3_server.send_push_promise(
                    stream_id=1,
                    headers=[
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/bad.css"),
                    ],
                )

            # send push promises
            for i in range(0, 9):
                h3_server.send_push_promise(
                    stream_id=stream_id,
                    headers=[
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", "/{}.css".format(i).encode("ascii")),
                    ],
                )

            # send one too many
            with self.assertRaises(NoAvailablePushIDError):
                h3_server.send_push_promise(
                    stream_id=stream_id,
                    headers=[
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/9.css"),
                    ],
                )

    def test_send_data_after_trailers(self):
        """
        We should not send DATA after trailers.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
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
            stream_id=stream_id, headers=[(b"x-some-trailer", b"foo")], end_stream=False
        )
        with self.assertRaises(FrameUnexpected):
            h3_client.send_data(stream_id=stream_id, data=b"hello", end_stream=False)

    def test_send_data_before_headers(self):
        """
        We should not send DATA before headers.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        stream_id = quic_client.get_next_available_stream_id()
        with self.assertRaises(FrameUnexpected):
            h3_client.send_data(stream_id=stream_id, data=b"hello", end_stream=False)

    def test_send_headers_after_trailers(self):
        """
        We should not send HEADERS after trailers.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
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
            stream_id=stream_id, headers=[(b"x-some-trailer", b"foo")], end_stream=False
        )
        with self.assertRaises(FrameUnexpected):
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[(b"x-other-trailer", b"foo")],
                end_stream=False,
            )

    def test_send_push_promise_from_client(self):
        """
        Clients cannot send a push promise.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        with self.assertRaises(RuntimeError) as cm:
            h3_client.send_push_promise(stream_id=0, headers=[])
        self.assertEqual(str(cm.exception), "Only servers may send a push promise.")

    def test_blocked_stream(self):
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        # Send request.
        h3_client.send_headers(
            stream_id=0,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ],
            end_stream=True,
        )

        h3_client.handle_event(
            StreamDataReceived(
                stream_id=3,
                data=binascii.unhexlify(
                    "0004170150000680020000074064091040bcc0000000faceb00c"
                ),
                end_stream=False,
            )
        )
        h3_client.handle_event(
            StreamDataReceived(stream_id=7, data=b"\x02", end_stream=False)
        )
        h3_client.handle_event(
            StreamDataReceived(stream_id=11, data=b"\x03", end_stream=False)
        )
        h3_client.handle_event(
            StreamDataReceived(
                stream_id=0, data=binascii.unhexlify("01040280d910"), end_stream=False
            )
        )
        h3_client.handle_event(
            StreamDataReceived(
                stream_id=0,
                data=binascii.unhexlify(
                    "00408d796f752072656163686564206d766673742e6e65742c20726561636820"
                    "746865202f6563686f20656e64706f696e7420666f7220616e206563686f2072"
                    "6573706f6e7365207175657279202f3c6e756d6265723e20656e64706f696e74"
                    "7320666f722061207661726961626c652073697a6520726573706f6e73652077"
                    "6974682072616e646f6d206279746573"
                ),
                end_stream=True,
            )
        )
        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=7,
                    data=binascii.unhexlify(
                        "3fe101c696d07abe941094cb6d0a08017d403971966e32ca98b46f"
                    ),
                    end_stream=False,
                )
            ),
            [
                HeadersReceived(
                    headers=[
                        (b":status", b"200"),
                        (b"date", b"Mon, 22 Jul 2019 06:33:33 GMT"),
                    ],
                    stream_id=0,
                    stream_ended=False,
                ),
                DataReceived(
                    data=(
                        b"you reached mvfst.net, reach the /echo endpoint for an "
                        b"echo response query /<number> endpoints for a variable "
                        b"size response with random bytes"
                    ),
                    stream_id=0,
                    stream_ended=True,
                ),
            ],
        )

        # The stream is no longer tracked.
        self.assertNotIn(0, h3_client._stream)

    def test_blocked_stream_push_promise(self):
        """
        A PUSH_PROMISE whose header block is blocked must be resumed as a
        PUSH_PROMISE, see RFC 9204 section 2.1.2.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        # Send request.
        h3_client.send_headers(
            stream_id=0,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ],
            end_stream=True,
        )

        # Receive a response ending with a PUSH_PROMISE which references
        # dynamic table entries which have not been received yet.
        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=binascii.unhexlify("01030000d90507000381d1d71011"),
                    end_stream=True,
                )
            ),
            [
                HeadersReceived(
                    headers=[(b":status", b"200")],
                    stream_id=0,
                    stream_ended=False,
                )
            ],
        )

        # Receive the dynamic table entries on the QPACK encoder stream.
        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=3,
                    data=binascii.unhexlify("023fe11fc086a0e41d139d09c1866075d6b9108f"),
                    end_stream=False,
                )
            ),
            [
                PushPromiseReceived(
                    headers=[
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/app.css"),
                    ],
                    push_id=0,
                    stream_id=0,
                ),
                DataReceived(data=b"", stream_id=0, stream_ended=True),
            ],
        )
        self.assertIsNone(quic_client.closed)

        # The stream is no longer tracked.
        self.assertNotIn(0, h3_client._stream)

    def test_blocked_stream_push_promise_then_data(self):
        """
        Frames following a blocked PUSH_PROMISE must be processed once it
        is resumed.
        """
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        # Send request.
        h3_client.send_headers(
            stream_id=0,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ],
            end_stream=True,
        )

        # Receive a response with a PUSH_PROMISE which references dynamic
        # table entries which have not been received yet, followed by DATA.
        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=binascii.unhexlify(
                        "01030000d90507000381d1d71011000568656c6c6f"
                    ),
                    end_stream=True,
                )
            ),
            [
                HeadersReceived(
                    headers=[(b":status", b"200")],
                    stream_id=0,
                    stream_ended=False,
                )
            ],
        )

        # Receive the dynamic table entries on the QPACK encoder stream.
        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=3,
                    data=binascii.unhexlify("023fe11fc086a0e41d139d09c1866075d6b9108f"),
                    end_stream=False,
                )
            ),
            [
                PushPromiseReceived(
                    headers=[
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/app.css"),
                    ],
                    push_id=0,
                    stream_id=0,
                ),
                DataReceived(data=b"hello", stream_id=0, stream_ended=True),
            ],
        )
        self.assertIsNone(quic_client.closed)

        # The stream is no longer tracked.
        self.assertNotIn(0, h3_client._stream)

    def test_blocked_stream_reset(self):
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        # Send request.
        h3_client.send_headers(
            stream_id=0,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ],
            end_stream=True,
        )

        # Receive response headers, which are blocked.
        h3_client.handle_event(
            StreamDataReceived(
                stream_id=3,
                data=binascii.unhexlify(
                    "0004170150000680020000074064091040bcc0000000faceb00c"
                ),
                end_stream=False,
            )
        )
        h3_client.handle_event(
            StreamDataReceived(stream_id=7, data=b"\x02", end_stream=False)
        )
        h3_client.handle_event(
            StreamDataReceived(stream_id=11, data=b"\x03", end_stream=False)
        )
        h3_client.handle_event(
            StreamDataReceived(
                stream_id=0, data=binascii.unhexlify("01040280d910"), end_stream=False
            )
        )
        self.assertTrue(h3_client._stream[0].blocked)
        quic_client.stream_queue.clear()

        # The server resets the stream.
        self.assertEqual(
            h3_client.handle_event(StreamReset(error_code=0, stream_id=0)), []
        )
        self.assertNotIn(0, h3_client._stream)

        # A Stream Cancellation is sent on the QPACK decoder stream.
        self.assertEqual(
            b"".join(
                event.data
                for event in quic_client.stream_queue
                if event.stream_id == h3_client._local_decoder_stream_id
            ),
            b"\x40",
        )

        # The encoder stream data no longer unblocks the stream.
        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=7,
                    data=binascii.unhexlify(
                        "3fe101c696d07abe941094cb6d0a08017d403971966e32ca98b46f"
                    ),
                    end_stream=False,
                )
            ),
            [],
        )
        self.assertNotIn(0, h3_client._stream)

    def test_blocked_stream_trailer(self):
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        h3_client = H3Connection(quic_client)

        h3_client.handle_event(
            StreamDataReceived(
                stream_id=3,
                data=binascii.unhexlify(
                    "0004170150000680020000074064091040bcc0000000faceb00c"
                ),
                end_stream=False,
            )
        )
        h3_client.handle_event(
            StreamDataReceived(stream_id=7, data=b"\x02", end_stream=False)
        )
        h3_client.handle_event(
            StreamDataReceived(stream_id=11, data=b"\x03", end_stream=False)
        )

        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=binascii.unhexlify(
                        "011b0000d95696d07abe941094cb6d0a08017d403971966e32ca98b46f"
                    ),
                    end_stream=False,
                )
            ),
            [
                HeadersReceived(
                    headers=[
                        (b":status", b"200"),
                        (b"date", b"Mon, 22 Jul 2019 06:33:33 GMT"),
                    ],
                    stream_id=0,
                    stream_ended=False,
                )
            ],
        )

        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=binascii.unhexlify(
                        "00408d796f752072656163686564206d766673742e6e65742c20726561636820"
                        "746865202f6563686f20656e64706f696e7420666f7220616e206563686f2072"
                        "6573706f6e7365207175657279202f3c6e756d6265723e20656e64706f696e74"
                        "7320666f722061207661726961626c652073697a6520726573706f6e73652077"
                        "6974682072616e646f6d206279746573"
                    ),
                    end_stream=False,
                )
            ),
            [
                DataReceived(
                    data=(
                        b"you reached mvfst.net, reach the /echo endpoint for an "
                        b"echo response query /<number> endpoints for a variable "
                        b"size response with random bytes"
                    ),
                    stream_id=0,
                    stream_ended=False,
                )
            ],
        )

        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=0, data=binascii.unhexlify("0103028010"), end_stream=True
                )
            ),
            [],
        )

        self.assertEqual(
            h3_client.handle_event(
                StreamDataReceived(
                    stream_id=7,
                    data=binascii.unhexlify("6af2b20f49564d833505b38294e7"),
                    end_stream=False,
                )
            ),
            [
                HeadersReceived(
                    headers=[(b"x-some-trailer", b"foo")],
                    stream_id=0,
                    stream_ended=True,
                    push_id=None,
                )
            ],
        )

    def test_uni_stream_grease(self):
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

    def test_uni_stream_reset(self):
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
            self.assertEqual(h3_server._decoder_bytes_sent, 0)

    def test_request_with_trailers(self):
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

    def test_uni_stream_type(self):
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

    def test_validate_settings_h3_datagram_invalid_value(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
            quic_server.closed,
            (
                ErrorCode.H3_SETTINGS_ERROR,
                "H3_DATAGRAM setting must be 0 or 1",
            ),
        )

    def test_validate_settings_h3_datagram_without_transport_parameter(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        # receive SETTINGS with H3_DATAGRAM=1 but no max_datagram_frame_size TP
        settings = copy.copy(DUMMY_SETTINGS)
        settings[Setting.H3_DATAGRAM] = 1
        h3_server.handle_event(
            StreamDataReceived(
                stream_id=2,
                data=encode_uint_var(StreamType.CONTROL)
                + encode_frame(FrameType.SETTINGS, encode_settings(settings)),
                end_stream=False,
            )
        )
        self.assertEqual(
            quic_server.closed,
            (
                ErrorCode.H3_SETTINGS_ERROR,
                "H3_DATAGRAM requires max_datagram_frame_size transport parameter",
            ),
        )

    def test_validate_settings_enable_connect_protocol_invalid_value(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
            quic_server.closed,
            (
                ErrorCode.H3_SETTINGS_ERROR,
                "ENABLE_CONNECT_PROTOCOL setting must be 0 or 1",
            ),
        )

    def test_validate_settings_enable_webtransport_invalid_value(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
            quic_server.closed,
            (
                ErrorCode.H3_SETTINGS_ERROR,
                "ENABLE_WEBTRANSPORT setting must be 0 or 1",
            ),
        )

    def test_validate_settings_enable_webtransport_without_h3_datagram(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
            quic_server.closed,
            (
                ErrorCode.H3_SETTINGS_ERROR,
                "ENABLE_WEBTRANSPORT requires H3_DATAGRAM",
            ),
        )

    def _content_length_template(self, content_length, data, end_at, expected_closed):
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
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
            h3_client.send_data(stream_id=stream_id, data=data, end_stream=end_stream)
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
        h3_transfer(quic_client, h3_server)
        self.assertEqual(quic_server.closed, expected_closed)

    def test_content_length_not_specified_is_ok(self):
        """
        If a content-length is specified and OK, all is good.
        """
        self._content_length_template(None, b"hello world", "data", None)

    def test_content_length_is_ok(self):
        """
        If a content-length is specified and OK, all is good.
        """
        self._content_length_template(b"11", b"hello world", "data", None)

    def test_content_length_that_is_not_an_int_rejected(self):
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

    def test_content_length_that_is_negative_is_rejected(self):
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

    def test_content_length_does_not_match_data_length(self):
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

    def test_content_length_does_not_match_when_headers_end_stream(self):
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

    def test_content_length_does_not_match_when_trailers_end_stream(self):
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

    def test_streams_are_closed_after_requests(self):
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            for _ in range(6):
                self._make_request(h3_client, h3_server)

            # Only 3 streams should be opened: Control, QPACK encoder and QPACK decoder
            self.assertEqual(len(h3_client._stream), 3)
            self.assertEqual(len(h3_server._stream), 3)

    def test_streams_are_closed_after_reset(self):
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            stream_id = self._send_request_headers(h3_client, h3_server)
            decoder_bytes_sent = h3_server._decoder_bytes_sent

            # The client resets the request.
            quic_client.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])

            # A Stream Cancellation is sent on the QPACK decoder stream.
            self.assertEqual(h3_server._decoder_bytes_sent, decoder_bytes_sent + 1)

            # The stream is kept until the server finishes sending.
            self.assertIn(stream_id, h3_server._stream)
            h3_server.send_headers(
                stream_id=stream_id, headers=[(b":status", b"200")], end_stream=True
            )
            self.assertNotIn(stream_id, h3_server._stream)

    def test_streams_are_closed_after_reset_and_stop_sending(self):
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)
            stream_id = self._send_request_headers(h3_client, h3_server)

            # The client resets the request and asks the server to stop sending.
            quic_client.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            quic_client.stop_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertNotIn(stream_id, h3_server._stream)

    def test_streams_are_closed_after_stop_sending(self):
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

    def test_streams_are_not_closed_prematurely(self):
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

    def test_double_sending_stream_closing(self):
        quic_client = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=True)
        )
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

        with self.assertRaises(FrameUnexpected) as assert_err:
            h3_client.send_data(stream_id, b"data", end_stream=True)

        self.assertEqual(str(assert_err.exception), "stream was already ended")


class H3ParserTest(TestCase):
    def test_parse_settings_duplicate_identifier(self):
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

    def test_parse_settings_reserved_identifier(self):
        buf = Buffer(capacity=1024)
        buf.push_uint_var(0)
        buf.push_uint_var(123)

        with self.assertRaises(SettingsError) as cm:
            parse_settings(buf.data)
        self.assertEqual(
            cm.exception.reason_phrase, "Setting identifier 0x0 is reserved"
        )

    def test_validate_push_promise_headers(self):
        # OK
        validate_push_promise_headers(
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":authority", b"localhost"),
            ]
        )
        validate_push_promise_headers(
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":authority", b"localhost"),
                (b"x-foo", b"bar"),
            ]
        )
        # Connection-specific fields and TE are forbidden in pushed requests.
        for name in (
            b"connection",
            b"keep-alive",
            b"proxy-connection",
            b"transfer-encoding",
            b"upgrade",
            b"te",
        ):
            with self.subTest(header=name), self.assertRaises(MessageError) as cm:
                validate_push_promise_headers([(name, b"value")])
            self.assertEqual(cm.exception.reason_phrase, "Forbidden header %r" % name)

        # invalid pseudo-header
        with self.assertRaises(MessageError) as cm:
            validate_push_promise_headers([(b":status", b"foo")])
        self.assertEqual(
            cm.exception.reason_phrase, "Pseudo-header b':status' is not valid"
        )

        # duplicate pseudo-header
        with self.assertRaises(MessageError) as cm:
            validate_push_promise_headers(
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
            validate_push_promise_headers(
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
            validate_push_promise_headers(
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                ]
            )
        self.assertEqual(
            cm.exception.reason_phrase,
            "Pseudo-headers [b':authority'] are missing",
        )

    def test_validate_request_headers(self):
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

        # The TE header is allowed in requests only when its value is trailers.
        validate_request_headers(
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":authority", b"localhost"),
                (b"te", b"trailers"),
            ]
        )

        # bad te
        with self.assertRaises(MessageError) as cm:
            validate_request_headers([(b"te", b"bogus")])
        self.assertEqual(
            cm.exception.reason_phrase,
            "The only valid value for te is trailers",
        )

        # Connection-specific fields, including Transfer-Encoding, are forbidden.
        for name in (
            b"connection",
            b"keep-alive",
            b"proxy-connection",
            b"transfer-encoding",
            b"upgrade",
        ):
            with self.subTest(header=name), self.assertRaises(MessageError) as cm:
                validate_request_headers([(name, b"value")])
            self.assertEqual(cm.exception.reason_phrase, "Forbidden header %r" % name)

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

    def test_validate_response_headers(self):
        # OK
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

        # Connection-specific fields and TE are forbidden in responses.
        for name in (
            b"connection",
            b"keep-alive",
            b"proxy-connection",
            b"transfer-encoding",
            b"upgrade",
            b"te",
        ):
            with self.subTest(header=name), self.assertRaises(MessageError) as cm:
                validate_response_headers([(b":status", b"200"), (name, b"value")])
            self.assertEqual(cm.exception.reason_phrase, "Forbidden header %r" % name)

    def test_validate_trailers(self):
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

        # Connection-specific fields and TE are forbidden in trailers.
        for name in (
            b"connection",
            b"keep-alive",
            b"proxy-connection",
            b"transfer-encoding",
            b"upgrade",
            b"te",
        ):
            with self.subTest(header=name), self.assertRaises(MessageError) as cm:
                validate_trailers([(name, b"value")])
            self.assertEqual(cm.exception.reason_phrase, "Forbidden header %r" % name)
