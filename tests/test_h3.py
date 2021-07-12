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
from aioquic.h3.exceptions import NoAvailablePushIDError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
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

    def test_handle_control_frame_headers(self):
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

            # receive push promise / reponse
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

            # send push promises
            for i in range(0, 8):
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
                        (b":path", b"/8.css"),
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

    def test_blocked_stream(self):
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
                14, b"\xff\xff\xff\xff\xff\xff\xff\xfeGREASE is the word"
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])

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

    def test_validate_settings_enable_webtransport_invalid_value(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        # receive SETTINGS with an invalid SETTINGS_ENABLE_WEBTRANSPORT value
        settings = copy.copy(DUMMY_SETTINGS)
        settings[Setting.SETTINGS_ENABLE_WEBTRANSPORT] = 2
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
                "SETTINGS_ENABLE_WEBTRANSPORT setting must be 0 or 1",
            ),
        )

    def test_validate_settings_enable_webtransport_without_h3_datagram(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        # receive SETTINGS requesting WebTransport, but DATAGRAM was not offered
        settings = copy.copy(DUMMY_SETTINGS)
        settings[Setting.SETTINGS_ENABLE_WEBTRANSPORT] = 1
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
                "SETTINGS_ENABLE_WEBTRANSPORT requires H3_DATAGRAM",
            ),
        )


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
            cm.exception.reason_phrase, "Header b'X-Foo' contains uppercase letters"
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
            "Pseudo-headers [b':path', b':scheme'] are missing",
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
