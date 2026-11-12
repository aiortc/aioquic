from aioquic.buffer import UINT_VAR_MAX, encode_uint_var
from aioquic.h3.connection import (
    H3_ALPN,
    ErrorCode,
    FrameType,
    H3Connection,
    StreamType,
    encode_frame,
)
from aioquic.h3.events import (
    DatagramReceived,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.h3.exceptions import InvalidStreamIdError, InvalidStreamTypeError
from aioquic.quic.events import DatagramFrameReceived

from .test_h3 import (
    closed,
    h3_client_and_server,
    h3_transfer,
)
from .utils import TestCase

QUIC_CONFIGURATION_OPTIONS = {
    "alpn_protocols": H3_ALPN,
    "max_datagram_frame_size": 65536,
}


class WebTransportTest(TestCase):
    def _check_bidirectional_stream(
        self, h3_opener: H3Connection, h3_acceptor: H3Connection, session_id: int
    ) -> None:
        quic_opener = h3_opener._quic
        quic_acceptor = h3_acceptor._quic

        # Opener opens a bidirectional stream and ends its half.
        stream_id = h3_opener.create_webtransport_stream(session_id)
        quic_opener.send_stream_data(stream_id, b"foo", end_stream=True)
        events = h3_transfer(quic_opener, h3_acceptor)
        self.assertEqual(
            events,
            [
                WebTransportStreamDataReceived(
                    data=b"foo",
                    session_id=session_id,
                    stream_ended=True,
                    stream_id=stream_id,
                )
            ],
        )

        # Only the opener, which awaits the reply, still tracks the stream.
        self.assertIn(stream_id, h3_opener._stream)
        self.assertNotIn(stream_id, h3_acceptor._stream)

        # Acceptor replies and ends its half.
        quic_acceptor.send_stream_data(stream_id, b"bar", end_stream=True)
        events = h3_transfer(quic_acceptor, h3_opener)
        self.assertEqual(
            events,
            [
                WebTransportStreamDataReceived(
                    data=b"bar",
                    session_id=session_id,
                    stream_ended=True,
                    stream_id=stream_id,
                )
            ],
        )

        # The stream is no longer tracked.
        self.assertNotIn(stream_id, h3_opener._stream)
        self.assertNotIn(stream_id, h3_acceptor._stream)

    def _make_session(self, h3_client: H3Connection, h3_server: H3Connection) -> int:
        quic_client = h3_client._quic
        quic_server = h3_server._quic

        # send request
        stream_id = quic_client.get_next_available_stream_id()
        h3_client.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
                (b":protocol", b"webtransport"),
            ],
        )

        # receive request
        events = h3_transfer(quic_client, h3_server)
        self.assertEqual(
            events,
            [
                HeadersReceived(
                    headers=[
                        (b":method", b"CONNECT"),
                        (b":scheme", b"https"),
                        (b":authority", b"localhost"),
                        (b":path", b"/"),
                        (b":protocol", b"webtransport"),
                    ],
                    stream_id=stream_id,
                    stream_ended=False,
                )
            ],
        )

        # send response
        h3_server.send_headers(
            stream_id=stream_id,
            headers=[
                (b":status", b"200"),
            ],
        )

        # receive response
        events = h3_transfer(quic_server, h3_client)
        self.assertEqual(
            events,
            [
                HeadersReceived(
                    headers=[
                        (b":status", b"200"),
                    ],
                    stream_id=stream_id,
                    stream_ended=False,
                ),
            ],
        )

        return stream_id

    def test_bidirectional_stream(self) -> None:
        """
        A bidirectional WebTransport stream belongs to WebTransport in both
        directions (draft-ietf-webtrans-http3-02 section 2).
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client opens the stream, server replies.
            self._check_bidirectional_stream(h3_client, h3_server, session_id)

    def test_bidirectional_stream_acceptor_receives_reset(self) -> None:
        """
        When the peer resets its half of a stream it opened, HTTP/3 releases the
        stream and leaves our sending half alone.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client opens a bidirectional stream and sends data.
            stream_id = h3_client.create_webtransport_stream(session_id)
            quic_client.send_stream_data(stream_id, b"foo")
            h3_transfer(quic_client, h3_server)
            self.assertIn(stream_id, h3_server._stream)

            # Client resets its half of the stream.
            quic_client.reset_stream(stream_id, error_code=0)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])

            # The stream is no longer tracked, the server's sending part is left
            # open.
            self.assertNotIn(stream_id, h3_server._stream)
            self.assertFalse(quic_server._streams[stream_id].sender.reset_pending)

    def test_bidirectional_stream_opener_receives_reset(self) -> None:
        """
        When the peer resets its half of a stream we opened, HTTP/3 releases the
        stream and leaves our sending half alone.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client opens a bidirectional stream and sends data.
            stream_id = h3_client.create_webtransport_stream(session_id)
            quic_client.send_stream_data(stream_id, b"foo")
            h3_transfer(quic_client, h3_server)
            self.assertIn(stream_id, h3_client._stream)

            # Server resets its half of the stream.
            quic_server.reset_stream(stream_id, error_code=0)
            self.assertEqual(h3_transfer(quic_server, h3_client), [])

            # The stream is no longer tracked, the client's sending part is left
            # open.
            self.assertNotIn(stream_id, h3_client._stream)
            self.assertFalse(quic_client._streams[stream_id].sender.reset_pending)

    def test_bidirectional_stream_opener_receives_stop_sending(self) -> None:
        """
        When the peer stops our half of a stream we opened, HTTP/3 keeps the
        stream until the peer's half ends, so the reply is still payload.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client opens a bidirectional stream and sends data.
            stream_id = h3_client.create_webtransport_stream(session_id)
            quic_client.send_stream_data(stream_id, b"foo")
            h3_transfer(quic_client, h3_server)

            # Server sends STOP_SENDING for the client's half of the stream.
            quic_server.stop_stream(stream_id, error_code=0)
            self.assertEqual(h3_transfer(quic_server, h3_client), [])
            self.assertIn(stream_id, h3_client._stream)

            # Server replies and ends its half.
            quic_server.send_stream_data(stream_id, b"bar", end_stream=True)
            events = h3_transfer(quic_server, h3_client)
            self.assertEqual(
                events,
                [
                    WebTransportStreamDataReceived(
                        data=b"bar",
                        session_id=session_id,
                        stream_ended=True,
                        stream_id=stream_id,
                    )
                ],
            )

            # The stream is no longer tracked.
            self.assertNotIn(stream_id, h3_client._stream)

    def test_bidirectional_stream_server_initiated(self) -> None:
        """
        A server-initiated bidirectional WebTransport stream behaves like a
        client-initiated one.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Server opens the stream, client replies.
            self._check_bidirectional_stream(h3_server, h3_client, session_id)

    def test_bidirectional_stream_signal_after_unknown_frame(self) -> None:
        """
        A WEBTRANSPORT_STREAM signal must be the very first bytes of a stream
        (draft-ietf-webtrans-http3-15 section 4.3).
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client sends an unknown frame, then a WEBTRANSPORT_STREAM signal.
            stream_id = quic_client.get_next_available_stream_id()
            quic_client.send_stream_data(
                stream_id,
                encode_frame(0x21, b"")
                + encode_uint_var(FrameType.WEBTRANSPORT_STREAM)
                + encode_uint_var(session_id),
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_FRAME_ERROR,
                    "WEBTRANSPORT_STREAM must open a request stream",
                ),
            )

    def test_bidirectional_stream_signal_on_connect_stream(self) -> None:
        """
        A WEBTRANSPORT_STREAM signal on the CONNECT stream is a connection
        error (draft-ietf-webtrans-http3-15 section 4.3). It is sent before the
        response, so only the request's HEADERS make it invalid.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Client sends a CONNECT request, then a WEBTRANSPORT_STREAM signal.
            session_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=session_id,
                headers=[
                    (b":method", b"CONNECT"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                    (b":protocol", b"webtransport"),
                ],
            )
            quic_client.send_stream_data(
                session_id,
                encode_uint_var(FrameType.WEBTRANSPORT_STREAM)
                + encode_uint_var(session_id),
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_FRAME_ERROR,
                    "WEBTRANSPORT_STREAM must open a request stream",
                ),
            )

    def test_bidirectional_stream_signal_on_request_stream(self) -> None:
        """
        A WEBTRANSPORT_STREAM signal in reply to a request we sent is a
        connection error (draft-ietf-webtrans-http3-15 section 4.3).
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client sends a request.
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

            # Server replies with a WEBTRANSPORT_STREAM signal.
            quic_server.send_stream_data(
                stream_id,
                encode_uint_var(FrameType.WEBTRANSPORT_STREAM)
                + encode_uint_var(session_id),
            )
            self.assertEqual(h3_transfer(quic_server, h3_client), [])
            self.assertEqual(
                closed(quic_client),
                (
                    ErrorCode.H3_FRAME_ERROR,
                    "WEBTRANSPORT_STREAM must open a request stream",
                ),
            )

    def test_bidirectional_stream_signal_without_webtransport(self) -> None:
        """
        Without WebTransport, a WEBTRANSPORT_STREAM frame on a request stream is
        an unknown frame and is ignored, wherever it appears (RFC 9114 section 9).
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # Client sends WEBTRANSPORT_STREAM frames before and after a request.
            stream_id = quic_client.get_next_available_stream_id()
            quic_client.send_stream_data(
                stream_id, encode_frame(FrameType.WEBTRANSPORT_STREAM, b"foo")
            )
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
            )
            quic_client.send_stream_data(
                stream_id, encode_frame(FrameType.WEBTRANSPORT_STREAM, b"bar")
            )

            # Server only sees the request.
            self.assertEqual(
                h3_transfer(quic_client, h3_server),
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
                    )
                ],
            )
            self.assertIsNone(closed(quic_server))

    def test_control_stream_signal(self) -> None:
        """
        A WEBTRANSPORT_STREAM signal on the control stream is a connection
        error (draft-ietf-webtrans-http3-15 section 4.3).
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client sends a WEBTRANSPORT_STREAM signal on its control stream.
            assert h3_client._local_control_stream_id is not None
            quic_client.send_stream_data(
                h3_client._local_control_stream_id,
                encode_uint_var(FrameType.WEBTRANSPORT_STREAM)
                + encode_uint_var(session_id),
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertEqual(
                closed(quic_server),
                (
                    ErrorCode.H3_FRAME_ERROR,
                    "WEBTRANSPORT_STREAM must open a request stream",
                ),
            )

    def test_control_stream_signal_without_webtransport(self) -> None:
        """
        Without WebTransport, a WEBTRANSPORT_STREAM frame on the control stream
        is an unknown frame and is ignored (RFC 9114 section 9).
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # Client sends a WEBTRANSPORT_STREAM frame on its control stream.
            assert h3_client._local_control_stream_id is not None
            quic_client.send_stream_data(
                h3_client._local_control_stream_id,
                encode_frame(FrameType.WEBTRANSPORT_STREAM, b"foo"),
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertIsNone(closed(quic_server))

    def test_create_webtransport_stream_invalid_session(self) -> None:
        """
        A session ID must be the ID of a client-initiated bidirectional stream,
        which carries the CONNECT request (draft-ietf-webtrans-http3-02 section 2).
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)

            for is_unidirectional in (False, True):
                with self.subTest(is_unidirectional=is_unidirectional):
                    stream_id = quic_client.get_next_available_stream_id(
                        is_unidirectional=is_unidirectional
                    )
                    for session_id in (1, 2, 3):
                        with self.subTest(session_id=session_id):
                            with self.assertRaisesMessage(
                                InvalidStreamTypeError,
                                "WebTransport sessions can only be client-initiated "
                                "bidirectional streams",
                            ):
                                h3_client.create_webtransport_stream(
                                    session_id, is_unidirectional=is_unidirectional
                                )
                    self.assertNotIn(stream_id, quic_client._streams)
                    self.assertNotIn(stream_id, h3_client._stream)

    def test_create_webtransport_stream_out_of_range(self) -> None:
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)

            for is_unidirectional in (False, True):
                with self.subTest(is_unidirectional=is_unidirectional):
                    stream_id = quic_client.get_next_available_stream_id(
                        is_unidirectional=is_unidirectional
                    )
                    for session_id in (-4, UINT_VAR_MAX + 1):
                        with self.subTest(session_id=session_id):
                            with self.assertRaisesMessage(
                                InvalidStreamIdError,
                                "Stream ID must be between 0 and 2^62 - 1",
                            ):
                                h3_client.create_webtransport_stream(
                                    session_id, is_unidirectional=is_unidirectional
                                )
                    self.assertNotIn(stream_id, quic_client._streams)
                    self.assertNotIn(stream_id, h3_client._stream)

    def test_create_webtransport_stream_without_webtransport(self) -> None:
        """
        Without WebTransport, no WebTransport stream can be created.
        """
        with h3_client_and_server() as (quic_client, quic_server):
            h3_client = H3Connection(quic_client)

            for is_unidirectional in (False, True):
                with self.subTest(is_unidirectional=is_unidirectional):
                    stream_id = quic_client.get_next_available_stream_id(
                        is_unidirectional=is_unidirectional
                    )
                    with self.assertRaisesMessage(
                        InvalidStreamTypeError, "WebTransport is not enabled"
                    ):
                        h3_client.create_webtransport_stream(
                            0, is_unidirectional=is_unidirectional
                        )
                    self.assertNotIn(stream_id, quic_client._streams)
                    self.assertNotIn(stream_id, h3_client._stream)

    def test_stream_fragmented_prefix(self) -> None:
        """
        A WebTransport stream's prefix, the frame type or stream type then the
        session ID, can be received one byte at a time, and its data is passed
        on as each byte arrives.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            for is_unidirectional in (False, True):
                with self.subTest(is_unidirectional=is_unidirectional):
                    # Client opens a stream and ends its half.
                    stream_id = h3_client.create_webtransport_stream(
                        session_id, is_unidirectional=is_unidirectional
                    )
                    quic_client.send_stream_data(stream_id, b"foo", end_stream=True)

                    # Server receives the data one byte at a time.
                    events = h3_transfer(quic_client, h3_server, split=True)
                    self.assertEqual(
                        events,
                        [
                            WebTransportStreamDataReceived(
                                data=data,
                                session_id=session_id,
                                stream_ended=stream_ended,
                                stream_id=stream_id,
                            )
                            for data, stream_ended in (
                                (b"f", False),
                                (b"o", False),
                                (b"o", False),
                                (b"", True),
                            )
                        ],
                    )

                    # The stream is no longer tracked.
                    self.assertNotIn(stream_id, h3_server._stream)

    def test_unidirectional_stream(self) -> None:
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client opens a unidirectional stream and ends it.
            stream_id = h3_client.create_webtransport_stream(
                session_id, is_unidirectional=True
            )
            quic_client.send_stream_data(stream_id, b"foo", end_stream=True)

            # Server receives the data.
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    WebTransportStreamDataReceived(
                        data=b"foo",
                        session_id=session_id,
                        stream_ended=True,
                        stream_id=stream_id,
                    )
                ],
            )

            # The stream is no longer tracked.
            self.assertNotIn(stream_id, h3_server._stream)

    def test_unidirectional_stream_headers(self) -> None:
        """
        HTTP messages cannot be sent on a WebTransport unidirectional stream.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)
            session_id = self._make_session(h3_client, h3_server)

            stream_id = h3_server.create_webtransport_stream(
                session_id, is_unidirectional=True
            )
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
                h3_server.send_data(stream_id=stream_id, data=b"hello", end_stream=True)
            self.assertNotIn(stream_id, h3_server._stream)

    def test_unidirectional_stream_reset(self) -> None:
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client opens a unidirectional stream and sends data.
            stream_id = h3_client.create_webtransport_stream(
                session_id, is_unidirectional=True
            )
            quic_client.send_stream_data(stream_id, b"foo")
            h3_transfer(quic_client, h3_server)
            self.assertIn(stream_id, h3_server._stream)

            # Client resets the stream.
            quic_client.reset_stream(stream_id, error_code=0)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])

            # The stream is no longer tracked.
            self.assertNotIn(stream_id, h3_server._stream)

    def test_unidirectional_stream_without_webtransport(self) -> None:
        """
        Without WebTransport, a WebTransport unidirectional stream has an
        unknown stream type and its data is discarded (RFC 9114 section 6.2).
        """
        with h3_client_and_server() as (quic_client, quic_server):
            H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            # Client opens a WebTransport unidirectional stream and ends it.
            stream_id = quic_client.get_next_available_stream_id(is_unidirectional=True)
            quic_client.send_stream_data(
                stream_id,
                encode_uint_var(StreamType.WEBTRANSPORT) + encode_uint_var(0) + b"foo",
                end_stream=True,
            )
            self.assertEqual(h3_transfer(quic_client, h3_server), [])
            self.assertIsNone(closed(quic_server))

            # The stream is no longer tracked.
            self.assertNotIn(stream_id, h3_server._stream)

    def test_datagram(self) -> None:
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # create session
            session_id = self._make_session(h3_client, h3_server)

            # send datagram on a server-initiated stream
            with self.assertRaisesMessage(
                InvalidStreamTypeError,
                "Datagrams can only be sent for client-initiated bidirectional streams",
            ):
                h3_client.send_datagram(data=b"foo", stream_id=1)

            # send datagram
            h3_client.send_datagram(data=b"foo", stream_id=session_id)

            # receive datagram
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [DatagramReceived(data=b"foo", stream_id=session_id)],
            )

    def test_datagram_out_of_range(self) -> None:
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            for stream_id in (-4, UINT_VAR_MAX + 1):
                with self.subTest(stream_id=stream_id):
                    with self.assertRaisesMessage(
                        InvalidStreamIdError, "Stream ID must be between 0 and 2^62 - 1"
                    ):
                        h3_client.send_datagram(data=b"foo", stream_id=stream_id)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])

            # The largest client-initiated bidirectional stream ID is sent.
            h3_client.send_datagram(data=b"foo", stream_id=UINT_VAR_MAX - 3)
            self.assertEqual(
                h3_transfer(quic_client, h3_server),
                [DatagramReceived(data=b"foo", stream_id=UINT_VAR_MAX - 3)],
            )

    def test_handle_datagram_truncated(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive a datagram with a truncated session ID
            h3_server.handle_event(DatagramFrameReceived(data=b"\xff"))
            self.assertEqual(
                closed(quic_server),
                (ErrorCode.H3_DATAGRAM_ERROR, "Could not parse quarter stream ID"),
            )
