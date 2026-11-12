from aioquic.buffer import UINT_VAR_MAX, encode_uint_var
from aioquic.h3.connection import H3_ALPN, ErrorCode, FrameType, H3Connection
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
        Both halves of a bidirectional WebTransport stream carry payload, not
        HTTP/3 frames (draft-ietf-webtrans-http3 section 4.3).
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

    def test_bidirectional_stream_signal_on_connect_stream(self) -> None:
        """
        A WEBTRANSPORT_STREAM signal on the CONNECT stream does not end the
        sending half of the session's stream, even before the server responds.
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
            h3_transfer(quic_client, h3_server)

            # The session's stream is still tracked.
            self.assertIn(session_id, h3_server._stream)

            # The server can still respond on the session's stream.
            h3_server.send_headers(stream_id=session_id, headers=[(b":status", b"200")])
            h3_server.send_data(session_id, b"", end_stream=True)

    def test_bidirectional_stream_signal_on_request_stream(self) -> None:
        """
        A WEBTRANSPORT_STREAM signal on a request stream we opened does not end
        the sending half of the request stream.
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

            # Server sends a WEBTRANSPORT_STREAM signal on the request stream.
            quic_server.send_stream_data(
                stream_id,
                encode_uint_var(FrameType.WEBTRANSPORT_STREAM)
                + encode_uint_var(session_id),
            )
            h3_transfer(quic_server, h3_client)

            # The request stream is still tracked.
            self.assertIn(stream_id, h3_client._stream)

            # The client can still end the request stream.
            h3_client.send_data(stream_id, b"", end_stream=True)

    def test_create_webtransport_stream_invalid_session(self) -> None:
        """
        A session ID must be the ID of a client-initiated bidirectional stream,
        which carries the CONNECT request (draft-ietf-webtrans-http3).
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
