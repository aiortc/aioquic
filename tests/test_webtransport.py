from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.h3.exceptions import InvalidStreamTypeError
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
                    push_id=None,
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
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # create session
            session_id = self._make_session(h3_client, h3_server)

            # send data on bidirectional stream
            stream_id = h3_client.create_webtransport_stream(session_id)
            quic_client.send_stream_data(stream_id, b"foo", end_stream=True)

            # receive data
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

    def test_bidirectional_stream_fragmented_frame(self) -> None:
        """
        A bidirectional WebTransport stream's frame header and session ID can be
        received one byte at a time, and its data is passed on as each byte
        arrives.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # create session
            session_id = self._make_session(h3_client, h3_server)

            # send data on bidirectional stream
            stream_id = h3_client.create_webtransport_stream(session_id)
            quic_client.send_stream_data(stream_id, b"foo", end_stream=True)

            # receive data
            events = h3_transfer(quic_client, h3_server, split=True)
            self.assertEqual(
                events,
                [
                    WebTransportStreamDataReceived(
                        data=b"f",
                        session_id=session_id,
                        stream_ended=False,
                        stream_id=stream_id,
                    ),
                    WebTransportStreamDataReceived(
                        data=b"o",
                        session_id=session_id,
                        stream_ended=False,
                        stream_id=stream_id,
                    ),
                    WebTransportStreamDataReceived(
                        data=b"o",
                        session_id=session_id,
                        stream_ended=False,
                        stream_id=stream_id,
                    ),
                    WebTransportStreamDataReceived(
                        data=b"",
                        session_id=session_id,
                        stream_ended=True,
                        stream_id=stream_id,
                    ),
                ],
            )

    def test_bidirectional_stream_reset(self) -> None:
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Send data on bidirectional stream, then reset it.
            stream_id = h3_client.create_webtransport_stream(session_id)
            quic_client.send_stream_data(stream_id, b"foo")
            h3_transfer(quic_client, h3_server)
            quic_client.reset_stream(stream_id, error_code=0)
            self.assertEqual(h3_transfer(quic_client, h3_server), [])

            # The server's sending part of the stream is left open.
            self.assertIn(stream_id, h3_server._stream)
            self.assertFalse(quic_server._streams[stream_id].sender.reset_pending)

    def test_bidirectional_stream_server_initiated(self) -> None:
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # create session
            session_id = self._make_session(h3_client, h3_server)

            # send data on bidirectional stream
            stream_id = h3_server.create_webtransport_stream(session_id)
            quic_server.send_stream_data(stream_id, b"foo", end_stream=True)

            # receive data
            events = h3_transfer(quic_server, h3_client)
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

    def test_unidirectional_stream(self) -> None:
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # create session
            session_id = self._make_session(h3_client, h3_server)

            # send data on unidirectional stream
            stream_id = h3_client.create_webtransport_stream(
                session_id, is_unidirectional=True
            )
            quic_client.send_stream_data(stream_id, b"foo", end_stream=True)

            # receive data
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

            # the stream is no longer tracked
            self.assertNotIn(stream_id, h3_server._stream)

    def test_unidirectional_stream_fragmented_frame(self) -> None:
        """
        A unidirectional WebTransport stream's stream type and session ID can be
        received one byte at a time, and its data is passed on as each byte
        arrives.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # create session
            session_id = self._make_session(h3_client, h3_server)

            # send data on unidirectional stream
            stream_id = h3_client.create_webtransport_stream(
                session_id, is_unidirectional=True
            )
            quic_client.send_stream_data(stream_id, b"foo", end_stream=True)

            # receive data
            events = h3_transfer(quic_client, h3_server, split=True)
            self.assertEqual(
                events,
                [
                    WebTransportStreamDataReceived(
                        data=b"f",
                        session_id=session_id,
                        stream_ended=False,
                        stream_id=stream_id,
                    ),
                    WebTransportStreamDataReceived(
                        data=b"o",
                        session_id=session_id,
                        stream_ended=False,
                        stream_id=stream_id,
                    ),
                    WebTransportStreamDataReceived(
                        data=b"o",
                        session_id=session_id,
                        stream_ended=False,
                        stream_id=stream_id,
                    ),
                    WebTransportStreamDataReceived(
                        data=b"",
                        session_id=session_id,
                        stream_ended=True,
                        stream_id=stream_id,
                    ),
                ],
            )

            # the stream is no longer tracked
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
                "Headers and data can only be sent on request and push streams",
            ):
                h3_server.send_headers(
                    stream_id=stream_id, headers=[(b":status", b"200")]
                )
            with self.assertRaisesMessage(
                InvalidStreamTypeError,
                "Headers and data can only be sent on request and push streams",
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

            # Send data on unidirectional stream, then reset it.
            stream_id = h3_client.create_webtransport_stream(
                session_id, is_unidirectional=True
            )
            quic_client.send_stream_data(stream_id, b"foo")
            h3_transfer(quic_client, h3_server)
            self.assertIn(stream_id, h3_server._stream)

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

    def test_handle_datagram_truncated(self) -> None:
        with h3_client_and_server() as (quic_client, quic_server):
            h3_server = H3Connection(quic_server)

            # receive a datagram with a truncated session ID
            h3_server.handle_event(DatagramFrameReceived(data=b"\xff"))
            self.assertEqual(
                closed(quic_server),
                (ErrorCode.H3_DATAGRAM_ERROR, "Could not parse quarter stream ID"),
            )
