from unittest import TestCase

from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.h3.exceptions import InvalidStreamTypeError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived

from .test_h3 import (
    FakeQuicConnection,
    h3_client_and_server,
    h3_fake_client_and_server,
    h3_transfer,
)

QUIC_CONFIGURATION_OPTIONS = {
    "alpn_protocols": H3_ALPN,
    "max_datagram_frame_size": 65536,
}


class WebTransportTest(TestCase):
    def _make_session(self, h3_client, h3_server):
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

    def test_bidirectional_stream(self):
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

    def test_bidirectional_stream_client_receives(self):
        """
        Data the server sends on a client-initiated WebTransport stream is
        payload, not HTTP/3 frames (draft-ietf-webtrans-http3 section 4.3).
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # Create session.
            session_id = self._make_session(h3_client, h3_server)

            # Client opens a bidirectional stream, server receives it.
            stream_id = h3_client.create_webtransport_stream(session_id)
            quic_client.send_stream_data(stream_id, b"foo", end_stream=True)
            h3_transfer(quic_client, h3_server)

            # Server replies on the same stream, client receives the payload.
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

    def test_bidirectional_stream_fragmented_frame(self):
        with h3_fake_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
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

    def test_bidirectional_stream_reset(self):
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

    def test_bidirectional_stream_server_initiated(self):
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

    def test_unidirectional_stream(self):
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

    def test_unidirectional_stream_fragmented_frame(self):
        with h3_fake_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
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

    def test_unidirectional_stream_reset(self):
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

    def test_datagram(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # create session
            session_id = self._make_session(h3_client, h3_server)

            # send datagram on a server-initiated stream
            with self.assertRaises(InvalidStreamTypeError):
                h3_client.send_datagram(data=b"foo", stream_id=1)

            # send datagram
            h3_client.send_datagram(data=b"foo", stream_id=session_id)

            # receive datagram
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [DatagramReceived(data=b"foo", stream_id=session_id)],
            )

    def test_handle_datagram_truncated(self):
        quic_server = FakeQuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
        h3_server = H3Connection(quic_server)

        # receive a datagram with a truncated session ID
        h3_server.handle_event(DatagramFrameReceived(data=b"\xff"))
        self.assertEqual(
            quic_server.closed,
            (ErrorCode.H3_DATAGRAM_ERROR, "Could not parse quarter stream ID"),
        )
