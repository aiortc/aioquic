from unittest import TestCase

from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
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

    def test_datagram(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            # create session
            session_id = self._make_session(h3_client, h3_server)

            # send datagram
            h3_client.send_datagram(data=b"foo", flow_id=session_id)

            # receive datagram
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [DatagramReceived(data=b"foo", flow_id=session_id)],
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
            (
                ErrorCode.H3_GENERAL_PROTOCOL_ERROR,
                "Could not parse flow ID",
            ),
        )
