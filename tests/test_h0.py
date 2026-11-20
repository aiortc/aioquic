import contextlib

from aioquic.buffer import UINT_VAR_MAX
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.h3.exceptions import (
    InvalidConnectionStateError,
    InvalidStreamIdError,
    InvalidStreamStateError,
)
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

from .test_connection import client_and_server, transfer
from .utils import TestCase


def h0_client_and_server() -> contextlib.AbstractContextManager[
    tuple[QuicConnection, QuicConnection]
]:
    return client_and_server(
        client_options={"alpn_protocols": H0_ALPN},
        server_options={"alpn_protocols": H0_ALPN},
    )


def h0_transfer(
    quic_sender: QuicConnection, h0_receiver: H0Connection
) -> list[H3Event]:
    quic_receiver = h0_receiver._quic
    transfer(quic_sender, quic_receiver)

    # process QUIC events
    http_events = []
    event = quic_receiver.next_event()
    while event is not None:
        http_events.extend(h0_receiver.handle_event(event))
        event = quic_receiver.next_event()
    return http_events


def send_request(h0_client: H0Connection, h0_server: H0Connection) -> int:
    """
    Send a request from `h0_client` to `h0_server` and return its stream ID.
    """
    stream_id = h0_client.quic_connection.get_next_available_stream_id()
    h0_client.send_headers(
        stream_id=stream_id,
        headers=[(b":method", b"GET"), (b":path", b"/")],
        end_stream=True,
    )
    h0_transfer(h0_client.quic_connection, h0_server)
    return stream_id


class H0ConnectionTest(TestCase):
    def test_connect(self) -> None:
        with h0_client_and_server() as (quic_client, quic_server):
            h0_client = H0Connection(quic_client)
            h0_server = H0Connection(quic_server)

            # send request
            stream_id = quic_client.get_next_available_stream_id()
            h0_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
            )
            h0_client.send_data(stream_id=stream_id, data=b"", end_stream=True)

            # receive request
            events = h0_transfer(quic_client, h0_server)
            self.assertEqual(len(events), 2)

            assert isinstance(events[0], HeadersReceived)
            self.assertEqual(
                events[0].headers, [(b":method", b"GET"), (b":path", b"/")]
            )
            self.assertEqual(events[0].stream_id, stream_id)
            self.assertEqual(events[0].stream_ended, False)

            assert isinstance(events[1], DataReceived)
            self.assertEqual(events[1].data, b"")
            self.assertEqual(events[1].stream_id, stream_id)
            self.assertEqual(events[1].stream_ended, True)

            # send response
            h0_server.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"text/html; charset=utf-8"),
                ],
            )
            h0_server.send_data(
                stream_id=stream_id,
                data=b"<html><body>hello</body></html>",
                end_stream=True,
            )

            # receive response
            events = h0_transfer(quic_server, h0_client)
            self.assertEqual(len(events), 2)

            assert isinstance(events[0], HeadersReceived)
            self.assertEqual(events[0].headers, [])
            self.assertEqual(events[0].stream_id, stream_id)
            self.assertEqual(events[0].stream_ended, False)

            assert isinstance(events[1], DataReceived)
            self.assertEqual(events[1].data, b"<html><body>hello</body></html>")
            self.assertEqual(events[1].stream_id, stream_id)
            self.assertEqual(events[1].stream_ended, True)

    def test_headers_only(self) -> None:
        with h0_client_and_server() as (quic_client, quic_server):
            h0_client = H0Connection(quic_client)
            h0_server = H0Connection(quic_server)

            # send request
            stream_id = quic_client.get_next_available_stream_id()
            h0_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"HEAD"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
                end_stream=True,
            )

            # receive request
            events = h0_transfer(quic_client, h0_server)
            self.assertEqual(len(events), 2)

            assert isinstance(events[0], HeadersReceived)
            self.assertEqual(
                events[0].headers, [(b":method", b"HEAD"), (b":path", b"/")]
            )
            self.assertEqual(events[0].stream_id, stream_id)
            self.assertEqual(events[0].stream_ended, False)

            assert isinstance(events[1], DataReceived)
            self.assertEqual(events[1].data, b"")
            self.assertEqual(events[1].stream_id, stream_id)
            self.assertEqual(events[1].stream_ended, True)

            # send response
            h0_server.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"text/html; charset=utf-8"),
                ],
                end_stream=True,
            )

            # receive response
            events = h0_transfer(quic_server, h0_client)
            self.assertEqual(len(events), 2)

            assert isinstance(events[0], HeadersReceived)
            self.assertEqual(events[0].headers, [])
            self.assertEqual(events[0].stream_id, stream_id)
            self.assertEqual(events[0].stream_ended, False)

            assert isinstance(events[1], DataReceived)
            self.assertEqual(events[1].data, b"")
            self.assertEqual(events[1].stream_id, stream_id)
            self.assertEqual(events[1].stream_ended, True)

    def test_fragmented_request(self) -> None:
        with h0_client_and_server() as (quic_client, quic_server):
            h0_server = H0Connection(quic_server)
            stream_id = 0

            # receive first fragment of the request
            events = h0_server.handle_event(
                StreamDataReceived(
                    data=b"GET /012", end_stream=False, stream_id=stream_id
                )
            )
            self.assertEqual(len(events), 0)

            # receive second fragment of the request
            events = h0_server.handle_event(
                StreamDataReceived(
                    data=b"34567890", end_stream=False, stream_id=stream_id
                )
            )

            # receive final fragment of the request
            events = h0_server.handle_event(
                StreamDataReceived(
                    data=b"123456\r\n", end_stream=True, stream_id=stream_id
                )
            )
            self.assertEqual(len(events), 2)

            assert isinstance(events[0], HeadersReceived)
            self.assertEqual(
                events[0].headers,
                [(b":method", b"GET"), (b":path", b"/01234567890123456")],
            )
            self.assertEqual(events[0].stream_id, stream_id)
            self.assertEqual(events[0].stream_ended, False)

            assert isinstance(events[1], DataReceived)
            self.assertEqual(events[1].data, b"")
            self.assertEqual(events[1].stream_id, stream_id)
            self.assertEqual(events[1].stream_ended, True)

    def test_quic_connection(self) -> None:
        with h0_client_and_server() as (quic_client, quic_server):
            h0_client = H0Connection(quic_client)
            self.assertIs(h0_client.quic_connection, quic_client)

    def test_send_after_connection_closed(self) -> None:
        """
        Once the connection is closing, headers and data are refused before
        anything is queued. A stream ID out of range is still reported as such.
        """
        with h0_client_and_server() as (quic_client, quic_server):
            h0_client = H0Connection(quic_client)
            stream_id = quic_client.get_next_available_stream_id()

            quic_client.close()
            with self.assertRaisesMessage(
                InvalidConnectionStateError,
                "Cannot send once the connection is closing",
            ):
                h0_client.send_headers(
                    stream_id=stream_id,
                    headers=[(b":method", b"GET"), (b":path", b"/")],
                )
            with self.assertRaisesMessage(
                InvalidConnectionStateError,
                "Cannot send once the connection is closing",
            ):
                h0_client.send_data(stream_id=stream_id, data=b"", end_stream=True)
            self.assertNotIn(stream_id, quic_client._streams)

            for invalid_stream_id in (-4, UINT_VAR_MAX + 1):
                with self.subTest(stream_id=invalid_stream_id):
                    with self.assertRaisesMessage(
                        InvalidStreamIdError, "Stream ID must be between 0 and 2^62 - 1"
                    ):
                        h0_client.send_data(
                            stream_id=invalid_stream_id, data=b"", end_stream=True
                        )

    def test_send_on_stream_not_open(self) -> None:
        """
        Headers and data are refused on a stream which is not open: one the peer
        has not opened, or one which was ended, reset, or stopped by the peer.
        """
        with h0_client_and_server() as (quic_client, quic_server):
            h0_client = H0Connection(quic_client)
            h0_server = H0Connection(quic_server)
            ended_stream_id = send_request(h0_client, h0_server)
            reset_stream_id = send_request(h0_client, h0_server)
            stopped_stream_id = send_request(h0_client, h0_server)

            h0_server.send_data(stream_id=ended_stream_id, data=b"", end_stream=True)
            quic_server.reset_stream(reset_stream_id, error_code=0)
            quic_client.stop_stream(stopped_stream_id, error_code=0)
            h0_transfer(quic_client, h0_server)

            for stream_id in (
                quic_client.get_next_available_stream_id(),
                ended_stream_id,
                reset_stream_id,
                stopped_stream_id,
            ):
                with self.subTest(stream_id=stream_id):
                    with self.assertRaisesMessage(
                        InvalidStreamStateError,
                        "Cannot send on a stream which is not open",
                    ):
                        h0_server.send_headers(
                            stream_id=stream_id, headers=[(b":status", b"200")]
                        )
                    with self.assertRaisesMessage(
                        InvalidStreamStateError,
                        "Cannot send on a stream which is not open",
                    ):
                        h0_server.send_data(
                            stream_id=stream_id, data=b"hello", end_stream=True
                        )
