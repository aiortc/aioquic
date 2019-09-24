import asyncio
import binascii
import random
import socket
from unittest import TestCase
from unittest.mock import patch

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicProtocolVersion

from .utils import SERVER_CERTFILE, SERVER_KEYFILE, generate_ec_certificate, run

real_sendto = socket.socket.sendto


def sendto_with_loss(self, data, addr=None):
    """
    Simulate 25% packet loss.
    """
    if random.random() > 0.25:
        real_sendto(self, data, addr)


class SessionTicketStore:
    def __init__(self):
        self.tickets = {}

    def add(self, ticket):
        self.tickets[ticket.ticket] = ticket

    def pop(self, label):
        return self.tickets.pop(label, None)


async def run_client(host, port=4433, request=b"ping", **kwargs):
    async with connect(host, port, **kwargs) as client:
        reader, writer = await client.create_stream()
        assert writer.can_write_eof() is True
        assert writer.get_extra_info("stream_id") == 0

        writer.write(request)
        writer.write_eof()

        return await reader.read()


def handle_stream(reader, writer):
    async def serve():
        data = await reader.read()
        writer.write(bytes(reversed(data)))
        writer.write_eof()

    asyncio.ensure_future(serve())


async def run_server(configuration=None, **kwargs):
    if configuration is None:
        configuration = QuicConfiguration(is_client=False)
        configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    return await serve(
        host="::",
        port="4433",
        configuration=configuration,
        stream_handler=handle_stream,
        **kwargs
    )


class HighLevelTest(TestCase):
    def test_connect_and_serve(self):
        server, response = run(asyncio.gather(run_server(), run_client("127.0.0.1")))
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_and_serve_ec_certificate(self):
        certificate, private_key = generate_ec_certificate(common_name="localhost")

        server, response = run(
            asyncio.gather(
                run_server(
                    configuration=QuicConfiguration(
                        certificate=certificate,
                        private_key=private_key,
                        is_client=False,
                    )
                ),
                run_client("127.0.0.1"),
            )
        )

        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_and_serve_large(self):
        """
        Transfer enough data to require raising MAX_DATA and MAX_STREAM_DATA.
        """
        data = b"Z" * 2097152
        server, response = run(
            asyncio.gather(run_server(), run_client("127.0.0.1", request=data))
        )
        self.assertEqual(response, data)
        server.close()

    def test_connect_and_serve_writelines(self):
        async def run_client_writelines(host, port=4433):
            async with connect(host, port) as client:
                reader, writer = await client.create_stream()
                assert writer.can_write_eof() is True

                writer.writelines([b"01234567", b"89012345"])
                writer.write_eof()

                return await reader.read()

        server, response = run(
            asyncio.gather(run_server(), run_client_writelines("127.0.0.1"))
        )
        self.assertEqual(response, b"5432109876543210")
        server.close()

    @patch("socket.socket.sendto", new_callable=lambda: sendto_with_loss)
    def test_connect_and_serve_with_packet_loss(self, mock_sendto):
        """
        This test ensures handshake success and stream data is successfully sent
        and received in the presence of packet loss (randomized 25% in each direction).
        """
        data = b"Z" * 65536

        server_configuration = QuicConfiguration(
            idle_timeout=300.0, is_client=False, quic_logger=QuicLogger()
        )
        server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)

        server, response = run(
            asyncio.gather(
                run_server(configuration=server_configuration, stateless_retry=True),
                run_client(
                    "127.0.0.1",
                    configuration=QuicConfiguration(
                        is_client=True, idle_timeout=300.0, quic_logger=QuicLogger()
                    ),
                    request=data,
                ),
            )
        )
        self.assertEqual(response, data)
        server.close()

    def test_connect_and_serve_with_session_ticket(self):
        client_ticket = None
        store = SessionTicketStore()

        def save_ticket(t):
            nonlocal client_ticket
            client_ticket = t

        # first request
        server, response = run(
            asyncio.gather(
                run_server(session_ticket_handler=store.add),
                run_client("127.0.0.1", session_ticket_handler=save_ticket),
            )
        )
        self.assertEqual(response, b"gnip")
        server.close()

        self.assertIsNotNone(client_ticket)

        # second request
        server, response = run(
            asyncio.gather(
                run_server(session_ticket_fetcher=store.pop),
                run_client(
                    "127.0.0.1",
                    configuration=QuicConfiguration(
                        is_client=True, session_ticket=client_ticket
                    ),
                ),
            )
        )
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_and_serve_with_sni(self):
        server, response = run(asyncio.gather(run_server(), run_client("localhost")))
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_and_serve_with_stateless_retry(self):
        server, response = run(
            asyncio.gather(run_server(stateless_retry=True), run_client("127.0.0.1"))
        )
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_and_serve_with_stateless_retry_bad_original_connection_id(self):
        """
        If the server's transport parameters do not have the correct
        original_connection_id the connection fail.
        """

        def create_protocol(*args, **kwargs):
            protocol = QuicConnectionProtocol(*args, **kwargs)
            protocol._quic._original_connection_id = None
            return protocol

        server = run(run_server(create_protocol=create_protocol, stateless_retry=True))
        with self.assertRaises(ConnectionError):
            run(run_client("127.0.0.1"))
        server.close()

    @patch("aioquic.quic.retry.QuicRetryTokenHandler.validate_token")
    def test_connect_and_serve_with_stateless_retry_bad(self, mock_validate):
        mock_validate.side_effect = ValueError("Decryption failed.")

        server = run(run_server(stateless_retry=True))
        with self.assertRaises(ConnectionError):
            run(
                run_client(
                    "127.0.0.1",
                    configuration=QuicConfiguration(is_client=True, idle_timeout=4.0),
                )
            )
        server.close()

    def test_connect_and_serve_with_version_negotiation(self):
        server, response = run(
            asyncio.gather(
                run_server(),
                run_client(
                    "127.0.0.1",
                    configuration=QuicConfiguration(
                        is_client=True,
                        quic_logger=QuicLogger(),
                        supported_versions=[0x1A2A3A4A, QuicProtocolVersion.DRAFT_23],
                    ),
                ),
            )
        )
        self.assertEqual(response, b"gnip")
        server.close()

    def test_connect_timeout(self):
        with self.assertRaises(ConnectionError):
            run(
                run_client(
                    "127.0.0.1",
                    port=4400,
                    configuration=QuicConfiguration(is_client=True, idle_timeout=5),
                )
            )

    def test_change_connection_id(self):
        async def run_client_key_update(host, port=4433):
            async with connect(host, port) as client:
                await client.ping()
                client.change_connection_id()
                await client.ping()

        server, _ = run(
            asyncio.gather(
                run_server(stateless_retry=False), run_client_key_update("127.0.0.1")
            )
        )
        server.close()

    def test_key_update(self):
        async def run_client_key_update(host, port=4433):
            async with connect(host, port) as client:
                await client.ping()
                client.request_key_update()
                await client.ping()

        server, _ = run(
            asyncio.gather(
                run_server(stateless_retry=False), run_client_key_update("127.0.0.1")
            )
        )
        server.close()

    def test_ping(self):
        async def run_client_ping(host, port=4433):
            async with connect(host, port) as client:
                await client.ping()
                await client.ping()

        server, _ = run(
            asyncio.gather(
                run_server(stateless_retry=False), run_client_ping("127.0.0.1")
            )
        )
        server.close()

    def test_server_receives_garbage(self):
        server = run(run_server(stateless_retry=False))
        server.datagram_received(binascii.unhexlify("c00000000080"), ("1.2.3.4", 1234))
        server.close()
