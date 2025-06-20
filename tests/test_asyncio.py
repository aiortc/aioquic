import asyncio
import binascii
import contextlib
import random
import socket
from typing import AsyncGenerator, Optional
from unittest import TestCase, skipIf
from unittest.mock import AsyncMock, MagicMock, patch

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger
from cryptography.hazmat.primitives import serialization

from .utils import (
    SERVER_CACERTFILE,
    SERVER_CERTFILE,
    SERVER_COMBINEDFILE,
    SERVER_KEYFILE,
    SKIP_TESTS,
    asynctest,
    generate_ec_certificate,
    generate_ed448_certificate,
    generate_ed25519_certificate,
    generate_rsa_certificate,
)

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


def handle_stream(reader, writer):
    async def serve():
        data = await reader.read()
        writer.write(bytes(reversed(data)))
        writer.write_eof()

    asyncio.ensure_future(serve())


class HighLevelTest(TestCase):
    def setUp(self):
        self.bogus_port = 1024
        self.server_host = "localhost"

    async def run_client(
        self,
        *,
        port: int,
        host=None,
        cadata=None,
        cafile=SERVER_CACERTFILE,
        configuration=None,
        request=b"ping",
        **kwargs,
    ) -> bytes:
        if host is None:
            host = self.server_host
        if configuration is None:
            configuration = QuicConfiguration(is_client=True)
        configuration.load_verify_locations(cadata=cadata, cafile=cafile)
        async with connect(host, port, configuration=configuration, **kwargs) as client:
            # waiting for connected when connected returns immediately
            await client.wait_connected()

            reader, writer = await client.create_stream()
            self.assertEqual(writer.can_write_eof(), True)
            self.assertEqual(writer.get_extra_info("stream_id"), 0)

            writer.write(request)
            writer.write_eof()

            response = await reader.read()

            # explicit no-op close to test that multiple closes are harmless.
            writer.close()

        # waiting for closed when closed returns immediately
        await client.wait_closed()

        return response

    @contextlib.asynccontextmanager
    async def run_server(
        self, configuration: Optional[QuicConfiguration] = None, host="::", **kwargs
    ) -> AsyncGenerator[int, None]:
        if configuration is None:
            configuration = QuicConfiguration(is_client=False)
            configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        server = await serve(
            host=host,
            port=0,
            configuration=configuration,
            stream_handler=handle_stream,
            **kwargs,
        )
        try:
            yield server._transport.get_extra_info("sockname")[1]
        finally:
            server.close()

    @asynctest
    async def test_connect_and_serve(self) -> None:
        async with self.run_server() as server_port:
            response = await self.run_client(port=server_port)
            self.assertEqual(response, b"gnip")

    @asynctest
    async def test_connect_and_serve_ipv4(self) -> None:
        certificate, private_key = generate_rsa_certificate(
            alternative_names=["localhost", "127.0.0.1"], common_name="localhost"
        )
        async with self.run_server(
            configuration=QuicConfiguration(
                certificate=certificate,
                private_key=private_key,
                is_client=False,
            ),
            host="0.0.0.0",
        ) as server_port:
            response = await self.run_client(
                cadata=certificate.public_bytes(serialization.Encoding.PEM),
                cafile=None,
                host="127.0.0.1",
                port=server_port,
            )
            self.assertEqual(response, b"gnip")

    @skipIf("ipv6" in SKIP_TESTS, "Skipping IPv6 tests")
    @asynctest
    async def test_connect_and_serve_ipv6(self) -> None:
        certificate, private_key = generate_rsa_certificate(
            alternative_names=["localhost", "::1"], common_name="localhost"
        )
        async with self.run_server(
            configuration=QuicConfiguration(
                certificate=certificate,
                private_key=private_key,
                is_client=False,
            ),
            host="::",
        ) as server_port:
            response = await self.run_client(
                cadata=certificate.public_bytes(serialization.Encoding.PEM),
                cafile=None,
                host="::1",
                port=server_port,
            )
            self.assertEqual(response, b"gnip")

    async def _test_connect_and_serve_with_certificate(
        self, certificate, private_key
    ) -> None:
        async with self.run_server(
            configuration=QuicConfiguration(
                certificate=certificate,
                private_key=private_key,
                is_client=False,
            )
        ) as server_port:
            response = await self.run_client(
                cadata=certificate.public_bytes(serialization.Encoding.PEM),
                cafile=None,
                port=server_port,
            )
            self.assertEqual(response, b"gnip")

    @asynctest
    async def test_connect_and_serve_with_ec_certificate(self):
        await self._test_connect_and_serve_with_certificate(
            *generate_ec_certificate(
                alternative_names=["localhost"], common_name="localhost"
            )
        )

    @asynctest
    async def test_connect_and_serve_with_ed25519_certificate(self):
        await self._test_connect_and_serve_with_certificate(
            *generate_ed25519_certificate(
                alternative_names=["localhost"], common_name="localhost"
            )
        )

    @skipIf("ed448" in SKIP_TESTS, "Skipping ed448 tests")
    @asynctest
    async def test_connect_and_serve_with_ed448_certificate(self):
        await self._test_connect_and_serve_with_certificate(
            *generate_ed448_certificate(
                alternative_names=["localhost"], common_name="localhost"
            )
        )

    @asynctest
    async def test_connect_and_serve_with_rsa_certificate(self):
        await self._test_connect_and_serve_with_certificate(
            *generate_rsa_certificate(
                alternative_names=["localhost"], common_name="localhost"
            )
        )

    @asynctest
    async def test_connect_and_serve_large(self):
        """
        Transfer enough data to require raising MAX_DATA and MAX_STREAM_DATA.
        """
        data = b"Z" * 2097152
        async with self.run_server() as server_port:
            response = await self.run_client(port=server_port, request=data)
            self.assertEqual(response, data)

    @asynctest
    async def test_connect_and_serve_without_client_configuration(self):
        async with self.run_server() as server_port:
            with self.assertRaises(ConnectionError):
                async with connect(self.server_host, server_port) as client:
                    await client.ping()

    @asynctest
    async def test_connect_and_serve_writelines(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                reader, writer = await client.create_stream()
                assert writer.can_write_eof() is True

                writer.writelines([b"01234567", b"89012345"])
                writer.write_eof()

                response = await reader.read()
                self.assertEqual(response, b"5432109876543210")

    @skipIf("loss" in SKIP_TESTS, "Skipping loss tests")
    @patch("socket.socket.sendto", new_callable=lambda: sendto_with_loss)
    @asynctest
    async def test_connect_and_serve_with_packet_loss(self, mock_sendto) -> None:
        """
        This test ensures handshake success and stream data is successfully sent
        and received in the presence of packet loss (randomized 25% in each direction).
        """
        data = b"Z" * 65536

        server_configuration = QuicConfiguration(
            is_client=False, quic_logger=QuicLogger()
        )
        server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        async with self.run_server(configuration=server_configuration) as server_port:
            response = await self.run_client(
                configuration=QuicConfiguration(
                    is_client=True, quic_logger=QuicLogger()
                ),
                port=server_port,
                request=data,
            )
        self.assertEqual(response, data)

    @asynctest
    async def test_connect_and_serve_with_session_ticket(self):
        client_ticket = None
        store = SessionTicketStore()

        def save_ticket(t):
            nonlocal client_ticket
            client_ticket = t

        async with self.run_server(
            session_ticket_fetcher=store.pop, session_ticket_handler=store.add
        ) as server_port:
            # first request
            response = await self.run_client(
                port=server_port, session_ticket_handler=save_ticket
            )
            self.assertEqual(response, b"gnip")

            self.assertIsNotNone(client_ticket)

            # second request
            response = await self.run_client(
                configuration=QuicConfiguration(
                    is_client=True, session_ticket=client_ticket
                ),
                port=server_port,
            )
            self.assertEqual(response, b"gnip")

    @asynctest
    async def test_connect_and_serve_with_retry(self):
        async with self.run_server(retry=True) as server_port:
            response = await self.run_client(port=server_port)
            self.assertEqual(response, b"gnip")

    @asynctest
    async def test_connect_and_serve_with_retry_bad_original_destination_connection_id(
        self,
    ):
        """
        If the server's transport parameters do not have the correct
        original_destination_connection_id the connection must fail.
        """

        def create_protocol(*args, **kwargs):
            protocol = QuicConnectionProtocol(*args, **kwargs)
            protocol._quic._original_destination_connection_id = None
            return protocol

        async with self.run_server(
            create_protocol=create_protocol, retry=True
        ) as server_port:
            with self.assertRaises(ConnectionError):
                await self.run_client(port=server_port)

    @asynctest
    async def test_connect_and_serve_with_retry_bad_retry_source_connection_id(self):
        """
        If the server's transport parameters do not have the correct
        retry_source_connection_id the connection must fail.
        """

        def create_protocol(*args, **kwargs):
            protocol = QuicConnectionProtocol(*args, **kwargs)
            protocol._quic._retry_source_connection_id = None
            return protocol

        async with self.run_server(
            create_protocol=create_protocol, retry=True
        ) as server_port:
            with self.assertRaises(ConnectionError):
                await self.run_client(port=server_port)

    @patch("aioquic.quic.retry.QuicRetryTokenHandler.validate_token")
    @asynctest
    async def test_connect_and_serve_with_retry_bad_token(self, mock_validate) -> None:
        mock_validate.side_effect = ValueError("Decryption failed.")

        async with self.run_server(retry=True) as server_port:
            with self.assertRaises(ConnectionError):
                await self.run_client(
                    configuration=QuicConfiguration(is_client=True, idle_timeout=4.0),
                    port=server_port,
                )

    @asynctest
    async def test_connect_and_serve_with_version_negotiation(self) -> None:
        async with self.run_server() as server_port:
            # force version negotiation
            configuration = QuicConfiguration(is_client=True, quic_logger=QuicLogger())
            configuration.supported_versions.insert(0, 0x1A2A3A4A)

            response = await self.run_client(
                configuration=configuration, port=server_port
            )
            self.assertEqual(response, b"gnip")

    @asynctest
    async def test_connect_timeout(self) -> None:
        with self.assertRaises(ConnectionError):
            await self.run_client(
                port=self.bogus_port,
                configuration=QuicConfiguration(is_client=True, idle_timeout=5),
            )

    @asynctest
    async def test_connect_timeout_no_wait_connected(self) -> None:
        with self.assertRaises(ConnectionError):
            configuration = QuicConfiguration(is_client=True, idle_timeout=5)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host,
                self.bogus_port,
                configuration=configuration,
                wait_connected=False,
            ) as client:
                await client.ping()

    @asynctest
    async def test_connect_local_port(self) -> None:
        async with self.run_server() as server_port:
            response = await self.run_client(local_port=3456, port=server_port)
            self.assertEqual(response, b"gnip")

    @asynctest
    async def test_connect_local_port_bind(self) -> None:
        with self.assertRaises(OverflowError):
            await self.run_client(local_port=-1, port=self.bogus_port)

    @asynctest
    async def test_change_connection_id(self) -> None:
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                client.change_connection_id()
                await client.ping()

    @asynctest
    async def test_key_update(self) -> None:
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                client.request_key_update()
                await client.ping()

    @asynctest
    async def test_ping(self) -> None:
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                await client.ping()

    @asynctest
    async def test_ping_parallel(self) -> None:
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                coros = [client.ping() for x in range(16)]
                await asyncio.gather(*coros)

    @asynctest
    async def test_server_receives_garbage(self) -> None:
        configuration = QuicConfiguration(is_client=False)
        configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        server = await serve(
            host=self.server_host,
            port=0,
            configuration=configuration,
        )
        server.datagram_received(binascii.unhexlify("c00000000080"), ("1.2.3.4", 1234))
        server.close()

    @asynctest
    async def test_combined_key(self) -> None:
        config1 = QuicConfiguration()
        config2 = QuicConfiguration()
        config1.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        config2.load_cert_chain(SERVER_COMBINEDFILE)

        self.assertEqual(config1.certificate, config2.certificate)


class AsyncioClientConnectBindTest(TestCase):
    @asynctest
    async def test_connect_bind_address_ipv4(self):
        captured_sock = None

        async def mock_create_datagram_endpoint(protocol_factory, sock=None, **kwargs):
            nonlocal captured_sock
            captured_sock = sock  # Capture the socket

            transport_mock = AsyncMock()
            protocol_mock = AsyncMock()
            protocol_mock.wait_connected = AsyncMock(return_value=None)
            protocol_mock.wait_closed = AsyncMock(return_value=None)
            # Simulate protocol creation if necessary, or ensure it's handled
            # by connect's create_protocol default or a passed mock.
            # For this test, the focus is on sock.bind, not the protocol itself.
            return transport_mock, protocol_mock

        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                side_effect=mock_create_datagram_endpoint
            )
            mock_get_loop.return_value = mock_loop

            config = QuicConfiguration(is_client=True, server_name="example.com")
            test_ip = "127.0.0.1"

            try:
                async with connect(
                    "example.com",
                    4433,
                    configuration=config,
                    local_ip=test_ip,
                    wait_connected=False,
                ):
                    pass  # Connection setup and teardown is handled by async with
            except Exception:
                # We want to assert on the socket even if connect fails later
                pass

            self.assertIsNotNone(captured_sock, "Socket was not captured")
            self.assertEqual(
                captured_sock.family,
                socket.AF_INET,
                "Socket family should be AF_INET for IPv4 bind address",
            )
            # getsockname() returns (ip, port) for AF_INET
            self.assertEqual(
                captured_sock.getsockname()[0],
                test_ip,
                "Socket bind address mismatch for IPv4",
            )

    @asynctest
    async def test_connect_bind_address_ipv6(self):
        captured_sock = None

        async def mock_create_datagram_endpoint(protocol_factory, sock=None, **kwargs):
            nonlocal captured_sock
            captured_sock = sock
            transport_mock = AsyncMock()
            protocol_mock = AsyncMock()
            protocol_mock.wait_connected = AsyncMock(return_value=None)
            protocol_mock.wait_closed = AsyncMock(return_value=None)
            return transport_mock, protocol_mock

        with (
            patch("asyncio.get_running_loop") as mock_get_loop,
            patch("socket.socket") as mock_socket_constructor,
        ):
            mock_created_socket = MagicMock()  # Removed spec=socket.socket
            mock_created_socket.family = socket.AF_INET6
            mock_created_socket.bind = MagicMock()
            # Ensure getsockname returns a tuple of the correct length for AF_INET6
            mock_created_socket.getsockname = MagicMock(
                return_value=("::1", 12345, 0, 0)
            )
            mock_created_socket.setsockopt = MagicMock()
            mock_created_socket.close = MagicMock()
            mock_socket_constructor.return_value = mock_created_socket

            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                side_effect=mock_create_datagram_endpoint
            )
            # Simulate getaddrinfo for the remote host
            mock_loop.getaddrinfo = AsyncMock(
                return_value=[
                    (
                        socket.AF_INET6,
                        socket.SOCK_DGRAM,
                        0,
                        "",
                        ("remote_ipv6", 4433, 0, 0),
                    )
                ]
            )
            mock_get_loop.return_value = mock_loop

            config = QuicConfiguration(is_client=True, server_name="example.com")
            test_ip = "::1"

            try:
                async with connect(
                    "example.com",  # Remote hostname
                    4433,
                    configuration=config,
                    local_ip=test_ip,  # local IPv6
                    wait_connected=False,
                ):
                    pass
            except Exception:
                pass  # Allow test to proceed to assertions even if connect fails later

            self.assertIsNotNone(captured_sock, "Socket was not captured")
            mock_socket_constructor.assert_called_once_with(
                socket.AF_INET6, socket.SOCK_DGRAM
            )
            mock_created_socket.bind.assert_called_once_with(
                (test_ip, 0, 0, 0)
            )  # local_port defaults to 0
            self.assertEqual(
                captured_sock.family,
                socket.AF_INET6,
                "Socket family should be AF_INET6 for IPv6 bind address",
            )
            # getsockname() returns (ip, port, flowinfo, scopeid) for AF_INET6
            self.assertEqual(
                captured_sock.getsockname()[0],
                test_ip,
                "Socket bind address mismatch for IPv6",
            )

    @asynctest
    async def test_connect_bind_default(self):
        captured_sock = None

        async def mock_create_datagram_endpoint(protocol_factory, sock=None, **kwargs):
            nonlocal captured_sock
            captured_sock = sock
            transport_mock = AsyncMock()
            protocol_mock = AsyncMock()
            protocol_mock.wait_connected = AsyncMock(return_value=None)
            protocol_mock.wait_closed = AsyncMock(return_value=None)
            return transport_mock, protocol_mock

        with (
            patch("asyncio.get_running_loop") as mock_get_loop,
            patch("socket.socket") as mock_socket_constructor,
        ):
            mock_created_socket = MagicMock()  # Removed spec=socket.socket
            # Default binding attempts AF_INET6.
            mock_created_socket.family = socket.AF_INET6
            mock_created_socket.bind = MagicMock()
            # getsockname for ("াইল", 0, 0, 0) default bind
            mock_created_socket.getsockname = MagicMock(
                return_value=("::", 12345, 0, 0)
            )
            mock_created_socket.setsockopt = MagicMock()
            mock_created_socket.close = MagicMock()
            mock_socket_constructor.return_value = mock_created_socket

            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                side_effect=mock_create_datagram_endpoint
            )
            # Simulate getaddrinfo for the remote host
            mock_loop.getaddrinfo = AsyncMock(
                return_value=[
                    (
                        socket.AF_INET6,
                        socket.SOCK_DGRAM,
                        0,
                        "",
                        ("remote_ipv6", 4433, 0, 0),
                    )
                ]
            )
            mock_get_loop.return_value = mock_loop

            config = QuicConfiguration(is_client=True, server_name="example.com")

            try:
                async with connect(
                    "example.com",  # Remote hostname
                    4433,
                    configuration=config,
                    local_ip=None,  # Default local_ip
                    wait_connected=False,
                ):
                    pass
            except Exception:
                pass  # Allow test to proceed to assertions

            self.assertIsNotNone(
                captured_sock, "Socket was not captured for default bind"
            )
            # Assert that socket.socket was called to create an AF_INET6 socket
            mock_socket_constructor.assert_called_once_with(
                socket.AF_INET6, socket.SOCK_DGRAM
            )
            # Assert that bind was called with "::" and default port 0
            mock_created_socket.bind.assert_called_once_with(("::", 0, 0, 0))
            self.assertEqual(
                captured_sock.family,
                socket.AF_INET6,
                "Default bind socket family should be AF_INET6",
            )
            # For an AF_INET6 socket bound to ("::", port, 0, 0)
            # getsockname()[0] should be "::" on most systems.
            # Some systems might return "0.0.0.0" if IPV6_V6ONLY=0 is very effective,
            # but given the bind call, "::" is the direct expectation.
            self.assertEqual(
                captured_sock.getsockname()[0],
                "::",
                "Default bind address should be '::'",
            )

    @asynctest
    async def test_connect_invalid_local_ip_string(self):
        """
        Test connect() when local_ip is an invalid IP address string.
        Expect ValueError.
        """
        config = QuicConfiguration(is_client=True, server_name="example.com")
        with self.assertRaisesRegex(
            ValueError, "Invalid IP address format for local_ip"
        ):
            async with connect(
                "example.com",
                4433,
                configuration=config,
                local_ip="not.an.ip",
            ):
                pass  # Should not reach here

    @asynctest
    async def test_connect_getaddrinfo_gaierror(self):
        """
        Test connect() when loop.getaddrinfo raises socket.gaierror.
        Expect ValueError.
        """
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(
                side_effect=socket.gaierror("Test gaierror")
            )
            mock_get_loop.return_value = mock_loop

            config = QuicConfiguration(is_client=True, server_name="example.com")
            with self.assertRaisesRegex(ValueError, "Error resolving remote host"):
                async with connect("example.com", 4433, configuration=config):
                    pass  # Should not reach here

    @asynctest
    async def test_connect_getaddrinfo_empty_list(self):
        """
        Test connect() when loop.getaddrinfo returns an empty list for infos.
        Expect ValueError.
        """
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(return_value=[])  # Empty list
            mock_get_loop.return_value = mock_loop

            config = QuicConfiguration(is_client=True, server_name="example.com")
            with self.assertRaisesRegex(
                ValueError, "No address information found for remote host"
            ):
                async with connect("example.com", 4433, configuration=config):
                    pass  # Should not reach here

    @asynctest
    async def test_connect_bind_oserror_ipv4(self):
        """
        Test connect() when socket.bind() raises OSError for an IPv4 local_ip.
        Ensure sock.close() is called.
        """
        mock_socket_instance = AsyncMock()
        # bind is synchronous, so use MagicMock
        mock_socket_instance.bind = MagicMock(side_effect=OSError("Bind error"))
        # Used in finally block if error happens after assignment
        mock_socket_instance.family = socket.AF_INET

        with (
            patch("asyncio.get_running_loop") as mock_get_loop,
            patch("socket.socket") as mock_socket_constructor,
        ):
            mock_loop = AsyncMock()
            # Simulate successful getaddrinfo for remote host
            mock_loop.getaddrinfo = AsyncMock(
                return_value=[
                    (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("remote_ip", 4433))
                ]
            )
            # loop.create_datagram_endpoint should also be an AsyncMock for this
            # test's purpose, but we will assert it's not called.
            mock_loop.create_datagram_endpoint = AsyncMock()
            mock_get_loop.return_value = mock_loop
            mock_socket_constructor.return_value = mock_socket_instance

            config = QuicConfiguration(is_client=True, server_name="example.com")
            with self.assertRaises(OSError):
                async with connect(
                    "example.com",
                    4433,
                    configuration=config,
                    local_ip="127.0.0.1",  # IPv4 local_ip
                ):
                    pass  # Should not reach here

            # Called in except and finally
            self.assertEqual(mock_socket_instance.close.call_count, 2)
            mock_loop.create_datagram_endpoint.assert_not_called()

    @asynctest
    async def test_connect_bind_oserror_ipv6(self):
        """
        Test connect() when socket.bind() raises OSError for an IPv6 local_ip.
        Ensure sock.close() is called.
        """
        mock_socket_instance = AsyncMock()
        # bind is synchronous, so use MagicMock
        mock_socket_instance.bind = MagicMock(side_effect=OSError("Bind error"))
        mock_socket_instance.family = socket.AF_INET6  # Used in finally block

        with (
            patch("asyncio.get_running_loop") as mock_get_loop,
            patch("socket.socket") as mock_socket_constructor,
        ):
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(
                return_value=[
                    (
                        socket.AF_INET6,
                        socket.SOCK_DGRAM,
                        0,
                        "",
                        ("::remote", 4433, 0, 0),
                    )
                ]
            )
            # loop.create_datagram_endpoint should also be an AsyncMock for this
            # test's purpose, but we will assert it's not called.
            mock_loop.create_datagram_endpoint = AsyncMock()
            mock_get_loop.return_value = mock_loop
            mock_socket_constructor.return_value = mock_socket_instance

            config = QuicConfiguration(is_client=True, server_name="example.com")
            with self.assertRaises(OSError):
                async with connect(
                    "example.com",  # Hostname, getaddrinfo will be mocked
                    4433,
                    configuration=config,
                    local_ip="::1",  # IPv6 local_ip
                ):
                    pass  # Should not reach here

            # Called in except and finally
            self.assertEqual(mock_socket_instance.close.call_count, 2)
            mock_loop.create_datagram_endpoint.assert_not_called()

    @asynctest
    async def test_connect_ipv4_local_ipv6_remote_mismatch(self):
        """
        Test connect() with IPv4 local_ip and non-IPv4-mapped IPv6 remote.
        Expect ValueError and ensure sock.close() is called.
        """
        mock_socket_instance = MagicMock()  # Changed to MagicMock
        # Simulate a successfully bound AF_INET socket
        mock_socket_instance.bind = MagicMock()  # Changed to MagicMock
        mock_socket_instance.family = socket.AF_INET
        # getsockname() needs to return a valid tuple for AF_INET
        # for the error message formatting
        mock_socket_instance.getsockname = MagicMock( # Changed to MagicMock
            return_value=("127.0.0.1", 12345)
        )

        with (
            patch("asyncio.get_running_loop") as mock_get_loop,
            patch("socket.socket") as mock_socket_constructor,
        ):
            mock_loop = AsyncMock()
            # Remote address is pure IPv6
            mock_loop.getaddrinfo = AsyncMock(
                return_value=[
                    (
                        socket.AF_INET6,
                        socket.SOCK_DGRAM,
                        0,
                        "",
                        ("::1", 4433, 0, 0),
                    )
                ]
            )
            mock_get_loop.return_value = mock_loop
            mock_socket_constructor.return_value = mock_socket_instance

            config = QuicConfiguration(is_client=True, server_name="example.com")
            expected_error_msg = (
                "Cannot connect to IPv6 remote host ::1 "
                "from a locally bound IPv4 address 127.0.0.1"
            )
            with self.assertRaisesRegex(ValueError, expected_error_msg):
                async with connect(
                    "::1",  # Remote host, matching getaddrinfo
                    4433,
                    configuration=config,
                    local_ip="127.0.0.1",  # IPv4 local_ip
                ):
                    pass  # Should not reach here

            mock_socket_instance.close.assert_called_once()

    @asynctest
    async def test_connect_unexpected_error_during_bind_phase_closes_socket(self):
        """
        Test that sock.close() is called if an unexpected error occurs after
        socket creation but before 'completed = True' in the binding phase.
        This tests the 'finally' block within the binding try-except.
        """
        # Use MagicMock for the socket instance as its methods (setsockopt, close) are sync
        mock_socket_instance = MagicMock()
        # We want socket creation to succeed.
        # setsockopt will be made to raise an unexpected error.
        # setsockopt is synchronous.
        mock_socket_instance.setsockopt = MagicMock(
            side_effect=RuntimeError("Unexpected setsockopt error")
        )
        # family needs to be set for the error path in connect() if setsockopt fails.
        mock_socket_instance.family = socket.AF_INET6

        # ipaddress.ip_address is not patched here, allowing the real one to be called.
        with (
            patch("asyncio.get_running_loop") as mock_get_loop,
            patch("socket.socket") as mock_socket_constructor,
        ):
            mock_loop = AsyncMock()
            # getaddrinfo must succeed. We'll use an IPv6 remote to match local_ip="::1"
            mock_loop.getaddrinfo = AsyncMock(
                return_value=[
                    (
                        socket.AF_INET6,
                        socket.SOCK_DGRAM,
                        0,
                        "",
                        ("::remote", 4433, 0, 0),
                    )
                ]
            )
            mock_get_loop.return_value = mock_loop

            mock_socket_constructor.return_value = mock_socket_instance
            # ip_address parsing should succeed for "::1"
            # We need to ensure that the actual ipaddress.ip_address is used,
            # not a default AsyncMock, so we don't mock its return_value here
            # unless necessary for other paths.
            # For this test, we let it pass through or mock it to succeed.
            # If ipaddress.ip_address itself is the source of error,
            # it's a different test. Here, we assume ipaddress.ip_address("::1") works.

            config = QuicConfiguration(is_client=True, server_name="example.com")
            with self.assertRaisesRegex(RuntimeError, "Unexpected setsockopt error"):
                async with connect(
                    "example.com",  # remote host
                    4433,
                    configuration=config,
                    # IPv6 local_ip to trigger setsockopt for IPV6_V6ONLY
                    local_ip="::1",
                ):
                    pass  # Should not reach here

            # Crucial assertion: socket was created, then an error occurred,
            # so the finally block should close it.
            mock_socket_constructor.assert_called_once_with(
                socket.AF_INET6, socket.SOCK_DGRAM
            )
            # Ensure setsockopt was called
            mock_socket_instance.setsockopt.assert_called_once()
            mock_socket_instance.close.assert_called_once()

    @asynctest
    async def test_connect_error_post_endpoint_creation_cleans_up(self):
        """
        Test that protocol.close(), protocol.wait_closed(), and transport.close()
        are called if an exception occurs after create_datagram_endpoint
        but before the protocol is yielded.
        """
        mock_transport = AsyncMock()
        mock_transport.close = MagicMock()  # Synchronous call

        mock_protocol = AsyncMock(spec=QuicConnectionProtocol)
        # protocol.connect is synchronous
        mock_protocol.connect = MagicMock(
            side_effect=RuntimeError("Protocol connect error")
        )
        # protocol.close is synchronous
        mock_protocol.close = MagicMock()
        # protocol.wait_closed is asynchronous
        mock_protocol.wait_closed = AsyncMock(return_value=None)

        with (
            patch("asyncio.get_running_loop") as mock_get_loop,
            patch("socket.socket") as mock_socket_constructor,
            # Removed patch("ipaddress.ip_address")
        ):
            mock_loop = AsyncMock()
            # Remote address is AF_INET
            mock_loop.getaddrinfo = AsyncMock(
                return_value=[
                    (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("127.0.0.1", 4433))
                ]
            )

            # Mock the socket instance that will be created
            mock_socket_instance = MagicMock() # Changed to MagicMock
            # Default local binding attempts AF_INET6 first.
            # Let's assume this succeeds for setting up sock.family.
            mock_socket_instance.family = socket.AF_INET6
            mock_socket_constructor.return_value = mock_socket_instance

            # create_datagram_endpoint should succeed and return our mocks
            mock_loop.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            mock_get_loop.return_value = mock_loop

            config = QuicConfiguration(is_client=True, server_name="example.com")

            with self.assertRaisesRegex(RuntimeError, "Protocol connect error"):
                async with connect(
                    "127.0.0.1",
                    4433,
                    configuration=config,
                    # local_ip=None, # Default behavior
                    wait_connected=True,  # Ensure protocol.connect is called
                ):
                    pass  # Should not reach here

            # Assertions for cleanup
            mock_protocol.close.assert_called_once()
            mock_protocol.wait_closed.assert_called_once()
            mock_transport.close.assert_called_once()
