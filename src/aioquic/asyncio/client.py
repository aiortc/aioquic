import asyncio
import ipaddress
import socket
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Callable, Optional, cast

from ..quic.configuration import QuicConfiguration
from ..quic.connection import QuicConnection, QuicTokenHandler
from ..tls import SessionTicketHandler
from .protocol import QuicConnectionProtocol, QuicStreamHandler

__all__ = ["connect"]


@asynccontextmanager
async def connect(
    host: str,
    port: int,
    *,
    configuration: Optional[QuicConfiguration] = None,
    create_protocol: Optional[Callable] = QuicConnectionProtocol,
    session_ticket_handler: Optional[SessionTicketHandler] = None,
    stream_handler: Optional[QuicStreamHandler] = None,
    token_handler: Optional[QuicTokenHandler] = None,
    wait_connected: bool = True,
    local_port: int = 0,
    local_ip: Optional[str] = None,
) -> AsyncGenerator[QuicConnectionProtocol, None]:
    """
    Connect to a QUIC server at the given `host` and `port`.

    :meth:`connect()` returns an awaitable. Awaiting it yields a
    :class:`~aioquic.asyncio.QuicConnectionProtocol` which can be used to
    create streams.

    :func:`connect` also accepts the following optional arguments:

    * ``configuration`` is a :class:`~aioquic.quic.configuration.QuicConfiguration`
      configuration object.
    * ``create_protocol`` allows customizing the :class:`~asyncio.Protocol` that
      manages the connection. It should be a callable or class accepting the same
      arguments as :class:`~aioquic.asyncio.QuicConnectionProtocol` and returning
      an instance of :class:`~aioquic.asyncio.QuicConnectionProtocol` or a subclass.
    * ``session_ticket_handler`` is a callback which is invoked by the TLS
      engine when a new session ticket is received.
    * ``stream_handler`` is a callback which is invoked whenever a stream is
      created. It must accept two arguments: a :class:`asyncio.StreamReader`
      and a :class:`asyncio.StreamWriter`.
    * ``wait_connected`` indicates whether the context manager should wait for the
      connection to be established before yielding the
      :class:`~aioquic.asyncio.QuicConnectionProtocol`. By default this is `True` but
      you can set it to `False` if you want to immediately start sending data using
      0-RTT.
    * ``local_port`` is the UDP port number that this client wants to bind.
    * ``local_ip`` is the local IP address to bind to. If not specified, "::"
      (any IPv6 or IPv4 address) is used.
    """
    loop = asyncio.get_running_loop()

    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as e:
        raise ValueError(f"Error resolving remote host '{host}': {e}") from e

    if not infos:  # Should not happen if gaierror isn't raised, but defensive
        raise ValueError(f"No address information found for remote host '{host}'")

    resolved_remote_addr = infos[0][4]  # Standard tuple (host, port) or
    # (host, port, flow, scope)
    # Determine original family of resolved_remote_addr
    original_remote_addr_family = (
        socket.AF_INET if len(resolved_remote_addr) == 2 else socket.AF_INET6
    )

    # prepare QUIC connection
    if configuration is None:
        configuration = QuicConfiguration(is_client=True)
    if configuration.server_name is None:
        configuration.server_name = host
    connection = QuicConnection(
        configuration=configuration,
        session_ticket_handler=session_ticket_handler,
        token_handler=token_handler,
    )

    sock = None  # Initialize sock
    completed = False
    try:
        if local_ip:
            # Attempt to parse the provided local_ip
            try:
                parsed_local_ip = ipaddress.ip_address(local_ip)
            except ValueError as e:
                # Raise an error if local_ip is not a valid IP address string
                raise ValueError(
                    f"Invalid IP address format for local_ip: '{local_ip}'"
                ) from e

            if parsed_local_ip.version == 4:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Bind to the IPv4 address and local_port
                sock.bind((local_ip, local_port))
            elif parsed_local_ip.version == 6:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                try:
                    # For IPv6, allow binding to IPv4 addresses as well
                    # if the OS supports it
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except (OSError, AttributeError):
                    # Silently ignore if setting IPV6_V6ONLY fails
                    # (e.g., OS doesn't support it)
                    # The socket will then be IPv6 only.
                    pass
                # Bind to the IPv6 address, local_port, flowinfo, and scopeid
                sock.bind((local_ip, local_port, 0, 0))
            else:
                # This case should not be reached with ipaddress module
                if sock:  # Should not be created yet, but for safety.
                    sock.close()
                raise ValueError(f"Unknown IP address version for local_ip: {local_ip}")
        else:
            # Default behavior: Create a dual-stack IPv6 socket
            # if local_ip is not provided
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (OSError, AttributeError):
                # Silently ignore if setting IPV6_V6ONLY fails
                pass
            # Bind to "::" (all IPv6 addresses) and local_port
            sock.bind(("::", local_port, 0, 0))

        completed = True  # Mark as completed if bind is successful

    except OSError as e:  # Catch socket-related errors during socket() or bind()
        if sock:
            sock.close()  # Ensure socket is closed on error
        raise e  # Re-raise the original OSError
    except ValueError:  # Catch ValueErrors from ipaddress parsing or our own raises
        if sock:  # Should be None if ipaddress.ip_address fails, but for safety.
            sock.close()
        raise  # Re-raise the ValueError
    finally:
        # This finally block is crucial. If 'completed' is False AND 'sock' exists,
        # it means an exception occurred after socket creation
        # but before 'completed = True',
        # and that exception was not an OSError or ValueError caught above,
        # or an error happened during the exception handling itself.
        if not completed and sock:
            sock.close()

    addr_for_protocol = None
    if sock.family == socket.AF_INET:
        if original_remote_addr_family == socket.AF_INET:
            addr_for_protocol = resolved_remote_addr  # IPv4 local, IPv4 remote
        elif original_remote_addr_family == socket.AF_INET6:
            # IPv4 local, IPv6 remote. Try to extract IPv4 if it's IPv4-mapped.
            remote_ip_str = resolved_remote_addr[0]
            if remote_ip_str.startswith("::ffff:"):
                ipv4_part = remote_ip_str[7:]
                addr_for_protocol = (ipv4_part, resolved_remote_addr[1])
            else:
                # Pure IPv6 remote, cannot connect from AF_INET local socket
                if sock:
                    sock.close()  # Close local socket before raising
                raise ValueError(
                    f"Cannot connect to IPv6 remote host {resolved_remote_addr[0]} "
                    f"from a locally bound IPv4 address {local_ip or 'default'}"
                )
    elif sock.family == socket.AF_INET6:
        if original_remote_addr_family == socket.AF_INET:
            # IPv6 local, IPv4 remote. Map to IPv4-mapped IPv6 address.
            addr_for_protocol = (
                "::ffff:" + resolved_remote_addr[0],
                resolved_remote_addr[1],
                0,
                0,
            )
        elif original_remote_addr_family == socket.AF_INET6:
            addr_for_protocol = resolved_remote_addr  # IPv6 local, IPv6 remote
    else:  # Should not happen
        if sock:
            sock.close()
        raise RuntimeError(f"Unknown local socket family: {sock.family}")

    if addr_for_protocol is None:  # Should be covered by logic above
        if sock:
            sock.close()
        raise RuntimeError("Failed to determine address for protocol connect")

    # connect
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: create_protocol(connection, stream_handler=stream_handler),
        sock=sock,  # Use the already created and bound sock
    )
    protocol = cast(QuicConnectionProtocol, protocol)
    try:
        # Use addr_for_protocol for the connection
        protocol.connect(addr_for_protocol, transmit=wait_connected)
        if wait_connected:
            await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()
