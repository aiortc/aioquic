import abc
import argparse
import asyncio
import contextlib
import functools
import importlib
import logging
import time
from collections import deque
from collections.abc import Callable
from email.utils import formatdate
from typing import Any

import aioquic
import wsproto
import wsproto.events
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    DataReceived,
    H3Event,
    HeadersReceived,
    ResetReceived,
    StopReceived,
    WebTransportStreamDataReceived,
)
from aioquic.h3.exceptions import InvalidConnectionStateError, InvalidStreamStateError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated, QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import SessionTicket

try:
    import uvloop
except ImportError:
    uvloop = None

AsgiApplication = Callable
HttpConnection = H0Connection | H3Connection

# Since spec version 2.4, send() raises an OSError once the client has gone.
ASGI_VERSION = {"spec_version": "2.4", "version": "3.0"}
SERVER_NAME = "aioquic/" + aioquic.__version__

logger = logging.getLogger("http3_server")


class AsgiHandler(abc.ABC):
    """
    Runs an ASGI application for one request stream.
    """

    # The message receive() gives once the client has gone.
    disconnect_message: dict
    disconnected: bool
    queue: asyncio.Queue[dict]

    def client_went_away(self) -> None:
        # Tell the application once.
        if not self.disconnected:
            self.disconnected = True
            self.queue.put_nowait(dict(self.disconnect_message))

    @abc.abstractmethod
    def http_event_received(self, event: H3Event) -> None: ...

    @abc.abstractmethod
    async def run_asgi(self, app: AsgiApplication) -> None: ...

    async def receive(self) -> dict:
        return await self.queue.get()

    async def send(self, message: dict) -> None:
        try:
            await self._send(message)
        except (InvalidConnectionStateError, InvalidStreamStateError) as exc:
            # Usually because the client has gone away.
            self.disconnected = True
            raise ClientDisconnected from exc

    def _log_application_error(self) -> None:
        if self.disconnected:
            # Once the client has gone, failing is expected, but the error is
            # still useful when the application stops for another reason.
            logger.debug(
                "ASGI application stopped after the client went away", exc_info=True
            )
        else:
            logger.exception("Error in ASGI application")

    @abc.abstractmethod
    async def _send(self, message: dict) -> None: ...


class ClientDisconnected(OSError):
    """
    Raised by the ASGI ``send`` callable once the client has gone away.
    """


class HttpRequestHandler(AsgiHandler):
    disconnect_message = {"type": "http.disconnect"}

    def __init__(
        self,
        *,
        connection: HttpConnection,
        scope: dict,
        stream_ended: bool,
        stream_id: int,
        transmit: Callable[[], None],
    ) -> None:
        self.connection = connection
        self.disconnected = False
        self.queue: asyncio.Queue[dict] = asyncio.Queue()
        self.response_started = False
        self.scope = scope
        self.stream_id = stream_id
        self.transmit = transmit

        if stream_ended:
            self.queue.put_nowait({"type": "http.request"})

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, DataReceived):
            self.queue.put_nowait(
                {
                    "type": "http.request",
                    "body": event.data,
                    "more_body": not event.stream_ended,
                }
            )
        elif isinstance(event, HeadersReceived) and event.stream_ended:
            self.queue.put_nowait(
                {"type": "http.request", "body": b"", "more_body": False}
            )
        elif isinstance(event, (ResetReceived, StopReceived)):
            # The client cancelled the request.
            self.client_went_away()

    async def run_asgi(self, app: AsgiApplication) -> None:
        try:
            await app(self.scope, self.receive, self.send)
        except Exception:
            self._log_application_error()
            if not self.response_started:
                with contextlib.suppress(ClientDisconnected):
                    await self.send(
                        {"type": "http.response.start", "status": 500, "headers": []}
                    )
                    await self.send({"type": "http.response.body"})

    async def _send(self, message: dict) -> None:
        if message["type"] == "http.response.start":
            self.connection.send_headers(
                stream_id=self.stream_id,
                headers=[
                    (b":status", str(message["status"]).encode()),
                    (b"server", SERVER_NAME.encode()),
                    (b"date", formatdate(time.time(), usegmt=True).encode()),
                ]
                + [(k, v) for k, v in message["headers"]],
            )
            self.response_started = True
        elif message["type"] == "http.response.body":
            more_body = message.get("more_body", False)
            self.connection.send_data(
                stream_id=self.stream_id,
                data=message.get("body", b""),
                end_stream=not more_body,
            )
            if not more_body:
                self.queue.put_nowait({"type": "http.disconnect"})
        self.transmit()


class WebSocketHandler(AsgiHandler):
    # 1006: the connection was lost without a closing handshake.
    disconnect_message = {"type": "websocket.disconnect", "code": 1006}

    def __init__(
        self,
        *,
        connection: HttpConnection,
        scope: dict,
        stream_id: int,
        transmit: Callable[[], None],
    ) -> None:
        self.closed = False
        self.connection = connection
        self.disconnected = False
        self.http_event_queue: deque[DataReceived] = deque()
        self.queue: asyncio.Queue[dict] = asyncio.Queue()
        self.scope = scope
        self.stream_id = stream_id
        self.transmit = transmit
        self.websocket: wsproto.Connection | None = None

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (ResetReceived, StopReceived)):
            # The client went away without a closing handshake.
            self.client_went_away()
        elif isinstance(event, DataReceived) and not self.closed:
            if self.websocket is not None:
                self.websocket.receive_data(event.data)

                for ws_event in self.websocket.events():
                    self.websocket_event_received(ws_event)
            else:
                # delay event processing until we get `websocket.accept`
                # from the ASGI application
                self.http_event_queue.append(event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait({"type": "websocket.receive", "text": event.data})
        elif isinstance(event, wsproto.events.Message):
            self.queue.put_nowait({"type": "websocket.receive", "bytes": event.data})
        elif isinstance(event, wsproto.events.CloseConnection):
            self.queue.put_nowait({"type": "websocket.disconnect", "code": event.code})

    async def run_asgi(self, app: AsgiApplication) -> None:
        self.queue.put_nowait({"type": "websocket.connect"})

        code = 1000
        try:
            await app(self.scope, self.receive, self.send)
        except Exception:
            self._log_application_error()
            # 1011: the server hit an unexpected condition (RFC 6455 section 7.4.1).
            code = 1011
        finally:
            if not self.closed:
                with contextlib.suppress(ClientDisconnected):
                    await self.send({"type": "websocket.close", "code": code})

    async def _send(self, message: dict) -> None:
        data = b""
        end_stream = False
        if message["type"] == "websocket.accept":
            subprotocol = message.get("subprotocol")

            self.websocket = wsproto.Connection(wsproto.ConnectionType.SERVER)

            headers = [
                (b":status", b"200"),
                (b"server", SERVER_NAME.encode()),
                (b"date", formatdate(time.time(), usegmt=True).encode()),
            ] + [(k, v) for k, v in message.get("headers", [])]
            if subprotocol is not None:
                headers.append((b"sec-websocket-protocol", subprotocol.encode()))
            self.connection.send_headers(stream_id=self.stream_id, headers=headers)

            # consume backlog
            while self.http_event_queue:
                self.http_event_received(self.http_event_queue.popleft())

        elif message["type"] == "websocket.close":
            if self.websocket is not None:
                data = self.websocket.send(
                    wsproto.events.CloseConnection(
                        code=message["code"], reason=message.get("reason")
                    )
                )
            else:
                self.connection.send_headers(
                    stream_id=self.stream_id, headers=[(b":status", b"403")]
                )
            end_stream = True
        elif message["type"] == "websocket.send":
            if message.get("text") is not None:
                data = self.websocket.send(
                    wsproto.events.TextMessage(data=message["text"])
                )
            elif message.get("bytes") is not None:
                data = self.websocket.send(
                    wsproto.events.Message(data=message["bytes"])
                )

        if data:
            self.connection.send_data(
                stream_id=self.stream_id, data=data, end_stream=end_stream
            )
        if end_stream:
            self.closed = True
        self.transmit()


class WebTransportHandler(AsgiHandler):
    disconnect_message = {"type": "webtransport.disconnect"}

    def __init__(
        self,
        *,
        connection: H3Connection,
        scope: dict,
        stream_id: int,
        transmit: Callable[[], None],
    ) -> None:
        self.accepted = False
        self.closed = False
        self.connection = connection
        self.disconnected = False
        self.http_event_queue: deque[H3Event] = deque()
        self.queue: asyncio.Queue[dict] = asyncio.Queue()
        self.scope = scope
        self.stream_id = stream_id
        self.transmit = transmit

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (ResetReceived, StopReceived)):
            # The client went away without closing the session.
            self.client_went_away()
        elif not self.closed:
            if self.accepted:
                if isinstance(event, DataReceived) and event.stream_ended:
                    # The client closed the session.
                    self.queue.put_nowait({"type": "webtransport.disconnect"})
                elif isinstance(event, DatagramReceived):
                    self.queue.put_nowait(
                        {
                            "data": event.data,
                            "type": "webtransport.datagram.receive",
                        }
                    )
                elif isinstance(event, WebTransportStreamDataReceived):
                    self.queue.put_nowait(
                        {
                            "data": event.data,
                            "stream": event.stream_id,
                            "type": "webtransport.stream.receive",
                        }
                    )
            else:
                # delay event processing until we get `webtransport.accept`
                # from the ASGI application
                self.http_event_queue.append(event)

    async def run_asgi(self, app: AsgiApplication) -> None:
        self.queue.put_nowait({"type": "webtransport.connect"})

        try:
            await app(self.scope, self.receive, self.send)
        except Exception:
            self._log_application_error()
        finally:
            if not self.closed:
                with contextlib.suppress(ClientDisconnected):
                    await self.send({"type": "webtransport.close"})

    async def _send(self, message: dict) -> None:
        data = b""
        end_stream = False

        if message["type"] == "webtransport.accept":
            self.accepted = True

            headers = [
                (b":status", b"200"),
                (b"server", SERVER_NAME.encode()),
                (b"date", formatdate(time.time(), usegmt=True).encode()),
                (b"sec-webtransport-http3-draft", b"draft02"),
            ]
            self.connection.send_headers(stream_id=self.stream_id, headers=headers)

            # consume backlog
            while self.http_event_queue:
                self.http_event_received(self.http_event_queue.popleft())
        elif message["type"] == "webtransport.close":
            if not self.accepted:
                self.connection.send_headers(
                    stream_id=self.stream_id, headers=[(b":status", b"403")]
                )
            end_stream = True
        elif message["type"] == "webtransport.datagram.send":
            self.connection.send_datagram(
                stream_id=self.stream_id, data=message["data"]
            )
        elif message["type"] == "webtransport.stream.send":
            self.connection.quic_connection.send_stream_data(
                stream_id=message["stream"], data=message["data"]
            )

        if data or end_stream:
            self.connection.send_data(
                stream_id=self.stream_id, data=data, end_stream=end_stream
            )
        if end_stream:
            self.closed = True
        self.transmit()


class HttpServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._handlers: dict[int, AsgiHandler] = {}
        self._http: HttpConnection | None = None
        self._tasks: set[asyncio.Task] = set()

    def http_event_received(self, event: H3Event) -> None:
        # Trailers can still arrive once the request's handler is gone.
        if isinstance(event, HeadersReceived) and not event.is_trailers:
            headers = []
            http_version = "0.9" if isinstance(self._http, H0Connection) else "3"
            raw_path = b""
            method = ""
            protocol = None
            for header, value in event.headers:
                if header == b":authority":
                    headers.append((b"host", value))
                elif header == b":method":
                    method = value.decode()
                elif header == b":path":
                    raw_path = value
                elif header == b":protocol":
                    protocol = value.decode()
                elif header and not header.startswith(b":"):
                    headers.append((header, value))

            if b"?" in raw_path:
                path_bytes, query_string = raw_path.split(b"?", maxsplit=1)
            else:
                path_bytes, query_string = raw_path, b""
            path = path_bytes.decode()
            self.quic_connection._logger.info("HTTP request %s %s", method, path)

            client_addr = self._http.quic_connection.get_peer_address()
            assert client_addr is not None
            client = (client_addr[0], client_addr[1])

            handler: AsgiHandler
            scope: dict
            if method == "CONNECT" and protocol == "websocket":
                subprotocols: list[str] = []
                for header, value in event.headers:
                    if header == b"sec-websocket-protocol":
                        subprotocols = [x.strip() for x in value.decode().split(",")]
                scope = {
                    "asgi": dict(ASGI_VERSION),
                    "client": client,
                    "headers": headers,
                    "http_version": http_version,
                    "method": method,
                    "path": path,
                    "query_string": query_string,
                    "raw_path": raw_path,
                    "root_path": "",
                    "scheme": "wss",
                    "subprotocols": subprotocols,
                    "type": "websocket",
                }
                handler = WebSocketHandler(
                    connection=self._http,
                    scope=scope,
                    stream_id=event.stream_id,
                    transmit=self.transmit,
                )
            elif method == "CONNECT" and protocol == "webtransport":
                assert isinstance(self._http, H3Connection), (
                    "WebTransport is only supported over HTTP/3"
                )
                scope = {
                    "asgi": dict(ASGI_VERSION),
                    "client": client,
                    "headers": headers,
                    "http_version": http_version,
                    "method": method,
                    "path": path,
                    "query_string": query_string,
                    "raw_path": raw_path,
                    "root_path": "",
                    "scheme": "https",
                    "type": "webtransport",
                }
                handler = WebTransportHandler(
                    connection=self._http,
                    scope=scope,
                    stream_id=event.stream_id,
                    transmit=self.transmit,
                )
            else:
                scope = {
                    "asgi": dict(ASGI_VERSION),
                    "client": client,
                    "headers": headers,
                    "http_version": http_version,
                    "method": method,
                    "path": path,
                    "query_string": query_string,
                    "raw_path": raw_path,
                    "root_path": "",
                    "scheme": "https",
                    "type": "http",
                }
                handler = HttpRequestHandler(
                    connection=self._http,
                    scope=scope,
                    stream_ended=event.stream_ended,
                    stream_id=event.stream_id,
                    transmit=self.transmit,
                )
            self._handlers[event.stream_id] = handler
            # The event loop only keeps a weak reference to tasks. Once the task
            # ends, the handler is no longer needed and later events are dropped.
            task = asyncio.create_task(handler.run_asgi(application))
            self._tasks.add(task)
            task.add_done_callback(functools.partial(self._task_done, event.stream_id))
        elif (
            isinstance(
                event,
                (
                    DataReceived,
                    DatagramReceived,
                    HeadersReceived,
                    ResetReceived,
                    StopReceived,
                ),
            )
            and event.stream_id in self._handlers
        ):
            self._handlers[event.stream_id].http_event_received(event)
        elif (
            isinstance(event, WebTransportStreamDataReceived)
            and event.session_id in self._handlers
        ):
            self._handlers[event.session_id].http_event_received(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = H3Connection(
                    self.quic_connection, enable_webtransport=True
                )
            elif event.alpn_protocol in H0_ALPN:
                self._http = H0Connection(self.quic_connection)

        # Pass event to the HTTP layer.
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

        # The end of the connection ends every request on it.
        if isinstance(event, ConnectionTerminated):
            for handler in self._handlers.values():
                handler.client_went_away()

    def _task_done(self, stream_id: int, task: asyncio.Task) -> None:
        self._handlers.pop(stream_id)
        self._tasks.discard(task)


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> SessionTicket | None:
        return self.tickets.pop(label, None)


async def main(
    host: str,
    port: int,
    configuration: QuicConfiguration,
    session_ticket_store: SessionTicketStore,
    retry: bool,
) -> None:
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=HttpServerProtocol,
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=retry,
    )
    await asyncio.Future()


if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=False)

    parser = argparse.ArgumentParser(description="QUIC server")
    parser.add_argument(
        "app",
        type=str,
        nargs="?",
        default="demo:app",
        help="the ASGI application as <module>:<attribute>",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--congestion-control-algorithm",
        type=str,
        default="reno",
        help="use the specified congestion control algorithm",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--legacy-http",
        action="store_true",
        help="use HTTP/0.9",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4433,
        help="listen on the specified port (defaults to 4433)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "--max-datagram-size",
        type=int,
        default=defaults.max_datagram_size,
        help="maximum datagram size to send, excluding UDP or IP overhead",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="send a retry for new connections",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # import ASGI application
    module_str, attr_str = args.app.split(":", maxsplit=1)
    module = importlib.import_module(module_str)
    application = getattr(module, attr_str)

    # create QUIC logger
    if args.quic_log:
        quic_logger = QuicFileLogger(args.quic_log)
    else:
        quic_logger = None

    # open SSL log file
    if args.secrets_log:
        secrets_log_file = open(args.secrets_log, "a")
    else:
        secrets_log_file = None

    configuration = QuicConfiguration(
        alpn_protocols=H0_ALPN if args.legacy_http else H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        is_client=False,
        max_datagram_frame_size=65535,
        max_datagram_size=args.max_datagram_size,
        quic_logger=quic_logger,
        secrets_log_file=secrets_log_file,
    )

    # load SSL certificate and key
    configuration.load_cert_chain(args.certificate, args.private_key)

    if uvloop is not None:
        uvloop.install()

    try:
        asyncio.run(
            main(
                host=args.host,
                port=args.port,
                configuration=configuration,
                session_ticket_store=SessionTicketStore(),
                retry=args.retry,
            )
        )
    except KeyboardInterrupt:
        pass
