import asyncio
from collections.abc import Callable
from typing import Any, cast

from ..quic import events
from ..quic.connection import (
    NetworkAddress,
    QuicConnection,
    stream_is_client_initiated,
)
from ..quic.packet import QuicErrorCode

QuicConnectionIdHandler = Callable[[bytes], None]
QuicStreamHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], None]


class QuicConnectionProtocol(asyncio.DatagramProtocol):
    def __init__(
        self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
    ):
        loop = asyncio.get_running_loop()

        self._adapters: dict[int, QuicStreamAdapter] = {}
        self._closed = asyncio.Event()
        self._connected = False
        self._connected_waiter: asyncio.Future[None] | None = None
        self._loop = loop
        self._ping_waiters: dict[int, asyncio.Future[None]] = {}
        self._quic = quic
        self._stream_handler = stream_handler
        self._timer: asyncio.TimerHandle | None = None
        self._timer_at: float | None = None
        self._transmit_task: asyncio.Handle | None = None
        self._transport: asyncio.DatagramTransport | None = None

        # callbacks
        self._connection_id_issued_handler: QuicConnectionIdHandler = lambda c: None
        self._connection_id_retired_handler: QuicConnectionIdHandler = lambda c: None
        self._connection_terminated_handler: Callable[[], None] = lambda: None

    @property
    def quic_connection(self) -> QuicConnection:
        """
        Return the QUIC connection driven by this protocol.
        """
        return self._quic

    def change_connection_id(self) -> None:
        """
        Change the connection ID used to communicate with the peer.

        The previous connection ID will be retired.
        """
        self._quic.change_connection_id()
        self.transmit()

    def close(
        self,
        error_code: int = QuicErrorCode.NO_ERROR,
        reason_phrase: str = "",
    ) -> None:
        """
        Close the connection.

        :param error_code: An error code indicating why the connection is
                           being closed.
        :param reason_phrase: A human-readable explanation of why the
                              connection is being closed.
        """
        self._quic.close(
            error_code=error_code,
            reason_phrase=reason_phrase,
        )
        self.transmit()

    def connect(self, addr: NetworkAddress, transmit: bool = True) -> None:
        """
        Initiate the TLS handshake.

        This method can only be called for clients and a single time.
        """
        self._quic.connect(addr, now=self._loop.time())
        if transmit:
            self.transmit()

    async def create_stream(
        self, is_unidirectional: bool = False
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Create a QUIC stream and return a pair of (reader, writer) objects.

        The returned reader and writer objects are instances of
        :class:`asyncio.StreamReader` and :class:`asyncio.StreamWriter` classes.

        :raises ConnectionError: If the connection is closing or closed.
        """
        if self._quic.is_closing():
            raise ConnectionError("Connection closed")
        stream_id = self._quic.get_next_available_stream_id(
            is_unidirectional=is_unidirectional
        )
        # Opening the stream reserves its ID, without sending anything.
        self._quic.send_stream_data(stream_id, b"")
        return self._create_stream(stream_id)

    def request_key_update(self) -> None:
        """
        Request an update of the encryption keys.
        """
        self._quic.request_key_update()
        self.transmit()

    async def ping(self) -> None:
        """
        Ping the peer and wait for the response.
        """
        waiter = self._loop.create_future()
        uid = id(waiter)
        self._ping_waiters[uid] = waiter
        self._quic.send_ping(uid)
        self.transmit()
        await asyncio.shield(waiter)

    def transmit(self) -> None:
        """
        Send pending datagrams to the peer and arm the timer if needed.

        This method is called automatically when data is received from the peer
        or when a timer goes off. If you interact directly with the underlying
        :class:`~aioquic.quic.connection.QuicConnection`, make sure you call this
        method whenever data needs to be sent out to the network.
        """
        self._transmit_task = None

        # send datagrams
        for data, addr in self._quic.datagrams_to_send(now=self._loop.time()):
            self._transport.sendto(data, addr)

        # re-arm timer
        timer_at = self._quic.get_timer()
        if self._timer is not None and self._timer_at != timer_at:
            self._timer.cancel()
            self._timer = None
        if self._timer is None and timer_at is not None:
            self._timer = self._loop.call_at(timer_at, self._handle_timer)
        self._timer_at = timer_at

    async def wait_closed(self) -> None:
        """
        Wait for the connection to be closed.
        """
        await self._closed.wait()

    async def wait_connected(self) -> None:
        """
        Wait for the TLS handshake to complete.
        """
        if self._connected_waiter is not None:
            raise RuntimeError("Already awaiting connected")
        if not self._connected:
            self._connected_waiter = self._loop.create_future()
            await asyncio.shield(self._connected_waiter)

    # asyncio.Transport

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """:meta private:"""
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes | str, addr: NetworkAddress) -> None:
        """:meta private:"""
        self._quic.receive_datagram(cast(bytes, data), addr, now=self._loop.time())
        self._process_events()
        self.transmit()

    # overridable

    def quic_event_received(self, event: events.QuicEvent) -> None:
        """
        Called when a QUIC event is received.

        Reimplement this in your subclass to handle the events.
        """
        # FIXME: move this to a subclass
        if isinstance(event, events.ConnectionTerminated):
            for adapter in self._adapters.values():
                adapter._connection_terminated()
            self._adapters.clear()
        elif isinstance(event, events.StopSendingReceived):
            adapter = self._adapters.get(event.stream_id, None)
            if adapter is not None:
                adapter._stop_received(event.error_code)
        elif isinstance(event, events.StreamDataReceived):
            adapter = self._adapter_for_event(event.stream_id)
            if adapter is not None:
                adapter._data_received(event.data, event.end_stream)
        elif isinstance(event, events.StreamReset):
            adapter = self._adapter_for_event(event.stream_id)
            if adapter is not None:
                adapter._reset_received(event.error_code)

    # private

    def _adapter_for_event(self, stream_id: int) -> "QuicStreamAdapter | None":
        """
        Return the adapter of the stream an event concerns, passing a stream the
        peer has just opened to the stream handler.

        Without a stream handler, the streams the peer opens are ignored.
        """
        adapter = self._adapters.get(stream_id, None)
        if (
            adapter is None
            and self._stream_handler is not None
            and stream_is_client_initiated(stream_id)
            != self._quic.configuration.is_client
        ):
            reader, writer = self._create_stream(stream_id)
            self._stream_handler(reader, writer)
            adapter = self._adapters[stream_id]
        return adapter

    def _create_stream(
        self, stream_id: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader = asyncio.StreamReader()
        adapter = QuicStreamAdapter(self, stream_id, reader)
        # The adapter feeds the reader, and QuicStreamWriter does not use the
        # protocol, which only satisfies the StreamWriter constructor.
        protocol = asyncio.streams.StreamReaderProtocol(reader)
        writer = QuicStreamWriter(adapter, protocol, reader, self._loop)
        self._adapters[stream_id] = adapter
        return reader, writer

    def _handle_timer(self) -> None:
        now = max(self._timer_at, self._loop.time())
        self._timer = None
        self._timer_at = None
        self._quic.handle_timer(now=now)
        self._process_events()
        self.transmit()

    def _process_events(self) -> None:
        event = self._quic.next_event()
        while event is not None:
            if isinstance(event, events.ConnectionIdIssued):
                self._connection_id_issued_handler(event.connection_id)
            elif isinstance(event, events.ConnectionIdRetired):
                self._connection_id_retired_handler(event.connection_id)
            elif isinstance(event, events.ConnectionTerminated):
                self._connection_terminated_handler()

                # abort connection waiter
                if self._connected_waiter is not None:
                    waiter = self._connected_waiter
                    self._connected_waiter = None
                    waiter.set_exception(ConnectionError)

                # abort ping waiters
                for waiter in self._ping_waiters.values():
                    waiter.set_exception(ConnectionError)
                self._ping_waiters.clear()

                self._closed.set()
            elif isinstance(event, events.HandshakeCompleted):
                if self._connected_waiter is not None:
                    waiter = self._connected_waiter
                    self._connected = True
                    self._connected_waiter = None
                    waiter.set_result(None)
            elif isinstance(event, events.PingAcknowledged):
                waiter = self._ping_waiters.pop(event.uid, None)
                if waiter is not None:
                    waiter.set_result(None)
            self.quic_event_received(event)
            event = self._quic.next_event()

    def _transmit_soon(self) -> None:
        if self._transmit_task is None:
            self._transmit_task = self._loop.call_soon(self.transmit)


class QuicStreamAdapter(asyncio.Transport):
    def __init__(
        self,
        protocol: QuicConnectionProtocol,
        stream_id: int,
        reader: asyncio.StreamReader,
    ):
        self.stream_id = stream_id
        self._aborted = False
        self._closed = protocol._loop.create_future()
        # Whether we closed the sending part ourselves, as writing is then a
        # mistake rather than a consequence of what the network did.
        self._eof = False
        self._exception: ConnectionError | None = None
        self._protocol = protocol
        self._reader = reader
        self._receive_finished = not protocol._quic._stream_can_receive(stream_id)
        if self._receive_finished:
            # Nothing is ever received on our unidirectional streams.
            reader.feed_eof()
        if not self.can_write_eof():
            # Nothing is ever sent on the peer's unidirectional streams.
            self._closed.set_result(None)
            self._eof = True
        else:
            # The peer may have stopped its stream before its first data arrived,
            # and QUIC then already reset the sending part (RFC 9000 section 3.5).
            stream = protocol._quic._streams.get(stream_id)
            if stream is not None and stream.sender._reset_error_code is not None:
                self._stop_received(stream.sender._reset_error_code)

    def abort(self) -> None:
        """
        Reset the sending part of the stream and stop the receiving part, with
        error code 0.
        """
        if self._aborted or self._protocol._adapters.get(self.stream_id) is not self:
            # The stream was already aborted, or both its parts have ended.
            return
        self._aborted = True
        self._eof = True
        if self.can_write_eof():
            self._protocol._quic.reset_stream(self.stream_id, error_code=0)
        if not self._receive_finished:
            self._protocol._quic.stop_stream(self.stream_id, error_code=0)
            self._reader.feed_eof()
        if not self._closed.done():
            self._closed.set_result(None)
        self._protocol._transmit_soon()
        self._discard_if_finished()

    def can_write_eof(self) -> bool:
        return self._protocol._quic._stream_can_send(self.stream_id)

    def close(self) -> None:
        self.write_eof()

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """
        Get information about the underlying QUIC stream.
        """
        if name == "stream_id":
            return self.stream_id
        return default

    def is_closing(self) -> bool:
        return self._closed.done() or self._protocol._quic.is_closing()

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self._eof:
            raise RuntimeError("Cannot write to a closed stream")
        if self.is_closing():
            # As on TCP, the data is discarded and drain() tells why.
            return
        self._protocol._quic.send_stream_data(self.stream_id, bytes(data))
        self._protocol._transmit_soon()

    def write_eof(self) -> None:
        if self._closed.done():
            return
        self._eof = True
        if self._protocol._quic.is_closing():
            # As on TCP, the end of the stream is never sent, and wait_closed()
            # tells why.
            self._exception = ConnectionError("Connection closed")
        else:
            self._protocol._quic.send_stream_data(self.stream_id, b"", end_stream=True)
            self._protocol._transmit_soon()
        self._closed.set_result(None)
        self._discard_if_finished()

    def _connection_terminated(self) -> None:
        if not self._receive_finished and not self._aborted:
            self._reader.set_exception(ConnectionError("Connection closed"))
        if not self._closed.done():
            self._exception = ConnectionError("Connection closed")
            self._closed.set_result(None)

    def _data_received(self, data: bytes, end_stream: bool) -> None:
        # Data can still arrive after abort() (RFC 9000 section 3.5).
        if not self._aborted:
            self._reader.feed_data(data)
            if end_stream:
                self._reader.feed_eof()
        if end_stream:
            self._receive_finished = True
            self._discard_if_finished()

    def _discard_if_finished(self) -> None:
        """
        Stop tracking the stream once no further event can concern it.
        """
        if self._receive_finished and self._closed.done():
            self._protocol._adapters.pop(self.stream_id, None)

    def _reset_received(self, error_code: int) -> None:
        if not self._aborted:
            self._reader.set_exception(
                ConnectionResetError(
                    f"Stream {self.stream_id} reset by peer with error code "
                    f"{error_code}"
                )
            )
        self._receive_finished = True
        self._discard_if_finished()

    def _stop_received(self, error_code: int) -> None:
        if self._closed.done():
            # All the data was written, and QUIC handles the request.
            return
        self._exception = ConnectionResetError(
            f"Stream {self.stream_id} stopped by peer with error code {error_code}"
        )
        self._closed.set_result(None)
        self._discard_if_finished()


class QuicStreamWriter(asyncio.StreamWriter):
    async def drain(self) -> None:
        """
        Raise if the peer stopped the stream or the connection is closing,
        otherwise return immediately, as writes are never paused.
        """
        # Unlike TCP, a reset by the peer only ends the receiving part of the
        # stream, so the reader's exception must not be raised here.
        adapter = cast(QuicStreamAdapter, self.transport)
        if adapter._exception is not None:
            raise adapter._exception
        if adapter._protocol._quic.is_closing():
            raise ConnectionError("Connection closed")

    async def wait_closed(self) -> None:
        """
        Wait until the sending part of the stream is closed, and raise if the
        peer stopped the stream or the connection closed first.

        This does not wait for the peer to receive the data: closing the
        connection straight afterwards can still discard data that has not
        been sent yet.
        """
        adapter = cast(QuicStreamAdapter, self.transport)
        await asyncio.shield(adapter._closed)
        if adapter._exception is not None:
            raise adapter._exception
