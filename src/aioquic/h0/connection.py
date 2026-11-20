from aioquic.buffer import UINT_VAR_MAX
from aioquic.h3.events import DataReceived, H3Event, Headers, HeadersReceived
from aioquic.h3.exceptions import (
    InvalidConnectionStateError,
    InvalidStreamIdError,
    InvalidStreamStateError,
)
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent, StreamDataReceived

H0_ALPN = ["hq-interop"]


class H0Connection:
    """
    An HTTP/0.9 connection object.
    """

    def __init__(self, quic: QuicConnection):
        self._buffer: dict[int, bytes] = {}
        self._headers_received: dict[int, bool] = {}
        self._is_client = quic.configuration.is_client
        self._quic = quic

    def handle_event(self, event: QuicEvent) -> list[H3Event]:
        http_events: list[H3Event] = []

        if isinstance(event, StreamDataReceived) and (event.stream_id % 4) == 0:
            data = self._buffer.pop(event.stream_id, b"") + event.data
            if not self._headers_received.get(event.stream_id, False):
                if self._is_client:
                    http_events.append(
                        HeadersReceived(
                            headers=[], stream_ended=False, stream_id=event.stream_id
                        )
                    )
                elif data.endswith(b"\r\n") or event.end_stream:
                    method, path = data.rstrip().split(b" ", 1)
                    http_events.append(
                        HeadersReceived(
                            headers=[(b":method", method), (b":path", path)],
                            stream_ended=False,
                            stream_id=event.stream_id,
                        )
                    )
                    data = b""
                else:
                    # incomplete request, stash the data
                    self._buffer[event.stream_id] = data
                    return http_events
                self._headers_received[event.stream_id] = True

            http_events.append(
                DataReceived(
                    data=data, stream_ended=event.end_stream, stream_id=event.stream_id
                )
            )

        return http_events

    @property
    def quic_connection(self) -> QuicConnection:
        """
        Return the QUIC connection this HTTP/0.9 connection runs on.
        """
        return self._quic

    def send_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        """
        Send data on the given stream.

        :param stream_id: The stream ID on which to send the data.
        :param data: The data to send.
        :param end_stream: Whether to end the stream.
        :raises ~aioquic.h3.exceptions.InvalidStreamIdError:
            If the stream ID is out of range.
        :raises ~aioquic.h3.exceptions.InvalidConnectionStateError:
            If the connection is closing or closed.
        :raises ~aioquic.h3.exceptions.InvalidStreamStateError:
            If the stream is not open.
        """
        self._check_sending_allowed(stream_id)
        self._quic.send_stream_data(stream_id, data, end_stream)

    def send_headers(
        self, stream_id: int, headers: Headers, end_stream: bool = False
    ) -> None:
        """
        Send headers on the given stream.

        A client sends the request line, a server sends no data.

        :param stream_id: The stream ID on which to send the headers.
        :param headers: The HTTP headers to send.
        :param end_stream: Whether to end the stream.
        :raises ~aioquic.h3.exceptions.InvalidStreamIdError:
            If the stream ID is out of range.
        :raises ~aioquic.h3.exceptions.InvalidConnectionStateError:
            If the connection is closing or closed.
        :raises ~aioquic.h3.exceptions.InvalidStreamStateError:
            If the stream is not open.
        """
        self._check_sending_allowed(stream_id)
        if self._is_client:
            headers_dict = dict(headers)
            data = headers_dict[b":method"] + b" " + headers_dict[b":path"] + b"\r\n"
        else:
            data = b""
        self._quic.send_stream_data(stream_id, data, end_stream)

    def _check_sending_allowed(self, stream_id: int) -> None:
        """
        Check data can be sent on the stream, before anything is sent.
        """
        if not 0 <= stream_id <= UINT_VAR_MAX:
            raise InvalidStreamIdError("Stream ID must be between 0 and 2^62 - 1")
        if self._quic.is_closing():
            raise InvalidConnectionStateError(
                "Cannot send once the connection is closing"
            )
        if not self._quic.can_send_stream_data(stream_id):
            raise InvalidStreamStateError("Cannot send on a stream which is not open")
