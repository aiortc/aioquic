from dataclasses import dataclass

Headers = list[tuple[bytes, bytes]]


class H3Event:
    """
    Base class for HTTP/3 events.
    """


@dataclass
class DataReceived(H3Event):
    """
    The DataReceived event is fired whenever data is received on a stream from
    the remote peer.
    """

    data: bytes
    "The data which was received."

    stream_id: int
    "The ID of the stream the data was received for."

    stream_ended: bool
    "Whether the STREAM frame had the FIN bit set."


@dataclass
class DatagramReceived(H3Event):
    """
    The DatagramReceived is fired whenever a datagram is received from the
    the remote peer.
    """

    data: bytes
    "The data which was received."

    stream_id: int
    "The ID of the stream the data was received for."


@dataclass
class GoAwayReceived(H3Event):
    """
    The GoAwayReceived event is fired when a client receives a GOAWAY frame, as
    the server starts shutting down the connection (RFC 9114 section 5.2).

    The client MUST NOT initiate new requests on this connection. Requests on
    streams whose ID is ``stream_id`` or higher were not processed by the
    server and can be retried on another connection. A server may send several
    GOAWAY frames, each with an ID no higher than the last.
    """

    stream_id: int
    "The first request stream ID the server will not process."


@dataclass
class HeadersReceived(H3Event):
    """
    The HeadersReceived event is fired whenever headers are received.
    """

    headers: Headers
    "The headers."

    stream_id: int
    "The ID of the stream the headers were received for."

    stream_ended: bool
    "Whether the STREAM frame had the FIN bit set."


@dataclass
class PushPromiseReceived(H3Event):
    """
    Kept for compatibility, as server push is no longer supported.
    """

    headers: Headers
    push_id: int
    stream_id: int


@dataclass
class WebTransportStreamDataReceived(H3Event):
    """
    The WebTransportStreamDataReceived is fired whenever data is received
    for a WebTransport stream.

    .. warning::

        This event is experimental, as WebTransport over HTTP/3 is still an
        Internet-Draft (draft-ietf-webtrans-http3). It could change or be
        removed in a future release.
    """

    data: bytes
    "The data which was received."

    stream_id: int
    "The ID of the stream the data was received for."

    stream_ended: bool
    "Whether the STREAM frame had the FIN bit set."

    session_id: int
    "The ID of the session the data was received for."
