import logging
import re
import warnings
from enum import Enum, IntEnum
from typing import Any

import pylsqpack
from aioquic._deprecations import deprecate_positional_argument
from aioquic.buffer import (
    UINT_VAR_MAX,
    UINT_VAR_MAX_SIZE,
    Buffer,
    BufferReadError,
    encode_uint_var,
)
from aioquic.h3.events import (
    DatagramReceived,
    DataReceived,
    GoAwayReceived,
    H3Event,
    Headers,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.h3.exceptions import (
    H3Error,
    InvalidStreamIdError,
    InvalidStreamStateError,
    InvalidStreamTypeError,
    NoAvailablePushIDError,
)
from aioquic.quic.connection import (
    QuicConnection,
    stream_is_client_initiated,
    stream_is_unidirectional,
)
from aioquic.quic.events import (
    DatagramFrameReceived,
    QuicEvent,
    StopSendingReceived,
    StreamDataReceived,
    StreamReset,
)
from aioquic.quic.exceptions import StreamStateError
from aioquic.quic.logger import QuicLoggerTrace

logger = logging.getLogger("http3")

# Connection-specific fields (RFC 9110 section 7.6.1), which make an HTTP/3
# message malformed (RFC 9114 section 4.2).
CONNECTION_SPECIFIC_HEADERS = frozenset(
    (
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"te",
        b"transfer-encoding",
        b"upgrade",
    )
)
H3_ALPN = ["h3"]
# The largest decoded field section we accept, which we advertise in the
# SETTINGS_MAX_FIELD_SECTION_SIZE setting (RFC 9114 section 4.2.2).
MAX_FIELD_SECTION_SIZE = 65536
# The largest SETTINGS frame payload we send or accept, far above the few dozen
# bytes of real SETTINGS frames.
MAX_SETTINGS_SIZE = 4096
# Frame types used in HTTP/2 which have no HTTP/3 equivalent, receiving them
# is an error (RFC 9114 section 7.2.8 and section 11.2.1).
RESERVED_FRAME_TYPES = (0x2, 0x6, 0x8, 0x9)
# Setting identifiers used in HTTP/2 which have no HTTP/3 equivalent, receiving
# them is an error (RFC 9114 section 7.2.4.1 and section 11.2.2).
RESERVED_SETTINGS = (0x0, 0x2, 0x3, 0x4, 0x5)
UPPERCASE = re.compile(b"[A-Z]")
COLON = 0x3A
NUL = 0x00
LF = 0x0A
CR = 0x0D
SP = 0x20
HTAB = 0x09
WHITESPACE = (SP, HTAB)


class ErrorCode(IntEnum):
    H3_DATAGRAM_ERROR = 0x33
    H3_NO_ERROR = 0x100
    H3_GENERAL_PROTOCOL_ERROR = 0x101
    H3_INTERNAL_ERROR = 0x102
    H3_STREAM_CREATION_ERROR = 0x103
    H3_CLOSED_CRITICAL_STREAM = 0x104
    H3_FRAME_UNEXPECTED = 0x105
    H3_FRAME_ERROR = 0x106
    H3_EXCESSIVE_LOAD = 0x107
    H3_ID_ERROR = 0x108
    H3_SETTINGS_ERROR = 0x109
    H3_MISSING_SETTINGS = 0x10A
    H3_REQUEST_REJECTED = 0x10B
    H3_REQUEST_CANCELLED = 0x10C
    H3_REQUEST_INCOMPLETE = 0x10D
    H3_MESSAGE_ERROR = 0x10E
    H3_CONNECT_ERROR = 0x10F
    H3_VERSION_FALLBACK = 0x110
    QPACK_DECOMPRESSION_FAILED = 0x200
    QPACK_ENCODER_STREAM_ERROR = 0x201
    QPACK_DECODER_STREAM_ERROR = 0x202


class FrameType(IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    CANCEL_PUSH = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    GOAWAY = 0x7
    MAX_PUSH_ID = 0xD
    WEBTRANSPORT_STREAM = 0x41


class HeadersState(Enum):
    INITIAL = 0
    AFTER_HEADERS = 1
    AFTER_TRAILERS = 2


class Setting(IntEnum):
    QPACK_MAX_TABLE_CAPACITY = 0x1
    MAX_FIELD_SECTION_SIZE = 0x6
    QPACK_BLOCKED_STREAMS = 0x7

    # https://datatracker.ietf.org/doc/html/rfc9220#section-5
    ENABLE_CONNECT_PROTOCOL = 0x8
    # https://datatracker.ietf.org/doc/html/rfc9297#section-5.1
    H3_DATAGRAM = 0x33
    # https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http2-02#section-10.1
    ENABLE_WEBTRANSPORT = 0x2B603742

    # Dummy setting to check it is correctly ignored by the peer.
    # https://datatracker.ietf.org/doc/html/rfc9114#section-7.2.4.1
    DUMMY = 0x21


class StreamType(IntEnum):
    CONTROL = 0
    PUSH = 1
    QPACK_ENCODER = 2
    QPACK_DECODER = 3
    WEBTRANSPORT = 0x54


class ProtocolError(Exception):
    """
    Base class for protocol errors.

    These errors are not exposed to the API user, they are handled
    in :meth:`H3Connection.handle_event`.
    """

    error_code = ErrorCode.H3_GENERAL_PROTOCOL_ERROR

    def __init__(self, reason_phrase: str = ""):
        self.reason_phrase = reason_phrase


class QpackDecompressionFailed(ProtocolError):
    error_code = ErrorCode.QPACK_DECOMPRESSION_FAILED


class QpackDecoderStreamError(ProtocolError):
    error_code = ErrorCode.QPACK_DECODER_STREAM_ERROR


class QpackEncoderStreamError(ProtocolError):
    error_code = ErrorCode.QPACK_ENCODER_STREAM_ERROR


class ClosedCriticalStream(ProtocolError):
    error_code = ErrorCode.H3_CLOSED_CRITICAL_STREAM


class DatagramError(ProtocolError):
    error_code = ErrorCode.H3_DATAGRAM_ERROR


class ExcessiveLoad(ProtocolError):
    error_code = ErrorCode.H3_EXCESSIVE_LOAD


class FrameError(ProtocolError):
    error_code = ErrorCode.H3_FRAME_ERROR


class FrameUnexpected(ProtocolError):
    error_code = ErrorCode.H3_FRAME_UNEXPECTED


class IdError(ProtocolError):
    error_code = ErrorCode.H3_ID_ERROR


class MessageError(ProtocolError):
    error_code = ErrorCode.H3_MESSAGE_ERROR


class MissingSettingsError(ProtocolError):
    error_code = ErrorCode.H3_MISSING_SETTINGS


class SettingsError(ProtocolError):
    error_code = ErrorCode.H3_SETTINGS_ERROR


class StreamCreationError(ProtocolError):
    error_code = ErrorCode.H3_STREAM_CREATION_ERROR


def encode_frame(frame_type: int, frame_data: bytes) -> bytes:
    frame_length = len(frame_data)
    buf = Buffer(capacity=frame_length + 2 * UINT_VAR_MAX_SIZE)
    buf.push_uint_var(frame_type)
    buf.push_uint_var(frame_length)
    buf.push_bytes(frame_data)
    return buf.data


def encode_settings(settings: dict[int, int]) -> bytes:
    buf = Buffer(capacity=MAX_SETTINGS_SIZE)
    for setting, value in settings.items():
        buf.push_uint_var(setting)
        buf.push_uint_var(value)
    return buf.data


def is_interim_response(headers: Headers) -> bool:
    """
    Return whether the headers are those of an interim (1xx) response.
    """
    for key, value in headers:
        if key == b":status":
            return value.startswith(b"1")
    return False


def parse_id_frame(frame_type: FrameType, data: bytes) -> int:
    """
    Parse the payload of a frame which carries a single ID, such as GOAWAY or
    MAX_PUSH_ID.
    """
    buf = Buffer(data=data)
    try:
        frame_id = buf.pull_uint_var()
    except BufferReadError:
        raise FrameError(f"Could not parse {frame_type.name} frame")
    if not buf.eof():
        raise FrameError(f"{frame_type.name} frame has trailing data")
    return frame_id


def parse_settings(data: bytes) -> dict[int, int]:
    buf = Buffer(data=data)
    settings: dict[int, int] = {}
    while not buf.eof():
        try:
            setting = buf.pull_uint_var()
            value = buf.pull_uint_var()
        except BufferReadError:
            raise FrameError("Could not parse SETTINGS frame")
        if setting in RESERVED_SETTINGS:
            raise SettingsError(f"Setting identifier 0x{setting:x} is reserved")
        if setting in settings:
            raise SettingsError(f"Setting identifier 0x{setting:x} is included twice")
        settings[setting] = value
    return dict(settings)


def stream_is_request_response(stream_id: int) -> bool:
    """
    Returns True if the stream is a client-initiated bidirectional stream.
    """
    return stream_id % 4 == 0


def validate_header_name(key: bytes) -> None:
    """
    Validate a header name as specified by RFC 9113 section 8.2.1.
    """
    for i, c in enumerate(key):
        if c <= 0x20 or (c >= 0x41 and c <= 0x5A) or c >= 0x7F:
            raise MessageError(f"Header {key!r} contains invalid characters")
        if c == COLON and i != 0:
            # Colon not at start, definitely bad.  Keys starting with a colon
            # will be checked in pseudo-header validation code.
            raise MessageError(f"Header {key!r} contains a non-initial colon")


def validate_header_value(key: bytes, value: bytes) -> None:
    """
    Validate a header value as specified by RFC 9113 section 8.2.1.
    """
    for c in value:
        if c == NUL or c == LF or c == CR:
            raise MessageError(f"Header {key!r} value has forbidden characters")
    if len(value) > 0:
        first = value[0]
        if first in WHITESPACE:
            raise MessageError(f"Header {key!r} value starts with whitespace")
        if len(value) > 1:
            last = value[-1]
            if last in WHITESPACE:
                raise MessageError(f"Header {key!r} value ends with whitespace")


def validate_headers(
    headers: Headers,
    *,
    allow_te: bool = False,
    allowed_pseudo_headers: frozenset[bytes],
    required_pseudo_headers: frozenset[bytes],
    stream: "H3Stream | None" = None,
) -> None:
    after_pseudo_headers = False
    authority: bytes | None = None
    path: bytes | None = None
    scheme: bytes | None = None
    seen_pseudo_headers: set[bytes] = set()
    for key, value in headers:
        validate_header_name(key)
        validate_header_value(key, value)

        if key.startswith(b":"):
            # pseudo-headers
            if after_pseudo_headers:
                raise MessageError(
                    f"Pseudo-header {key!r} is not allowed after regular headers"
                )
            if key not in allowed_pseudo_headers:
                raise MessageError(f"Pseudo-header {key!r} is not valid")
            if key in seen_pseudo_headers:
                raise MessageError(f"Pseudo-header {key!r} is included twice")
            seen_pseudo_headers.add(key)

            # store value
            if key == b":authority":
                authority = value
            elif key == b":path":
                path = value
            elif key == b":scheme":
                scheme = value
        else:
            # regular headers
            after_pseudo_headers = True
            # a few more semantic checks
            if key == b"content-length":
                try:
                    content_length = int(value)
                    if content_length < 0:
                        raise ValueError
                except ValueError:
                    raise MessageError("content-length is not a non-negative integer")
                if stream:
                    stream.expected_content_length = content_length
            elif key == b"te" and allow_te:
                # TE may only be "trailers" in request headers (RFC 9114 section 4.2).
                if value.lower() != b"trailers":
                    raise MessageError(f"Header {key!r} value is not trailers")
            elif key in CONNECTION_SPECIFIC_HEADERS:
                raise MessageError(f"Header {key!r} is connection-specific")

    # check required pseudo-headers are present
    missing = required_pseudo_headers.difference(seen_pseudo_headers)
    if missing:
        raise MessageError(f"Pseudo-headers {sorted(missing)} are missing")

    if scheme in (b"http", b"https"):
        if not authority:
            raise MessageError("Pseudo-header b':authority' cannot be empty")
        if not path:
            raise MessageError("Pseudo-header b':path' cannot be empty")


def validate_request_headers(
    headers: Headers, stream: "H3Stream | None" = None
) -> None:
    validate_headers(
        headers,
        allow_te=True,
        allowed_pseudo_headers=frozenset(
            # FIXME: The pseudo-header :protocol is not actually defined, but
            # we use it for the WebSocket demo.
            (b":method", b":scheme", b":authority", b":path", b":protocol")
        ),
        required_pseudo_headers=frozenset((b":method", b":authority")),
        stream=stream,
    )


def validate_response_headers(
    headers: Headers, stream: "H3Stream | None" = None
) -> None:
    validate_headers(
        headers,
        allowed_pseudo_headers=frozenset((b":status",)),
        required_pseudo_headers=frozenset((b":status",)),
        stream=stream,
    )

    # The status code is a three-digit integer (RFC 9110 section 15).
    status = dict(headers)[b":status"]
    if len(status) != 3 or not status.isdigit():
        raise MessageError(f"Pseudo-header b':status' has invalid value {status!r}")

    # HTTP/3 does not support 101 Switching Protocols (RFC 9114 section 4.5).
    if status == b"101":
        raise MessageError("Pseudo-header b':status' cannot be 101")


def validate_trailers(headers: Headers) -> None:
    validate_headers(
        headers,
        allowed_pseudo_headers=frozenset(),
        required_pseudo_headers=frozenset(),
    )


class H3Stream:
    def __init__(self, stream_id: int) -> None:
        self.buffer = b""
        self.receiving_ended = False
        self.sending_ended = False
        self.frame_received = False
        self.frame_size: int | None = None
        self.frame_type: int | None = None
        self.headers_recv_state: HeadersState = HeadersState.INITIAL
        self.headers_send_state: HeadersState = HeadersState.INITIAL
        self.interim_response_received = False
        self.session_id: int | None = None
        self.stream_id = stream_id
        self.stream_type: int | None = None
        self.expected_content_length: int | None = None
        self.content_length: int = 0

    def is_ended(self) -> bool:
        return self.sending_ended and self.receiving_ended


class H3Connection:
    """
    A low-level HTTP/3 connection object.

    .. warning::

        The ``enable_webtransport`` option is experimental, as WebTransport over
        HTTP/3 is still an Internet-Draft (draft-ietf-webtrans-http3). It could
        change or be removed in a future release.

    .. deprecated:: 1.8.0

        Passing ``enable_webtransport`` as a positional argument is deprecated,
        pass it as a keyword argument instead.

    :param quic: A :class:`~aioquic.quic.connection.QuicConnection` instance.
    :param enable_webtransport: Whether to enable WebTransport.
    """

    @deprecate_positional_argument("enable_webtransport")
    def __init__(
        self, quic: QuicConnection, *, enable_webtransport: bool = False
    ) -> None:
        # settings
        # We use no dynamic table, so header blocks never wait for its entries
        # and no stream data is held while they arrive (RFC 9204 sections 2.1.2
        # and 3.2.3).
        self._max_table_capacity = 0
        self._blocked_streams = 0
        self._enable_webtransport = enable_webtransport

        self._is_client = quic.configuration.is_client
        self._is_done = False
        self._quic = quic
        self._quic_logger: QuicLoggerTrace | None = quic._quic_logger
        self._decoder = pylsqpack.Decoder(
            self._max_table_capacity,
            self._blocked_streams,
            max_field_section_size=MAX_FIELD_SECTION_SIZE,
        )
        self._encoder = pylsqpack.Encoder()
        self._settings_received = False
        self._stream: dict[int, H3Stream] = {}

        # The maximum push ID received by a server, which never pushes.
        self._max_push_id: int | None = None
        self._received_goaway_id: int | None = None

        self._local_control_stream_id: int | None = None
        self._local_decoder_stream_id: int | None = None
        self._local_encoder_stream_id: int | None = None

        self._peer_control_stream_id: int | None = None
        self._peer_decoder_stream_id: int | None = None
        self._peer_encoder_stream_id: int | None = None
        self._received_settings: dict[int, int] | None = None
        self._sent_settings: dict[int, int] | None = None

        self._init_connection()

    def create_webtransport_stream(
        self, session_id: int, is_unidirectional: bool = False
    ) -> int:
        """
        Create a WebTransport stream and return the stream ID.

        .. warning::

            This method is experimental, as WebTransport over HTTP/3 is still an
            Internet-Draft (draft-ietf-webtrans-http3). It could change or be
            removed in a future release.

        .. aioquic_transmit::

        :param session_id: The WebTransport session identifier.
        :param is_unidirectional: Whether to create a unidirectional stream.
        :raises ~aioquic.h3.exceptions.InvalidStreamIdError:
            If the session ID is out of range.
        :raises ~aioquic.h3.exceptions.InvalidStreamTypeError:
            If WebTransport is not enabled, or the session ID is not a
            client-initiated bidirectional stream.
        """
        if not self._enable_webtransport:
            raise InvalidStreamTypeError("WebTransport is not enabled")

        self._check_stream_id(session_id)

        # The session ID is the ID of the CONNECT stream which established the
        # session (draft-ietf-webtrans-http3-02 section 2).
        if not stream_is_request_response(session_id):
            raise InvalidStreamTypeError(
                "WebTransport sessions can only be client-initiated bidirectional "
                "streams"
            )

        if is_unidirectional:
            stream_id = self._create_uni_stream(StreamType.WEBTRANSPORT)
            self._quic.send_stream_data(stream_id, encode_uint_var(session_id))
        else:
            stream_id = self._quic.get_next_available_stream_id()
            self._log_stream_type(
                stream_id=stream_id, stream_type=StreamType.WEBTRANSPORT
            )
            self._quic.send_stream_data(
                stream_id,
                encode_uint_var(FrameType.WEBTRANSPORT_STREAM)
                + encode_uint_var(session_id),
            )

            # The stream belongs to WebTransport in both directions
            # (draft-ietf-webtrans-http3-02 section 2), so the peer's reply has no
            # 0x41 prefix: record the stream now. HTTP/3 sends nothing after the
            # prefix, so only the peer's half keeps the state alive.
            stream = H3Stream(stream_id)
            stream.frame_type = FrameType.WEBTRANSPORT_STREAM
            stream.session_id = session_id
            stream.sending_ended = True
            self._stream[stream_id] = stream
        return stream_id

    def handle_event(self, event: QuicEvent) -> list[H3Event]:
        """
        Handle a QUIC event and return a list of HTTP events.

        :param event: The QUIC event to handle.
        """

        if not self._is_done:
            try:
                if isinstance(event, StreamDataReceived):
                    return self._receive_stream_data(event)
                elif isinstance(event, DatagramFrameReceived):
                    return self._receive_datagram(event.data)
                elif isinstance(event, StopSendingReceived):
                    self._receive_stop_sending(event.stream_id)
                elif isinstance(event, StreamReset):
                    self._receive_stream_reset(event.stream_id)
            except ProtocolError as exc:
                self._is_done = True
                self._quic.close(
                    error_code=exc.error_code, reason_phrase=exc.reason_phrase
                )

        return []

    def send_datagram(self, stream_id: int, data: bytes) -> None:
        """
        Send a datagram for the specified stream.

        .. aioquic_transmit::

        :param stream_id: The stream ID.
        :param data: The HTTP/3 datagram payload.
        :raises ~aioquic.h3.exceptions.InvalidStreamIdError:
            If the stream ID is out of range.
        :raises ~aioquic.h3.exceptions.InvalidStreamTypeError:
            If the stream is not a client-initiated bidirectional stream.
        """
        self._check_stream_id(stream_id)

        # check stream ID is valid
        if not stream_is_request_response(stream_id):
            raise InvalidStreamTypeError(
                "Datagrams can only be sent for client-initiated bidirectional streams"
            )

        self._quic.send_datagram_frame(encode_uint_var(stream_id // 4) + data)

    def send_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        """
        Send data on the given stream.

        .. aioquic_transmit::

        :param stream_id: The stream ID on which to send the data.
        :param data: The data to send.
        :param end_stream: Whether to end the stream.
        :raises ~aioquic.h3.exceptions.InvalidStreamIdError:
            If the stream ID is out of range.
        :raises ~aioquic.h3.exceptions.InvalidStreamTypeError:
            If the stream is not a request stream.
        :raises ~aioquic.h3.exceptions.InvalidStreamStateError:
            If data is sent before the headers, after the trailers, or after the
            stream was ended or reset.
        """
        self._check_stream_type_for_sending(stream_id)

        stream = self._stream.get(stream_id)
        if stream is not None and stream.sending_ended:
            raise InvalidStreamStateError("Cannot send after the stream was ended")
        if stream is None or stream.headers_send_state == HeadersState.INITIAL:
            raise InvalidStreamStateError("Cannot send data before the headers")
        if stream.headers_send_state == HeadersState.AFTER_TRAILERS:
            raise InvalidStreamStateError("Cannot send data after the trailers")

        # log frame
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                name="http3:frame_created",
                data=self._quic_logger.encode_http3_data_frame(
                    length=len(data), stream_id=stream_id
                ),
            )

        self._send_request_stream_data(
            stream_id, encode_frame(FrameType.DATA, data), end_stream
        )
        if end_stream:
            stream.sending_ended = True
            self._store_or_discard_stream(stream)

    def send_headers(
        self, stream_id: int, headers: Headers, end_stream: bool = False
    ) -> None:
        """
        Send headers on the given stream.

        .. aioquic_transmit::

        :param stream_id: The stream ID on which to send the headers.
        :param headers: The HTTP headers to send.
        :param end_stream: Whether to end the stream.
        :raises ~aioquic.h3.exceptions.InvalidStreamIdError:
            If the stream ID is out of range.
        :raises ~aioquic.h3.exceptions.InvalidStreamTypeError:
            If the stream is not a request stream.
        :raises ~aioquic.h3.exceptions.InvalidStreamStateError:
            If headers are sent after the trailers, after the stream was ended or
            reset, or on a stream the peer has not opened, or an interim response
            would end the stream.
        :raises ~aioquic.h3.exceptions.H3Error:
            If the peer stopped the QPACK encoder stream.
        """
        self._check_stream_type_for_sending(stream_id)

        # The stream's state is only stored once the headers are sent.
        stream = self._stream.get(stream_id)
        if stream is None:
            stream = H3Stream(stream_id)
        if stream.sending_ended:
            raise InvalidStreamStateError("Cannot send after the stream was ended")
        if stream.headers_send_state == HeadersState.AFTER_TRAILERS:
            raise InvalidStreamStateError("Cannot send headers after the trailers")

        # Interim responses precede the final response (RFC 9114 section 4.1).
        interim = (
            not self._is_client
            and stream.headers_send_state == HeadersState.INITIAL
            and is_interim_response(headers)
        )
        if end_stream and interim:
            raise InvalidStreamStateError(
                "Cannot end the stream with an interim response"
            )

        frame_data = self._encode_headers(stream_id, headers)

        # log frame
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                name="http3:frame_created",
                data=self._quic_logger.encode_http3_headers_frame(
                    length=len(frame_data), headers=headers, stream_id=stream_id
                ),
            )

        self._send_request_stream_data(
            stream_id, encode_frame(FrameType.HEADERS, frame_data), end_stream
        )
        if stream.headers_send_state != HeadersState.INITIAL:
            stream.headers_send_state = HeadersState.AFTER_TRAILERS
        elif not interim:
            stream.headers_send_state = HeadersState.AFTER_HEADERS
        if end_stream:
            stream.sending_ended = True
        self._store_or_discard_stream(stream)

    # Server push is no longer supported: this stub is kept for servers which
    # still call it, without a docstring so that it stays out of the docs.
    def send_push_promise(self, stream_id: int, headers: Headers) -> int:
        warnings.warn(
            "send_push_promise() is deprecated and will be removed, as server push "
            "is no longer supported",
            DeprecationWarning,
            stacklevel=2,
        )
        raise NoAvailablePushIDError

    @property
    def received_settings(self) -> dict[int, int] | None:
        """
        Return the received SETTINGS frame, or None.
        """
        return self._received_settings

    @property
    def sent_settings(self) -> dict[int, int] | None:
        """
        Return the sent SETTINGS frame, or None.
        """
        return self._sent_settings

    def _abort_incomplete_request(self, stream_id: int) -> None:
        """
        Abort the response to a request stream which terminated before the
        request's headers were passed to the application (RFC 9114 section 4.1).
        """
        self._quic.reset_stream(stream_id, ErrorCode.H3_REQUEST_INCOMPLETE)

    def _check_control_frame_header(self, frame_type: int, frame_size: int) -> None:
        """
        Check a frame header received on the peer's control stream.

        This is called as soon as the frame header is parsed, so that invalid
        frames are rejected without buffering their payload.
        """
        # The first frame on the control stream MUST be SETTINGS, and unknown
        # frame types do not satisfy this requirement (RFC 9114 section 6.2.1
        # and section 9).
        if frame_type != FrameType.SETTINGS and not self._settings_received:
            raise MissingSettingsError

        if frame_type == FrameType.SETTINGS and self._settings_received:
            # RFC 9114 section 7.2.4
            raise FrameUnexpected("SETTINGS have already been received")
        elif frame_type == FrameType.MAX_PUSH_ID and self._is_client:
            # RFC 9114 section 7.2.7
            raise FrameUnexpected("Servers must not send MAX_PUSH_ID")
        elif (
            frame_type in (FrameType.GOAWAY, FrameType.MAX_PUSH_ID)
            and frame_size > UINT_VAR_MAX_SIZE
        ):
            # The payload is a single variable-length integer, so a longer one
            # has trailing data (RFC 9114 sections 7.1, 7.2.6 and 7.2.7).
            raise FrameError(f"{FrameType(frame_type).name} frame has trailing data")
        elif frame_type == FrameType.SETTINGS and frame_size > MAX_SETTINGS_SIZE:
            raise ExcessiveLoad("SETTINGS frame is too large")
        elif frame_type == FrameType.CANCEL_PUSH:
            # We never push and clients never allow a push ID, so no push ID can
            # be cancelled (RFC 9114 section 7.2.3).
            raise IdError("Server push is not supported")
        elif frame_type == FrameType.WEBTRANSPORT_STREAM and self._enable_webtransport:
            # Only the very first bytes of a request stream can carry the signal
            # value (draft-ietf-webtrans-http3-15 section 4.3, which is stricter
            # than the draft-02 we signal).
            raise FrameError("WEBTRANSPORT_STREAM must open a request stream")
        elif frame_type in (
            FrameType.DATA,
            FrameType.HEADERS,
            FrameType.PUSH_PROMISE,
            *RESERVED_FRAME_TYPES,
        ):
            # RFC 9114 sections 7.2.1, 7.2.2, 7.2.5 and 7.2.8
            raise FrameUnexpected("Invalid frame type on control stream")

    def _check_request_frame_header(
        self, stream: H3Stream, frame_type: int, frame_size: int
    ) -> None:
        """
        Check a frame header received on a request stream.

        This is called as soon as the frame header is parsed, so that invalid
        frames are rejected without buffering their payload.
        """
        if frame_type == FrameType.PUSH_PROMISE:
            if self._is_client:
                # We never send MAX_PUSH_ID, so any push ID is larger than the
                # maximum push ID (RFC 9114 section 7.2.5).
                raise IdError("Server push is not supported")
            # RFC 9114 section 7.2.5
            raise FrameUnexpected("Clients must not send PUSH_PROMISE")
        elif frame_type in (
            FrameType.CANCEL_PUSH,
            FrameType.SETTINGS,
            FrameType.GOAWAY,
            FrameType.MAX_PUSH_ID,
            *RESERVED_FRAME_TYPES,
        ):
            # RFC 9114 sections 4.1 and 7.2.3 to 7.2.8
            raise FrameUnexpected("Invalid frame type on request stream")
        elif (
            frame_type == FrameType.WEBTRANSPORT_STREAM
            and self._enable_webtransport
            and (
                stream.frame_received
                or stream.headers_send_state != HeadersState.INITIAL
            )
        ):
            # Only the very first bytes of a stream can carry the signal value, and a
            # request we sent already opened the stream. This follows
            # draft-ietf-webtrans-http3-15 section 4.3, which is stricter than the
            # draft-02 we signal.
            raise FrameError("WEBTRANSPORT_STREAM must open a request stream")
        elif (
            frame_type == FrameType.HEADERS
            and frame_size > MAX_FIELD_SECTION_SIZE * 3 // 2
        ):
            # The margin allows for encoders which Huffman-code strings even when
            # this makes them longer (RFC 9114 section 10.5.1).
            raise ExcessiveLoad("HEADERS frame is too large")

    def _check_stream_id(self, stream_id: int) -> None:
        """
        Check the stream ID is one QUIC can represent (RFC 9000 section 2.1).
        """
        if not 0 <= stream_id <= UINT_VAR_MAX:
            raise InvalidStreamIdError("Stream ID must be between 0 and 2^62 - 1")

    def _check_stream_type_for_sending(self, stream_id: int) -> None:
        """
        Check the stream ID is in range and a request stream, before any state is
        created for it.
        """
        self._check_stream_id(stream_id)
        if stream_is_request_response(stream_id):
            return

        if stream_is_unidirectional(stream_id) and (
            stream_is_client_initiated(stream_id) != self._is_client
        ):
            raise InvalidStreamTypeError(
                "Cannot send on the peer's unidirectional streams"
            )

        # HTTP messages are only sent on request streams, not on server-initiated
        # bidirectional streams (RFC 9114 section 6.1) nor on our unidirectional
        # streams (RFC 9114 section 6.2), such as the control and QPACK streams.
        raise InvalidStreamTypeError(
            "Headers and data can only be sent on request streams"
        )

    def _create_uni_stream(self, stream_type: int) -> int:
        """
        Create an unidirectional stream of the given type.
        """
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._log_stream_type(stream_id=stream_id, stream_type=stream_type)
        self._quic.send_stream_data(stream_id, encode_uint_var(stream_type))
        return stream_id

    def _decode_headers(self, stream_id: int, frame_data: bytes) -> Headers:
        """
        Decode a HEADERS block and send decoder updates on the decoder stream.
        """
        try:
            decoder, headers = self._decoder.feed_header(stream_id, frame_data)
            self._quic.send_stream_data(self._local_decoder_stream_id, decoder)
        except pylsqpack.FieldSectionTooLarge as exc:
            raise ExcessiveLoad("Field section is too large") from exc
        except pylsqpack.DecompressionFailed as exc:
            raise QpackDecompressionFailed() from exc

        return headers

    def _encode_headers(self, stream_id: int, headers: Headers) -> bytes:
        """
        Encode a HEADERS block and send encoder updates on the encoder stream.
        """
        encoder, frame_data = self._encoder.encode(stream_id, headers)
        try:
            self._quic.send_stream_data(self._local_encoder_stream_id, encoder)
        except StreamStateError as exc:
            # The peer stopped the stream, which closes the connection (RFC 9204
            # section 4.2).
            raise H3Error(
                "Cannot send headers once the QPACK encoder stream was stopped"
            ) from exc
        return frame_data

    def _get_local_settings(self) -> dict[int, int]:
        """
        Return the local HTTP/3 settings.
        """
        settings: dict[int, int] = {
            Setting.QPACK_MAX_TABLE_CAPACITY: self._max_table_capacity,
            Setting.QPACK_BLOCKED_STREAMS: self._blocked_streams,
            Setting.MAX_FIELD_SECTION_SIZE: MAX_FIELD_SECTION_SIZE,
            Setting.ENABLE_CONNECT_PROTOCOL: 1,
            Setting.DUMMY: 1,
        }
        if self._enable_webtransport:
            settings[Setting.H3_DATAGRAM] = 1
            settings[Setting.ENABLE_WEBTRANSPORT] = 1
        return settings

    def _handle_control_frame(
        self, frame_type: int, frame_data: bytes
    ) -> GoAwayReceived | None:
        """
        Handle a SETTINGS, MAX_PUSH_ID or GOAWAY frame received on the peer's
        control stream.

        The frame header must have been validated by `_check_control_frame_header`.
        """
        if frame_type == FrameType.SETTINGS:
            settings = parse_settings(frame_data)
            self._validate_settings(settings)
            self._received_settings = settings
            encoder = self._encoder.apply_settings(
                max_table_capacity=settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, 0),
                blocked_streams=settings.get(Setting.QPACK_BLOCKED_STREAMS, 0),
            )
            self._quic.send_stream_data(self._local_encoder_stream_id, encoder)
            self._settings_received = True
        elif frame_type == FrameType.MAX_PUSH_ID:
            max_push_id = parse_id_frame(FrameType.MAX_PUSH_ID, frame_data)

            # The maximum push ID cannot be reduced, see RFC 9114 section 7.2.7.
            if self._max_push_id is not None and max_push_id < self._max_push_id:
                raise IdError("MAX_PUSH_ID reduced the maximum push ID")
            self._max_push_id = max_push_id
        else:
            goaway_id = parse_id_frame(FrameType.GOAWAY, frame_data)

            # A server's GOAWAY carries a client-initiated bidirectional stream ID
            # (RFC 9114 section 7.2.6).
            if self._is_client and not stream_is_request_response(goaway_id):
                raise IdError(
                    "GOAWAY does not carry a client-initiated bidirectional stream ID"
                )

            # A GOAWAY cannot increase the ID of a previous one (RFC 9114 section 5.2).
            if (
                self._received_goaway_id is not None
                and goaway_id > self._received_goaway_id
            ):
                raise IdError("GOAWAY increased the ID of a previous GOAWAY")
            self._received_goaway_id = goaway_id

            # A client's GOAWAY carries a push ID, which is of no use as we never
            # push.
            if self._is_client:
                return GoAwayReceived(stream_id=goaway_id)
        return None

    def _check_content_length(self, stream: H3Stream) -> None:
        if (
            stream.expected_content_length is not None
            and stream.content_length != stream.expected_content_length
        ):
            raise MessageError("content-length does not match data size")

    def _handle_request_frame(
        self,
        frame_type: int,
        frame_data: bytes,
        stream: H3Stream,
        stream_ended: bool,
    ) -> list[H3Event]:
        """
        Handle a DATA or HEADERS frame received on a request stream.
        """
        http_events: list[H3Event] = []

        if frame_type == FrameType.DATA:
            # check DATA frame is allowed
            if stream.headers_recv_state != HeadersState.AFTER_HEADERS:
                raise FrameUnexpected("DATA frame is not allowed in this state")

            if frame_data is not None:
                stream.content_length += len(frame_data)

            if stream_ended:
                self._check_content_length(stream)

            if stream_ended or frame_data:
                http_events.append(
                    DataReceived(
                        data=frame_data,
                        stream_ended=stream_ended,
                        stream_id=stream.stream_id,
                    )
                )
        else:
            # check HEADERS frame is allowed
            if stream.headers_recv_state == HeadersState.AFTER_TRAILERS:
                raise FrameUnexpected("HEADERS frame is not allowed in this state")

            headers = self._decode_headers(stream.stream_id, frame_data)

            # validate headers
            interim = False
            if stream.headers_recv_state == HeadersState.INITIAL:
                if self._is_client:
                    interim = is_interim_response(headers)
                    # Interim responses have no content, so their content-length
                    # does not apply (RFC 9110 section 6.4.1).
                    validate_response_headers(headers, None if interim else stream)
                    if interim:
                        stream.interim_response_received = True
                else:
                    validate_request_headers(headers, stream)
            else:
                validate_trailers(headers)

            # content-length needs checking even when there is no data
            if stream_ended:
                # A final response must follow interim responses (RFC 9114
                # section 4.1).
                if interim:
                    raise MessageError("Interim response cannot end the stream")
                self._check_content_length(stream)

            # log frame
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    name="http3:frame_parsed",
                    data=self._quic_logger.encode_http3_headers_frame(
                        length=len(frame_data),
                        headers=headers,
                        stream_id=stream.stream_id,
                    ),
                )

            # update state and emit headers
            if stream.headers_recv_state == HeadersState.INITIAL:
                if not interim:
                    stream.headers_recv_state = HeadersState.AFTER_HEADERS
            else:
                stream.headers_recv_state = HeadersState.AFTER_TRAILERS
            http_events.append(
                HeadersReceived(
                    headers=headers,
                    stream_id=stream.stream_id,
                    stream_ended=stream_ended,
                )
            )
        return http_events

    def _handle_request_end(self, stream: H3Stream) -> list[H3Event]:
        """
        Handle the end of a request stream which is not conveyed by
        a DATA or HEADERS frame.
        """
        if not self._is_client and stream.headers_recv_state == HeadersState.INITIAL:
            # The application never saw the request, so nothing would respond.
            self._abort_incomplete_request(stream.stream_id)
            stream.sending_ended = True
            return []

        # A final response must follow interim responses (RFC 9114 section 4.1).
        if (
            stream.interim_response_received
            and stream.headers_recv_state == HeadersState.INITIAL
        ):
            raise MessageError("Interim response cannot end the stream")

        self._check_content_length(stream)

        return [
            DataReceived(
                data=b"",
                stream_id=stream.stream_id,
                stream_ended=True,
            )
        ]

    def _init_connection(self) -> None:
        # send our settings
        self._local_control_stream_id = self._create_uni_stream(StreamType.CONTROL)
        self._sent_settings = self._get_local_settings()
        self._quic.send_stream_data(
            self._local_control_stream_id,
            encode_frame(FrameType.SETTINGS, encode_settings(self._sent_settings)),
        )

        # create encoder and decoder streams
        self._local_encoder_stream_id = self._create_uni_stream(
            StreamType.QPACK_ENCODER
        )
        self._local_decoder_stream_id = self._create_uni_stream(
            StreamType.QPACK_DECODER
        )

    def _log_stream_type(self, stream_id: int, stream_type: int) -> None:
        if self._quic_logger is not None:
            data: dict[str, Any] = {
                "initiator": "local"
                if stream_is_client_initiated(stream_id) == self._is_client
                else "remote",
                "stream_id": stream_id,
            }
            type_name = {
                0: "control",
                2: "qpack_encode",
                3: "qpack_decode",
            }.get(stream_type)
            if type_name is not None:
                data["stream_type"] = type_name
            else:
                # Other types, including WebTransport's, have no qlog name.
                data["stream_type"] = "unknown"
                data["stream_type_bytes"] = stream_type

            self._quic_logger.log_event(name="http3:stream_type_set", data=data)

    def _receive_datagram(self, data: bytes) -> list[H3Event]:
        """
        Handle a datagram.
        """
        buf = Buffer(data=data)
        try:
            quarter_stream_id = buf.pull_uint_var()
        except BufferReadError:
            raise DatagramError("Could not parse quarter stream ID")
        return [
            DatagramReceived(data=data[buf.tell() :], stream_id=quarter_stream_id * 4)
        ]

    def _receive_stop_sending(self, stream_id: int) -> None:
        """
        Handle the peer asking us to stop sending on a stream.
        """
        if stream_id in (
            self._local_control_stream_id,
            self._local_decoder_stream_id,
            self._local_encoder_stream_id,
        ):
            raise ClosedCriticalStream("Stopping a critical stream is not allowed")

        # The QUIC layer has already reset the sending part of the stream.
        stream = self._stream.get(stream_id)
        if stream is not None:
            stream.sending_ended = True
            self._store_or_discard_stream(stream)

    def _receive_stream_data(self, event: StreamDataReceived) -> list[H3Event]:
        stream_id = event.stream_id
        stream = self._stream.get(stream_id)
        if stream is None:
            stream = H3Stream(stream_id)
            if stream_is_unidirectional(stream_id):
                # Only the peer's unidirectional streams have state, and we
                # never send on them.
                stream.sending_ended = True
            self._stream[stream_id] = stream
        if stream_is_unidirectional(stream_id):
            http_events = self._receive_stream_data_uni(
                stream, event.data, event.end_stream
            )
        else:
            http_events = self._receive_request_data(
                stream, event.data, event.end_stream
            )
        self._store_or_discard_stream(stream)
        return http_events

    def _receive_request_data(
        self, stream: H3Stream, data: bytes, stream_ended: bool
    ) -> list[H3Event]:
        """
        Handle data received on a request stream.
        """
        http_events: list[H3Event] = []

        stream.buffer += data
        if stream_ended:
            stream.receiving_ended = True

        # shortcut for WEBTRANSPORT_STREAM frame fragments
        if (
            stream.frame_type == FrameType.WEBTRANSPORT_STREAM
            and stream.session_id is not None
        ):
            http_events.append(
                WebTransportStreamDataReceived(
                    data=stream.buffer,
                    session_id=stream.session_id,
                    stream_id=stream.stream_id,
                    stream_ended=stream_ended,
                )
            )
            stream.buffer = b""
            return http_events

        # shortcut for DATA frame fragments
        if (
            stream.frame_type == FrameType.DATA
            and stream.frame_size is not None
            and len(stream.buffer) < stream.frame_size
            and not stream_ended
        ):
            stream.content_length += len(stream.buffer)
            http_events.append(
                DataReceived(
                    data=stream.buffer,
                    stream_id=stream.stream_id,
                    stream_ended=False,
                )
            )
            stream.frame_size -= len(stream.buffer)
            stream.buffer = b""
            return http_events

        # handle lone FIN
        if stream_ended and not stream.buffer and stream.frame_size is None:
            http_events.extend(self._handle_request_end(stream))
            return http_events

        buf = Buffer(data=stream.buffer)
        consumed = 0

        while not buf.eof():
            # fetch next frame header
            if stream.frame_size is None:
                try:
                    stream.frame_type = buf.pull_uint_var()
                    stream.frame_size = buf.pull_uint_var()
                except BufferReadError:
                    break
                consumed = buf.tell()

                self._check_request_frame_header(
                    stream=stream,
                    frame_type=stream.frame_type,
                    frame_size=stream.frame_size,
                )
                stream.frame_received = True

                # WEBTRANSPORT_STREAM frames last until the end of the stream.
                # Without WebTransport, they are unknown frames (RFC 9114 section 9).
                if (
                    stream.frame_type == FrameType.WEBTRANSPORT_STREAM
                    and self._enable_webtransport
                ):
                    stream.session_id = stream.frame_size
                    stream.frame_size = None

                    # HTTP/3 sends nothing on a WebTransport stream it accepted, so
                    # only the peer's half keeps the state alive.
                    stream.sending_ended = True

                    frame_data = stream.buffer[consumed:]
                    stream.buffer = b""

                    self._log_stream_type(
                        stream_id=stream.stream_id, stream_type=StreamType.WEBTRANSPORT
                    )

                    if frame_data or stream_ended:
                        http_events.append(
                            WebTransportStreamDataReceived(
                                data=frame_data,
                                session_id=stream.session_id,
                                stream_id=stream.stream_id,
                                stream_ended=stream_ended,
                            )
                        )
                    return http_events

                # log frame
                if (
                    self._quic_logger is not None
                    and stream.frame_type == FrameType.DATA
                ):
                    self._quic_logger.log_event(
                        name="http3:frame_parsed",
                        data=self._quic_logger.encode_http3_data_frame(
                            length=stream.frame_size, stream_id=stream.stream_id
                        ),
                    )

            # check how much data is available
            chunk_size = min(stream.frame_size, buf.capacity - consumed)

            # Unknown frame types MUST be ignored (RFC 9114 section 7.2.8 and
            # section 9) and their length is unbounded, so discard their payload
            # as it arrives instead of buffering it (RFC 9114 section 10.5).
            if stream.frame_type not in (FrameType.DATA, FrameType.HEADERS):
                buf.seek(consumed + chunk_size)
                consumed = buf.tell()
                stream.frame_size -= chunk_size
                if not stream.frame_size:
                    stream.frame_size = None
                    stream.frame_type = None

                # Unknown frames can be the last frame on the stream, see
                # RFC 9114 section 4.1.
                if stream.receiving_ended and buf.eof() and stream.frame_size is None:
                    http_events.extend(self._handle_request_end(stream))
                continue

            if stream.frame_type != FrameType.DATA and chunk_size < stream.frame_size:
                break

            # read available data
            frame_data = buf.pull_bytes(chunk_size)
            frame_type = stream.frame_type
            consumed = buf.tell()

            # detect end of frame
            stream.frame_size -= chunk_size
            if not stream.frame_size:
                stream.frame_size = None
                stream.frame_type = None

            http_events.extend(
                self._handle_request_frame(
                    frame_type=frame_type,
                    frame_data=frame_data,
                    stream=stream,
                    stream_ended=(
                        stream.receiving_ended
                        and buf.eof()
                        and stream.frame_size is None
                    ),
                )
            )

        # remove processed data from buffer
        stream.buffer = stream.buffer[consumed:]

        # A frame truncated by the end of the stream is an error, see
        # RFC 9114 section 7.1.
        if stream.receiving_ended and (stream.buffer or stream.frame_size is not None):
            raise FrameError("Frame is truncated by the end of the stream")

        return http_events

    def _receive_stream_data_uni(
        self, stream: H3Stream, data: bytes, stream_ended: bool
    ) -> list[H3Event]:
        http_events: list[H3Event] = []

        stream.buffer += data
        if stream_ended:
            stream.receiving_ended = True

        buf = Buffer(data=stream.buffer)
        consumed = 0

        while (
            stream.stream_type == StreamType.CONTROL
            or (
                stream.stream_type == StreamType.WEBTRANSPORT
                and self._enable_webtransport
            )
            or not buf.eof()
        ):
            # fetch stream type for unidirectional streams
            if stream.stream_type is None:
                try:
                    stream.stream_type = buf.pull_uint_var()
                except BufferReadError:
                    break
                consumed = buf.tell()

                if stream.stream_type == StreamType.PUSH:
                    if self._is_client:
                        # We never send MAX_PUSH_ID (RFC 9114 section 4.6).
                        raise IdError("Server push is not supported")
                    # Only servers can push, see RFC 9114 section 6.2.2.
                    raise StreamCreationError("Clients must not open push streams")

                # check unicity
                if stream.stream_type == StreamType.CONTROL:
                    if self._peer_control_stream_id is not None:
                        raise StreamCreationError("Only one control stream is allowed")
                    self._peer_control_stream_id = stream.stream_id
                elif stream.stream_type == StreamType.QPACK_DECODER:
                    if self._peer_decoder_stream_id is not None:
                        raise StreamCreationError(
                            "Only one QPACK decoder stream is allowed"
                        )
                    self._peer_decoder_stream_id = stream.stream_id
                elif stream.stream_type == StreamType.QPACK_ENCODER:
                    if self._peer_encoder_stream_id is not None:
                        raise StreamCreationError(
                            "Only one QPACK encoder stream is allowed"
                        )
                    self._peer_encoder_stream_id = stream.stream_id

                self._log_stream_type(
                    stream_id=stream.stream_id, stream_type=stream.stream_type
                )

            if stream.stream_type == StreamType.CONTROL:
                if stream_ended:
                    raise ClosedCriticalStream("Closing control stream is not allowed")

                # fetch next frame header
                if stream.frame_size is None:
                    try:
                        stream.frame_type = buf.pull_uint_var()
                        stream.frame_size = buf.pull_uint_var()
                    except BufferReadError:
                        break
                    consumed = buf.tell()

                    self._check_control_frame_header(
                        stream.frame_type, stream.frame_size
                    )

                frame_type = stream.frame_type
                frame_size = stream.frame_size
                available = buf.capacity - consumed
                if frame_type in (
                    FrameType.SETTINGS,
                    FrameType.GOAWAY,
                    FrameType.MAX_PUSH_ID,
                ):
                    # wait for the complete frame
                    if available < frame_size:
                        break
                    frame_data = buf.pull_bytes(frame_size)
                    consumed = buf.tell()
                    stream.frame_size = None
                    stream.frame_type = None

                    event = self._handle_control_frame(frame_type, frame_data)
                    if event is not None:
                        http_events.append(event)
                else:
                    # Unknown frame types MUST be ignored (RFC 9114 section
                    # 7.2.8 and section 9) and their length is unbounded, so
                    # discard their payload as it arrives instead of buffering
                    # it (RFC 9114 section 10.5).
                    if available == 0 and frame_size > 0:
                        break
                    chunk_size = min(frame_size, available)
                    buf.seek(consumed + chunk_size)
                    consumed = buf.tell()
                    stream.frame_size = frame_size - chunk_size
                    if not stream.frame_size:
                        stream.frame_size = None
                        stream.frame_type = None
            elif (
                stream.stream_type == StreamType.WEBTRANSPORT
                and self._enable_webtransport
            ):
                # fetch session id
                if stream.session_id is None:
                    try:
                        stream.session_id = buf.pull_uint_var()
                    except BufferReadError:
                        break
                    consumed = buf.tell()

                frame_data = stream.buffer[consumed:]
                stream.buffer = b""

                if frame_data or stream_ended:
                    http_events.append(
                        WebTransportStreamDataReceived(
                            data=frame_data,
                            session_id=stream.session_id,
                            stream_ended=stream.receiving_ended,
                            stream_id=stream.stream_id,
                        )
                    )
                return http_events
            elif stream.stream_type == StreamType.QPACK_DECODER:
                # feed unframed data to decoder
                data = buf.pull_bytes(buf.capacity - buf.tell())
                consumed = buf.tell()
                try:
                    self._encoder.feed_decoder(data)
                except pylsqpack.DecoderStreamError as exc:
                    raise QpackDecoderStreamError() from exc
            elif stream.stream_type == StreamType.QPACK_ENCODER:
                # feed unframed data to encoder
                data = buf.pull_bytes(buf.capacity - buf.tell())
                consumed = buf.tell()
                try:
                    self._decoder.feed_encoder(data)
                except pylsqpack.EncoderStreamError as exc:
                    raise QpackEncoderStreamError() from exc
            else:
                # unknown stream type, discard data
                buf.seek(buf.capacity)
                consumed = buf.tell()

        # remove processed data from buffer
        stream.buffer = stream.buffer[consumed:]

        return http_events

    def _receive_stream_reset(self, stream_id: int) -> None:
        """
        Handle the peer resetting a stream.
        """
        if stream_id in (
            self._peer_control_stream_id,
            self._peer_decoder_stream_id,
            self._peer_encoder_stream_id,
        ):
            raise ClosedCriticalStream("Resetting a critical stream is not allowed")

        stream = self._stream.get(stream_id)

        # Header blocks on the stream will not be decoded, let the peer's
        # encoder know (RFC 9204 section 4.4.2).
        if not stream_is_unidirectional(stream_id):
            decoder = self._decoder.cancel_stream(stream_id)
            self._quic.send_stream_data(self._local_decoder_stream_id, decoder)

        if stream is not None:
            stream.buffer = b""
            stream.receiving_ended = True

        # The application never saw the request, so nothing would respond.
        if (
            not self._is_client
            and stream_is_request_response(stream_id)
            and (
                stream is None
                or (
                    stream.headers_recv_state == HeadersState.INITIAL
                    and stream.session_id is None
                )
            )
        ):
            self._abort_incomplete_request(stream_id)
            if stream is not None:
                stream.sending_ended = True

        if stream is not None:
            self._store_or_discard_stream(stream)

    def _send_request_stream_data(
        self, stream_id: int, data: bytes, end_stream: bool
    ) -> None:
        """
        Send data on a request stream, raising an H3 exception if QUIC refuses it.
        """
        try:
            self._quic.send_stream_data(stream_id, data, end_stream)
        except StreamStateError as exc:
            message = {
                "Cannot send data after FIN": "Cannot send after the stream was ended",
                "Cannot send data after the stream was reset": (
                    "Cannot send after the stream was reset"
                ),
                "Cannot send data on a finished stream": (
                    "Cannot send after the stream was ended"
                ),
                "Cannot send data on unknown peer-initiated stream": (
                    "Cannot send on a stream the peer has not opened"
                ),
            }.get(str(exc), str(exc))
            raise InvalidStreamStateError(message) from exc

    def _store_or_discard_stream(self, stream: H3Stream) -> None:
        """
        Store a stream's state, or discard it once both sides have ended.
        """
        if stream.is_ended():
            self._stream.pop(stream.stream_id, None)
        else:
            self._stream[stream.stream_id] = stream

    def _validate_settings(self, settings: dict[int, int]) -> None:
        for setting in [
            Setting.ENABLE_CONNECT_PROTOCOL,
            Setting.ENABLE_WEBTRANSPORT,
            Setting.H3_DATAGRAM,
        ]:
            if setting in settings and settings[setting] not in (0, 1):
                raise SettingsError(f"{setting.name} setting must be 0 or 1")

        if (
            settings.get(Setting.ENABLE_WEBTRANSPORT) == 1
            and settings.get(Setting.H3_DATAGRAM) != 1
        ):
            raise SettingsError("ENABLE_WEBTRANSPORT requires H3_DATAGRAM")
