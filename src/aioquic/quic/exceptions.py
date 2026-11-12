class QuicError(Exception):
    """
    Base class for QUIC exceptions.

    The exceptions which :class:`~aioquic.quic.connection.QuicConnection` raises
    derive from this class.
    """


class ConnectionConfigurationError(QuicError, ValueError):
    """
    A connection was created with an invalid configuration or arguments, such as
    a server configuration without a certificate.
    """


class ConnectionStateError(QuicError, RuntimeError):
    """
    An action was attempted which the connection does not allow in its current
    state, such as initiating the handshake a second time, or resetting a stream
    reliably before the handshake completes.
    """


class DatagramFrameCapacityError(QuicError, ValueError):
    """
    A payload was passed which exceeds the capacity of a DATAGRAM frame, as
    returned by
    :meth:`~aioquic.quic.connection.QuicConnection.get_datagram_frame_capacity`.
    """


class OutOfRangeError(QuicError, ValueError):
    """
    A value was passed which the protocol cannot represent, such as a negative
    error code or a stream ID above 2^62 - 1.
    """


class StreamStateError(QuicError, RuntimeError):
    """
    An action was attempted on a stream in an invalid state, such as sending
    after the stream was ended or reset, or on a stream the peer has not opened.
    """


class StreamTypeError(QuicError, ValueError):
    """
    An action was attempted on a stream of the wrong type, such as sending on
    one of the peer's unidirectional streams.
    """
