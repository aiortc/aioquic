class H3Error(Exception):
    """
    Base class for HTTP/3 exceptions.
    """


class DatagramCapacityError(H3Error, ValueError):
    """
    A payload was passed which exceeds the capacity of a datagram, as returned by
    :meth:`~aioquic.h3.connection.H3Connection.get_datagram_capacity`.
    """


class InvalidConnectionStateError(H3Error):
    """
    An action was attempted which the connection does not allow in its current
    state.
    """


class InvalidStreamIdError(H3Error):
    """
    A stream ID was passed which is outside the range QUIC allows, from 0 to
    2^62 - 1.
    """


class InvalidStreamStateError(H3Error):
    """
    An action was attempted on a stream in an invalid state, such as sending
    data before headers, or on a stream which is not open.
    """


class InvalidStreamTypeError(H3Error):
    """
    An action was attempted on an invalid stream type.
    """


class NoAvailablePushIDError(H3Error):
    """
    Kept for compatibility, as server push is no longer supported.
    """
