class H3Error(Exception):
    """
    Base class for HTTP/3 exceptions.
    """


class InvalidStreamStateError(H3Error):
    """
    An action was attempted on a stream in an invalid state, such as sending
    data before headers, or after the stream was ended.
    """


class InvalidStreamTypeError(H3Error):
    """
    An action was attempted on an invalid stream type.
    """


class NoAvailablePushIDError(H3Error):
    """
    There are no available push IDs left, or push is not supported
    by the remote party.
    """
