QUIC API
========

The QUIC API performs no I/O on its own, leaving this to the API user.
This allows you to integrate QUIC in any Python application, regardless of
the concurrency model you are using.

Connection
----------

.. automodule:: aioquic.quic.connection

    .. autoclass:: QuicConnection
        :members:


Configuration
-------------

.. automodule:: aioquic.quic.configuration

    .. autoclass:: QuicConfiguration
        :members:

.. automodule:: aioquic.quic.logger

    .. autoclass:: QuicLogger
        :members:

Events
------

.. automodule:: aioquic.quic.events

    .. autoclass:: QuicEvent
        :members:

    .. autoclass:: ConnectionTerminated
        :members:

    .. autoclass:: DatagramFrameReceived
        :members:

    .. autoclass:: HandshakeCompleted
        :members:

    .. autoclass:: PingAcknowledged
        :members:

    .. autoclass:: StopSendingReceived
        :members:

    .. autoclass:: StreamDataReceived
        :members:

    .. autoclass:: StreamReset
        :members:

Exceptions
----------

.. automodule:: aioquic.quic.exceptions

    .. autoclass:: QuicError
        :members:

    .. autoclass:: ConnectionConfigurationError
        :members:

    .. autoclass:: ConnectionStateError
        :members:

    .. autoclass:: DatagramFrameCapacityError
        :members:

    .. autoclass:: OutOfRangeError
        :members:

    .. autoclass:: StreamStateError
        :members:

    .. autoclass:: StreamTypeError
        :members:

TLS
---

.. automodule:: aioquic.tls

    .. autoclass:: CipherSuite()

        .. autoattribute:: TLS_AES_128_GCM_SHA256
            :no-value:

        .. autoattribute:: TLS_AES_256_GCM_SHA384
            :no-value:

        .. autoattribute:: TLS_CHACHA20_POLY1305_SHA256
            :no-value:
