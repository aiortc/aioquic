Changelog
=========

1.5.0
-----

* Fix several ways a peer could make memory usage grow without bound:

  * Retire HTTP/3 unidirectional streams once they end, and HTTP/3 streams
    which are reset or stopped by the peer, or which end while blocked on
    QPACK.
  * Stop delivering stream events after a stream's receiving side has
    finished, so a duplicate FIN or RESET_STREAM is not reported again.
  * Forget peer connection ID sequence numbers below ``retire_prior_to``.

* When a reset stream is reset again or receives more data, do not count its
  final size against connection-level flow control a second time. Counting it
  twice could close a well-behaved peer's connection with FLOW_CONTROL_ERROR.
* Close the connection with ``H3_FRAME_ERROR`` when a SETTINGS or PUSH_PROMISE
  frame is truncated, instead of raising an exception to the application.
* Abort the TLS handshake with an ``illegal_parameter`` alert when the peer's
  key share is invalid, and only accept key shares for groups the server
  supports.
* Stop using assertions to validate data received from the peer, so malformed
  input closes the connection or drops the packet, including when running with
  ``-O``.
* Raise :class:`ValueError` for invalid arguments and :class:`RuntimeError`
  for calls made in the wrong state, such as writing to a stream after it has
  ended or been reset, instead of failing an assertion.
* Send a QPACK Stream Cancellation when a stream with a blocked header block
  is reset, and treat resetting or stopping an HTTP/3 control or QPACK stream
  as a connection error, as :rfc:`9114` and :rfc:`9204` require.
* Do not send a FIN when closing the writer of a receive-only stream in the
  :doc:`asyncio API <asyncio>`.
* Require `pylsqpack`_ 1.0 or later.

1.4.0
-----

* Perform header protection and payload encryption in Python using
  `cryptography`_ instead of a C extension linked to `OpenSSL`_. This fixes
  memory safety issues when handling malformed packets, lifts the 1500-byte
  limit on received packets and removes the need for OpenSSL development
  headers when building from source.
* Discard duplicate packets as required by :rfc:`9000` section 12.3.
* Limit the number of network paths per connection.
* Do not reply to Version Negotiation packets with another Version
  Negotiation packet.
* Discard unknown HTTP/3 frames incrementally instead of buffering them.
* Handle HTTP/3 frame types as defined by :rfc:`9114`.
* Add support for Python 3.15, drop support for Python 3.10.

1.3.0
-----

* Ensure PATH_CHALLENGE frames are sent before other frame types.
* Reclaim memory when HTTP/3 streams end.
* Limit the number of remote PATH_CHALLENGE stored per path.
* Avoid assertion error when receiving multiple STOP_SENDING frames.
* Improve type annotations.
* Make it possible to use LibreSSL instead of OpenSSL.
* Add support Python 3.13 and 3.14, drop support for Python 3.8 and 3.9.
* Build binary wheels for `musllinux`_.
* Build binary wheels against `OpenSSL`_ 3.5.4.
* Add command-line argument to the `http3_client` example to request
  a key update during interoperability tests.

1.2.0
-----

* Add support for compatible version handling as defined in :rfc:`9368`.
* Add support for QUIC Version 2, as defined in :rfc:`9369`.
* Drop support for draft QUIC versions which were obsoleted by :rfc:`9000`.
* Improve datagram padding to allow better packet coalescing and reduce the
  number of roundtrips during connection establishement.
* Fix server anti-amplification checks during address validation to take into
  account invalid packets, such as datagram-level padding.
* Allow asyncio clients to make efficient use of 0-RTT by passing
  `wait_connected=False` to :meth:`~aioquic.asyncio.connect`.
* Add command-line arguments to the `http3_client` example for client
  certificates and negotiating QUIC Version 2.

1.1.0
-----

* Improve path challenge handling and compliance with :rfc:`9000`.
* Limit the amount of buffered CRYPTO data to avoid memory exhaustion.
* Enable SHA-384 based signature algorithms and SECP384R1 key exchange.
* Build binary wheels against `OpenSSL`_ 3.3.0.

1.0.0
-----

* Ensure no data is sent after a stream reset.
* Make :class:`~aioquic.h3.connection.H3Connection`'s
  :meth:`~aioquic.h3.connection.H3Connection.send_datagram` and
  :meth:`~aioquic.h3.connection.H3Connection.send_push_promise` methods raise an
  :class:`~aioquic.h3.exceptions.InvalidStreamTypeError` exception if an
  invalid stream ID is specified.
* Improve the documentation for
  :class:`~aioquic.asyncio.QuicConnectionProtocol`'s
  :meth:`~aioquic.asyncio.QuicConnectionProtocol.transmit` method.
* Fix :meth:`~datetime.datetime.utcnow` deprecation warning on Python 3.12
  by using `cryptography`_ 42.0 and timezone-aware :class:`~datetime.datetime`
  instances when validating TLS certificates.
* Build binary wheels against `OpenSSL`_ 3.2.0.
* Ignore any non-ASCII ALPN values received.
* Perform more extensive HTTP/3 header validation in
  :class:`~aioquic.h3.connection.H3Connection`.
* Fix exceptions when draining stream writers in the :doc:`asyncio API <asyncio>`.
* Set the :class:`~aioquic.quic.connection.QuicConnection` idle timer according to
  :rfc:`9000` section 10.1.
* Implement fairer stream scheduling in :class:`~aioquic.quic.connection.QuicConnection`
  to avoid head-of-line blocking.
* Only load `certifi`_ root certificates if none was specified in the
  :class:`~aioquic.quic.configuration.QuicConfiguration`.
* Improve padding of UDP datagrams containing Initial packets to comply with :rfc:`9000`
  section 14.1.
* Limit the number of pending connection IDs marked for retirement to prevent a possible
  DoS attack.

.. _certifi: https://github.com/certifi/python-certifi
.. _cryptography: https://cryptography.io/
.. _musllinux: https://peps.python.org/pep-0656/
.. _OpenSSL: https://www.openssl.org/
.. _pylsqpack: https://github.com/aiortc/pylsqpack
