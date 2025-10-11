Changelog
=========

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
