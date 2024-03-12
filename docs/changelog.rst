Changelog
=========

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
.. _OpenSSL: https://www.openssl.org/
