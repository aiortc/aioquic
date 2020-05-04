Examples
========

DNS over QUIC
.............

By default the server will use the `Google Public DNS`_ service, you can this
with the ``--resolver`` argument.

.. code-block:: console

    $ python examples/doq_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem

You can then run the client with a specific query:

.. code-block:: console

    $ python examples/doq_client.py --ca-certs tests/pycacert.pem --dns_type "A" --query "quic.aiortc.org" --port 4784

.. _Google Public DNS: https://developers.google.com/speed/public-dns
