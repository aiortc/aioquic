import dataclasses
import datetime
import ssl
from collections.abc import Callable
from functools import partial
from typing import Any
from unittest import skipIf
from unittest.mock import patch

from aioquic import tls
from aioquic.buffer import Buffer, BufferReadError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import (
    Certificate,
    CertificateRequest,
    ClientHello,
    Context,
    EncryptedExtensions,
    NewSessionTicket,
    ServerHello,
    SessionTicket,
    State,
    load_pem_x509_certificates,
    pull_block,
    pull_certificate_request,
    pull_certificate_verify,
    pull_client_hello,
    pull_encrypted_extensions,
    pull_new_session_ticket,
    pull_server_hello,
    pull_server_name,
    push_certificate,
    push_certificate_request,
    push_certificate_verify,
    push_client_hello,
    push_encrypted_extensions,
    push_new_session_ticket,
    push_server_hello,
    push_server_name,
    verify_certificate,
)
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .utils import (
    SERVER_CACERTFILE,
    SERVER_CERTFILE,
    SERVER_KEYFILE,
    SKIP_TESTS,
    CertificatePrivateKey,
    TestCase,
    generate_ec_certificate,
    generate_ed448_certificate,
    generate_ed25519_certificate,
    generate_rsa_certificate,
    load_cert_chain,
)

# TLS treats the QUIC transport parameters as opaque data.
CLIENT_QUIC_TRANSPORT_PARAMETERS = b"client transport parameters"
SERVER_QUIC_TRANSPORT_PARAMETERS = b"server transport parameters"


class BufferTest(TestCase):
    def test_pull_block_truncated(self) -> None:
        buf = Buffer(capacity=0)
        with self.assertRaises(BufferReadError):
            with pull_block(buf, 1):
                pass


def corrupt_hello_version(data: bytes) -> bytes:
    """
    Corrupt a ClientHello or ServerHello's protocol version.
    """
    return data[:4] + b"\xff\xff" + data[6:]


def create_buffers() -> dict[tls.Epoch, Buffer]:
    return {
        tls.Epoch.INITIAL: Buffer(capacity=4096),
        tls.Epoch.HANDSHAKE: Buffer(capacity=4096),
        tls.Epoch.ONE_RTT: Buffer(capacity=4096),
    }


def create_session_ticket() -> SessionTicket:
    """
    Create an TLS_AES_256_GCM_SHA384 session ticket, valid for an hour.
    """
    now = datetime.datetime.now(datetime.UTC)
    return SessionTicket(
        age_add=0,
        cipher_suite=tls.CipherSuite.TLS_AES_256_GCM_SHA384,
        not_valid_after=now + datetime.timedelta(hours=1),
        not_valid_before=now,
        resumption_secret=bytes(48),
        server_name="localhost",
        ticket=b"ticket",
    )


def merge_buffers(buffers: dict[tls.Epoch, Buffer]) -> bytes:
    return b"".join(x.data for x in buffers.values())


def modify_certificate_verify(data: bytes, **changes: Any) -> bytes:
    """
    Replace fields of the CertificateVerify in `data`, a flight of handshake
    messages.
    """
    # Skip the messages before it, using their type and length header.
    start = 0
    while data[start] != tls.HandshakeType.CERTIFICATE_VERIFY:
        start += 4 + int.from_bytes(data[start + 1 : start + 4], byteorder="big")
    buf = Buffer(data=data)
    buf.seek(start)
    verify = dataclasses.replace(pull_certificate_verify(buf), **changes)
    output = Buffer(capacity=buf.tell() - start + 64)
    push_certificate_verify(output, verify)
    return data[:start] + output.data + data[buf.tell() :]


def modify_server_hello(data: bytes, **changes: Any) -> bytes:
    """
    Replace fields of the ServerHello at the start of `data`.
    """
    buf = Buffer(data=data)
    hello = dataclasses.replace(pull_server_hello(buf), **changes)
    output = Buffer(capacity=len(data) + 64)
    push_server_hello(output, hello)
    return output.data + data[buf.tell() :]


def rename_client_hello_extension(data: bytes, extension_type: int) -> bytes:
    """
    Rename an extension of the ClientHello at the start of `data` to a GREASE
    type, which the server ignores.
    """
    buf = Buffer(data=data)
    buf.seek(4 + 2 + 32)  # handshake header, legacy version, random
    tls.pull_opaque(buf, 1)  # legacy_session_id
    tls.pull_opaque(buf, 2)  # cipher_suites
    tls.pull_opaque(buf, 1)  # legacy_compression_methods
    end = buf.pull_uint16() + buf.tell()
    while buf.tell() < end:
        start = buf.tell()
        if buf.pull_uint16() == extension_type:
            return data[:start] + b"\xfa\xfa" + data[start + 2 :]
        tls.pull_opaque(buf, 2)
    raise ValueError(f"ClientHello has no extension {extension_type}")


def reset_buffers(buffers: dict[tls.Epoch, Buffer]) -> None:
    for k in buffers.keys():
        buffers[k].seek(0)


class ContextTest(TestCase):
    def assertClientHello(self, data: bytes) -> None:
        self.assertEqual(data[0], tls.HandshakeType.CLIENT_HELLO)
        self.assertGreaterEqual(len(data), 161)
        self.assertLessEqual(len(data), 536)

    def create_client(
        self,
        alpn_protocols: list[str] | None = None,
        cadata: bytes | None = None,
        cafile: str | None = SERVER_CACERTFILE,
        cipher_suites: list[tls.CipherSuite] | None = None,
        verify_mode: int | None = None,
    ) -> Context:
        client = Context(
            alpn_protocols=alpn_protocols,
            cadata=cadata,
            cafile=cafile,
            cipher_suites=cipher_suites,
            is_client=True,
            verify_mode=verify_mode,
        )
        client.handshake_extensions = [
            (
                tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                CLIENT_QUIC_TRANSPORT_PARAMETERS,
            )
        ]
        self.assertEqual(client.state, State.CLIENT_HANDSHAKE_START)
        return client

    def create_server(
        self,
        alpn_protocols: list[str] | None = None,
        cipher_suites: list[tls.CipherSuite] | None = None,
    ) -> Context:
        configuration = QuicConfiguration(is_client=False)
        load_cert_chain(configuration, SERVER_CERTFILE, SERVER_KEYFILE)

        server = Context(
            alpn_protocols=alpn_protocols,
            cipher_suites=cipher_suites,
            is_client=False,
            max_early_data=0xFFFFFFFF,
        )
        server.certificate = configuration.certificate
        server.certificate_private_key = configuration.private_key
        server.handshake_extensions = [
            (
                tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                SERVER_QUIC_TRANSPORT_PARAMETERS,
            )
        ]
        self.assertEqual(server.state, State.SERVER_EXPECT_CLIENT_HELLO)
        return server

    def handshake_with_client_input_corruption(
        self,
        corrupt_client_input: Callable[[bytes], bytes],
        expected_exception: tls.Alert,
        legacy_session_id: bytes = b"",
    ) -> None:
        client = self.create_client()
        client.legacy_session_id = legacy_session_id
        server = self.create_server()

        # Send client hello.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        self.assertEqual(client.state, State.CLIENT_EXPECT_SERVER_HELLO)
        server_input = merge_buffers(client_buf)
        reset_buffers(client_buf)

        # Handle client hello.
        #
        # send server hello, encrypted extensions, certificate, certificate verify,
        # finished.
        server_buf = create_buffers()
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_EXPECT_FINISHED)
        client_input = merge_buffers(server_buf)
        reset_buffers(server_buf)

        # Corrupt the server's flight.
        client_input = corrupt_client_input(client_input)

        # Handle server hello, encrypted extensions, certificate, certificate verify,
        # finished.
        with self.assertRaisesMessage(
            expected_exception.__class__, str(expected_exception)
        ):
            client.handle_message(client_input, client_buf)

    def handshake_with_server_input_corruption(
        self,
        client_certificate: x509.Certificate,
        client_private_key: CertificatePrivateKey,
        corrupt_server_input: Callable[[bytes], bytes],
        expected_exception: tls.Alert,
    ) -> None:
        client = self.create_client()
        client.certificate = client_certificate
        client.certificate_private_key = client_private_key
        server = self.create_server()
        server._request_client_certificate = True

        # Send client hello.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        server_input = merge_buffers(client_buf)
        reset_buffers(client_buf)

        # Handle client hello.
        #
        # Send server hello, encrypted extensions, certificate request, certificate,
        # certificate verify, finished.
        server_buf = create_buffers()
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_EXPECT_CERTIFICATE)
        client_input = merge_buffers(server_buf)
        reset_buffers(server_buf)

        # Handle server hello, encrypted extensions, certificate request, certificate,
        # certificate verify, finished.
        #
        # Send certificate, certificate verify, finished.
        client.handle_message(client_input, client_buf)
        self.assertEqual(client.state, State.CLIENT_POST_HANDSHAKE)
        server_input = corrupt_server_input(merge_buffers(client_buf))

        # Handle certificate, certificate verify, finished.
        with self.assertRaisesMessage(
            expected_exception.__class__, str(expected_exception)
        ):
            server.handle_message(server_input, server_buf)

    def test_client_unexpected_message(self) -> None:
        client = self.create_client()

        client.state = State.CLIENT_EXPECT_SERVER_HELLO
        with self.assertRaises(tls.AlertUnexpectedMessage):
            client.handle_message(b"\x00\x00\x00\x00", create_buffers())

        client.state = State.CLIENT_EXPECT_ENCRYPTED_EXTENSIONS
        with self.assertRaises(tls.AlertUnexpectedMessage):
            client.handle_message(b"\x00\x00\x00\x00", create_buffers())

        client.state = State.CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE
        with self.assertRaises(tls.AlertUnexpectedMessage):
            client.handle_message(b"\x00\x00\x00\x00", create_buffers())

        client.state = State.CLIENT_EXPECT_CERTIFICATE
        with self.assertRaises(tls.AlertUnexpectedMessage):
            client.handle_message(b"\x00\x00\x00\x00", create_buffers())

        client.state = State.CLIENT_EXPECT_CERTIFICATE_VERIFY
        with self.assertRaises(tls.AlertUnexpectedMessage):
            client.handle_message(b"\x00\x00\x00\x00", create_buffers())

        client.state = State.CLIENT_EXPECT_FINISHED
        with self.assertRaises(tls.AlertUnexpectedMessage):
            client.handle_message(b"\x00\x00\x00\x00", create_buffers())

        client.state = State.CLIENT_POST_HANDSHAKE
        with self.assertRaises(tls.AlertUnexpectedMessage):
            client.handle_message(b"\x00\x00\x00\x00", create_buffers())

    def test_client_bad_hello_buffer_read_error(self) -> None:
        buf = Buffer(capacity=100)
        buf.push_uint8(tls.HandshakeType.SERVER_HELLO)
        with tls.push_block(buf, 3):
            pass

        self.handshake_with_client_input_corruption(
            # Receive a malformed ServerHello
            lambda x: buf.data,
            tls.AlertDecodeError("Could not parse TLS message"),
        )

    def test_client_bad_hello_cipher_suite(self) -> None:
        self.handshake_with_client_input_corruption(
            # Select TLS_AES_128_CCM_SHA256, which we did not offer.
            lambda x: modify_server_hello(x, cipher_suite=0x1304),
            tls.AlertIllegalParameter(
                "ServerHello has a cipher suite we did not advertise"
            ),
        )

    def test_client_bad_hello_compression_method(self) -> None:
        self.handshake_with_client_input_corruption(
            lambda x: modify_server_hello(x, compression_method=0xFF),
            tls.AlertIllegalParameter(
                "ServerHello has a compression method we did not advertise"
            ),
        )

    def test_client_bad_hello_invalid_key_share(self) -> None:
        self.handshake_with_client_input_corruption(
            # A SECP256R1 public key which is not a valid point encoding.
            lambda x: modify_server_hello(
                x, key_share=(tls.Group.SECP256R1, b"\x05" + bytes(64))
            ),
            tls.AlertIllegalParameter("ServerHello has an invalid key share"),
        )

    def test_client_bad_hello_key_share(self) -> None:
        self.handshake_with_client_input_corruption(
            lambda x: modify_server_hello(x, key_share=(0xFFFF, b"")),
            tls.AlertIllegalParameter(
                "ServerHello has a key share we did not advertise"
            ),
        )

    def test_client_bad_hello_legacy_session_id(self) -> None:
        self.handshake_with_client_input_corruption(
            # Echo a value although we sent none.
            lambda x: modify_server_hello(x, legacy_session_id=b"\xff"),
            tls.AlertIllegalParameter(
                "ServerHello has a legacy_session_id we did not send"
            ),
        )

    def test_client_bad_hello_legacy_session_id_not_echoed(self) -> None:
        self.handshake_with_client_input_corruption(
            # Drop the value we sent.
            lambda x: modify_server_hello(x, legacy_session_id=b""),
            tls.AlertIllegalParameter(
                "ServerHello has a legacy_session_id we did not send"
            ),
            legacy_session_id=bytes(32),
        )

    def test_client_bad_hello_legacy_session_id_too_long(self) -> None:
        self.handshake_with_client_input_corruption(
            lambda x: modify_server_hello(x, legacy_session_id=bytes(33)),
            tls.AlertDecodeError("legacy_session_id is too long"),
        )

    def test_client_bad_hello_no_key_share(self) -> None:
        self.handshake_with_client_input_corruption(
            lambda x: modify_server_hello(x, key_share=None),
            tls.AlertMissingExtension("ServerHello has no key share"),
        )

    def test_client_bad_hello_prohibited_extension(self) -> None:
        self.handshake_with_client_input_corruption(
            # We offered transport parameters, but they belong in EncryptedExtensions.
            lambda x: modify_server_hello(
                x,
                other_extensions=[(tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS, b"")],
            ),
            tls.AlertIllegalParameter("ServerHello has a prohibited extension 0x0039"),
        )

    def test_client_bad_hello_unsolicited_extension(self) -> None:
        self.handshake_with_client_input_corruption(
            # A GREASE value (RFC 8701).
            lambda x: modify_server_hello(x, other_extensions=[(0xFAFA, b"")]),
            tls.AlertUnsupportedExtension(
                "ServerHello has an unsolicited extension 0xfafa"
            ),
        )

    def test_client_bad_hello_version(self) -> None:
        self.handshake_with_client_input_corruption(
            lambda x: modify_server_hello(x, supported_version=0xFFFF),
            tls.AlertIllegalParameter("ServerHello has a version we did not advertise"),
        )

    def test_client_bad_certificate_verify_algorithm(self) -> None:
        self.handshake_with_client_input_corruption(
            lambda x: modify_certificate_verify(x, algorithm=0xFFFF),
            tls.AlertDecryptError(
                "CertificateVerify has a signature algorithm we did not advertise"
            ),
        )

    def test_client_bad_certificate_verify_algorithm_for_key(self) -> None:
        self.handshake_with_client_input_corruption(
            # Use an ECDSA signature algorithm with the server's RSA key.
            lambda x: modify_certificate_verify(
                x, algorithm=tls.SignatureAlgorithm.ECDSA_SECP256R1_SHA256
            ),
            tls.AlertDecryptError(
                "CertificateVerify has a signature algorithm which does not match "
                "the certificate's key"
            ),
        )

    def test_client_bad_certificate_verify_algorithm_rsa_pkcs1(self) -> None:
        self.handshake_with_client_input_corruption(
            # Replace RSA_PSS_RSAE_SHA256 by RSA_PKCS1_SHA256, which we advertise.
            lambda x: modify_certificate_verify(
                x, algorithm=tls.SignatureAlgorithm.RSA_PKCS1_SHA256
            ),
            tls.AlertIllegalParameter(
                "CertificateVerify has an RSASSA-PKCS1-v1_5 signature algorithm"
            ),
        )

    def test_client_bad_certificate_verify_data(self) -> None:
        self.handshake_with_client_input_corruption(
            lambda x: modify_certificate_verify(x, signature=bytes(4)),
            tls.AlertDecryptError(),
        )

    def test_client_bad_encrypted_extensions_early_data_without_psk(self) -> None:
        """
        A server may only accept early data if it accepts our PSK
        (RFC 9846 section 4.3.11).
        """
        client = self.create_client()
        client.session_ticket = dataclasses.replace(
            create_session_ticket(), max_early_data_size=0xFFFFFFFF
        )
        server = self.create_server()
        # The server does not know the ticket, but claims to accept early data.
        server.early_data_accepted = True

        with self.assertRaisesMessage(
            tls.AlertIllegalParameter,
            "EncryptedExtensions accepts early data without our PSK",
        ):
            self._handshake(client, server)

    def test_client_bad_encrypted_extensions_prohibited_extension(self) -> None:
        client = self.create_client()
        server = self.create_server()
        # We offered a key share, but the answer belongs in ServerHello.
        server.handshake_extensions.append((tls.ExtensionType.KEY_SHARE, b""))

        with self.assertRaisesMessage(
            tls.AlertIllegalParameter,
            "EncryptedExtensions has a prohibited extension 0x0033",
        ):
            self._handshake(client, server)

    def test_client_bad_encrypted_extensions_server_name_with_data(self) -> None:
        client = self.create_client()
        client._server_name = "localhost"
        server = self.create_server()
        # The acknowledgement of our server name must be empty.
        server.handshake_extensions.append((tls.ExtensionType.SERVER_NAME, b"junk"))

        with self.assertRaisesMessage(
            tls.AlertDecodeError, "EncryptedExtensions has a non-empty server_name"
        ):
            self._handshake(client, server)

    def test_client_bad_encrypted_extensions_unsolicited_alpn(self) -> None:
        client = self.create_client()
        server = self.create_server()
        # We did not offer ALPN.
        server.alpn_negotiated = "h3"

        with self.assertRaisesMessage(
            tls.AlertUnsupportedExtension, "EncryptedExtensions has an unsolicited ALPN"
        ):
            self._handshake(client, server)

    def test_client_bad_encrypted_extensions_unsolicited_early_data(self) -> None:
        client = self.create_client()
        server = self.create_server()
        # We did not offer early data.
        server.early_data_accepted = True

        with self.assertRaisesMessage(
            tls.AlertUnsupportedExtension,
            "EncryptedExtensions has an unsolicited early_data",
        ):
            self._handshake(client, server)

    def test_client_bad_encrypted_extensions_unsolicited_extension(self) -> None:
        client = self.create_client()
        server = self.create_server()
        # A GREASE value (RFC 8701).
        server.handshake_extensions.append((0xFAFA, b""))

        with self.assertRaisesMessage(
            tls.AlertUnsupportedExtension,
            "EncryptedExtensions has an unsolicited extension 0xfafa",
        ):
            self._handshake(client, server)

    def test_client_bad_encrypted_extensions_unsolicited_server_name(self) -> None:
        client = self.create_client()
        server = self.create_server()
        # We did not send a server name.
        server.handshake_extensions.append((tls.ExtensionType.SERVER_NAME, b""))

        with self.assertRaisesMessage(
            tls.AlertUnsupportedExtension,
            "EncryptedExtensions has an unsolicited extension 0x0000",
        ):
            self._handshake(client, server)

    def test_client_bad_finished_verify_data(self) -> None:
        self.handshake_with_client_input_corruption(
            # Mess with finished verify data.
            lambda x: x[:-4] + bytes(4),
            tls.AlertDecryptError(),
        )

    def test_client_empty_certificate(self) -> None:
        def encode_certificate(certificates: list[tuple[bytes, bytes]]) -> bytes:
            buf = Buffer(capacity=4096)
            push_certificate(
                buf, Certificate(request_context=b"", certificates=certificates)
            )
            return buf.data

        configuration = QuicConfiguration(is_client=False)
        load_cert_chain(configuration, SERVER_CERTFILE, SERVER_KEYFILE)
        certificate_data = configuration.certificate.public_bytes(
            serialization.Encoding.DER
        )

        self.handshake_with_client_input_corruption(
            # Replace the server's certificate list with an empty one.
            lambda x: x.replace(
                encode_certificate([(certificate_data, b"")]),
                encode_certificate([]),
            ),
            tls.AlertDecodeError("Certificate message is empty"),
        )

    def test_client_invalid_certificate_key(self) -> None:
        configuration = QuicConfiguration(is_client=False)
        load_cert_chain(configuration, SERVER_CERTFILE, SERVER_KEYFILE)
        certificate_data = configuration.certificate.public_bytes(
            serialization.Encoding.DER
        )

        self.handshake_with_client_input_corruption(
            # Replace the server's RSA public exponent with an invalid one.
            lambda x: x.replace(
                certificate_data,
                certificate_data.replace(
                    bytes.fromhex("0203010001"), bytes.fromhex("0203000001")
                ),
            ),
            tls.AlertBadCertificate("Certificate has an invalid key"),
        )

    def test_client_invalid_certificate_version(self) -> None:
        configuration = QuicConfiguration(is_client=False)
        load_cert_chain(configuration, SERVER_CERTFILE, SERVER_KEYFILE)
        certificate_data = configuration.certificate.public_bytes(
            serialization.Encoding.DER
        )

        self.handshake_with_client_input_corruption(
            # Replace the certificate's version, v3, with an undefined one.
            lambda x: x.replace(
                certificate_data,
                certificate_data.replace(
                    bytes.fromhex("a003020102"), bytes.fromhex("a003020142")
                ),
            ),
            tls.AlertBadCertificate("Certificate could not be parsed"),
        )

    def test_client_malformed_certificate(self) -> None:
        configuration = QuicConfiguration(is_client=False)
        load_cert_chain(configuration, SERVER_CERTFILE, SERVER_KEYFILE)
        certificate_data = configuration.certificate.public_bytes(
            serialization.Encoding.DER
        )

        self.handshake_with_client_input_corruption(
            # Corrupt the server's certificate, keeping its length unchanged.
            lambda x: x.replace(certificate_data, b"\x00" + certificate_data[1:]),
            tls.AlertBadCertificate("Certificate could not be parsed"),
        )

    def test_client_unsupported_certificate_key(self) -> None:
        configuration = QuicConfiguration(is_client=False)
        load_cert_chain(configuration, SERVER_CERTFILE, SERVER_KEYFILE)
        certificate_data = configuration.certificate.public_bytes(
            serialization.Encoding.DER
        )

        self.handshake_with_client_input_corruption(
            # Replace the rsaEncryption key algorithm with an unknown one.
            lambda x: x.replace(
                certificate_data,
                certificate_data.replace(
                    bytes.fromhex("06092a864886f70d010101"),
                    bytes.fromhex("06092a864886f70d01017f"),
                ),
            ),
            tls.AlertUnsupportedCertificate("Certificate has an unsupported key type"),
        )

    def test_server_bad_certificate_verify_algorithm_for_key(self) -> None:
        certificate, private_key = generate_ed25519_certificate(
            common_name="client.example.com"
        )

        self.handshake_with_server_input_corruption(
            certificate,
            private_key,
            # Use an RSA signature algorithm with the client's Ed25519 key.
            lambda x: modify_certificate_verify(
                x, algorithm=tls.SignatureAlgorithm.RSA_PSS_RSAE_SHA256
            ),
            tls.AlertDecryptError(
                "CertificateVerify has a signature algorithm which does not match "
                "the certificate's key"
            ),
        )

    def _server_fail_hello(
        self,
        client: Context,
        server: Context,
        missing_extension: tls.ExtensionType | None = None,
    ) -> None:
        # Send client hello, optionally without one of its extensions.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        self.assertEqual(client.state, State.CLIENT_EXPECT_SERVER_HELLO)
        server_input = merge_buffers(client_buf)
        if missing_extension is not None:
            server_input = rename_client_hello_extension(
                server_input, missing_extension
            )
        reset_buffers(client_buf)

        # Handle client hello.
        server_buf = create_buffers()
        server.handle_message(server_input, server_buf)

    def test_server_bad_hello_compression_methods(self) -> None:
        for compression_methods in [[tls.CompressionMethod.NULL, 1], [1]]:
            with self.subTest(compression_methods):
                client = self.create_client()
                client._legacy_compression_methods = compression_methods
                server = self.create_server()

                with self.assertRaisesMessage(
                    tls.AlertIllegalParameter,
                    "ClientHello has a compression method other than null",
                ):
                    self._server_fail_hello(client, server)

    def test_server_bad_hello_invalid_key_share(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.SECP256R1]
        server = self.create_server()

        # Send client hello with a public key which is not on the curve.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        public_key = tls.encode_public_key(client._ec_private_keys[0].public_key())[1]
        server_input = merge_buffers(client_buf).replace(
            public_key, b"\x05" + public_key[1:]
        )

        with self.assertRaisesMessage(
            tls.AlertIllegalParameter, "ClientHello has an invalid key share"
        ):
            server.handle_message(server_input, create_buffers())

    def test_server_bad_hello_invalid_key_share_x25519_all_zero(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.X25519]
        server = self.create_server()

        # Send client hello with an all-zero public key, for which the key
        # exchange fails.
        client_buf = create_buffers()
        try:
            client.handle_message(b"", client_buf)
        except UnsupportedAlgorithm as exc:
            self.skipTest(str(exc))
        public_key = tls.encode_public_key(client._x25519_private_key.public_key())[1]
        server_input = merge_buffers(client_buf).replace(public_key, bytes(32))

        with self.assertRaisesMessage(
            tls.AlertIllegalParameter, "ClientHello has an invalid key share"
        ):
            server.handle_message(server_input, create_buffers())

    def test_server_bad_hello_missing_extension(self) -> None:
        """
        A ClientHello without a PSK must send the extensions for (EC)DHE key
        exchange and signature algorithms (RFC 9846 section 9.2).
        """
        for extension_type, message in [
            (tls.ExtensionType.KEY_SHARE, "ClientHello has no key share"),
            (
                tls.ExtensionType.SIGNATURE_ALGORITHMS,
                "ClientHello has no signature algorithms",
            ),
            (tls.ExtensionType.SUPPORTED_GROUPS, "ClientHello has no supported groups"),
        ]:
            with self.subTest(extension_type.name):
                client = self.create_client()
                server = self.create_server()

                with self.assertRaisesMessage(tls.AlertMissingExtension, message):
                    self._server_fail_hello(
                        client, server, missing_extension=extension_type
                    )

    def test_server_bad_hello_missing_psk_key_exchange_modes(self) -> None:
        """
        A ClientHello offering a PSK must send its key exchange modes
        (RFC 9846 section 4.3.9).
        """
        client = self.create_client()
        client.session_ticket = create_session_ticket()
        server = self.create_server()

        with self.assertRaisesMessage(
            tls.AlertMissingExtension, "ClientHello has no PSK key exchange modes"
        ):
            self._server_fail_hello(
                client,
                server,
                missing_extension=tls.ExtensionType.PSK_KEY_EXCHANGE_MODES,
            )

    def test_server_bad_hello_psk_binder(self) -> None:
        ticket = create_session_ticket()
        client = self.create_client()
        client.session_ticket = ticket
        server = self.create_server()
        server.get_session_ticket_cb = lambda label: ticket

        # Send client hello, tampering with the PSK binder, which comes last.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        server_input = merge_buffers(client_buf)[:-4] + bytes(4)

        with self.assertRaisesMessage(
            tls.AlertHandshakeFailure, "ClientHello has an invalid PSK binder"
        ):
            server.handle_message(server_input, create_buffers())

    def test_server_bad_hello_rsa_pkcs1_signature(self) -> None:
        """
        RSASSA-PKCS1-v1_5 cannot be used in CertificateVerify (RFC 9846 section
        4.3.3).
        """
        for signature_algorithm in [
            tls.SignatureAlgorithm.RSA_PKCS1_SHA1,
            tls.SignatureAlgorithm.RSA_PKCS1_SHA256,
            tls.SignatureAlgorithm.RSA_PKCS1_SHA384,
        ]:
            with self.subTest(signature_algorithm.name):
                client = self.create_client()
                client._signature_algorithms = [signature_algorithm]
                server = self.create_server()

                with self.assertRaisesMessage(
                    tls.AlertHandshakeFailure,
                    "ClientHello has no supported signature algorithm",
                ):
                    self._server_fail_hello(client, server)

    def test_server_bad_hello_unsupported_alpn_protocol(self) -> None:
        client = self.create_client(alpn_protocols=["hq-interop"])
        server = self.create_server(alpn_protocols=["h3"])

        with self.assertRaisesMessage(
            tls.AlertNoApplicationProtocol, "ClientHello has no common ALPN protocol"
        ):
            self._server_fail_hello(client, server)

    def test_server_bad_hello_unsupported_cipher_suite(self) -> None:
        client = self.create_client(
            cipher_suites=[tls.CipherSuite.TLS_AES_128_GCM_SHA256]
        )

        server = self.create_server(
            cipher_suites=[tls.CipherSuite.TLS_AES_256_GCM_SHA384]
        )

        with self.assertRaisesMessage(
            tls.AlertHandshakeFailure, "ClientHello has no supported cipher suite"
        ):
            self._server_fail_hello(client, server)

    def test_server_bad_hello_unsupported_group(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.GREASE]

        server = self.create_server()

        with self.assertRaisesMessage(
            tls.AlertHandshakeFailure, "ClientHello has no supported key share"
        ):
            self._server_fail_hello(client, server)

    def test_server_bad_hello_unsupported_group_by_server(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.SECP256R1]

        server = self.create_server()
        server._supported_groups = [tls.Group.SECP384R1]

        with self.assertRaisesMessage(
            tls.AlertHandshakeFailure, "ClientHello has no supported key share"
        ):
            self._server_fail_hello(client, server)

    def test_server_bad_hello_unsupported_signature_algorithm(self) -> None:
        client = self.create_client()
        client._signature_algorithms = [tls.SignatureAlgorithm.ED448]

        server = self.create_server()

        with self.assertRaisesMessage(
            tls.AlertHandshakeFailure,
            "ClientHello has no supported signature algorithm",
        ):
            self._server_fail_hello(client, server)

    def test_server_bad_hello_unsupported_version(self) -> None:
        client = self.create_client()
        client._supported_versions = [tls.TLS_VERSION_1_2]

        server = self.create_server()

        with self.assertRaisesMessage(
            tls.AlertProtocolVersion, "ClientHello has no supported protocol version"
        ):
            self._server_fail_hello(client, server)

    def test_server_malformed_certificate(self) -> None:
        certificate, private_key = generate_rsa_certificate(
            common_name="client.example.com"
        )
        certificate_data = certificate.public_bytes(serialization.Encoding.DER)

        self.handshake_with_server_input_corruption(
            certificate,
            private_key,
            # Corrupt the client's certificate, keeping its length unchanged.
            lambda x: x.replace(certificate_data, b"\x00" + certificate_data[1:]),
            tls.AlertBadCertificate("Certificate could not be parsed"),
        )

    def test_server_message_too_large(self) -> None:
        """
        A message larger than 64 KiB is refused as soon as its header arrives.
        """

        def header(length: int) -> bytes:
            return bytes([tls.HandshakeType.CLIENT_HELLO]) + length.to_bytes(3, "big")

        # A ClientHello of the largest size is still awaited.
        server = self.create_server()
        server.handle_message(header(tls.MAX_HANDSHAKE_MESSAGE_SIZE), create_buffers())
        self.assertEqual(server.state, State.SERVER_EXPECT_CLIENT_HELLO)

        # A larger one is refused without waiting for its body.
        server = self.create_server()
        with self.assertRaisesMessage(
            tls.AlertIllegalParameter, "TLS message is too large"
        ):
            server.handle_message(
                header(tls.MAX_HANDSHAKE_MESSAGE_SIZE + 1), create_buffers()
            )

    def test_server_unexpected_message(self) -> None:
        server = self.create_server()

        server.state = State.SERVER_EXPECT_CLIENT_HELLO
        with self.assertRaises(tls.AlertUnexpectedMessage):
            server.handle_message(b"\x00\x00\x00\x00", create_buffers())

        server.state = State.SERVER_EXPECT_CERTIFICATE
        with self.assertRaises(tls.AlertUnexpectedMessage):
            server.handle_message(b"\x00\x00\x00\x00", create_buffers())

        server.state = State.SERVER_EXPECT_CERTIFICATE_VERIFY
        with self.assertRaises(tls.AlertUnexpectedMessage):
            server.handle_message(b"\x00\x00\x00\x00", create_buffers())

        server.state = State.SERVER_EXPECT_FINISHED
        with self.assertRaises(tls.AlertUnexpectedMessage):
            server.handle_message(b"\x00\x00\x00\x00", create_buffers())

        server.state = State.SERVER_POST_HANDSHAKE
        with self.assertRaises(tls.AlertUnexpectedMessage):
            server.handle_message(b"\x00\x00\x00\x00", create_buffers())

    def test_server_bad_finished_verify_data(self) -> None:
        client = self.create_client()
        server = self.create_server()

        # Send client hello.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        self.assertEqual(client.state, State.CLIENT_EXPECT_SERVER_HELLO)
        server_input = merge_buffers(client_buf)
        reset_buffers(client_buf)

        # Handle client hello.
        #
        # Send server hello, encrypted extensions, certificate, certificate verify,
        # finished.
        server_buf = create_buffers()
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_EXPECT_FINISHED)
        client_input = merge_buffers(server_buf)
        reset_buffers(server_buf)

        # Handle server hello, encrypted extensions, certificate, certificate verify,
        # finished.
        #
        # Send finished.
        client.handle_message(client_input, client_buf)
        self.assertEqual(client.state, State.CLIENT_POST_HANDSHAKE)
        server_input = merge_buffers(client_buf)
        reset_buffers(client_buf)

        # Mess with finished verify data.
        server_input = server_input[:-4] + bytes(4)

        # Handle finished.
        with self.assertRaises(tls.AlertDecryptError):
            server.handle_message(server_input, server_buf)

    def _handshake(self, client: Context, server: Context) -> None:
        # Send client hello.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        self.assertEqual(client.state, State.CLIENT_EXPECT_SERVER_HELLO)
        server_input = merge_buffers(client_buf)
        self.assertClientHello(server_input)
        reset_buffers(client_buf)

        # Handle client hello.
        #
        # Send server hello, encrypted extensions, certificate, certificate verify,
        # finished.
        server_buf = create_buffers()
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_EXPECT_FINISHED)
        client_input = merge_buffers(server_buf)
        self.assertGreaterEqual(len(client_input), 534)
        self.assertLessEqual(len(client_input), 2263)

        reset_buffers(server_buf)

        # Handle server hello, encrypted extensions, certificate, certificate verify,
        # finished.
        #
        # Send finished.
        client.handle_message(client_input, client_buf)
        self.assertEqual(client.state, State.CLIENT_POST_HANDSHAKE)
        server_input = merge_buffers(client_buf)
        self.assertEqual(len(server_input), 52)
        reset_buffers(client_buf)

        # Handle finished.
        #
        # Send (session ticket).
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_POST_HANDSHAKE)
        client_input = merge_buffers(server_buf)
        if server.new_session_ticket_cb is None:
            self.assertEqual(len(client_input), 0)
        else:
            self.assertEqual(len(client_input), 89)
        reset_buffers(server_buf)

        # Handle (session ticket).
        client.handle_message(client_input, client_buf)
        self.assertEqual(client.state, State.CLIENT_POST_HANDSHAKE)
        self.assertEqual(len(merge_buffers(client_buf)), 0)

        # check keys match
        self.assertEqual(client._dec_key, server._enc_key)
        self.assertEqual(client._enc_key, server._dec_key)

        # check cipher suite
        self.assertEqual(
            client.key_schedule.cipher_suite, tls.CipherSuite.TLS_AES_256_GCM_SHA384
        )
        self.assertEqual(
            server.key_schedule.cipher_suite, tls.CipherSuite.TLS_AES_256_GCM_SHA384
        )

    def test_handshake(self) -> None:
        client = self.create_client()
        server = self.create_server()

        self._handshake(client, server)

        # check ALPN matches
        self.assertEqual(client.alpn_negotiated, None)
        self.assertEqual(server.alpn_negotiated, None)

    def test_handshake_one_byte_at_a_time(self) -> None:
        """
        Handshake messages are reassembled when they arrive one byte at a time.
        """
        client = self.create_client()
        server = self.create_server()

        # Send client hello.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        server_input = merge_buffers(client_buf)
        reset_buffers(client_buf)

        # Handle client hello.
        #
        # Send server hello, encrypted extensions, certificate, certificate verify,
        # finished.
        server_buf = create_buffers()
        for i in range(len(server_input)):
            server.handle_message(server_input[i : i + 1], server_buf)
        self.assertEqual(server.state, State.SERVER_EXPECT_FINISHED)
        client_input = merge_buffers(server_buf)
        reset_buffers(server_buf)

        # Handle server hello, encrypted extensions, certificate, certificate verify,
        # finished.
        #
        # Send finished.
        for i in range(len(client_input)):
            client.handle_message(client_input[i : i + 1], client_buf)
        self.assertEqual(client.state, State.CLIENT_POST_HANDSHAKE)
        server_input = merge_buffers(client_buf)

        # Handle finished.
        for i in range(len(server_input)):
            server.handle_message(server_input[i : i + 1], server_buf)
        self.assertEqual(server.state, State.SERVER_POST_HANDSHAKE)

        # Check keys match.
        self.assertEqual(client._dec_key, server._enc_key)
        self.assertEqual(client._enc_key, server._dec_key)

    def test_handshake_with_certificate_request_no_certificate(self) -> None:
        # The server requests a certificate, but the client has none.
        client = self.create_client()
        server = self.create_server()
        server._request_client_certificate = True

        # Send client hello.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        self.assertEqual(client.state, State.CLIENT_EXPECT_SERVER_HELLO)
        server_input = merge_buffers(client_buf)
        self.assertClientHello(server_input)
        reset_buffers(client_buf)

        # Handle client hello.
        #
        # Send server hello, encrypted extensions, certificate request, certificate,
        # certificate verify, finished.
        server_buf = create_buffers()
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_EXPECT_CERTIFICATE)
        client_input = merge_buffers(server_buf)
        self.assertGreaterEqual(len(client_input), 534)
        self.assertLessEqual(len(client_input), 2263)

        reset_buffers(server_buf)

        # Handle server hello, encrypted extensions, certificate request, certificate,
        # certificate verify, finished.
        #
        # Send certificate, finished.
        client.handle_message(client_input, client_buf)
        self.assertEqual(client.state, State.CLIENT_POST_HANDSHAKE)
        server_input = merge_buffers(client_buf)
        self.assertEqual(len(server_input), 60)
        reset_buffers(client_buf)

        # Handle certificate, finished.
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_POST_HANDSHAKE)
        client_input = merge_buffers(server_buf)
        self.assertEqual(len(client_input), 0)

        # check keys match
        self.assertEqual(client._dec_key, server._enc_key)
        self.assertEqual(client._enc_key, server._dec_key)

        # check cipher suite
        self.assertEqual(
            client.key_schedule.cipher_suite, tls.CipherSuite.TLS_AES_256_GCM_SHA384
        )
        self.assertEqual(
            server.key_schedule.cipher_suite, tls.CipherSuite.TLS_AES_256_GCM_SHA384
        )

    def test_handshake_with_certificate_request_with_certificate(self) -> None:
        # The server requests a certificate, and the client has one.
        client = self.create_client()
        client.certificate, client.certificate_private_key = generate_rsa_certificate(
            common_name="client.example.com"
        )
        server = self.create_server()
        server._request_client_certificate = True

        # Send client hello.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        self.assertEqual(client.state, State.CLIENT_EXPECT_SERVER_HELLO)
        server_input = merge_buffers(client_buf)
        self.assertClientHello(server_input)
        reset_buffers(client_buf)

        # Handle client hello.
        #
        # Send server hello, encrypted extensions, certificate request, certificate,
        # certificate verify, finished.
        server_buf = create_buffers()
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_EXPECT_CERTIFICATE)
        client_input = merge_buffers(server_buf)
        self.assertGreaterEqual(len(client_input), 534)
        self.assertLessEqual(len(client_input), 2263)

        reset_buffers(server_buf)

        # Handle server hello, encrypted extensions, certificate request, certificate,
        # certificate verify, finished.
        #
        # Send certificate, certificate verify, finished.
        client.handle_message(client_input, client_buf)
        self.assertEqual(client.state, State.CLIENT_POST_HANDSHAKE)
        server_input = merge_buffers(client_buf)
        self.assertGreaterEqual(len(server_input), 1042)
        self.assertLessEqual(len(server_input), 1043)
        reset_buffers(client_buf)

        # Handle certificate, certificate verify, finished.
        server.handle_message(server_input, server_buf)
        self.assertEqual(server.state, State.SERVER_POST_HANDSHAKE)
        client_input = merge_buffers(server_buf)
        self.assertEqual(len(client_input), 0)

        # check keys match
        self.assertEqual(client._dec_key, server._enc_key)
        self.assertEqual(client._enc_key, server._dec_key)

        # check cipher suite
        self.assertEqual(
            client.key_schedule.cipher_suite, tls.CipherSuite.TLS_AES_256_GCM_SHA384
        )
        self.assertEqual(
            server.key_schedule.cipher_suite, tls.CipherSuite.TLS_AES_256_GCM_SHA384
        )

    def _test_handshake_with_certificate(
        self, certificate: x509.Certificate, private_key: CertificatePrivateKey
    ) -> None:
        server = self.create_server()
        server.certificate = certificate
        server.certificate_private_key = private_key

        client = self.create_client(
            cadata=server.certificate.public_bytes(serialization.Encoding.PEM),
            cafile=None,
        )

        self._handshake(client, server)

        # check ALPN matches
        self.assertEqual(client.alpn_negotiated, None)
        self.assertEqual(server.alpn_negotiated, None)

    def test_handshake_with_ec_certificate_secp256r1(self) -> None:
        self._test_handshake_with_certificate(
            *generate_ec_certificate(common_name="example.com", curve=ec.SECP256R1)
        )

    def test_handshake_with_ec_certificate_secp384r1(self) -> None:
        self._test_handshake_with_certificate(
            *generate_ec_certificate(common_name="example.com", curve=ec.SECP384R1)
        )

    def test_handshake_with_ed25519_certificate(self) -> None:
        self._test_handshake_with_certificate(
            *generate_ed25519_certificate(common_name="example.com")
        )

    @skipIf("ed448" in SKIP_TESTS, "Skipping ed448 tests")
    def test_handshake_with_ed448_certificate(self) -> None:
        self._test_handshake_with_certificate(
            *generate_ed448_certificate(common_name="example.com")
        )

    def test_handshake_with_alpn(self) -> None:
        client = self.create_client(alpn_protocols=["hq-interop"])
        server = self.create_server(alpn_protocols=["hq-interop", "h3"])

        self._handshake(client, server)

        # check ALPN matches
        self.assertEqual(client.alpn_negotiated, "hq-interop")
        self.assertEqual(server.alpn_negotiated, "hq-interop")

    def test_handshake_with_alpn_fail_client_not_offered(self) -> None:
        client = self.create_client(alpn_protocols=["hq-interop"])
        server = self.create_server(alpn_protocols=["hq-interop"])

        # The server selects a protocol the client did not offer.
        server.alpn_cb = lambda alpn_protocol: setattr(server, "alpn_negotiated", "h3")

        with self.assertRaisesMessage(
            tls.AlertNoApplicationProtocol, "No common ALPN protocols"
        ):
            self._handshake(client, server)

    def test_handshake_with_alpn_fail_client_not_selected(self) -> None:
        client = self.create_client(alpn_protocols=["hq-interop"])
        server = self.create_server()

        with self.assertRaisesMessage(
            tls.AlertNoApplicationProtocol, "No common ALPN protocols"
        ):
            self._handshake(client, server)

    def test_handshake_with_rsa_pss_rsae_sha256_signature(self) -> None:
        client = self.create_client()
        client._signature_algorithms = [tls.SignatureAlgorithm.RSA_PSS_RSAE_SHA256]
        server = self.create_server()

        self._handshake(client, server)

    def test_handshake_with_rsa_pss_rsae_sha384_signature(self) -> None:
        client = self.create_client()
        client._signature_algorithms = [tls.SignatureAlgorithm.RSA_PSS_RSAE_SHA384]
        server = self.create_server()

        self._handshake(client, server)

    def test_handshake_with_certificate_error(self) -> None:
        client = self.create_client(cafile=None)
        server = self.create_server()

        with self.assertRaisesMessage(
            tls.AlertBadCertificate, "unable to get local issuer certificate"
        ):
            self._handshake(client, server)

    def test_handshake_with_certificate_no_verify(self) -> None:
        client = self.create_client(cafile=None, verify_mode=ssl.CERT_NONE)
        server = self.create_server()

        self._handshake(client, server)

    def test_handshake_with_grease_group(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.GREASE, tls.Group.SECP256R1]
        server = self.create_server()

        self._handshake(client, server)

    def test_handshake_with_legacy_session_id(self) -> None:
        client = self.create_client()
        client.legacy_session_id = bytes(32)
        server = self.create_server()

        self._handshake(client, server)

    def test_handshake_with_secp256r1_group(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.SECP256R1]
        server = self.create_server()

        self._handshake(client, server)

    def test_handshake_with_secp384r1_group(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.SECP384R1]
        server = self.create_server()

        self._handshake(client, server)

    def test_handshake_with_server_name(self) -> None:
        client = self.create_client()
        client._server_name = "localhost"
        server = self.create_server()
        # Acknowledge the server name (RFC 6066 section 3) and send our groups
        # (RFC 9846 section 4.3.7).
        server.handshake_extensions += [
            (tls.ExtensionType.SERVER_NAME, b""),
            (tls.ExtensionType.SUPPORTED_GROUPS, b"\x00\x02\x00\x1d"),
        ]

        self._handshake(client, server)

    def test_handshake_with_server_supported_groups(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.SECP256R1, tls.Group.SECP384R1]
        server = self.create_server()
        server._supported_groups = [tls.Group.SECP384R1]

        self._handshake(client, server)

        # The server skipped the key share for a group it does not support.
        self.assertEqual(server._ec_private_keys[0].curve.name, "secp384r1")

    def test_handshake_with_x25519(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.X25519]
        server = self.create_server()

        try:
            self._handshake(client, server)
        except UnsupportedAlgorithm as exc:
            self.skipTest(str(exc))

    def test_handshake_with_x448(self) -> None:
        client = self.create_client()
        client._supported_groups = [tls.Group.X448]
        server = self.create_server()

        try:
            self._handshake(client, server)
        except UnsupportedAlgorithm as exc:
            self.skipTest(str(exc))

    def _resume(self, client: Context, server: Context) -> None:
        """
        Perform a handshake in which the server resumes the client's session.
        """
        client_input = self._resume_server_flight(client, server)

        # Handle server hello, encrypted extensions, finished.
        #
        # Send finished.
        client_buf = create_buffers()
        client.handle_message(client_input, client_buf)
        self.assertEqual(client.state, State.CLIENT_POST_HANDSHAKE)
        self.assertTrue(client.session_resumed)

        # Handle finished.
        server.handle_message(merge_buffers(client_buf), create_buffers())
        self.assertEqual(server.state, State.SERVER_POST_HANDSHAKE)

        # Check keys match.
        self.assertEqual(client._dec_key, server._enc_key)
        self.assertEqual(client._enc_key, server._dec_key)

    def _resume_server_flight(self, client: Context, server: Context) -> bytes:
        """
        Send the client's ClientHello with its session ticket, and return the
        server's first flight, in which it resumes the session.
        """
        # Send client hello with pre_shared_key.
        client_buf = create_buffers()
        client.handle_message(b"", client_buf)
        self.assertEqual(client.state, State.CLIENT_EXPECT_SERVER_HELLO)

        # Handle client hello.
        #
        # Send server hello, encrypted extensions, finished.
        server_buf = create_buffers()
        server.handle_message(merge_buffers(client_buf), server_buf)
        self.assertEqual(server.state, State.SERVER_EXPECT_FINISHED)
        self.assertTrue(server.session_resumed)
        return merge_buffers(server_buf)

    def test_session_ticket(self) -> None:
        client_tickets: list[SessionTicket] = []
        server_tickets: list[SessionTicket] = []

        def client_new_ticket(ticket: SessionTicket) -> None:
            client_tickets.append(ticket)

        def server_get_ticket(label: bytes) -> SessionTicket | None:
            for t in server_tickets:
                if t.ticket == label:
                    return t
            return None

        def server_new_ticket(ticket: SessionTicket) -> None:
            server_tickets.append(ticket)

        def first_handshake() -> None:
            client = self.create_client()
            client.new_session_ticket_cb = client_new_ticket

            server = self.create_server()
            server.new_session_ticket_cb = server_new_ticket

            self._handshake(client, server)

            # check session resumption was not used
            self.assertFalse(client.session_resumed)
            self.assertFalse(server.session_resumed)

            # check tickets match
            self.assertEqual(len(client_tickets), 1)
            self.assertEqual(len(server_tickets), 1)
            self.assertEqual(client_tickets[0].ticket, server_tickets[0].ticket)
            self.assertEqual(
                client_tickets[0].resumption_secret, server_tickets[0].resumption_secret
            )

        def second_handshake() -> None:
            client = self.create_client()
            client.session_ticket = client_tickets[0]

            server = self.create_server()
            server.get_session_ticket_cb = server_get_ticket

            self._resume(client, server)

        def second_handshake_bad_pre_shared_key() -> None:
            client = self.create_client()
            client.session_ticket = client_tickets[0]

            server = self.create_server()
            server.get_session_ticket_cb = server_get_ticket

            # Tamper with the selected identity, as we only offered one.
            client_input = modify_server_hello(
                self._resume_server_flight(client, server), pre_shared_key=1
            )

            # Handle server hello and abort.
            with self.assertRaises(tls.AlertIllegalParameter):
                client.handle_message(client_input, create_buffers())

        first_handshake()
        second_handshake()
        second_handshake_bad_pre_shared_key()

    def test_session_ticket_large(self) -> None:
        """
        Resumption works with a session ticket too large for a 1 KiB ClientHello.
        """
        client_tickets: list[SessionTicket] = []

        # Obtain a session ticket and make it larger.
        client = self.create_client()
        client.new_session_ticket_cb = client_tickets.append
        server = self.create_server()
        server.new_session_ticket_cb = lambda ticket: None
        self._handshake(client, server)
        ticket = dataclasses.replace(client_tickets[0], ticket=bytes(range(256)) * 8)

        # Resume, which requires the server to validate the binder.
        client = self.create_client()
        client.session_ticket = ticket
        server = self.create_server()
        server.get_session_ticket_cb = lambda label: ticket
        self._resume(client, server)

    def test_session_ticket_long_lifetime(self) -> None:
        """
        A client does not keep a session ticket for longer than 7 days, whatever
        its lifetime (RFC 9846 section 4.7.1).
        """
        client_tickets: list[SessionTicket] = []
        client = self.create_client()
        client.new_session_ticket_cb = client_tickets.append
        server = self.create_server()
        self._handshake(client, server)

        # Handle a session ticket with the largest lifetime.
        buf = Buffer(capacity=128)
        push_new_session_ticket(
            buf, NewSessionTicket(ticket_lifetime=0xFFFFFFFF, ticket=b"ticket")
        )
        client.handle_message(buf.data, create_buffers())

        self.assertEqual(len(client_tickets), 1)
        self.assertEqual(
            client_tickets[0].not_valid_after - client_tickets[0].not_valid_before,
            datetime.timedelta(days=7),
        )

    def _create_other_cipher_suite_contexts(
        self, client_cipher_suites: list[tls.CipherSuite]
    ) -> tuple[Context, Context]:
        """
        Create a client with an TLS_AES_128_GCM_SHA256 session ticket, and a server
        which only supports TLS_CHACHA20_POLY1305_SHA256.
        """
        now = datetime.datetime.now(datetime.UTC)
        ticket = SessionTicket(
            age_add=0,
            cipher_suite=tls.CipherSuite.TLS_AES_128_GCM_SHA256,
            not_valid_after=now + datetime.timedelta(hours=1),
            not_valid_before=now,
            resumption_secret=bytes(32),
            server_name="localhost",
            ticket=b"ticket",
        )
        client = self.create_client(cipher_suites=client_cipher_suites)
        client.session_ticket = ticket

        # The PSK is associated with SHA-256, so the server may accept it with
        # TLS_CHACHA20_POLY1305_SHA256. Our server requires the ticket's cipher suite,
        # so it is given the ticket with that cipher suite.
        server = self.create_server(
            cipher_suites=[tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256]
        )
        server.get_session_ticket_cb = lambda label: dataclasses.replace(
            ticket, cipher_suite=tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256
        )
        return client, server

    def test_session_ticket_other_cipher_suite_same_hash(self) -> None:
        """
        A client accepts resumption with a cipher suite other than the ticket's
        when it has the same hash (RFC 9846 section 4.3.11).
        """
        client, server = self._create_other_cipher_suite_contexts(
            [
                tls.CipherSuite.TLS_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            ]
        )
        self._resume(client, server)

        # Check session resumption used TLS_CHACHA20_POLY1305_SHA256.
        self.assertEqual(
            client.key_schedule.cipher_suite,
            tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        )
        self.assertEqual(
            server.key_schedule.cipher_suite,
            tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        )

    def test_session_ticket_other_cipher_suite_other_hash(self) -> None:
        """
        A client rejects resumption with a cipher suite whose hash is not the
        ticket's (RFC 9846 section 4.3.11).
        """
        client, server = self._create_other_cipher_suite_contexts(
            [
                tls.CipherSuite.TLS_AES_128_GCM_SHA256,
                tls.CipherSuite.TLS_AES_256_GCM_SHA384,
                tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            ]
        )

        # Tamper with the ServerHello to select TLS_AES_256_GCM_SHA384.
        client_input = modify_server_hello(
            self._resume_server_flight(client, server),
            cipher_suite=tls.CipherSuite.TLS_AES_256_GCM_SHA384,
        )

        # Handle server hello and abort.
        with self.assertRaises(tls.AlertIllegalParameter):
            client.handle_message(client_input, create_buffers())


class TlsTest(TestCase):
    def test_cipher_suite_aliases(self) -> None:
        # The names used before the TLS_ prefix was added still work.
        self.assertIs(
            tls.CipherSuite.AES_128_GCM_SHA256, tls.CipherSuite.TLS_AES_128_GCM_SHA256
        )
        self.assertIs(
            tls.CipherSuite["CHACHA20_POLY1305_SHA256"],
            tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        )

        # Only the new names are reported.
        self.assertEqual(
            tls.CipherSuite.AES_128_GCM_SHA256.name, "TLS_AES_128_GCM_SHA256"
        )
        self.assertEqual(
            [suite.name for suite in tls.CipherSuite],
            [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
            ],
        )

    def test_pull_block_incomplete_read(self) -> None:
        """
        If a block is not read until its end, an alert should be raised.
        """
        buf = Buffer(data=bytes([2, 0, 0]))
        with self.assertRaisesMessage(
            tls.AlertDecodeError, "extra bytes at the end of a block"
        ):
            with pull_block(buf, 1):
                buf.pull_bytes(1)

    def test_pull_certificate_request_with_unknown_extension(self) -> None:
        certificate_request = CertificateRequest(
            request_context=b"context",
            signature_algorithms=[tls.SignatureAlgorithm.RSA_PSS_RSAE_SHA256],
            other_extensions=[(0xFAFA, b"grease")],
        )
        buf = Buffer(capacity=1024)
        push_certificate_request(buf, certificate_request)

        self.assertEqual(
            pull_certificate_request(Buffer(data=buf.data)), certificate_request
        )

    def test_pull_client_hello_with_psk_and_other_extension(self) -> None:
        buf = Buffer(capacity=1000)

        # Prepare PSK.
        psk_buf = Buffer(capacity=100)
        tls.push_offered_psks(
            psk_buf,
            tls.OfferedPsks(
                identities=[],
                binders=[],
            ),
        )

        # Write a ClientHello with an extension *after* PSK.
        hello = ClientHello(
            random=bytes(32),
            legacy_session_id=b"",
            cipher_suites=[tls.CipherSuite.TLS_AES_128_GCM_SHA256],
            legacy_compression_methods=[tls.CompressionMethod.NULL],
            key_share=[],
            psk_key_exchange_modes=[tls.PskKeyExchangeMode.PSK_DHE_KE],
            signature_algorithms=[],
            supported_groups=[],
            supported_versions=[tls.TLS_VERSION_1_3],
            other_extensions=[
                (
                    tls.ExtensionType.PRE_SHARED_KEY,
                    psk_buf.data,
                ),
                (
                    tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                    CLIENT_QUIC_TRANSPORT_PARAMETERS,
                ),
            ],
        )
        push_client_hello(buf, hello)

        # Try reading it back.
        buf.seek(0)
        with self.assertRaisesMessage(
            tls.AlertIllegalParameter,
            "ClientHello has a pre_shared_key which is not the last extension",
        ):
            pull_client_hello(buf)

    def test_pull_client_hello_with_unexpected_version(self) -> None:
        buf = Buffer(capacity=1024)
        push_client_hello(
            buf,
            ClientHello(
                random=bytes(32),
                legacy_session_id=b"",
                cipher_suites=[tls.CipherSuite.TLS_AES_128_GCM_SHA256],
                legacy_compression_methods=[tls.CompressionMethod.NULL],
                key_share=[],
                signature_algorithms=[],
                supported_groups=[],
                supported_versions=[tls.TLS_VERSION_1_3],
            ),
        )

        with self.assertRaisesMessage(
            tls.AlertProtocolVersion, "ClientHello version is not 1.2"
        ):
            pull_client_hello(Buffer(data=corrupt_hello_version(buf.data)))

    def test_pull_server_hello_with_unexpected_version(self) -> None:
        buf = Buffer(capacity=1024)
        push_server_hello(
            buf,
            ServerHello(
                random=bytes(32),
                legacy_session_id=b"",
                cipher_suite=tls.CipherSuite.TLS_AES_128_GCM_SHA256,
                compression_method=tls.CompressionMethod.NULL,
                supported_version=tls.TLS_VERSION_1_3,
            ),
        )

        with self.assertRaisesMessage(
            tls.AlertProtocolVersion, "ServerHello version is not 1.2"
        ):
            pull_server_hello(Buffer(data=corrupt_hello_version(buf.data)))

    def test_pull_new_session_ticket_with_unknown_extension(self) -> None:
        new_session_ticket = NewSessionTicket(
            ticket_lifetime=86400,
            ticket_age_add=0x12345678,
            ticket_nonce=b"nonce",
            ticket=b"ticket",
            max_early_data_size=0xFFFFFFFF,
            other_extensions=[(0xFAFA, b"grease")],
        )
        buf = Buffer(capacity=1024)
        push_new_session_ticket(buf, new_session_ticket)

        self.assertEqual(
            pull_new_session_ticket(Buffer(data=buf.data)), new_session_ticket
        )

    def test_pull_encrypted_extensions_with_invalid_alpn(self) -> None:
        for desc, data in [
            ("empty", "080000080006001000020000"),
            ("two protocols", "0800000e000c001000080006026833026871"),
        ]:
            with self.subTest(desc):
                buf = Buffer(data=bytes.fromhex(data))
                with self.assertRaisesMessage(
                    tls.AlertDecodeError,
                    "ALPN extension must contain exactly one protocol",
                ):
                    pull_encrypted_extensions(buf)

    def test_pull_extension_with_trailing_data(self) -> None:
        """
        An extension with data left over after its structure requires a
        decode_error (RFC 9846 section 4.3).
        """
        # The leftover data could be read as an empty GREASE extension.
        trailing_data = b"\xfa\xfa\x00\x00"

        def assertTrailingData(pull: Callable[[Buffer], Any], buf: Buffer) -> None:
            with self.assertRaisesMessage(
                tls.AlertDecodeError, "extra bytes at the end of a block"
            ):
                pull(Buffer(data=buf.data))

        with self.subTest("CertificateRequest"):
            # push_certificate_request() always writes signature_algorithms, so
            # write a single one by hand, with an empty list and the leftover data.
            buf = Buffer(capacity=1024)
            buf.push_bytes(bytes.fromhex("0d00000d00000a000d00060000") + trailing_data)
            assertTrailingData(pull_certificate_request, buf)

        with self.subTest("ClientHello"):
            buf = Buffer(capacity=1024)
            push_client_hello(
                buf,
                ClientHello(
                    random=bytes(32),
                    legacy_session_id=b"",
                    cipher_suites=[tls.CipherSuite.TLS_AES_128_GCM_SHA256],
                    legacy_compression_methods=[tls.CompressionMethod.NULL],
                    key_share=[],
                    signature_algorithms=[],
                    supported_groups=[],
                    supported_versions=[tls.TLS_VERSION_1_3],
                    other_extensions=[(tls.ExtensionType.EARLY_DATA, trailing_data)],
                ),
            )
            assertTrailingData(pull_client_hello, buf)

        with self.subTest("EncryptedExtensions"):
            buf = Buffer(capacity=1024)
            push_encrypted_extensions(
                buf,
                EncryptedExtensions(
                    other_extensions=[(tls.ExtensionType.EARLY_DATA, trailing_data)]
                ),
            )
            assertTrailingData(pull_encrypted_extensions, buf)

        with self.subTest("NewSessionTicket"):
            buf = Buffer(capacity=1024)
            push_new_session_ticket(
                buf,
                NewSessionTicket(
                    ticket=b"ticket",
                    other_extensions=[
                        (
                            tls.ExtensionType.EARLY_DATA,
                            b"\xff\xff\xff\xff" + trailing_data,
                        )
                    ],
                ),
            )
            assertTrailingData(pull_new_session_ticket, buf)

        with self.subTest("ServerHello"):
            buf = Buffer(capacity=1024)
            push_server_hello(
                buf,
                ServerHello(
                    random=bytes(32),
                    legacy_session_id=b"",
                    cipher_suite=tls.CipherSuite.TLS_AES_128_GCM_SHA256,
                    compression_method=tls.CompressionMethod.NULL,
                    other_extensions=[
                        (
                            tls.ExtensionType.SUPPORTED_VERSIONS,
                            b"\x03\x04" + trailing_data,
                        )
                    ],
                ),
            )
            assertTrailingData(pull_server_hello, buf)

    def test_pull_extensions_repeated(self) -> None:
        """
        An extension type must not appear twice (RFC 9846 section 4.3).
        """
        # Two empty GREASE extensions of the same type.
        buf = Buffer(data=bytes.fromhex("0008fafa0000fafa0000"))
        with self.assertRaisesMessage(
            tls.AlertIllegalParameter, "Extension 0xfafa is repeated"
        ):
            tls.pull_extensions(buf, lambda extension_type, extension_length: None)

    def test_pull_server_name(self) -> None:
        buf = Buffer(data=b"\x00\x12\x00\x00\x0fwww.example.com")
        self.assertEqual(pull_server_name(buf), "www.example.com")

    def test_pull_server_name_with_bad_name_type(self) -> None:
        buf = Buffer(data=b"\x00\x12\xff\x00\x0fwww.example.com")
        with self.assertRaisesMessage(
            tls.AlertIllegalParameter, "ServerName has an unknown name type 255"
        ):
            pull_server_name(buf)

    def test_pull_server_name_with_non_ascii_name(self) -> None:
        buf = Buffer(data=b"\x00\x12\x00\x00\x0fwww.exampl\xe9.com")
        with self.assertRaisesMessage(tls.AlertDecodeError, "ServerName is not ASCII"):
            pull_server_name(buf)

    def test_push_server_name(self) -> None:
        buf = Buffer(128)
        push_server_name(buf, "www.example.com")
        self.assertEqual(buf.data, b"\x00\x12\x00\x00\x0fwww.example.com")


class VerifyCertificateTest(TestCase):
    def assertVerifyFails(
        self,
        certificate: x509.Certificate,
        expected_exception: tls.Alert,
        **kwargs: Any,
    ) -> None:
        with self.assertRaisesMessage(
            expected_exception.__class__, str(expected_exception)
        ):
            self._verify(certificate, **kwargs)

    def _verify(
        self,
        certificate: x509.Certificate,
        *,
        now: datetime.datetime | None = None,
        server_name: str | None = None,
        trusted: x509.Certificate | None = None,
    ) -> None:
        """
        Verify `certificate` at `now`, by default the start of its validity
        period, trusting `trusted`, by default the certificate itself.
        """
        if now is None:
            now = certificate.not_valid_before_utc
        if trusted is None:
            trusted = certificate
        with patch("aioquic.tls.utcnow", return_value=now):
            verify_certificate(
                cadata=trusted.public_bytes(serialization.Encoding.PEM),
                certificate=certificate,
                server_name=server_name,
            )

    def test_verify_certificate_chain(self) -> None:
        with open(SERVER_CERTFILE, "rb") as fp:
            certificate = load_pem_x509_certificates(fp.read())[0]

        with patch("aioquic.tls.utcnow") as mock_utcnow:
            mock_utcnow.return_value = certificate.not_valid_before_utc

            # fail
            with self.assertRaisesMessage(
                tls.AlertBadCertificate, "unable to get local issuer certificate"
            ):
                verify_certificate(certificate=certificate, server_name="localhost")

            # ok
            verify_certificate(
                cafile=SERVER_CACERTFILE,
                certificate=certificate,
                server_name="localhost",
            )

    def test_verify_certificate_chain_malformed(self) -> None:
        certificate, _ = generate_ec_certificate(common_name="example.com")

        # Make the subject's UTF8String invalid, which cryptography accepts
        # but OpenSSL does not.
        malformed = x509.load_der_x509_certificate(
            certificate.public_bytes(serialization.Encoding.DER).replace(
                b"\x0c\x0bexample.com", b"\x0c\x0b\xffxample.com"
            )
        )

        self.assertVerifyFails(
            malformed,
            tls.AlertBadCertificate("Certificate could not be parsed"),
            trusted=certificate,
        )

    def test_verify_certificate_chain_self_signed(self) -> None:
        certificate, _ = generate_ec_certificate(
            alternative_names=["localhost"], common_name="localhost"
        )

        with patch("aioquic.tls.utcnow") as mock_utcnow:
            mock_utcnow.return_value = certificate.not_valid_before_utc

            # fail
            with self.assertRaises(tls.AlertBadCertificate) as cm:
                verify_certificate(certificate=certificate, server_name="localhost")
            self.assertIn(
                str(cm.exception),
                (
                    "self signed certificate",
                    "self-signed certificate",
                ),
            )

            # ok
            verify_certificate(
                cadata=certificate.public_bytes(serialization.Encoding.PEM),
                certificate=certificate,
                server_name="localhost",
            )

    def test_verify_dates(self) -> None:
        certificate, _ = generate_ec_certificate(
            alternative_names=["example.com"], common_name="example.com"
        )
        second = datetime.timedelta(seconds=1)

        # Too early.
        self.assertVerifyFails(
            certificate,
            tls.AlertCertificateExpired("Certificate is not valid yet"),
            now=certificate.not_valid_before_utc - second,
            server_name="example.com",
        )

        # Valid.
        self._verify(certificate, server_name="example.com")
        self._verify(
            certificate, now=certificate.not_valid_after_utc, server_name="example.com"
        )

        # Too late.
        self.assertVerifyFails(
            certificate,
            tls.AlertCertificateExpired("Certificate is no longer valid"),
            now=certificate.not_valid_after_utc + second,
            server_name="example.com",
        )

    def test_verify_subject_no_subjaltname(self) -> None:
        certificate, _ = generate_ec_certificate(common_name="example.com")

        self.assertVerifyFails(
            certificate,
            tls.AlertBadCertificate(
                "Certificate does not contain any `subjectAltName`s."
            ),
            server_name="example.com",
        )

    def test_verify_subject_with_duplicate_extension(self) -> None:
        certificate, _ = generate_ec_certificate(
            alternative_names=["example.com"],
            common_name="example.com",
            extensions=[
                x509.UnrecognizedExtension(x509.ObjectIdentifier("2.5.29.99"), b"")
            ],
        )

        # Turn the unrecognized extension into a second subjectAltName, which is
        # only rejected once the extensions are accessed.
        duplicate = x509.load_der_x509_certificate(
            certificate.public_bytes(serialization.Encoding.DER).replace(
                bytes.fromhex("0603551d63"), bytes.fromhex("0603551d11")
            )
        )

        self.assertVerifyFails(
            duplicate,
            tls.AlertBadCertificate("Certificate extensions could not be parsed"),
            server_name="example.com",
            trusted=certificate,
        )

    def test_verify_subject_with_invalid_dns_pattern(self) -> None:
        # The subjectAltName has a dNSName containing a NUL byte.
        certificate, _ = generate_ec_certificate(
            common_name="example.com",
            extensions=[
                x509.UnrecognizedExtension(
                    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    bytes.fromhex("30058203610062"),
                )
            ],
        )

        self.assertVerifyFails(
            certificate,
            tls.AlertBadCertificate("Invalid DNS pattern b'a\\x00b'."),
            server_name="example.com",
        )

    def test_verify_subject_with_malformed_extension(self) -> None:
        # The certificate is only rejected once its extensions are accessed.
        for desc, value in [
            ("invalid DER", "ffff"),
            # cryptography does not support x400Address.
            ("x400Address", "3002a300"),
            # A directoryName whose commonName is a BIT STRING.
            ("directoryName", "3010a40e300c310a30080603550403030100"),
        ]:
            with self.subTest(desc):
                certificate, _ = generate_ec_certificate(
                    common_name="example.com",
                    extensions=[
                        x509.UnrecognizedExtension(
                            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                            bytes.fromhex(value),
                        )
                    ],
                )

                self.assertVerifyFails(
                    certificate,
                    tls.AlertBadCertificate(
                        "Certificate extensions could not be parsed"
                    ),
                    server_name="example.com",
                )

    def test_verify_subject_with_subjaltname(self) -> None:
        certificate, _ = generate_ec_certificate(
            alternative_names=["*.example.com", "example.com"],
            common_name="example.com",
        )

        # Valid.
        self._verify(certificate, server_name="example.com")
        self._verify(certificate, server_name="test.example.com")

        # Invalid.
        self.assertVerifyFails(
            certificate,
            tls.AlertBadCertificate(
                "hostname 'acme.com' doesn't match either of "
                "DNSPattern(pattern=b'*.example.com'), "
                "DNSPattern(pattern=b'example.com')"
            ),
            server_name="acme.com",
        )

    def test_verify_subject_with_subjaltname_ipaddress(self) -> None:
        certificate, _ = generate_ec_certificate(
            alternative_names=["1.2.3.4"],
            common_name="1.2.3.4",
        )

        # Valid.
        self._verify(certificate, server_name="1.2.3.4")

        # Invalid.
        self.assertVerifyFails(
            certificate,
            tls.AlertBadCertificate(
                "hostname '8.8.8.8' doesn't match "
                "IPAddressPattern(pattern=IPv4Address('1.2.3.4'))"
            ),
            server_name="8.8.8.8",
        )

    def test_pull_greased_alpn_list(self) -> None:
        """Test pulling a list alpns with an ASCII item, an undecodable binary value
        such as greasing might give us, a valid UTF-8 encoding, and another ASCII item.
        We should only return the ASCII values.

        We currently only accept ASCII ALPNs, even though technically ALPNs are
        arbitrary bytes values, as our API is a list of strings.
        """

        # the buffer is equivalent to "H2", b'\xff\xff', "é" in UTF-8, "H3"
        buf = Buffer(data=bytes.fromhex("000c02483202ffff02c3a9024833"))

        self.assertEqual(
            tls.pull_list(buf, 2, partial(tls.pull_alpn_protocol, buf)), ["H2", "H3"]
        )
