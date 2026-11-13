import os
import tempfile

from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .utils import TestCase, generate_ec_certificate, generate_rsa_certificate


def certificate_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def private_key_pem(
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
    format: serialization.PrivateFormat = serialization.PrivateFormat.PKCS8,
    password: bytes | None = None,
) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        format,
        serialization.NoEncryption()
        if password is None
        else serialization.BestAvailableEncryption(password),
    )


def public_key_pem(key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


class QuicConfigurationTest(TestCase):
    def assertLoaded(
        self,
        configuration: QuicConfiguration,
        certificate: x509.Certificate,
        key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
        chain: list[x509.Certificate] = [],
    ) -> None:
        self.assertEqual(configuration.certificate, certificate)
        self.assertEqual(configuration.certificate_chain, chain)
        self.assertEqual(public_key_pem(configuration.private_key), public_key_pem(key))

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.certificate, self.key = generate_ec_certificate(common_name="example.com")
        self.intermediate, _ = generate_ec_certificate(common_name="Intermediate")

    def test_load_cert_chain(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(certificate_pem(self.certificate)),
            self.write(private_key_pem(self.key)),
        )
        self.assertLoaded(configuration, self.certificate, self.key)

    def test_load_cert_chain_with_blank_line_after_certificates(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(
                certificate_pem(self.certificate)
                + certificate_pem(self.intermediate)
                + b"\n"
            ),
            self.write(private_key_pem(self.key)),
        )
        self.assertLoaded(
            configuration, self.certificate, self.key, chain=[self.intermediate]
        )

    def test_load_cert_chain_with_chain(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(
                certificate_pem(self.certificate) + certificate_pem(self.intermediate)
            ),
            self.write(private_key_pem(self.key)),
        )
        self.assertLoaded(
            configuration, self.certificate, self.key, chain=[self.intermediate]
        )

    def test_load_cert_chain_with_crlf_line_endings(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(
                (
                    private_key_pem(self.key)
                    + certificate_pem(self.certificate)
                    + certificate_pem(self.intermediate)
                ).replace(b"\n", b"\r\n")
            )
        )
        self.assertLoaded(
            configuration, self.certificate, self.key, chain=[self.intermediate]
        )

    def test_load_cert_chain_with_encrypted_key(self) -> None:
        keyfile = self.write(private_key_pem(self.key, password=b"secret"))
        passwords: list[bytes | str] = [b"secret", "secret"]
        for password in passwords:
            with self.subTest(password=password):
                configuration = QuicConfiguration()
                configuration.load_cert_chain(
                    self.write(certificate_pem(self.certificate)),
                    keyfile,
                    password=password,
                )
                self.assertLoaded(configuration, self.certificate, self.key)

    def test_load_cert_chain_with_encrypted_key_in_certfile(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(
                private_key_pem(self.key, password=b"secret")
                + certificate_pem(self.certificate)
            ),
            password="secret",
        )
        self.assertLoaded(configuration, self.certificate, self.key)

    def test_load_cert_chain_with_key_after_certificates(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(
                certificate_pem(self.certificate)
                + certificate_pem(self.intermediate)
                + private_key_pem(self.key)
            )
        )
        self.assertLoaded(
            configuration, self.certificate, self.key, chain=[self.intermediate]
        )

    def test_load_cert_chain_with_key_before_certificates(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(
                private_key_pem(self.key)
                + certificate_pem(self.certificate)
                + certificate_pem(self.intermediate)
            )
        )
        self.assertLoaded(
            configuration, self.certificate, self.key, chain=[self.intermediate]
        )

    def test_load_cert_chain_with_key_in_certfile_and_keyfile(self) -> None:
        # The key in certfile is ignored, so it need not be decrypted.
        other_key = ec.generate_private_key(ec.SECP256R1())
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(
                certificate_pem(self.certificate)
                + private_key_pem(other_key, password=b"secret")
            ),
            self.write(private_key_pem(self.key)),
        )
        self.assertLoaded(configuration, self.certificate, self.key)

    def test_load_cert_chain_with_key_in_traditional_format(self) -> None:
        rsa_certificate, rsa_key = generate_rsa_certificate(common_name="example.com")
        cases: list[
            tuple[
                x509.Certificate, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey, bytes
            ]
        ] = [
            (self.certificate, self.key, b"EC PRIVATE KEY"),
            (rsa_certificate, rsa_key, b"RSA PRIVATE KEY"),
        ]
        for certificate, key, label in cases:
            with self.subTest(label=label):
                key_pem = private_key_pem(
                    key, format=serialization.PrivateFormat.TraditionalOpenSSL
                )
                self.assertIn(b"-----BEGIN " + label + b"-----", key_pem)

                configuration = QuicConfiguration()
                configuration.load_cert_chain(
                    self.write(key_pem + certificate_pem(certificate))
                )
                self.assertLoaded(configuration, certificate, key)

    def test_load_cert_chain_with_mismatched_key(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(certificate_pem(self.certificate)),
            self.write(private_key_pem(self.key)),
        )

        # A failed load leaves the configuration unchanged.
        with self.assertRaisesMessage(
            ValueError, "Private key does not match the certificate"
        ):
            configuration.load_cert_chain(
                self.write(certificate_pem(self.intermediate)),
                self.write(private_key_pem(self.key)),
            )
        self.assertLoaded(configuration, self.certificate, self.key)

    def test_load_cert_chain_without_key(self) -> None:
        configuration = QuicConfiguration()
        configuration.load_cert_chain(
            self.write(certificate_pem(self.certificate)),
            self.write(private_key_pem(self.key)),
        )

        # A failed load leaves the configuration unchanged.
        with self.assertRaisesMessage(
            ValueError, "Certificate file does not contain a private key"
        ):
            configuration.load_cert_chain(
                self.write(certificate_pem(self.intermediate))
            )
        self.assertLoaded(configuration, self.certificate, self.key)

    def write(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(dir=self.directory.name, suffix=".pem")
        with os.fdopen(fd, "wb") as fp:
            fp.write(data)
        return path
