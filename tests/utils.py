import asyncio
import datetime
import functools
import ipaddress
import logging
import os
import tempfile
from typing import Callable, Coroutine, ParamSpec, TypeVar

from aioquic import tls
from aioquic.quic.packet import QuicPacketType
from aioquic.quic.packet_builder import QuicSentPacket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

K = TypeVar(
    "K",
    ec.EllipticCurvePrivateKey,
    ed448.Ed448PrivateKey,
    ed25519.Ed25519PrivateKey,
    rsa.RSAPrivateKey,
)
P = ParamSpec("P")


def ack_eliciting_packet(
    *,
    epoch: tls.Epoch = tls.Epoch.ONE_RTT,
    packet_number: int = 0,
    packet_type: QuicPacketType = QuicPacketType.ONE_RTT,
    sent_time: float,
) -> QuicSentPacket:
    """
    Return a sent packet which counts towards bytes in flight and elicits an
    acknowledgment.

    It defaults to 1-RTT, as congestion controllers ignore the packet number
    space. Its packet number defaults to 0 and its size is 1280 bytes.
    """
    return QuicSentPacket(
        epoch=epoch,
        in_flight=True,
        is_ack_eliciting=True,
        is_crypto_packet=False,
        packet_number=packet_number,
        packet_type=packet_type,
        sent_bytes=1280,
        sent_time=sent_time,
    )


def asynctest(
    coro: Callable[P, Coroutine[None, None, None]],
) -> Callable[P, None]:
    @functools.wraps(coro)
    def wrap(*args, **kwargs):
        asyncio.run(coro(*args, **kwargs))

    return wrap


def dns_name_or_ip_address(name: str) -> x509.GeneralName:
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return x509.DNSName(name)
    else:
        return x509.IPAddress(ip)


def generate_certificate(
    *,
    alternative_names: list[str],
    common_name: str,
    hash_algorithm,
    key: K,
) -> tuple[x509.Certificate, K]:
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    )

    # The certificate's start date is truncated to the second, and OpenSSL checks
    # it against a coarse clock which can lag behind by a few milliseconds, so a
    # certificate starting now may not be valid yet. Start it a second earlier.
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=1))
        .not_valid_after(now + datetime.timedelta(days=10))
    )
    if alternative_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [dns_name_or_ip_address(name) for name in alternative_names]
            ),
            critical=False,
        )
    cert = builder.sign(key, hash_algorithm)
    return cert, key


def generate_default_certificates() -> None:
    """
    Write the CA and server certificates used by default in tests.

    The server certificate mirrors the structure of the CPython test certificate
    these files used to contain, as handshake tests assert exact datagram sizes,
    and some of them rely on the server's first flight hitting the
    anti-amplification limit. This is why it uses 3072-bit RSA keys, fixed serial
    numbers and the same names and extensions.
    """
    # The certificates start a second earlier, see generate_certificate().
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "XY"),
            x509.NameAttribute(
                x509.NameOID.ORGANIZATION_NAME, "Python Software Foundation CA"
            ),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "our-ca-server"),
        ]
    )
    ca_serial_number = 0xCB2D80995A69525B
    ca_key_identifier = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(ca_serial_number)
        .not_valid_before(now - datetime.timedelta(seconds=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(ca_key_identifier, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_key_identifier
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "XY"),
                    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Castle Anthrax"),
                    x509.NameAttribute(
                        x509.NameOID.ORGANIZATION_NAME, "Python Software Foundation"
                    ),
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost"),
                ]
            )
        )
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(0xCB2D80995A69525C)
        .not_valid_before(now - datetime.timedelta(seconds=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=ca_key_identifier.digest,
                authority_cert_issuer=[x509.DirectoryName(ca_name)],
                authority_cert_serial_number=ca_serial_number,
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(
                            "http://testca.pythontest.net/testca/pycacert.cer"
                        ),
                    ),
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(
                            "http://testca.pythontest.net/testca/ocsp/"
                        ),
                    ),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "http://testca.pythontest.net/testca/revocation.crl"
                            )
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    server_key_pem = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    for path, data in [
        (SERVER_CACERTFILE, ca_cert_pem),
        (SERVER_CERTFILE, server_cert_pem),
        (SERVER_CERTFILE_WITH_CHAIN, server_cert_pem + ca_cert_pem),
        (SERVER_KEYFILE, server_key_pem),
        (SERVER_COMBINEDFILE, server_cert_pem + server_key_pem),
    ]:
        with open(path, "wb") as fp:
            fp.write(data)


def generate_ec_certificate(
    common_name: str, alternative_names: list[str] = [], curve=ec.SECP256R1
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(curve=curve())
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=hashes.SHA256(),
        key=key,
    )


def generate_ed25519_certificate(
    common_name: str, alternative_names: list[str] = []
) -> tuple[x509.Certificate, ed25519.Ed25519PrivateKey]:
    key = ed25519.Ed25519PrivateKey.generate()
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=None,
        key=key,
    )


def generate_ed448_certificate(
    common_name: str, alternative_names: list[str] = []
) -> tuple[x509.Certificate, ed448.Ed448PrivateKey]:
    key = ed448.Ed448PrivateKey.generate()
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=None,
        key=key,
    )


def generate_rsa_certificate(
    common_name: str, alternative_names: list[str] = []
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=hashes.SHA256(),
        key=key,
    )


def load(name: str) -> bytes:
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, "rb") as fp:
        return fp.read()


# Generate the default certificates in a temporary directory, which is removed
# when the interpreter exits.
_CERTIFICATE_DIRECTORY = tempfile.TemporaryDirectory()
SERVER_CACERTFILE = os.path.join(_CERTIFICATE_DIRECTORY.name, "pycacert.pem")
SERVER_CERTFILE = os.path.join(_CERTIFICATE_DIRECTORY.name, "ssl_cert.pem")
SERVER_CERTFILE_WITH_CHAIN = os.path.join(
    _CERTIFICATE_DIRECTORY.name, "ssl_cert_with_chain.pem"
)
SERVER_KEYFILE = os.path.join(_CERTIFICATE_DIRECTORY.name, "ssl_key.pem")
SERVER_COMBINEDFILE = os.path.join(_CERTIFICATE_DIRECTORY.name, "ssl_combined.pem")
generate_default_certificates()

SKIP_TESTS = frozenset(os.environ.get("AIOQUIC_SKIP_TESTS", "").split(","))

if os.environ.get("AIOQUIC_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
