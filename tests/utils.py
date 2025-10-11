import asyncio
import datetime
import functools
import ipaddress
import logging
import os
from typing import Callable, Coroutine, Optional, ParamSpec, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)

K = TypeVar(
    "K",
    ec.EllipticCurvePrivateKey,
    ed448.Ed448PrivateKey,
    ed25519.Ed25519PrivateKey,
    rsa.RSAPrivateKey,
)
P = ParamSpec("P")


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
    is_authority: bool = False,
    issuer_common_name: Optional[str] = None,
    issuer_key: Optional[CertificateIssuerPrivateKeyTypes] = None,
    key: K,
) -> tuple[x509.Certificate, K]:
    assert (issuer_common_name is None) == (issuer_key is None), (
        "isser_common_name and issuer_key must either both be None, or both be not None"
    )

    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])

    if issuer_common_name is not None:
        issuer = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_common_name)]
        )
    else:
        issuer = subject
        issuer_key = key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        )
    )
    if is_authority:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=False
        )
    if alternative_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [dns_name_or_ip_address(name) for name in alternative_names]
            ),
            critical=False,
        )
    cert = builder.sign(issuer_key, hash_algorithm)
    return cert, key


def generate_default_certificates() -> None:
    ca_common_name = "Some CA"

    ca_cert, ca_key = generate_rsa_certificate(
        common_name=ca_common_name,
        is_authority=True,
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    server_cert, server_key = generate_rsa_certificate(
        alternative_names=["localhost"],
        common_name="localhost",
        issuer_common_name=ca_common_name,
        issuer_key=ca_key,
    )
    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    server_key_pem = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    with open(SERVER_CACERTFILE, "wb") as fp:
        fp.write(ca_cert_pem)

    with open(SERVER_CERTFILE, "wb") as fp:
        fp.write(server_cert_pem)

    with open(SERVER_CERTFILE_WITH_CHAIN, "wb") as fp:
        fp.write(server_cert_pem + ca_cert_pem)

    with open(SERVER_KEYFILE, "wb") as fp:
        fp.write(server_key_pem)

    with open(SERVER_COMBINEDFILE, "wb") as fp:
        fp.write(server_cert_pem + server_key_pem)


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
    common_name: str,
    alternative_names: list[str] = [],
    is_authority: bool = False,
    issuer_common_name: Optional[str] = None,
    issuer_key: Optional[CertificateIssuerPrivateKeyTypes] = None,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=hashes.SHA256(),
        is_authority=is_authority,
        issuer_common_name=issuer_common_name,
        issuer_key=issuer_key,
        key=key,
    )


def load(name: str) -> bytes:
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, "rb") as fp:
        return fp.read()


# Generate default certificate files.
_SSL_DIRECTORY = os.path.join(os.path.dirname(__file__), "ssl")
os.makedirs(_SSL_DIRECTORY, exist_ok=True)
SERVER_CACERTFILE = os.path.join(_SSL_DIRECTORY, "cacert.pem")
SERVER_CERTFILE = os.path.join(_SSL_DIRECTORY, "ssl_cert.pem")
SERVER_CERTFILE_WITH_CHAIN = os.path.join(_SSL_DIRECTORY, "ssl_cert_with_chain.pem")
SERVER_KEYFILE = os.path.join(_SSL_DIRECTORY, "ssl_key.pem")
SERVER_COMBINEDFILE = os.path.join(_SSL_DIRECTORY, "ssl_combined.pem")

generate_default_certificates()

SKIP_TESTS = frozenset(os.environ.get("AIOQUIC_SKIP_TESTS", "").split(","))

if os.environ.get("AIOQUIC_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
