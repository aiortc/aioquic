import asyncio
import datetime
import functools
import ipaddress
import logging
import os
from typing import Callable, Coroutine, ParamSpec, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

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
    key: K,
) -> tuple[x509.Certificate, K]:
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    )

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
    if alternative_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [dns_name_or_ip_address(name) for name in alternative_names]
            ),
            critical=False,
        )
    cert = builder.sign(key, hash_algorithm)
    return cert, key


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


SERVER_CACERTFILE = os.path.join(os.path.dirname(__file__), "pycacert.pem")
SERVER_CERTFILE = os.path.join(os.path.dirname(__file__), "ssl_cert.pem")
SERVER_CERTFILE_WITH_CHAIN = os.path.join(
    os.path.dirname(__file__), "ssl_cert_with_chain.pem"
)
SERVER_KEYFILE = os.path.join(os.path.dirname(__file__), "ssl_key.pem")
SERVER_COMBINEDFILE = os.path.join(os.path.dirname(__file__), "ssl_combined.pem")
SKIP_TESTS = frozenset(os.environ.get("AIOQUIC_SKIP_TESTS", "").split(","))

if os.environ.get("AIOQUIC_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
