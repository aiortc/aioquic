import asyncio
import datetime
import logging
import os
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519


def generate_certificate(*, alternative_names, common_name, hash_algorithm, key):
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
    )
    if alternative_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in alternative_names]
            ),
            critical=False,
        )
    cert = builder.sign(key, hash_algorithm, default_backend())
    return cert, key


def generate_ec_certificate(common_name, alternative_names=[], curve=ec.SECP256R1):
    key = ec.generate_private_key(backend=default_backend(), curve=curve)
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=hashes.SHA256(),
        key=key,
    )


def generate_ed25519_certificate(common_name, alternative_names=[]):
    key = ed25519.Ed25519PrivateKey.generate()
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=None,
        key=key,
    )


def generate_ed448_certificate(common_name, alternative_names=[]):
    key = ed448.Ed448PrivateKey.generate()
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=None,
        key=key,
    )


def load(name):
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, "rb") as fp:
        return fp.read()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


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

if (
    sys.platform == "win32"
    and sys.version_info.major == 3
    and sys.version_info.minor == 8
):
    # Python 3.8 uses ProactorEventLoop by default,
    # which breaks UDP / IPv6 support, see:
    #
    # https://bugs.python.org/issue39148

    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
