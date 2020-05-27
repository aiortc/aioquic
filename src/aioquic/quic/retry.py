import ipaddress
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .connection import NetworkAddress


def encode_address(addr: NetworkAddress) -> bytes:
    return ipaddress.ip_address(addr[0]).packed + bytes([addr[1] >> 8, addr[1] & 0xFF])


class QuicRetryTokenHandler:
    def __init__(self) -> None:
        self._key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024, backend=default_backend()
        )

    def create_token(
        self,
        addr: NetworkAddress,
        original_destination_connection_id: bytes,
        retry_source_connection_id: bytes,
    ) -> bytes:
        retry_message = (
            encode_address(addr)
            + b"|"
            + original_destination_connection_id
            + b"|"
            + retry_source_connection_id
        )
        return self._key.public_key().encrypt(
            retry_message,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )

    def validate_token(self, addr: NetworkAddress, token: bytes) -> Tuple[bytes, bytes]:
        retry_message = self._key.decrypt(
            token,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        (
            encoded_addr,
            original_destination_connection_id,
            retry_source_connection_id,
        ) = retry_message.split(b"|", maxsplit=2)
        if encoded_addr != encode_address(addr):
            raise ValueError("Remote address does not match.")
        return original_destination_connection_id, retry_source_connection_id
