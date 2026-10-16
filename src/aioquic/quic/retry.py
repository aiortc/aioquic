import ipaddress
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..buffer import Buffer
from ..tls import pull_opaque, push_opaque
from .connection import NetworkAddress

NONCE_LENGTH = 12

# Clients return retry tokens immediately, so only accept them for a short
# time (RFC 9000 section 8.1.4).
TOKEN_LIFETIME = 30.0


def encode_address(addr: NetworkAddress) -> bytes:
    return ipaddress.ip_address(addr[0]).packed + bytes([addr[1] >> 8, addr[1] & 0xFF])


class QuicRetryTokenHandler:
    def __init__(self) -> None:
        self._aead = AESGCM(AESGCM.generate_key(bit_length=128))

    def create_token(
        self,
        *,
        address: NetworkAddress,
        original_destination_connection_id: bytes,
        retry_source_connection_id: bytes,
        now: float,
    ) -> bytes:
        buf = Buffer(capacity=512)
        push_opaque(buf, 1, encode_address(address))
        push_opaque(buf, 1, original_destination_connection_id)
        push_opaque(buf, 1, retry_source_connection_id)
        buf.push_uint64(int(now * 1000))
        nonce = os.urandom(NONCE_LENGTH)
        return nonce + self._aead.encrypt(nonce, buf.data, None)

    def validate_token(
        self,
        *,
        address: NetworkAddress,
        destination_cid: bytes,
        token: bytes,
        now: float,
    ) -> bytes:
        if len(token) < NONCE_LENGTH:
            raise ValueError("Token is invalid.")
        try:
            plaintext = self._aead.decrypt(
                token[:NONCE_LENGTH], token[NONCE_LENGTH:], None
            )
        except InvalidTag as exc:
            raise ValueError("Token is invalid.") from exc
        buf = Buffer(data=plaintext)
        encoded_addr = pull_opaque(buf, 1)
        original_destination_connection_id = pull_opaque(buf, 1)
        retry_source_connection_id = pull_opaque(buf, 1)
        issued_at = buf.pull_uint64() / 1000
        if encoded_addr != encode_address(address):
            raise ValueError("Remote address does not match.")
        # Clients MUST send to the Retry packet's Source Connection ID, so the
        # token is only valid for that connection ID (RFC 9000 section 17.2.5.2).
        if destination_cid != retry_source_connection_id:
            raise ValueError("Destination connection ID does not match.")
        if now - issued_at > TOKEN_LIFETIME:
            raise ValueError("Token has expired.")
        return original_destination_connection_id
