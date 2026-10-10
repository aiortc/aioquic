from typing import Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    aead,
    algorithms,
    modes,
)

AEAD_NONCE_LENGTH = 12
AEAD_TAG_LENGTH = 16

CHACHA20_ZEROS = bytes(5)
PACKET_NUMBER_LENGTH_MAX = 4
SAMPLE_LENGTH = 16


class CryptoError(ValueError):
    pass


class AEAD:
    _aead: Union[aead.AESGCM, aead.ChaCha20Poly1305]

    def __init__(self, cipher_name: bytes, key: bytes, iv: bytes) -> None:
        assert cipher_name in (b"aes-128-gcm", b"aes-256-gcm", b"chacha20-poly1305")
        assert len(iv) == AEAD_NONCE_LENGTH

        if cipher_name == b"chacha20-poly1305":
            self._aead = aead.ChaCha20Poly1305(key)
        else:
            self._aead = aead.AESGCM(key)
        self._iv = int.from_bytes(iv, "big")

    def decrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        try:
            return self._aead.decrypt(
                self._nonce(packet_number),
                data,
                associated_data,
            )
        except InvalidTag as exc:
            raise CryptoError(str(exc))

    def encrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        return self._aead.encrypt(
            self._nonce(packet_number),
            data,
            associated_data,
        )

    def _nonce(self, packet_number: int) -> bytes:
        return (self._iv ^ packet_number).to_bytes(AEAD_NONCE_LENGTH, "big")


class HeaderProtection:
    _encryptor: CipherContext

    def __init__(self, cipher_name: bytes, key: bytes) -> None:
        assert cipher_name in (b"aes-128-ecb", b"aes-256-ecb", b"chacha20")

        self._is_chacha20 = cipher_name == b"chacha20"
        if self._is_chacha20:
            # The nonce is replaced by the sample for every packet.
            self._encryptor = Cipher(
                algorithm=algorithms.ChaCha20(key, bytes(SAMPLE_LENGTH)),
                mode=None,
            ).encryptor()
        else:
            self._encryptor = Cipher(
                algorithm=algorithms.AES(key),
                mode=modes.ECB(),
            ).encryptor()

    def apply(self, plain_header: bytes, protected_payload: bytes) -> bytes:
        pn_length = (plain_header[0] & 0x03) + 1
        pn_offset = len(plain_header) - pn_length

        sample_offset = PACKET_NUMBER_LENGTH_MAX - pn_length
        mask = self._mask(
            protected_payload[sample_offset : sample_offset + SAMPLE_LENGTH]
        )

        buffer = bytearray(plain_header + protected_payload)
        if buffer[0] & 0x80:
            buffer[0] ^= mask[0] & 0x0F
        else:
            buffer[0] ^= mask[0] & 0x1F

        for i in range(pn_length):
            buffer[pn_offset + i] ^= mask[1 + i]

        return bytes(buffer)

    def remove(self, packet: bytes, pn_offset: int) -> tuple[bytes, int]:
        sample_offset = pn_offset + PACKET_NUMBER_LENGTH_MAX
        if sample_offset + SAMPLE_LENGTH > len(packet):
            raise CryptoError("Packet is too short to sample")
        mask = self._mask(packet[sample_offset : sample_offset + SAMPLE_LENGTH])

        buffer = bytearray(packet)
        if buffer[0] & 0x80:
            buffer[0] ^= mask[0] & 0x0F
        else:
            buffer[0] ^= mask[0] & 0x1F

        pn_length = (buffer[0] & 0x03) + 1
        pn_truncated = 0
        for i in range(pn_length):
            buffer[pn_offset + i] ^= mask[1 + i]
            pn_truncated = buffer[pn_offset + i] | (pn_truncated << 8)

        return bytes(buffer[: pn_offset + pn_length]), pn_truncated

    def _mask(self, sample: bytes) -> bytes:
        if self._is_chacha20:
            self._encryptor.reset_nonce(sample)
            return self._encryptor.update(CHACHA20_ZEROS)
        else:
            return self._encryptor.update(sample)
