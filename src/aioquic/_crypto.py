from typing import Tuple

from cryptography.hazmat.bindings.openssl.binding import Binding

AEAD_KEY_LENGTH_MAX = 32
AEAD_NONCE_LENGTH = 12
AEAD_TAG_LENGTH = 16

PACKET_LENGTH_MAX = 1500
SAMPLE_LENGTH = 16
PACKET_NUMBER_LENGTH_MAX = 4


class CryptoError(ValueError):
    pass


def _get_cipher_by_name(binding: Binding, cipher_name: bytes):  # -> EVP_CIPHER
    evp_cipher = binding.lib.EVP_get_cipherbyname(cipher_name)
    if evp_cipher == binding.ffi.NULL:
        raise CryptoError(f"Invalid cipher name: {cipher_name.decode()}")
    return evp_cipher


class AEAD:
    def __init__(self, cipher_name: bytes, key: bytes, iv: bytes) -> None:
        self._binding = Binding()

        # check and store key and iv
        self._key_len = len(key)
        if self._key_len > AEAD_KEY_LENGTH_MAX:
            raise CryptoError("Invalid key length")
        self._key = self._binding.ffi.from_buffer(key)
        if len(iv) != AEAD_NONCE_LENGTH:
            raise CryptoError("Invalid iv length")
        self._iv = self._binding.ffi.from_buffer(iv)

        # create cipher contexts
        evp_cipher = _get_cipher_by_name(self._binding, cipher_name)
        self._decrypt_ctx = self._create_ctx(evp_cipher, operation=0)
        self._encrypt_ctx = self._create_ctx(evp_cipher, operation=1)

        # allocate buffers
        self._nonce = self._binding.ffi.new("unsigned char[]", AEAD_NONCE_LENGTH)
        self._buffer = self._binding.ffi.new("unsigned char[]", PACKET_LENGTH_MAX)
        self._outlen = self._binding.ffi.new("int *")
        self._dummy_outlen = self._binding.ffi.new("int *")

    def _create_ctx(self, evp_cipher, operation: int):  # -> EVP_CIPHER_CTX *
        # create a cipher context with the given type and operation mode
        ctx = self._binding.lib.EVP_CIPHER_CTX_new()
        ctx = self._binding.ffi.gc(ctx, self._binding.lib.EVP_CIPHER_CTX_free)
        self._assert(
            self._binding.lib.EVP_CipherInit_ex(
                ctx,  # EVP_CIPHER_CTX *ctx
                evp_cipher,  # const EVP_CIPHER *type
                self._binding.ffi.NULL,  # ENGINE *impl
                self._binding.ffi.NULL,  # const unsigned char *key
                self._binding.ffi.NULL,  # const unsigned char *iv
                operation,  # int enc
            )
        )

        # specify key and initialization vector length
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_set_key_length(ctx, self._key_len)
        )
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_ctrl(
                ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.lib.EVP_CTRL_AEAD_SET_IVLEN,  # int cmd
                AEAD_NONCE_LENGTH,  # int ivlen
                self._binding.ffi.NULL,  # void *NULL
            )
        )
        return ctx

    def _assert(self, value) -> None:
        if not value:
            self._binding.lib.ERR_clear_error()
            raise CryptoError("OpenSSL call failed")

    def _init_nonce(self, packet_number: int) -> None:
        # reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.3

        # left-pad the reconstructed packet number (62 bits ~ 8 bytes) and XOR it with the IV
        self._binding.ffi.memmove(self._nonce, self._iv, AEAD_NONCE_LENGTH)
        for i in range(8):
            self._nonce[AEAD_NONCE_LENGTH - 1 - i] ^= (packet_number >> (8 * i)) & 0xFF

    def decrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        data_len = len(data)
        if data_len < AEAD_TAG_LENGTH or data_len > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")
        self._init_nonce(packet_number)

        # get the appended AEAD tag (data = cipher text + tag)
        data_buffer = self._binding.ffi.from_buffer(data)
        cipher_text_len = data_len - AEAD_TAG_LENGTH
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_ctrl(
                self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.lib.EVP_CTRL_AEAD_SET_TAG,  # int cmd
                AEAD_TAG_LENGTH,  # int taglen
                data_buffer + cipher_text_len,  # void *tag
            )
        )

        # set key and nonce
        self._assert(
            self._binding.lib.EVP_CipherInit_ex(
                self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.ffi.NULL,  # const EVP_CIPHER *type
                self._binding.ffi.NULL,  # ENGINE *impl
                self._key,  # const unsigned char *key
                self._nonce,  # const unsigned char *iv
                0,  # int enc
            )
        )

        # specify the header as additional authenticated data (AAD)
        self._assert(
            self._binding.lib.EVP_CipherUpdate(
                self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.ffi.NULL,  # unsigned char *out
                self._dummy_outlen,  # int *outl
                self._binding.ffi.from_buffer(
                    associated_data
                ),  # const unsigned char *in
                len(associated_data),  # int inl
            )
        )

        # decrypt the cipher text (i.e. received data excluding the appended tag)
        self._assert(
            self._binding.lib.EVP_CipherUpdate(
                self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._buffer,  # unsigned char *out
                self._outlen,  # int *outl
                data_buffer,  # const unsigned char *in
                cipher_text_len,  # int inl
            )
        )

        # finalize the operation
        self._assert(
            self._binding.lib.EVP_CipherFinal_ex(
                self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.ffi.NULL,  # unsigned char *outm
                self._dummy_outlen,  # int *outl
            )
        )

        # return the decrypted data
        return bytes(self._binding.ffi.buffer(self._buffer, self._outlen[0]))

    def encrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        data_len = len(data)
        if data_len > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")
        self._init_nonce(packet_number)

        # set key and nonce
        self._assert(
            self._binding.lib.EVP_CipherInit_ex(
                self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.ffi.NULL,  # const EVP_CIPHER *type
                self._binding.ffi.NULL,  # ENGINE *impl
                self._key,  # const unsigned char *key
                self._nonce,  # const unsigned char *iv
                1,  # int enc
            )
        )

        # specify the header as additional authenticated data (AAD)
        self._assert(
            self._binding.lib.EVP_CipherUpdate(
                self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.ffi.NULL,  # unsigned char *out
                self._dummy_outlen,  # int *outl
                self._binding.ffi.from_buffer(
                    associated_data
                ),  # const unsigned char *in
                len(associated_data),  # int inl
            )
        )

        # encrypt the data
        self._assert(
            self._binding.lib.EVP_CipherUpdate(
                self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._buffer,  # unsigned char *out
                self._outlen,  # int *outl
                self._binding.ffi.from_buffer(data),  # const unsigned char *in
                data_len,  # int inl
            )
        )

        # finalize the operation
        self._assert(
            self._binding.lib.EVP_CipherFinal_ex(
                self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.ffi.NULL,  # unsigned char *outm
                self._dummy_outlen,  # int *outl
            )
            and self._dummy_outlen[0] == 0
        )

        # append the AEAD tag to the cipher text
        if self._outlen[0] + AEAD_TAG_LENGTH > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_ctrl(
                self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.lib.EVP_CTRL_AEAD_GET_TAG,  # int cmd
                AEAD_TAG_LENGTH,  # int taglen
                self._buffer + self._outlen[0],  # void *tag
            )
        )

        # return the encrypted cipher text and AEAD tag
        return bytes(
            self._binding.ffi.buffer(self._buffer, self._outlen[0] + AEAD_TAG_LENGTH)
        )


class HeaderProtection:
    def __init__(self, cipher_name: bytes, key: bytes) -> None:
        self._is_chacha20 = cipher_name == b"chacha20"
        self._binding = Binding()

        # create cipher with given type
        evp_cipher = _get_cipher_by_name(self._binding, cipher_name)
        self._ctx = self._binding.lib.EVP_CIPHER_CTX_new()
        self._ctx = self._binding.ffi.gc(
            self._ctx, self._binding.lib.EVP_CIPHER_CTX_free
        )
        self._assert(
            self._binding.lib.EVP_CipherInit_ex(
                self._ctx,  # EVP_CIPHER_CTX *ctx
                evp_cipher,  # const EVP_CIPHER *type
                self._binding.ffi.NULL,  # ENGINE *impl
                self._binding.ffi.NULL,  # const unsigned char *key
                self._binding.ffi.NULL,  # const unsigned char *iv
                1,  # int enc
            )
        )

        # set cipher key
        self._assert(
            self._binding.lib.EVP_CIPHER_CTX_set_key_length(self._ctx, len(key))
        )
        self._assert(
            self._binding.lib.EVP_CipherInit_ex(
                self._ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.ffi.NULL,  # const EVP_CIPHER *type
                self._binding.ffi.NULL,  # ENGINE *impl
                self._binding.ffi.from_buffer(key),  # const unsigned char *key
                self._binding.ffi.NULL,  # const unsigned char *iv
                1,  # int enc
            )
        )

        # allocate buffers
        self._buffer = self._binding.ffi.new("unsigned char[]", PACKET_LENGTH_MAX)
        self._dummy_outlen = self._binding.ffi.new("int *")
        self._mask = self._binding.ffi.new("unsigned char[]", 31)
        self._zero = self._binding.ffi.new("unsigned char[]", 5)

    def _assert(self, value) -> None:
        if not value:
            self._binding.lib.ERR_clear_error()
            raise CryptoError("OpenSSL call failed")

    def _update_mask(self, pn_offset: int, buffer_len: int) -> None:
        # reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.2

        # sample data starts 4 bytes after the beginning of the Packet Number field (regardless of its length)
        sample_offset = pn_offset + 4
        assert pn_offset + SAMPLE_LENGTH <= buffer_len

        if self._is_chacha20:
            # reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.4

            # the first four bytes after pn_offset are block counter, the next 12 bytes are the nonce
            self._assert(
                self._binding.lib.EVP_CipherInit_ex(
                    self._ctx,  # EVP_CIPHER_CTX *ctx
                    self._binding.ffi.NULL,  # const EVP_CIPHER *type
                    self._binding.ffi.NULL,  # ENGINE *impl
                    self._binding.ffi.NULL,  # const unsigned char *key
                    self._buffer + sample_offset,  # const unsigned char *iv
                    1,  # int enc
                )
            )

            # ChaCha20 is used to protect 5 zero bytes
            self._assert(
                self._binding.lib.EVP_CipherUpdate(
                    self._ctx,  # EVP_CIPHER_CTX *ctx
                    self._mask,  # unsigned char *out
                    self._dummy_outlen,  # int *outl
                    self._zero,  # const unsigned char *in
                    len(self._zero),  # int inl
                )
            )
        else:
            # reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.3

            # AES-based header protected simply samples 16 bytes as input for AES-ECB
            self._assert(
                self._binding.lib.EVP_CipherUpdate(
                    self._ctx,  # EVP_CIPHER_CTX *ctx
                    self._mask,  # unsigned char *out
                    self._dummy_outlen,  # int *outl
                    self._buffer + sample_offset,  # const unsigned char *in
                    SAMPLE_LENGTH,  # int inl
                )
            )

    def _mask_header(self) -> None:
        # use one byte to mask 4 bits for long headers, and 5 bits for short ones
        if self._buffer[0] & 0x80:
            self._buffer[0] ^= self._mask[0] & 0x0F
        else:
            self._buffer[0] ^= self._mask[0] & 0x1F

    def _mask_packet_number(self, pn_offset: int, pn_length: int) -> int:
        # use the remaining (c.f. _mask_header) bytes to mask the packet number field
        # and calculate the truncated packet number
        pn_truncated = 0
        for i in range(pn_length):
            value = self._buffer[pn_offset + i] ^ self._mask[1 + i]
            self._buffer[pn_offset + i] = value
            pn_truncated = value | (pn_truncated << 8)
        return pn_truncated

    def apply(self, plain_header: bytes, protected_payload: bytes) -> bytes:
        # Reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1

        # read the Packet Number Length from the header
        pn_length = (plain_header[0] & 0x03) + 1

        # the Packet Number is the last field of the header, calculate it's offset
        pn_offset = len(plain_header) - pn_length

        # copy header and payload into the buffer
        self._binding.ffi.buffer(self._buffer, len(plain_header))[:] = plain_header
        self._binding.ffi.buffer(
            self._buffer + len(plain_header), len(protected_payload)
        )[:] = protected_payload
        buffer_len = len(plain_header) + len(protected_payload)

        # build the mask and use it
        self._update_mask(pn_offset, buffer_len)
        self._mask_header()
        self._mask_packet_number(pn_offset, pn_length)

        return bytes(self._binding.ffi.buffer(self._buffer, buffer_len))

    def remove(self, packet: bytes, encrypted_offset: int) -> Tuple[bytes, int]:
        # Reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1

        # copy the packet into the buffer
        packet_len = len(packet)
        self._binding.ffi.buffer(self._buffer, packet_len)[:] = packet

        # build the mask and use it to unmask the header first
        self._update_mask(encrypted_offset, packet_len)
        self._mask_header()

        # get the packet number length and unmask it as well
        pn_length = (self._buffer[0] & 0x03) + 1
        pn_truncated = self._mask_packet_number(encrypted_offset, pn_length)

        # return the header and the truncated packet number
        return (
            bytes(self._binding.ffi.buffer(self._buffer, encrypted_offset + pn_length)),
            pn_truncated,
        )
