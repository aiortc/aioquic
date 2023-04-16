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


class _CryptoBase:
    def __init__(self) -> None:
        self._binding = Binding()

    def _handle_openssl_failure(self) -> bool:
        self._binding.lib.ERR_clear_error()
        raise CryptoError("OpenSSL call failed")


class AEAD(_CryptoBase):
    def __init__(self, cipher_name: bytes, key: bytes, iv: bytes) -> None:
        super().__init__()

        # check and store key and iv
        if len(key) > AEAD_KEY_LENGTH_MAX:
            raise CryptoError("Invalid key length")
        self._key = key
        if len(iv) != AEAD_NONCE_LENGTH:
            raise CryptoError("Invalid iv length")
        self._iv = iv

        # create cipher contexts
        evp_cipher = _get_cipher_by_name(self._binding, cipher_name)
        self._decrypt_ctx = self._create_ctx(evp_cipher, operation=0)
        self._encrypt_ctx = self._create_ctx(evp_cipher, operation=1)

        # allocate buffers
        self._nonce = self._binding.ffi.new("unsigned char[]", AEAD_NONCE_LENGTH)
        self._buffer = self._binding.ffi.new("unsigned char[]", PACKET_LENGTH_MAX)
        self._buffer_view = self._binding.ffi.buffer(self._buffer)
        self._outlen = self._binding.ffi.new("int *")
        self._dummy_outlen = self._binding.ffi.new("int *")

    def _create_ctx(self, evp_cipher, operation: int):  # -> EVP_CIPHER_CTX *
        # create a cipher context with the given type and operation mode
        ctx = self._binding.ffi.gc(
            self._binding.lib.EVP_CIPHER_CTX_new(),
            self._binding.lib.EVP_CIPHER_CTX_free,
        )
        ctx != self._binding.ffi.NULL or self._handle_openssl_failure()
        self._binding.lib.EVP_CipherInit_ex(
            ctx,  # EVP_CIPHER_CTX *ctx
            evp_cipher,  # const EVP_CIPHER *type
            self._binding.ffi.NULL,  # ENGINE *impl
            self._binding.ffi.NULL,  # const unsigned char *key
            self._binding.ffi.NULL,  # const unsigned char *iv
            operation,  # int enc
        ) == 1 or self._handle_openssl_failure()

        # specify key and initialization vector length
        self._binding.lib.EVP_CIPHER_CTX_set_key_length(
            ctx,  # EVP_CIPHER_CTX *ctx
            len(self._key),  # int keylen
        ) == 1 or self._handle_openssl_failure()
        self._binding.lib.EVP_CIPHER_CTX_ctrl(
            ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.lib.EVP_CTRL_AEAD_SET_IVLEN,  # int cmd
            AEAD_NONCE_LENGTH,  # int ivlen
            self._binding.ffi.NULL,  # void *NULL
        ) == 1 or self._handle_openssl_failure()
        return ctx

    def _init_nonce(self, packet_number: int) -> None:
        # reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.3

        # left-pad the reconstructed packet number (62 bits ~ 8 bytes)
        # and XOR it with the IV
        self._binding.ffi.memmove(self._nonce, self._iv, AEAD_NONCE_LENGTH)
        for i in range(8):
            if packet_number == 0:
                break
            self._nonce[AEAD_NONCE_LENGTH - 1 - i] ^= packet_number & 0xFF
            packet_number >>= 8

    def decrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        if len(data) < AEAD_TAG_LENGTH or len(data) > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")
        self._init_nonce(packet_number)

        # get the appended AEAD tag (data = cipher text + tag)
        cipher_text_len = len(data) - AEAD_TAG_LENGTH
        self._binding.lib.EVP_CIPHER_CTX_ctrl(
            self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.lib.EVP_CTRL_AEAD_SET_TAG,  # int cmd
            AEAD_TAG_LENGTH,  # int taglen
            data[cipher_text_len:],  # void *tag
        ) == 1 or self._handle_openssl_failure()

        # set key and nonce
        self._binding.lib.EVP_CipherInit_ex(
            self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.ffi.NULL,  # const EVP_CIPHER *type
            self._binding.ffi.NULL,  # ENGINE *impl
            self._key,  # const unsigned char *key
            self._nonce,  # const unsigned char *iv
            0,  # int enc
        ) == 1 or self._handle_openssl_failure()

        # specify the header as additional authenticated data (AAD)
        self._binding.lib.EVP_CipherUpdate(
            self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.ffi.NULL,  # unsigned char *out
            self._dummy_outlen,  # int *outl
            associated_data,  # const unsigned char *in
            len(associated_data),  # int inl
        ) == 1 or self._handle_openssl_failure()

        # decrypt the cipher text (i.e. received data excluding the appended tag)
        self._binding.lib.EVP_CipherUpdate(
            self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._buffer,  # unsigned char *out
            self._outlen,  # int *outl
            data,  # const unsigned char *in
            cipher_text_len,  # int inl
        ) == 1 or self._handle_openssl_failure()

        # finalize the operation
        self._binding.lib.EVP_CipherFinal_ex(
            self._decrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.ffi.NULL,  # unsigned char *outm
            self._dummy_outlen,  # int *outl
        ) == 1 or self._handle_openssl_failure()

        # return the decrypted data
        return self._buffer_view[: self._outlen[0]]

    def encrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        if len(data) > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")
        self._init_nonce(packet_number)

        # set key and nonce
        self._binding.lib.EVP_CipherInit_ex(
            self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.ffi.NULL,  # const EVP_CIPHER *type
            self._binding.ffi.NULL,  # ENGINE *impl
            self._key,  # const unsigned char *key
            self._nonce,  # const unsigned char *iv
            1,  # int enc
        ) == 1 or self._handle_openssl_failure()

        # specify the header as additional authenticated data (AAD)
        self._binding.lib.EVP_CipherUpdate(
            self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.ffi.NULL,  # unsigned char *out
            self._dummy_outlen,  # int *outl
            associated_data,  # const unsigned char *in
            len(associated_data),  # int inl
        ) == 1 or self._handle_openssl_failure()

        # encrypt the data
        self._binding.lib.EVP_CipherUpdate(
            self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._buffer,  # unsigned char *out
            self._outlen,  # int *outl
            data,  # const unsigned char *in
            len(data),  # int inl
        ) == 1 or self._handle_openssl_failure()

        # finalize the operation
        self._binding.lib.EVP_CipherFinal_ex(
            self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.ffi.NULL,  # unsigned char *outm
            self._dummy_outlen,  # int *outl
        ) == 1 and self._dummy_outlen[0] == 0 or self._handle_openssl_failure()

        # append the AEAD tag to the cipher text
        outlen_with_tag = self._outlen[0] + AEAD_TAG_LENGTH
        if outlen_with_tag > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")
        self._binding.lib.EVP_CIPHER_CTX_ctrl(
            self._encrypt_ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.lib.EVP_CTRL_AEAD_GET_TAG,  # int cmd
            AEAD_TAG_LENGTH,  # int taglen
            self._buffer + self._outlen[0],  # void *tag
        ) == 1 or self._handle_openssl_failure()

        # return the encrypted cipher text and AEAD tag
        return self._buffer_view[:outlen_with_tag]


class HeaderProtection(_CryptoBase):
    def __init__(self, cipher_name: bytes, key: bytes) -> None:
        super().__init__()
        self._is_chacha20 = cipher_name == b"chacha20"
        if len(key) > AEAD_KEY_LENGTH_MAX:
            raise CryptoError("Invalid key length")

        # create cipher with given type
        evp_cipher = _get_cipher_by_name(self._binding, cipher_name)
        self._ctx = self._binding.ffi.gc(
            self._binding.lib.EVP_CIPHER_CTX_new(),
            self._binding.lib.EVP_CIPHER_CTX_free,
        )
        self._ctx != self._binding.ffi.NULL or self._handle_openssl_failure()
        self._binding.lib.EVP_CipherInit_ex(
            self._ctx,  # EVP_CIPHER_CTX *ctx
            evp_cipher,  # const EVP_CIPHER *type
            self._binding.ffi.NULL,  # ENGINE *impl
            self._binding.ffi.NULL,  # const unsigned char *key
            self._binding.ffi.NULL,  # const unsigned char *iv
            1,  # int enc
        ) == 1 or self._handle_openssl_failure()

        # set cipher key
        self._binding.lib.EVP_CIPHER_CTX_set_key_length(
            self._ctx,  # EVP_CIPHER_CTX *ctx
            len(key),  # int keylen
        ) == 1 or self._handle_openssl_failure()
        self._binding.lib.EVP_CipherInit_ex(
            self._ctx,  # EVP_CIPHER_CTX *ctx
            self._binding.ffi.NULL,  # const EVP_CIPHER *type
            self._binding.ffi.NULL,  # ENGINE *impl
            key,  # const unsigned char *key
            self._binding.ffi.NULL,  # const unsigned char *iv
            1,  # int enc
        ) == 1 or self._handle_openssl_failure()

        # allocate buffers
        self._buffer = self._binding.ffi.new("unsigned char[]", PACKET_LENGTH_MAX)
        self._buffer_view = self._binding.ffi.buffer(self._buffer)
        self._dummy_outlen = self._binding.ffi.new("int *")
        self._mask = self._binding.ffi.new("unsigned char[]", 31)
        self._zero = self._binding.ffi.new("unsigned char[]", 5)

    def _update_mask(self, pn_offset: int, buffer_len: int) -> None:
        # reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.2

        # sample data starts 4 bytes after the beginning of the Packet Number field
        # (regardless of its length)
        sample_offset = pn_offset + 4
        assert pn_offset + SAMPLE_LENGTH <= buffer_len

        if self._is_chacha20:
            # reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.4

            # the first four bytes after pn_offset are block counter,
            # the next 12 bytes are the nonce
            self._binding.lib.EVP_CipherInit_ex(
                self._ctx,  # EVP_CIPHER_CTX *ctx
                self._binding.ffi.NULL,  # const EVP_CIPHER *type
                self._binding.ffi.NULL,  # ENGINE *impl
                self._binding.ffi.NULL,  # const unsigned char *key
                self._buffer + sample_offset,  # const unsigned char *iv
                1,  # int enc
            ) == 1 or self._handle_openssl_failure()

            # ChaCha20 is used to protect 5 zero bytes
            self._binding.lib.EVP_CipherUpdate(
                self._ctx,  # EVP_CIPHER_CTX *ctx
                self._mask,  # unsigned char *out
                self._dummy_outlen,  # int *outl
                self._zero,  # const unsigned char *in
                len(self._zero),  # int inl
            ) == 1 or self._handle_openssl_failure()

        else:
            # reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.3

            # AES-based header protected simply samples 16 bytes as input for AES-ECB
            self._binding.lib.EVP_CipherUpdate(
                self._ctx,  # EVP_CIPHER_CTX *ctx
                self._mask,  # unsigned char *out
                self._dummy_outlen,  # int *outl
                self._buffer + sample_offset,  # const unsigned char *in
                SAMPLE_LENGTH,  # int inl
            ) == 1 or self._handle_openssl_failure()

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
        buffer_len = len(plain_header) + len(protected_payload)
        if buffer_len > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")

        # read the Packet Number Length from the header
        pn_length = (plain_header[0] & 0x03) + 1

        # the Packet Number is the last field of the header, calculate it's offset
        pn_offset = len(plain_header) - pn_length

        # copy header and payload into the buffer
        self._binding.ffi.memmove(self._buffer, plain_header, len(plain_header))
        self._binding.ffi.memmove(
            self._buffer + len(plain_header), protected_payload, len(protected_payload)
        )

        # build the mask and use it
        self._update_mask(pn_offset, buffer_len)
        self._mask_header()
        self._mask_packet_number(pn_offset, pn_length)

        return self._buffer_view[:buffer_len]

    def remove(self, packet: bytes, encrypted_offset: int) -> Tuple[bytes, int]:
        # Reference: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
        if len(packet) > PACKET_LENGTH_MAX:
            raise CryptoError("Invalid payload length")

        # copy the packet into the buffer
        self._binding.ffi.memmove(self._buffer, packet, len(packet))

        # build the mask and use it to unmask the header first
        self._update_mask(encrypted_offset, len(packet))
        self._mask_header()

        # get the packet number length and unmask it as well
        pn_length = (self._buffer[0] & 0x03) + 1
        pn_truncated = self._mask_packet_number(encrypted_offset, pn_length)

        # return the header and the truncated packet number
        return (
            self._buffer_view[: encrypted_offset + pn_length],
            pn_truncated,
        )
