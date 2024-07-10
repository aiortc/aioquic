# TODO, use the existing crypto built into aioquic
from Crypto.PublicKey import RSA
from aioquic.quic import ccrypto
from aioquic.quic.connection import (
    RSA_BIT_STRENGTH,
    RSA_PUBLIC_EXPONENT,
    AES_BLOCK_SIZE,
    GLOBAL_BYTE_ORDER
)
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

def split_keyed_payload(payload):
    return payload[:RSA_BIT_STRENGTH//8], payload[RSA_BIT_STRENGTH//8:]

def make_keyed_payload(rsa_key, payload):
    n_bytes = ccrypto.get_compact_key(rsa_key)
    keyed_payload = n_bytes + payload
    return keyed_payload

def generate_rsa(bits=RSA_BIT_STRENGTH):
    rng = Random.new().read
    key = RSA.generate(bits, rng, e=RSA_PUBLIC_EXPONENT)
    return key

def generate_rsa_public_key(n_bytes):
    n = int.from_bytes(n_bytes, GLOBAL_BYTE_ORDER)
    rsa_key = RSA.construct((n, RSA_PUBLIC_EXPONENT))
    rsa_public_key = rsa_key.publickey()
    return rsa_public_key

def encrypt(public_key, message):
    aes_key = Random.get_random_bytes(AES_BLOCK_SIZE)
    iv = Random.get_random_bytes(AES_BLOCK_SIZE)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(message, block_size=AES_BLOCK_SIZE))
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return iv + encrypted_aes_key + ciphertext

def try_decrypt(private_key, encrypted_payload, raise_on_error=False):
    try:
        iv = encrypted_payload[:AES_BLOCK_SIZE]
        encrypted_aes_key = encrypted_payload[AES_BLOCK_SIZE:AES_BLOCK_SIZE+RSA_BIT_STRENGTH//8]
        ciphertext = encrypted_payload[AES_BLOCK_SIZE+RSA_BIT_STRENGTH//8:]
        rsa_cipher = PKCS1_OAEP.new(private_key)
        decrypted_aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        aes_cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(aes_cipher.decrypt(ciphertext), block_size=AES_BLOCK_SIZE)
        return decrypted_message
    except:
        if raise_on_error:
            raise
        return None

def load_key(pem_file):
    with open(pem_file, "rb") as key_file:
        rsa_key = RSA.import_key(key_file.read())
        if rsa_key.size_in_bits() != RSA_BIT_STRENGTH:
            raise Exception(f"This tool requires {RSA_BIT_STRENGTH} bit RSA keys.")
        return rsa_key

def get_compact_key(rsa_key):
    modulus = rsa_key.n
    return modulus.to_bytes(RSA_BIT_STRENGTH // 8, byteorder=GLOBAL_BYTE_ORDER)

if __name__ == "__main__":
    # We would start with our private key
    private_key = generate_rsa()
    # We would get the n value to send over because it's high entropy and we
    # have an agreed upon public exponent
    n_bytes = get_compact_key(private_key)
    print(len(n_bytes))
    # After receiving the pulbic key n, the recipient would generate the
    # public key instance using the agreed upon public exponent
    public_key = generate_rsa_public_key(n_bytes=n_bytes)
    # It should then be usable to send, sign, etc
    message = b'QuiCC will be impossible to detect.'
    encrypted_payload = encrypt(public_key, message)
    decrypted_message = try_decrypt(private_key, encrypted_payload)
    print(decrypted_message)
    keyed_message = make_keyed_payload(private_key, encrypted_payload)
    n_bytes, split_encrypted_payload = split_keyed_payload(keyed_message)
    decrypted_message = try_decrypt(private_key, split_encrypted_payload)
    print(decrypted_message)
