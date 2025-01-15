# TODO, use the existing crypto built into aioquic
import logging
import zlib

from Crypto.PublicKey import RSA
from aioquic.quic import ccrypto
from aioquic.quic.connection import (
    RSA_BIT_STRENGTH,
    RSA_PUBLIC_EXPONENT,
    AES_BLOCK_SIZE,
    GLOBAL_BYTE_ORDER,
    create_peer_meta
)
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import shuffle

logger = logging.getLogger()

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
    compressed_message = zlib.compress(message)
    ciphertext = aes_cipher.encrypt(pad(compressed_message, block_size=AES_BLOCK_SIZE))
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return iv + encrypted_aes_key + ciphertext


def reconstruct_payload(buffer):
    """Reconstructs a buffer by splitting off the prefixes and payloads and re-ordering them

    Args:
        buffer (list of bytes): The cid buffer

    Returns:
        bytes: The reconstructed encrypted payload
    """
    payload_pairs = [(v[:4], v[4:]) for v in buffer]
    payload_chunks = [v[1] for v in sorted(payload_pairs)]
    return b''.join(payload_chunks)


def try_decrypt(private_key, buffer, raise_on_error=False):
    encrypted_payload = reconstruct_payload(buffer)
    try:
        iv = encrypted_payload[:AES_BLOCK_SIZE]
        encrypted_aes_key = encrypted_payload[AES_BLOCK_SIZE:AES_BLOCK_SIZE+RSA_BIT_STRENGTH//8]
        ciphertext = encrypted_payload[AES_BLOCK_SIZE+RSA_BIT_STRENGTH//8:]
        rsa_cipher = PKCS1_OAEP.new(private_key)
        decrypted_aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        aes_cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
        compressed_messsage = unpad(aes_cipher.decrypt(ciphertext), block_size=AES_BLOCK_SIZE)
        decrypted_message = zlib.decompress(compressed_messsage)
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

def generate_prefixes(n, size=4):
    """Generates a list of high-entropy prefixes

    Args:
        n (int): number of prefixes to generate

    Returns:
        list: A sorted list of 'n' high entropy bytes of length 'size'
    """
    prefixes = set()
    while len(prefixes) < n:
        prefixes.add(get_random_bytes(size))
    return sorted(list(prefixes))

def queue_message(host_ip, payload, queue, public_key, is_public_key=False):
    cid_payloads = []
    if is_public_key:
        # Make the key chunks 160 bits by prepending 128 bit chunks with 32 bits or random data
        cid_payloads = [get_random_bytes(4) + payload[i:i+16] for i in range(0, len(payload), 16)]    
    elif not is_public_key and not public_key:
        logger.error("RSA key required if sending a message or a file. Received %s", public_key)
        raise ValueError(f"RSA key required by {public_key} was provided.")
    else:
        encrypted_payload = ccrypto.encrypt(public_key, payload)
        cid_payloads = [encrypted_payload[i:i+16] for i in range(0, len(encrypted_payload), 16)]
        # Prepend an ordered, high-entropy prefix of bytes to each packet
        cid_payloads = [v[0] + v[1] for v in zip(generate_prefixes(len(cid_payloads)), cid_payloads)]
        # We don't want the prefixes to be ordered, so shuffle them out of order intentionally
        shuffle(cid_payloads) 

    for cid in cid_payloads:
        queue.put(cid)
    return len(cid_payloads)

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
