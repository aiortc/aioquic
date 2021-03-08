import binascii
from unittest import TestCase, skipIf

from aioquic.buffer import Buffer
from aioquic.quic.crypto import (
    INITIAL_CIPHER_SUITE,
    CryptoError,
    CryptoPair,
    derive_key_iv_hp,
)
from aioquic.quic.packet import PACKET_FIXED_BIT, QuicProtocolVersion
from aioquic.tls import CipherSuite

from .utils import SKIP_TESTS

PROTOCOL_VERSION = QuicProtocolVersion.DRAFT_29

CHACHA20_CLIENT_PACKET_NUMBER = 2
CHACHA20_CLIENT_PLAIN_HEADER = binascii.unhexlify(
    "e1ff0000160880b57c7b70d8524b0850fc2a28e240fd7640170002"
)
CHACHA20_CLIENT_PLAIN_PAYLOAD = binascii.unhexlify("0201000000")
CHACHA20_CLIENT_ENCRYPTED_PACKET = binascii.unhexlify(
    "e8ff0000160880b57c7b70d8524b0850fc2a28e240fd7640178313b04be98449"
    "eb10567e25ce930381f2a5b7da2db8db"
)

LONG_CLIENT_PACKET_NUMBER = 2
LONG_CLIENT_PLAIN_HEADER = binascii.unhexlify(
    "c3ff00001d088394c8f03e5157080000449e00000002"
)
LONG_CLIENT_PLAIN_PAYLOAD = binascii.unhexlify(
    "060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba1"
    "4131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006"
    "736572766572ff01000100000a00140012001d00170018001901000101010201"
    "03010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f"
    "2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e0403"
    "05030603020308040805080604010501060102010402050206020202002d0002"
    "0101001c00024001"
) + bytes(962)
LONG_CLIENT_ENCRYPTED_PACKET = binascii.unhexlify(
    "c5ff00001d088394c8f03e5157080000449e4a95245bfb66bc5f93032b7ddd89"
    "fe0ff15d9c4f7050fccdb71c1cd80512d4431643a53aafa1b0b518b44968b18b"
    "8d3e7a4d04c30b3ed9410325b2abb2dafb1c12f8b70479eb8df98abcaf95dd8f"
    "3d1c78660fbc719f88b23c8aef6771f3d50e10fdfb4c9d92386d44481b6c52d5"
    "9e5538d3d3942de9f13a7f8b702dc31724180da9df22714d01003fc5e3d165c9"
    "50e630b8540fbd81c9df0ee63f94997026c4f2e1887a2def79050ac2d86ba318"
    "e0b3adc4c5aa18bcf63c7cf8e85f569249813a2236a7e72269447cd1c755e451"
    "f5e77470eb3de64c8849d292820698029cfa18e5d66176fe6e5ba4ed18026f90"
    "900a5b4980e2f58e39151d5cd685b10929636d4f02e7fad2a5a458249f5c0298"
    "a6d53acbe41a7fc83fa7cc01973f7a74d1237a51974e097636b6203997f921d0"
    "7bc1940a6f2d0de9f5a11432946159ed6cc21df65c4ddd1115f86427259a196c"
    "7148b25b6478b0dc7766e1c4d1b1f5159f90eabc61636226244642ee148b464c"
    "9e619ee50a5e3ddc836227cad938987c4ea3c1fa7c75bbf88d89e9ada642b2b8"
    "8fe8107b7ea375b1b64889a4e9e5c38a1c896ce275a5658d250e2d76e1ed3a34"
    "ce7e3a3f383d0c996d0bed106c2899ca6fc263ef0455e74bb6ac1640ea7bfedc"
    "59f03fee0e1725ea150ff4d69a7660c5542119c71de270ae7c3ecfd1af2c4ce5"
    "51986949cc34a66b3e216bfe18b347e6c05fd050f85912db303a8f054ec23e38"
    "f44d1c725ab641ae929fecc8e3cefa5619df4231f5b4c009fa0c0bbc60bc75f7"
    "6d06ef154fc8577077d9d6a1d2bd9bf081dc783ece60111bea7da9e5a9748069"
    "d078b2bef48de04cabe3755b197d52b32046949ecaa310274b4aac0d008b1948"
    "c1082cdfe2083e386d4fd84c0ed0666d3ee26c4515c4fee73433ac703b690a9f"
    "7bf278a77486ace44c489a0c7ac8dfe4d1a58fb3a730b993ff0f0d61b4d89557"
    "831eb4c752ffd39c10f6b9f46d8db278da624fd800e4af85548a294c1518893a"
    "8778c4f6d6d73c93df200960104e062b388ea97dcf4016bced7f62b4f062cb6c"
    "04c20693d9a0e3b74ba8fe74cc01237884f40d765ae56a51688d985cf0ceaef4"
    "3045ed8c3f0c33bced08537f6882613acd3b08d665fce9dd8aa73171e2d3771a"
    "61dba2790e491d413d93d987e2745af29418e428be34941485c93447520ffe23"
    "1da2304d6a0fd5d07d0837220236966159bef3cf904d722324dd852513df39ae"
    "030d8173908da6364786d3c1bfcb19ea77a63b25f1e7fc661def480c5d00d444"
    "56269ebd84efd8e3a8b2c257eec76060682848cbf5194bc99e49ee75e4d0d254"
    "bad4bfd74970c30e44b65511d4ad0e6ec7398e08e01307eeeea14e46ccd87cf3"
    "6b285221254d8fc6a6765c524ded0085dca5bd688ddf722e2c0faf9d0fb2ce7a"
    "0c3f2cee19ca0ffba461ca8dc5d2c8178b0762cf67135558494d2a96f1a139f0"
    "edb42d2af89a9c9122b07acbc29e5e722df8615c343702491098478a389c9872"
    "a10b0c9875125e257c7bfdf27eef4060bd3d00f4c14fd3e3496c38d3c5d1a566"
    "8c39350effbc2d16ca17be4ce29f02ed969504dda2a8c6b9ff919e693ee79e09"
    "089316e7d1d89ec099db3b2b268725d888536a4b8bf9aee8fb43e82a4d919d48"
    "43b1ca70a2d8d3f725ead1391377dcc0"
)

LONG_SERVER_PACKET_NUMBER = 1
LONG_SERVER_PLAIN_HEADER = binascii.unhexlify(
    "c1ff00001d0008f067a5502a4262b50040740001"
)
LONG_SERVER_PLAIN_PAYLOAD = binascii.unhexlify(
    "0d0000000018410a020000560303eefce7f7b37ba1d1632e96677825ddf73988"
    "cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d"
    "89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b0002"
    "0304"
)
LONG_SERVER_ENCRYPTED_PACKET = binascii.unhexlify(
    "caff00001d0008f067a5502a4262b5004074aaf2f007823a5d3a1207c86ee491"
    "32824f0465243d082d868b107a38092bc80528664cbf9456ebf27673fb5fa506"
    "1ab573c9f001b81da028a00d52ab00b15bebaa70640e106cf2acd043e9c6b441"
    "1c0a79637134d8993701fe779e58c2fe753d14b0564021565ea92e57bc6faf56"
    "dfc7a40870e6"
)

SHORT_SERVER_PACKET_NUMBER = 3
SHORT_SERVER_PLAIN_HEADER = binascii.unhexlify("41b01fd24a586a9cf30003")
SHORT_SERVER_PLAIN_PAYLOAD = binascii.unhexlify(
    "06003904000035000151805a4bebf5000020b098c8dc4183e4c182572e10ac3e"
    "2b88897e0524c8461847548bd2dffa2c0ae60008002a0004ffffffff"
)
SHORT_SERVER_ENCRYPTED_PACKET = binascii.unhexlify(
    "5db01fd24a586a9cf33dec094aaec6d6b4b7a5e15f5a3f05d06cf1ad0355c19d"
    "cce0807eecf7bf1c844a66e1ecd1f74b2a2d69bfd25d217833edd973246597bd"
    "5107ea15cb1e210045396afa602fe23432f4ab24ce251b"
)


class CryptoTest(TestCase):
    """
    Test vectors from:

    https://tools.ietf.org/html/draft-ietf-quic-tls-18#appendix-A
    """

    def create_crypto(self, is_client):
        pair = CryptoPair()
        pair.setup_initial(
            cid=binascii.unhexlify("8394c8f03e515708"),
            is_client=is_client,
            version=PROTOCOL_VERSION,
        )
        return pair

    def test_derive_key_iv_hp(self):
        # client
        secret = binascii.unhexlify(
            "8a3515a14ae3c31b9c2d6d5bc58538ca5cd2baa119087143e60887428dcb52f6"
        )
        key, iv, hp = derive_key_iv_hp(INITIAL_CIPHER_SUITE, secret)
        self.assertEqual(key, binascii.unhexlify("98b0d7e5e7a402c67c33f350fa65ea54"))
        self.assertEqual(iv, binascii.unhexlify("19e94387805eb0b46c03a788"))
        self.assertEqual(hp, binascii.unhexlify("0edd982a6ac527f2eddcbb7348dea5d7"))

        # server
        secret = binascii.unhexlify(
            "47b2eaea6c266e32c0697a9e2a898bdf5c4fb3e5ac34f0e549bf2c58581a3811"
        )
        key, iv, hp = derive_key_iv_hp(INITIAL_CIPHER_SUITE, secret)
        self.assertEqual(key, binascii.unhexlify("9a8be902a9bdd91d16064ca118045fb4"))
        self.assertEqual(iv, binascii.unhexlify("0a82086d32205ba22241d8dc"))
        self.assertEqual(hp, binascii.unhexlify("94b9452d2b3c7c7f6da7fdd8593537fd"))

    @skipIf("chacha20" in SKIP_TESTS, "Skipping chacha20 tests")
    def test_decrypt_chacha20(self):
        pair = CryptoPair()
        pair.recv.setup(
            cipher_suite=CipherSuite.CHACHA20_POLY1305_SHA256,
            secret=binascii.unhexlify(
                "b42772df33c9719a32820d302aa664d080d7f5ea7a71a330f87864cb289ae8c0"
            ),
            version=PROTOCOL_VERSION,
        )

        plain_header, plain_payload, packet_number = pair.decrypt_packet(
            CHACHA20_CLIENT_ENCRYPTED_PACKET, 25, 0
        )
        self.assertEqual(plain_header, CHACHA20_CLIENT_PLAIN_HEADER)
        self.assertEqual(plain_payload, CHACHA20_CLIENT_PLAIN_PAYLOAD)
        self.assertEqual(packet_number, CHACHA20_CLIENT_PACKET_NUMBER)

    def test_decrypt_long_client(self):
        pair = self.create_crypto(is_client=False)

        plain_header, plain_payload, packet_number = pair.decrypt_packet(
            LONG_CLIENT_ENCRYPTED_PACKET, 18, 0
        )
        self.assertEqual(plain_header, LONG_CLIENT_PLAIN_HEADER)
        self.assertEqual(plain_payload, LONG_CLIENT_PLAIN_PAYLOAD)
        self.assertEqual(packet_number, LONG_CLIENT_PACKET_NUMBER)

    def test_decrypt_long_server(self):
        pair = self.create_crypto(is_client=True)

        plain_header, plain_payload, packet_number = pair.decrypt_packet(
            LONG_SERVER_ENCRYPTED_PACKET, 18, 0
        )
        self.assertEqual(plain_header, LONG_SERVER_PLAIN_HEADER)
        self.assertEqual(plain_payload, LONG_SERVER_PLAIN_PAYLOAD)
        self.assertEqual(packet_number, LONG_SERVER_PACKET_NUMBER)

    def test_decrypt_no_key(self):
        pair = CryptoPair()
        with self.assertRaises(CryptoError):
            pair.decrypt_packet(LONG_SERVER_ENCRYPTED_PACKET, 18, 0)

    def test_decrypt_short_server(self):
        pair = CryptoPair()
        pair.recv.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=binascii.unhexlify(
                "310281977cb8c1c1c1212d784b2d29e5a6489e23de848d370a5a2f9537f3a100"
            ),
            version=PROTOCOL_VERSION,
        )

        plain_header, plain_payload, packet_number = pair.decrypt_packet(
            SHORT_SERVER_ENCRYPTED_PACKET, 9, 0
        )
        self.assertEqual(plain_header, SHORT_SERVER_PLAIN_HEADER)
        self.assertEqual(plain_payload, SHORT_SERVER_PLAIN_PAYLOAD)
        self.assertEqual(packet_number, SHORT_SERVER_PACKET_NUMBER)

    @skipIf("chacha20" in SKIP_TESTS, "Skipping chacha20 tests")
    def test_encrypt_chacha20(self):
        pair = CryptoPair()
        pair.send.setup(
            cipher_suite=CipherSuite.CHACHA20_POLY1305_SHA256,
            secret=binascii.unhexlify(
                "b42772df33c9719a32820d302aa664d080d7f5ea7a71a330f87864cb289ae8c0"
            ),
            version=PROTOCOL_VERSION,
        )

        packet = pair.encrypt_packet(
            CHACHA20_CLIENT_PLAIN_HEADER,
            CHACHA20_CLIENT_PLAIN_PAYLOAD,
            CHACHA20_CLIENT_PACKET_NUMBER,
        )
        self.assertEqual(packet, CHACHA20_CLIENT_ENCRYPTED_PACKET)

    def test_encrypt_long_client(self):
        pair = self.create_crypto(is_client=True)

        packet = pair.encrypt_packet(
            LONG_CLIENT_PLAIN_HEADER,
            LONG_CLIENT_PLAIN_PAYLOAD,
            LONG_CLIENT_PACKET_NUMBER,
        )
        self.assertEqual(packet, LONG_CLIENT_ENCRYPTED_PACKET)

    def test_encrypt_long_server(self):
        pair = self.create_crypto(is_client=False)

        packet = pair.encrypt_packet(
            LONG_SERVER_PLAIN_HEADER,
            LONG_SERVER_PLAIN_PAYLOAD,
            LONG_SERVER_PACKET_NUMBER,
        )
        self.assertEqual(packet, LONG_SERVER_ENCRYPTED_PACKET)

    def test_encrypt_short_server(self):
        pair = CryptoPair()
        pair.send.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=binascii.unhexlify(
                "310281977cb8c1c1c1212d784b2d29e5a6489e23de848d370a5a2f9537f3a100"
            ),
            version=PROTOCOL_VERSION,
        )

        packet = pair.encrypt_packet(
            SHORT_SERVER_PLAIN_HEADER,
            SHORT_SERVER_PLAIN_PAYLOAD,
            SHORT_SERVER_PACKET_NUMBER,
        )
        self.assertEqual(packet, SHORT_SERVER_ENCRYPTED_PACKET)

    def test_key_update(self):
        pair1 = self.create_crypto(is_client=True)
        pair2 = self.create_crypto(is_client=False)

        def create_packet(key_phase, packet_number):
            buf = Buffer(capacity=100)
            buf.push_uint8(PACKET_FIXED_BIT | key_phase << 2 | 1)
            buf.push_bytes(binascii.unhexlify("8394c8f03e515708"))
            buf.push_uint16(packet_number)
            return buf.data, b"\x00\x01\x02\x03"

        def send(sender, receiver, packet_number=0):
            plain_header, plain_payload = create_packet(
                key_phase=sender.key_phase, packet_number=packet_number
            )
            encrypted = sender.encrypt_packet(
                plain_header, plain_payload, packet_number
            )
            recov_header, recov_payload, recov_packet_number = receiver.decrypt_packet(
                encrypted, len(plain_header) - 2, 0
            )
            self.assertEqual(recov_header, plain_header)
            self.assertEqual(recov_payload, plain_payload)
            self.assertEqual(recov_packet_number, packet_number)

        # roundtrip
        send(pair1, pair2, 0)
        send(pair2, pair1, 0)
        self.assertEqual(pair1.key_phase, 0)
        self.assertEqual(pair2.key_phase, 0)

        # pair 1 key update
        pair1.update_key()

        # roundtrip
        send(pair1, pair2, 1)
        send(pair2, pair1, 1)
        self.assertEqual(pair1.key_phase, 1)
        self.assertEqual(pair2.key_phase, 1)

        # pair 2 key update
        pair2.update_key()

        # roundtrip
        send(pair2, pair1, 2)
        send(pair1, pair2, 2)
        self.assertEqual(pair1.key_phase, 0)
        self.assertEqual(pair2.key_phase, 0)

        # pair 1 key - update, but not next to send
        pair1.update_key()

        # roundtrip
        send(pair2, pair1, 3)
        send(pair1, pair2, 3)
        self.assertEqual(pair1.key_phase, 1)
        self.assertEqual(pair2.key_phase, 1)
