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

PROTOCOL_VERSION = QuicProtocolVersion.VERSION_2

# https://datatracker.ietf.org/doc/html/rfc9369#appendix-A.5
CHACHA20_CLIENT_PACKET_NUMBER = 654360564
CHACHA20_CLIENT_PLAIN_HEADER = binascii.unhexlify("4200bff4")
CHACHA20_CLIENT_PLAIN_PAYLOAD = binascii.unhexlify("01")
CHACHA20_CLIENT_ENCRYPTED_PACKET = binascii.unhexlify(
    "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"
)

# https://datatracker.ietf.org/doc/html/rfc9369#appendix-A.2
LONG_CLIENT_PACKET_NUMBER = 2
LONG_CLIENT_PLAIN_HEADER = binascii.unhexlify(
    "d36b3343cf088394c8f03e5157080000449e00000002"
)
LONG_CLIENT_PLAIN_PAYLOAD = binascii.unhexlify(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806048000ffff"
) + bytes(917)
LONG_CLIENT_ENCRYPTED_PACKET = binascii.unhexlify(
    "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485"
    "dd04de806071bf03dceebfa162e75d6c96058bdbfb127cdfcbf903388e99ad04"
    "9f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d"
    "250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a"
    "12834e3f249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500"
    "cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd68"
    "18f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff33"
    "12ae50b187c1433c0f028edcc4c2838b6a9bfc226ca4b4530e7a4ccee1bfa2a3"
    "d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd"
    "6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520"
    "bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045"
    "636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1f"
    "ac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c12"
    "16ccce2d0193f958bb3850a833f7ae432b65bc5a53975c155aa4bcb4f7b2c4e5"
    "4df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4"
    "fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b"
    "8017c25ca9052ca1079d8b78aebd47876d330a30f6a8c6d61dd1ab5589329de7"
    "14d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff9"
    "9c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91"
    "abfe43960977c87471cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd"
    "80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db"
    "848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18"
    "d703dd84045a274ae8bfa73379661388d6991fe39b0d93debb41700b41f90a15"
    "c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc"
    "7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61"
    "f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e70710"
    "10d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b"
    "3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e"
    "06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6adc38b7ca7331dce"
    "8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1"
    "34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1"
    "e86215c2d54e6670e07383a27bbffb5addf47d66aa85a0c6f9f32e59d85a44dd"
    "5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3"
    "8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89"
    "d5974ee12e5cf7d5da4d6a31123041f33e61407e76cffcdcfd7e19ba58cf4b53"
    "6f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19"
    "9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96b"
    "a18b2faa745b6fe189cf772a9f84cbfc"
)

# https://datatracker.ietf.org/doc/html/rfc9369#appendix-A.3
LONG_SERVER_PACKET_NUMBER = 1
LONG_SERVER_PLAIN_HEADER = binascii.unhexlify(
    "d16b3343cf0008f067a5502a4262b50040750001"
)
LONG_SERVER_PLAIN_PAYLOAD = binascii.unhexlify(
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304"
)
LONG_SERVER_ENCRYPTED_PACKET = binascii.unhexlify(
    "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698"
    "baeea26b91eb761d9b89237bbf87263017915358230035f7fd3945d88965cf17"
    "f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2"
    "c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca8"
    "4bed8521e2e140"
)

SHORT_SERVER_PACKET_NUMBER = 3
SHORT_SERVER_PLAIN_HEADER = binascii.unhexlify("41b01fd24a586a9cf30003")
SHORT_SERVER_PLAIN_PAYLOAD = binascii.unhexlify(
    "06003904000035000151805a4bebf5000020b098c8dc4183e4c182572e10ac3e"
    "2b88897e0524c8461847548bd2dffa2c0ae60008002a0004ffffffff"
)
SHORT_SERVER_ENCRYPTED_PACKET = binascii.unhexlify(
    "59b01fd24a586a9cf3be262d3eb9b42ada03644d223dae08cbffd5bddab1cf02"
    "c33711d0cf5cdc785ce55a4d95c6a82e117ba937080ac6d063915f8c4ee28bd3"
    "d86949197c48e8550aa32612f9af806a6c20d6d10ed08f"
)


class CryptoTest(TestCase):
    """
    Test vectors from:

    https://datatracker.ietf.org/doc/html/rfc9001#appendix-A
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
        # https://datatracker.ietf.org/doc/html/rfc9369#appendix-A.1

        # client
        secret = binascii.unhexlify(
            "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"
        )
        key, iv, hp = derive_key_iv_hp(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=secret,
            version=PROTOCOL_VERSION,
        )
        self.assertEqual(key, binascii.unhexlify("8b1a0bc121284290a29e0971b5cd045d"))
        self.assertEqual(iv, binascii.unhexlify("91f73e2351d8fa91660e909f"))
        self.assertEqual(hp, binascii.unhexlify("45b95e15235d6f45a6b19cbcb0294ba9"))

        # server
        secret = binascii.unhexlify(
            "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1"
        )
        key, iv, hp = derive_key_iv_hp(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=secret,
            version=PROTOCOL_VERSION,
        )
        self.assertEqual(key, binascii.unhexlify("82db637861d55e1d011f19ea71d5d2a7"))
        self.assertEqual(iv, binascii.unhexlify("dd13c276499c0249d3310652"))
        self.assertEqual(hp, binascii.unhexlify("edf6d05c83121201b436e16877593c3a"))

    @skipIf("chacha20" in SKIP_TESTS, "Skipping chacha20 tests")
    def test_derive_key_iv_hp_chacha20(self):
        # https://datatracker.ietf.org/doc/html/rfc9369#appendix-A.5

        # server
        secret = binascii.unhexlify(
            "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
        )
        key, iv, hp = derive_key_iv_hp(
            cipher_suite=CipherSuite.CHACHA20_POLY1305_SHA256,
            secret=secret,
            version=PROTOCOL_VERSION,
        )
        self.assertEqual(
            key,
            binascii.unhexlify(
                "3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2"
            ),
        )
        self.assertEqual(iv, binascii.unhexlify("a6b5bc6ab7dafce30ffff5dd"))
        self.assertEqual(
            hp,
            binascii.unhexlify(
                "d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2"
            ),
        )

    @skipIf("chacha20" in SKIP_TESTS, "Skipping chacha20 tests")
    def test_decrypt_chacha20(self):
        pair = CryptoPair()
        pair.recv.setup(
            cipher_suite=CipherSuite.CHACHA20_POLY1305_SHA256,
            secret=binascii.unhexlify(
                "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
            ),
            version=PROTOCOL_VERSION,
        )

        plain_header, plain_payload, packet_number = pair.decrypt_packet(
            CHACHA20_CLIENT_ENCRYPTED_PACKET, 1, CHACHA20_CLIENT_PACKET_NUMBER
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
                "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
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
