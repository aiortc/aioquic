from aioquic.buffer import Buffer, BufferReadError
from aioquic.quic import packet
from aioquic.quic.packet import (
    QuicPacketType,
    QuicPreferredAddress,
    QuicProtocolVersion,
    QuicTransportParameters,
    QuicVersionInformation,
    decode_packet_number,
    encode_quic_retry,
    encode_quic_version_negotiation,
    get_retry_integrity_tag,
    pull_quic_header,
    pull_quic_preferred_address,
    pull_quic_transport_parameters,
    push_quic_preferred_address,
    push_quic_transport_parameters,
)
from aioquic.quic.rangeset import RangeSet

from .test_crypto_v1 import LONG_CLIENT_ENCRYPTED_PACKET as CLIENT_INITIAL_V1
from .test_crypto_v1 import LONG_SERVER_ENCRYPTED_PACKET as SERVER_INITIAL_V1
from .test_crypto_v2 import LONG_CLIENT_ENCRYPTED_PACKET as CLIENT_INITIAL_V2
from .test_crypto_v2 import LONG_SERVER_ENCRYPTED_PACKET as SERVER_INITIAL_V2
from .utils import TestCase


class PacketTest(TestCase):
    def test_decode_packet_number(self) -> None:
        # expected = 0
        for i in range(0, 256):
            self.assertEqual(decode_packet_number(i, 8, expected=0), i)

        # expected = 128
        self.assertEqual(decode_packet_number(0, 8, expected=128), 256)
        for i in range(1, 256):
            self.assertEqual(decode_packet_number(i, 8, expected=128), i)

        # expected = 129
        self.assertEqual(decode_packet_number(0, 8, expected=129), 256)
        self.assertEqual(decode_packet_number(1, 8, expected=129), 257)
        for i in range(2, 256):
            self.assertEqual(decode_packet_number(i, 8, expected=129), i)

        # expected = 256
        for i in range(0, 128):
            self.assertEqual(decode_packet_number(i, 8, expected=256), 256 + i)
        for i in range(129, 256):
            self.assertEqual(decode_packet_number(i, 8, expected=256), i)

    def test_pull_empty(self) -> None:
        buf = Buffer(data=b"")
        with self.assertRaises(BufferReadError):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_initial_client_v1(self) -> None:
        buf = Buffer(data=CLIENT_INITIAL_V1)
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_1)
        self.assertEqual(header.packet_type, QuicPacketType.INITIAL)
        self.assertEqual(header.packet_length, 1200)
        self.assertEqual(header.destination_cid, bytes.fromhex("8394c8f03e515708"))
        self.assertEqual(header.source_cid, b"")
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(buf.tell(), 18)

    def test_pull_initial_client_v1_truncated(self) -> None:
        buf = Buffer(data=CLIENT_INITIAL_V1[0:100])
        with self.assertRaisesMessage(ValueError, "Packet payload is truncated"):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_initial_client_v2(self) -> None:
        buf = Buffer(data=CLIENT_INITIAL_V2)
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_2)
        self.assertEqual(header.packet_type, QuicPacketType.INITIAL)
        self.assertEqual(header.packet_length, 1200)
        self.assertEqual(header.destination_cid, bytes.fromhex("8394c8f03e515708"))
        self.assertEqual(header.source_cid, b"")
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(buf.tell(), 18)

    def test_pull_initial_server_v1(self) -> None:
        buf = Buffer(data=SERVER_INITIAL_V1)
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_1)
        self.assertEqual(header.packet_type, QuicPacketType.INITIAL)
        self.assertEqual(header.packet_length, 135)
        self.assertEqual(header.destination_cid, b"")
        self.assertEqual(header.source_cid, bytes.fromhex("f067a5502a4262b5"))
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(buf.tell(), 18)

    def test_pull_initial_server_v2(self) -> None:
        buf = Buffer(data=SERVER_INITIAL_V2)
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_2)
        self.assertEqual(header.packet_type, QuicPacketType.INITIAL)
        self.assertEqual(header.packet_length, 135)
        self.assertEqual(header.destination_cid, b"")
        self.assertEqual(header.source_cid, bytes.fromhex("f067a5502a4262b5"))
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(buf.tell(), 18)

    def test_pull_retry_v1(self) -> None:
        # https://datatracker.ietf.org/doc/html/rfc9001#appendix-A.4
        original_destination_cid = bytes.fromhex("8394c8f03e515708")

        data = bytes.fromhex(
            "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"
        )
        buf = Buffer(data=data)
        header = pull_quic_header(buf)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_1)
        self.assertEqual(header.packet_type, QuicPacketType.RETRY)
        self.assertEqual(header.packet_length, 36)
        self.assertEqual(header.destination_cid, b"")
        self.assertEqual(header.source_cid, bytes.fromhex("f067a5502a4262b5"))
        self.assertEqual(header.token, b"token")
        self.assertEqual(
            header.integrity_tag, bytes.fromhex("04a265ba2eff4d829058fb3f0f2496ba")
        )
        self.assertEqual(buf.tell(), 36)

        # check integrity
        self.assertEqual(
            get_retry_integrity_tag(
                buf.data_slice(0, 20), original_destination_cid, version=header.version
            ),
            header.integrity_tag,
        )

        # serialize
        encoded = encode_quic_retry(
            version=header.version,
            source_cid=header.source_cid,
            destination_cid=header.destination_cid,
            original_destination_cid=original_destination_cid,
            retry_token=header.token,
            # This value is arbitrary, we set it to match the value in the RFC.
            unused=0xF,
        )
        self.assertEqual(encoded, data)

    def test_pull_retry_v2(self) -> None:
        # https://datatracker.ietf.org/doc/html/rfc9369#appendix-A.4
        original_destination_cid = bytes.fromhex("8394c8f03e515708")

        data = bytes.fromhex(
            "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6"
        )
        buf = Buffer(data=data)
        header = pull_quic_header(buf)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_2)
        self.assertEqual(header.packet_type, QuicPacketType.RETRY)
        self.assertEqual(header.packet_length, 36)
        self.assertEqual(header.destination_cid, b"")
        self.assertEqual(header.source_cid, bytes.fromhex("f067a5502a4262b5"))
        self.assertEqual(header.token, b"token")
        self.assertEqual(
            header.integrity_tag, bytes.fromhex("c8646ce8bfe33952d955543665dcc7b6")
        )
        self.assertEqual(buf.tell(), 36)

        # check integrity
        self.assertEqual(
            get_retry_integrity_tag(
                buf.data_slice(0, 20), original_destination_cid, version=header.version
            ),
            header.integrity_tag,
        )

        # serialize
        encoded = encode_quic_retry(
            version=header.version,
            source_cid=header.source_cid,
            destination_cid=header.destination_cid,
            original_destination_cid=original_destination_cid,
            retry_token=header.token,
            # This value is arbitrary, we set it to match the value in the RFC.
            unused=0xF,
        )
        self.assertEqual(encoded, data)

    def test_pull_version_negotiation(self) -> None:
        data = bytes.fromhex(
            "ea00000000089aac5a49ba87a84908f92f4336fa951ba14547471600000001"
        )

        buf = Buffer(data=data)
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(header.version, QuicProtocolVersion.NEGOTIATION)
        self.assertEqual(header.packet_type, QuicPacketType.VERSION_NEGOTIATION)
        self.assertEqual(header.packet_length, 31)
        self.assertEqual(header.destination_cid, bytes.fromhex("9aac5a49ba87a849"))
        self.assertEqual(header.source_cid, bytes.fromhex("f92f4336fa951ba1"))
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(
            header.supported_versions, [0x45474716, QuicProtocolVersion.VERSION_1]
        )
        self.assertEqual(buf.tell(), 31)

        encoded = encode_quic_version_negotiation(
            destination_cid=header.destination_cid,
            source_cid=header.source_cid,
            supported_versions=header.supported_versions,
        )

        # The first byte may differ as it is random.
        self.assertEqual(encoded[1:], data[1:])

    def test_pull_long_header_dcid_too_long(self) -> None:
        buf = Buffer(
            data=bytes.fromhex(
                "c6ff0000161500000000000000000000000000000000000000000000004"
                "01c514f99ec4bbf1f7a30f9b0c94fef717f1c1d07fec24c99a864da7ede"
            )
        )
        with self.assertRaisesMessage(
            ValueError, "Destination CID is too long (21 bytes)"
        ):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_long_header_scid_too_long(self) -> None:
        buf = Buffer(
            data=bytes.fromhex(
                "c2ff0000160015000000000000000000000000000000000000000000004"
                "01cfcee99ec4bbf1f7a30f9b0c9417b8c263cdd8cc972a4439d68a46320"
            )
        )
        with self.assertRaisesMessage(ValueError, "Source CID is too long (21 bytes)"):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_long_header_no_fixed_bit(self) -> None:
        buf = Buffer(data=b"\x80\xff\x00\x00\x11\x00\x00")
        with self.assertRaisesMessage(ValueError, "Packet fixed bit is zero"):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_long_header_too_short(self) -> None:
        buf = Buffer(data=b"\xc0\x00")
        with self.assertRaises(BufferReadError):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_short_header(self) -> None:
        buf = Buffer(data=bytes.fromhex("5df45aa7b59c0e1ad6e668f5304cd4fd1fb3799327"))
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(header.version, None)
        self.assertEqual(header.packet_type, QuicPacketType.ONE_RTT)
        self.assertEqual(header.packet_length, 21)
        self.assertEqual(header.destination_cid, bytes.fromhex("f45aa7b59c0e1ad6"))
        self.assertEqual(header.source_cid, b"")
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(buf.tell(), 9)

    def test_pull_short_header_no_fixed_bit(self) -> None:
        buf = Buffer(data=b"\x00")
        with self.assertRaisesMessage(ValueError, "Packet fixed bit is zero"):
            pull_quic_header(buf, host_cid_length=8)


class ParamsTest(TestCase):
    maxDiff = None

    def test_params(self) -> None:
        data = bytes.fromhex(
            "010267100210cc2fd6e7d97a53ab5be85b28d75c8008030247e404048005fff"
            "a05048000ffff06048000ffff0801060a01030b0119"
        )

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(
            params,
            QuicTransportParameters(
                max_idle_timeout=10000,
                stateless_reset_token=b"\xcc/\xd6\xe7\xd9zS\xab[\xe8[(\xd7\\\x80\x08",
                max_udp_payload_size=2020,
                initial_max_data=393210,
                initial_max_stream_data_bidi_local=65535,
                initial_max_stream_data_bidi_remote=65535,
                initial_max_stream_data_uni=None,
                initial_max_streams_bidi=6,
                initial_max_streams_uni=None,
                ack_delay_exponent=3,
                max_ack_delay=25,
            ),
        )

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        self.assertEqual(len(buf.data), len(data))

    def test_params_disable_active_migration(self) -> None:
        data = bytes.fromhex("0c00")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(params, QuicTransportParameters(disable_active_migration=True))

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        self.assertEqual(buf.data, data)

    def test_params_max_ack_delay(self) -> None:
        data = bytes.fromhex("0b010a")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(params, QuicTransportParameters(max_ack_delay=10))

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        self.assertEqual(buf.data, data)

    def test_params_max_ack_delay_length_mismatch(self) -> None:
        buf = Buffer(data=bytes.fromhex("0b020a"))
        with self.assertRaisesMessage(
            ValueError, "Transport parameter length does not match"
        ):
            pull_quic_transport_parameters(buf)

    def test_params_preferred_address(self) -> None:
        data = bytes.fromhex(
            "0d3b8ba27b8611532400890200000000f03c91fffe69a45411531262c4518d6"
            "3013f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4"
        )

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(
            params,
            QuicTransportParameters(
                preferred_address=QuicPreferredAddress(
                    ipv4_address=("139.162.123.134", 4435),
                    ipv6_address=("2400:8902::f03c:91ff:fe69:a454", 4435),
                    connection_id=b"b\xc4Q\x8dc\x01?\x0c(~\xd3W>\xfa\x90\x95`7",
                    stateless_reset_token=b"F\xb2\xe0-EH\x0b\xa6d>\\n}H\xec\xb4",
                ),
            ),
        )

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        self.assertEqual(buf.data, data)

    def test_params_reset_stream_at(self) -> None:
        data = bytes.fromhex("1d00")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(params, QuicTransportParameters(reset_stream_at=True))

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        self.assertEqual(buf.data, data)

    def test_params_reset_stream_at_not_empty(self) -> None:
        buf = Buffer(data=bytes.fromhex("1d0100"))
        with self.assertRaisesMessage(
            ValueError, "Transport parameter length does not match"
        ):
            pull_quic_transport_parameters(buf)

    def test_params_unknown(self) -> None:
        data = bytes.fromhex("8000ff000100")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(params, QuicTransportParameters())

    def test_params_version_information(self) -> None:
        data = bytes.fromhex("110c00000001000000016b3343cf")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(
            params,
            QuicTransportParameters(
                version_information=QuicVersionInformation(
                    chosen_version=QuicProtocolVersion.VERSION_1,
                    available_versions=[
                        QuicProtocolVersion.VERSION_1,
                        QuicProtocolVersion.VERSION_2,
                    ],
                ),
            ),
        )

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        self.assertEqual(buf.data, data)

    def test_params_version_information_available_version_0(self) -> None:
        buf = Buffer(data=bytes.fromhex("11080000000100000000"))
        with self.assertRaisesMessage(
            ValueError, "Version Information must not contain version 0"
        ):
            pull_quic_transport_parameters(buf)

    def test_params_version_information_chosen_version_0(self) -> None:
        buf = Buffer(data=bytes.fromhex("110400000000"))
        with self.assertRaisesMessage(
            ValueError, "Version Information must not contain version 0"
        ):
            pull_quic_transport_parameters(buf)

    def test_params_version_information_length_not_divisible_by_four(self) -> None:
        buf = Buffer(data=bytes.fromhex("11050000000100"))
        with self.assertRaisesMessage(
            ValueError, "Transport parameter length does not match"
        ):
            pull_quic_transport_parameters(buf)

    def test_params_version_information_truncated(self) -> None:
        buf = Buffer(data=bytes.fromhex("110800000000"))
        with self.assertRaisesMessage(ValueError, "Read out of bounds"):
            pull_quic_transport_parameters(buf)

    def test_preferred_address_ipv4_only(self) -> None:
        data = bytes.fromhex(
            "8ba27b8611530000000000000000000000000000000000001262c4518d63013"
            "f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4"
        )

        # parse
        buf = Buffer(data=data)
        preferred_address = pull_quic_preferred_address(buf)
        self.assertEqual(
            preferred_address,
            QuicPreferredAddress(
                ipv4_address=("139.162.123.134", 4435),
                ipv6_address=None,
                connection_id=b"b\xc4Q\x8dc\x01?\x0c(~\xd3W>\xfa\x90\x95`7",
                stateless_reset_token=b"F\xb2\xe0-EH\x0b\xa6d>\\n}H\xec\xb4",
            ),
        )

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_preferred_address(buf, preferred_address)
        self.assertEqual(buf.data, data)

    def test_preferred_address_invalid_connection_id_length(self) -> None:
        for connection_id_length in [0, 21]:
            with self.subTest(connection_id_length=connection_id_length):
                buf = Buffer(capacity=64)
                buf.push_bytes(bytes(24))
                buf.push_uint8(connection_id_length)
                buf.push_bytes(bytes(connection_id_length + 16))
                buf.seek(0)
                with self.assertRaisesMessage(
                    ValueError,
                    "Invalid preferred address CID length "
                    f"({connection_id_length} bytes)",
                ):
                    pull_quic_preferred_address(buf)

    def test_preferred_address_ipv6_only(self) -> None:
        data = bytes.fromhex(
            "0000000000002400890200000000f03c91fffe69a45411531262c4518d63013"
            "f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4"
        )

        # parse
        buf = Buffer(data=data)
        preferred_address = pull_quic_preferred_address(buf)
        self.assertEqual(
            preferred_address,
            QuicPreferredAddress(
                ipv4_address=None,
                ipv6_address=("2400:8902::f03c:91ff:fe69:a454", 4435),
                connection_id=b"b\xc4Q\x8dc\x01?\x0c(~\xd3W>\xfa\x90\x95`7",
                stateless_reset_token=b"F\xb2\xe0-EH\x0b\xa6d>\\n}H\xec\xb4",
            ),
        )

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_preferred_address(buf, preferred_address)
        self.assertEqual(buf.data, data)


class FrameTest(TestCase):
    def test_ack_frame(self) -> None:
        data = b"\x00\x02\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 1)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay, buf.capacity)
        self.assertEqual(buf.data, data)

    def test_ack_frame_truncated(self) -> None:
        small = RangeSet([range(0, 1), range(2, 3), range(4, 5)])
        large = RangeSet([range(996, 997), range(998, 999), range(1000, 1001)])
        for rangeset, capacity, ranges, data in [
            # The largest possible encoding fits, all ranges are pushed.
            (small, 64, 3, b"\x04\x02\x02\x00\x00\x00\x00\x00"),
            # Fields take at most one byte, like the largest acknowledged packet
            # number, and the oldest ranges which do not fit are omitted.
            (small, 8, 3, b"\x04\x02\x02\x00\x00\x00\x00\x00"),
            (small, 7, 2, b"\x04\x02\x01\x00\x00\x00"),
            (small, 5, 1, b"\x04\x02\x00\x00"),
            # Fields take at most two bytes, like the largest acknowledged packet
            # number, so fewer ranges may be pushed than would fit.
            (large, 16, 3, b"\x43\xe8\x02\x02\x00\x00\x00\x00\x00"),
            (large, 15, 2, b"\x43\xe8\x02\x01\x00\x00\x00"),
            (large, 9, 1, b"\x43\xe8\x02\x00\x00"),
        ]:
            with self.subTest(rangeset=rangeset, capacity=capacity):
                buf = Buffer(capacity=capacity)
                self.assertEqual(
                    packet.push_ack_frame(buf, rangeset, 2, capacity), ranges
                )
                self.assertEqual(buf.data, data)

                # The newest ranges are pushed.
                buf = Buffer(data=data)
                self.assertEqual(
                    packet.pull_ack_frame(buf), (RangeSet(list(rangeset)[-ranges:]), 2)
                )

    def test_ack_frame_with_negative_first_range(self) -> None:
        # Largest acknowledged 0, first ACK range 1.
        buf = Buffer(data=b"\x00\x02\x00\x01")
        with self.assertRaisesMessage(
            ValueError, "ACK range contains a negative packet number"
        ):
            packet.pull_ack_frame(buf)

    def test_ack_frame_with_negative_gap(self) -> None:
        # Largest acknowledged 2, first ACK range 0, gap 1, ACK range 0.
        buf = Buffer(data=b"\x02\x02\x01\x00\x01\x00")
        with self.assertRaisesMessage(
            ValueError, "ACK range contains a negative packet number"
        ):
            packet.pull_ack_frame(buf)

    def test_ack_frame_with_one_range(self) -> None:
        data = b"\x02\x02\x01\x00\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 1), range(2, 3)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay, buf.capacity)
        self.assertEqual(buf.data, data)

    def test_ack_frame_with_one_range_2(self) -> None:
        data = b"\x05\x02\x01\x00\x00\x03"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 4), range(5, 6)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay, buf.capacity)
        self.assertEqual(buf.data, data)

    def test_ack_frame_with_one_range_3(self) -> None:
        data = b"\x05\x02\x01\x00\x01\x02"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 3), range(5, 6)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay, buf.capacity)
        self.assertEqual(buf.data, data)

    def test_ack_frame_with_two_ranges(self) -> None:
        data = b"\x04\x02\x02\x00\x00\x00\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 1), range(2, 3), range(4, 5)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay, buf.capacity)
        self.assertEqual(buf.data, data)
