import binascii
from unittest import TestCase

from aioquic.buffer import Buffer, BufferReadError
from aioquic.quic import packet
from aioquic.quic.packet import (
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_RETRY,
    QuicPreferredAddress,
    QuicProtocolVersion,
    QuicTransportParameters,
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

from .utils import load


class PacketTest(TestCase):
    def test_decode_packet_number(self):
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

    def test_pull_empty(self):
        buf = Buffer(data=b"")
        with self.assertRaises(BufferReadError):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_initial_client(self):
        buf = Buffer(data=load("initial_client.bin"))
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertTrue(header.is_long_header)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_1)
        self.assertEqual(header.packet_type, PACKET_TYPE_INITIAL)
        self.assertEqual(header.destination_cid, binascii.unhexlify("858b39368b8e3c6e"))
        self.assertEqual(header.source_cid, b"")
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(header.rest_length, 1262)
        self.assertEqual(buf.tell(), 18)

    def test_pull_initial_client_truncated(self):
        buf = Buffer(data=load("initial_client.bin")[0:100])
        with self.assertRaises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(str(cm.exception), "Packet payload is truncated")

    def test_pull_initial_server(self):
        buf = Buffer(data=load("initial_server.bin"))
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertTrue(header.is_long_header)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_1)
        self.assertEqual(header.packet_type, PACKET_TYPE_INITIAL)
        self.assertEqual(header.destination_cid, b"")
        self.assertEqual(header.source_cid, binascii.unhexlify("195c68344e28d479"))
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(header.rest_length, 184)
        self.assertEqual(buf.tell(), 18)

    def test_pull_retry(self):
        original_destination_cid = binascii.unhexlify("fbbd219b7363b64b")

        data = load("retry.bin")
        buf = Buffer(data=data)
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertTrue(header.is_long_header)
        self.assertEqual(header.version, QuicProtocolVersion.VERSION_1)
        self.assertEqual(header.packet_type, PACKET_TYPE_RETRY)
        self.assertEqual(header.destination_cid, binascii.unhexlify("e9d146d8d14cb28e"))
        self.assertEqual(
            header.source_cid,
            binascii.unhexlify("0b0a205a648fcf82d85f128b67bbe08053e6"),
        )
        self.assertEqual(
            header.token,
            binascii.unhexlify(
                "44397a35d698393c134b08a932737859f446d3aadd00ed81540c8d8de172"
                "906d3e7a111b503f9729b8928e7528f9a86a4581f9ebb4cb3b53c283661e"
                "8530741a99192ee56914c5626998ec0f"
            ),
        )
        self.assertEqual(
            header.integrity_tag, binascii.unhexlify("4620aafd42f1d630588b27575a12da5c")
        )
        self.assertEqual(header.rest_length, 0)
        self.assertEqual(buf.tell(), 125)

        # check integrity
        if False:
            self.assertEqual(
                get_retry_integrity_tag(
                    buf.data_slice(0, 109),
                    original_destination_cid,
                    version=header.version,
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
        )
        with open("bob.bin", "wb") as fp:
            fp.write(encoded)
        self.assertEqual(encoded, data)

    def test_pull_retry_draft_29(self):
        original_destination_cid = binascii.unhexlify("fbbd219b7363b64b")

        data = load("retry_draft_29.bin")
        buf = Buffer(data=data)
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertTrue(header.is_long_header)
        self.assertEqual(header.version, QuicProtocolVersion.DRAFT_29)
        self.assertEqual(header.packet_type, PACKET_TYPE_RETRY)
        self.assertEqual(header.destination_cid, binascii.unhexlify("e9d146d8d14cb28e"))
        self.assertEqual(
            header.source_cid,
            binascii.unhexlify("0b0a205a648fcf82d85f128b67bbe08053e6"),
        )
        self.assertEqual(
            header.token,
            binascii.unhexlify(
                "44397a35d698393c134b08a932737859f446d3aadd00ed81540c8d8de172"
                "906d3e7a111b503f9729b8928e7528f9a86a4581f9ebb4cb3b53c283661e"
                "8530741a99192ee56914c5626998ec0f"
            ),
        )
        self.assertEqual(
            header.integrity_tag, binascii.unhexlify("e65b170337b611270f10f4e633b6f51b")
        )
        self.assertEqual(header.rest_length, 0)
        self.assertEqual(buf.tell(), 125)

        # check integrity
        self.assertEqual(
            get_retry_integrity_tag(
                buf.data_slice(0, 109), original_destination_cid, version=header.version
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
        )
        self.assertEqual(encoded, data)

    def test_pull_version_negotiation(self):
        buf = Buffer(data=load("version_negotiation.bin"))
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertTrue(header.is_long_header)
        self.assertEqual(header.version, QuicProtocolVersion.NEGOTIATION)
        self.assertEqual(header.packet_type, None)
        self.assertEqual(header.destination_cid, binascii.unhexlify("9aac5a49ba87a849"))
        self.assertEqual(header.source_cid, binascii.unhexlify("f92f4336fa951ba1"))
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(header.rest_length, 8)
        self.assertEqual(buf.tell(), 23)

        versions = []
        while not buf.eof():
            versions.append(buf.pull_uint32())
        self.assertEqual(versions, [0x45474716, QuicProtocolVersion.VERSION_1]),

    def test_pull_long_header_dcid_too_long(self):
        buf = Buffer(
            data=binascii.unhexlify(
                "c6ff0000161500000000000000000000000000000000000000000000004"
                "01c514f99ec4bbf1f7a30f9b0c94fef717f1c1d07fec24c99a864da7ede"
            )
        )
        with self.assertRaises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(str(cm.exception), "Destination CID is too long (21 bytes)")

    def test_pull_long_header_scid_too_long(self):
        buf = Buffer(
            data=binascii.unhexlify(
                "c2ff0000160015000000000000000000000000000000000000000000004"
                "01cfcee99ec4bbf1f7a30f9b0c9417b8c263cdd8cc972a4439d68a46320"
            )
        )
        with self.assertRaises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(str(cm.exception), "Source CID is too long (21 bytes)")

    def test_pull_long_header_no_fixed_bit(self):
        buf = Buffer(data=b"\x80\xff\x00\x00\x11\x00\x00")
        with self.assertRaises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(str(cm.exception), "Packet fixed bit is zero")

    def test_pull_long_header_too_short(self):
        buf = Buffer(data=b"\xc0\x00")
        with self.assertRaises(BufferReadError):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_short_header(self):
        buf = Buffer(data=load("short_header.bin"))
        header = pull_quic_header(buf, host_cid_length=8)
        self.assertFalse(header.is_long_header)
        self.assertEqual(header.version, None)
        self.assertEqual(header.packet_type, 0x50)
        self.assertEqual(header.destination_cid, binascii.unhexlify("f45aa7b59c0e1ad6"))
        self.assertEqual(header.source_cid, b"")
        self.assertEqual(header.token, b"")
        self.assertEqual(header.integrity_tag, b"")
        self.assertEqual(header.rest_length, 12)
        self.assertEqual(buf.tell(), 9)

    def test_pull_short_header_no_fixed_bit(self):
        buf = Buffer(data=b"\x00")
        with self.assertRaises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        self.assertEqual(str(cm.exception), "Packet fixed bit is zero")

    def test_encode_quic_version_negotiation(self):
        data = encode_quic_version_negotiation(
            destination_cid=binascii.unhexlify("9aac5a49ba87a849"),
            source_cid=binascii.unhexlify("f92f4336fa951ba1"),
            supported_versions=[0x45474716, QuicProtocolVersion.VERSION_1],
        )
        self.assertEqual(data[1:], load("version_negotiation.bin")[1:])


class ParamsTest(TestCase):
    maxDiff = None

    def test_params(self):
        data = binascii.unhexlify(
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

    def test_params_disable_active_migration(self):
        data = binascii.unhexlify("0c00")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(params, QuicTransportParameters(disable_active_migration=True))

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        self.assertEqual(buf.data, data)

    def test_params_preferred_address(self):
        data = binascii.unhexlify(
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
        buf = Buffer(capacity=1000)
        push_quic_transport_parameters(buf, params)
        self.assertEqual(buf.data, data)

    def test_params_unknown(self):
        data = binascii.unhexlify("8000ff000100")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        self.assertEqual(params, QuicTransportParameters())

    def test_preferred_address_ipv4_only(self):
        data = binascii.unhexlify(
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

    def test_preferred_address_ipv6_only(self):
        data = binascii.unhexlify(
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
    def test_ack_frame(self):
        data = b"\x00\x02\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 1)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        self.assertEqual(buf.data, data)

    def test_ack_frame_with_one_range(self):
        data = b"\x02\x02\x01\x00\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 1), range(2, 3)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        self.assertEqual(buf.data, data)

    def test_ack_frame_with_one_range_2(self):
        data = b"\x05\x02\x01\x00\x00\x03"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 4), range(5, 6)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        self.assertEqual(buf.data, data)

    def test_ack_frame_with_one_range_3(self):
        data = b"\x05\x02\x01\x00\x01\x02"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 3), range(5, 6)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        self.assertEqual(buf.data, data)

    def test_ack_frame_with_two_ranges(self):
        data = b"\x04\x02\x02\x00\x00\x00\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        self.assertEqual(list(rangeset), [range(0, 1), range(2, 3), range(4, 5)])
        self.assertEqual(delay, 2)

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        self.assertEqual(buf.data, data)
