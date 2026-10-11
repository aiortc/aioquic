import math
from unittest import TestCase

from aioquic import tls
from aioquic.quic.packet import QuicPacketType
from aioquic.quic.packet_builder import QuicSentPacket
from aioquic.quic.rangeset import RangeSet
from aioquic.quic.recovery import QuicPacketRecovery, QuicPacketSpace


def ack_eliciting_packet(
    *, epoch: tls.Epoch, packet_type: QuicPacketType, sent_time: float
) -> QuicSentPacket:
    return QuicSentPacket(
        epoch=epoch,
        in_flight=True,
        is_ack_eliciting=True,
        is_crypto_packet=False,
        packet_number=0,
        packet_type=packet_type,
        sent_bytes=1280,
        sent_time=sent_time,
    )


def send_probe():
    pass


def take_rtt_sample(recovery: QuicPacketRecovery, space: QuicPacketSpace) -> None:
    """
    Send a packet at 0.0 and receive its acknowledgment at 0.1, which gives a
    PTO period of 0.3 without max_ack_delay.
    """
    recovery.on_packet_sent(
        packet=ack_eliciting_packet(
            epoch=tls.Epoch.INITIAL,
            packet_type=QuicPacketType.INITIAL,
            sent_time=0.0,
        ),
        space=space,
    )
    recovery.on_ack_received(
        ack_rangeset=RangeSet([range(0, 1)]),
        ack_delay=0.0,
        now=0.1,
        space=space,
    )


class QuicPacketRecoveryRenoTest(TestCase):
    def setUp(self):
        self.INITIAL_SPACE = QuicPacketSpace()
        self.HANDSHAKE_SPACE = QuicPacketSpace()
        self.ONE_RTT_SPACE = QuicPacketSpace(is_application_data=True)

        self.recovery = QuicPacketRecovery(
            congestion_control_algorithm="reno",
            initial_rtt=0.1,
            max_datagram_size=1280,
            peer_completed_address_validation=True,
            send_probe=send_probe,
        )
        self.recovery.spaces = [
            self.INITIAL_SPACE,
            self.HANDSHAKE_SPACE,
            self.ONE_RTT_SPACE,
        ]

    def test_discard_space(self):
        self.recovery.discard_space(self.INITIAL_SPACE)

    def test_get_loss_detection_time_application_data(self):
        take_rtt_sample(self.recovery, self.INITIAL_SPACE)

        # The PTO is not armed before the handshake is confirmed.
        self.recovery.on_packet_sent(
            packet=ack_eliciting_packet(
                epoch=tls.Epoch.ONE_RTT,
                packet_type=QuicPacketType.ONE_RTT,
                sent_time=1.0,
            ),
            space=self.ONE_RTT_SPACE,
        )
        self.assertIsNone(self.recovery.get_loss_detection_time())

        # The PTO is armed once the handshake is confirmed, including max_ack_delay.
        self.recovery.handshake_confirmed = True
        self.recovery.on_packet_sent(
            packet=ack_eliciting_packet(
                epoch=tls.Epoch.ONE_RTT,
                packet_type=QuicPacketType.ONE_RTT,
                sent_time=2.0,
            ),
            space=self.ONE_RTT_SPACE,
        )
        self.assertAlmostEqual(self.recovery.get_loss_detection_time(), 2.325)

    def test_get_loss_detection_time_handshake(self):
        take_rtt_sample(self.recovery, self.INITIAL_SPACE)

        # The PTO does not include max_ack_delay.
        self.recovery.on_packet_sent(
            packet=ack_eliciting_packet(
                epoch=tls.Epoch.HANDSHAKE,
                packet_type=QuicPacketType.HANDSHAKE,
                sent_time=1.0,
            ),
            space=self.HANDSHAKE_SPACE,
        )
        self.assertAlmostEqual(self.recovery.get_loss_detection_time(), 1.3)

    def test_get_loss_detection_time_nothing_in_flight(self):
        self.assertIsNone(self.recovery.get_loss_detection_time())

    def test_get_loss_detection_time_without_address_validation(self):
        self.recovery.peer_completed_address_validation = False
        self.recovery.on_packet_sent(
            packet=ack_eliciting_packet(
                epoch=tls.Epoch.INITIAL,
                packet_type=QuicPacketType.INITIAL,
                sent_time=0.0,
            ),
            space=self.INITIAL_SPACE,
        )
        self.recovery.discard_space(self.INITIAL_SPACE)

        # The client keeps the PTO armed with nothing in flight.
        self.assertAlmostEqual(self.recovery.get_loss_detection_time(), 0.2)

    def test_on_ack_received_ack_eliciting(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )
        space = self.ONE_RTT_SPACE

        #  packet sent
        self.recovery.on_packet_sent(packet=packet, space=space)
        self.assertEqual(self.recovery.bytes_in_flight, 1280)
        self.assertEqual(space.ack_eliciting_in_flight, 1)
        self.assertEqual(len(space.sent_packets), 1)

        # packet ack'd
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(0, 1)]),
            ack_delay=0.0,
            now=10.0,
            space=space,
        )
        self.assertEqual(self.recovery.bytes_in_flight, 0)
        self.assertEqual(space.ack_eliciting_in_flight, 0)
        self.assertEqual(len(space.sent_packets), 0)

        # check RTT
        self.assertTrue(self.recovery._rtt_initialized)
        self.assertEqual(self.recovery._rtt_latest, 10.0)
        self.assertEqual(self.recovery._rtt_min, 10.0)
        self.assertEqual(self.recovery._rtt_smoothed, 10.0)

    def test_on_ack_received_non_ack_eliciting(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=False,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=123.45,
        )
        space = self.ONE_RTT_SPACE

        #  packet sent
        self.recovery.on_packet_sent(packet=packet, space=space)
        self.assertEqual(self.recovery.bytes_in_flight, 1280)
        self.assertEqual(space.ack_eliciting_in_flight, 0)
        self.assertEqual(len(space.sent_packets), 1)

        # packet ack'd
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(0, 1)]),
            ack_delay=0.0,
            now=10.0,
            space=space,
        )
        self.assertEqual(self.recovery.bytes_in_flight, 0)
        self.assertEqual(space.ack_eliciting_in_flight, 0)
        self.assertEqual(len(space.sent_packets), 0)

        # check RTT
        self.assertFalse(self.recovery._rtt_initialized)
        self.assertEqual(self.recovery._rtt_latest, 0.0)
        self.assertEqual(self.recovery._rtt_min, math.inf)
        self.assertEqual(self.recovery._rtt_smoothed, 0.0)

    def test_on_ack_received_without_address_validation(self):
        self.recovery.peer_completed_address_validation = False
        self.recovery.on_packet_sent(
            packet=ack_eliciting_packet(
                epoch=tls.Epoch.INITIAL,
                packet_type=QuicPacketType.INITIAL,
                sent_time=0.0,
            ),
            space=self.INITIAL_SPACE,
        )
        self.recovery.on_loss_detection_timeout(now=0.2)
        self.assertEqual(self.recovery._pto_count, 1)

        # The PTO count is not reset by an INITIAL acknowledgment.
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(0, 1)]),
            ack_delay=0.0,
            now=0.3,
            space=self.INITIAL_SPACE,
        )
        self.assertEqual(self.recovery._pto_count, 1)

        # The PTO count is reset once the server validated the client's address.
        self.recovery.peer_completed_address_validation = True
        self.recovery.on_packet_sent(
            packet=ack_eliciting_packet(
                epoch=tls.Epoch.HANDSHAKE,
                packet_type=QuicPacketType.HANDSHAKE,
                sent_time=0.3,
            ),
            space=self.HANDSHAKE_SPACE,
        )
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(0, 1)]),
            ack_delay=0.0,
            now=0.4,
            space=self.HANDSHAKE_SPACE,
        )
        self.assertEqual(self.recovery._pto_count, 0)

    def test_on_packet_lost_crypto(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.INITIAL,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=True,
            packet_number=0,
            packet_type=QuicPacketType.INITIAL,
            sent_bytes=1280,
            sent_time=0.0,
        )
        space = self.INITIAL_SPACE

        self.recovery.on_packet_sent(packet=packet, space=space)
        self.assertEqual(self.recovery.bytes_in_flight, 1280)
        self.assertEqual(space.ack_eliciting_in_flight, 1)
        self.assertEqual(len(space.sent_packets), 1)

        self.recovery._detect_loss(space=space, now=1.0)
        self.assertEqual(self.recovery.bytes_in_flight, 0)
        self.assertEqual(space.ack_eliciting_in_flight, 0)
        self.assertEqual(len(space.sent_packets), 0)
