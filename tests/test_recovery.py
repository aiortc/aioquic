import math
from unittest import TestCase

from aioquic import tls
from aioquic.quic.congestion.base import K_MINIMUM_WINDOW
from aioquic.quic.packet import QuicPacketType
from aioquic.quic.packet_builder import QuicDeliveryState, QuicSentPacket
from aioquic.quic.rangeset import RangeSet
from aioquic.quic.recovery import (
    MAX_ACK_RANGES,
    QuicPacketNumberWindow,
    QuicPacketPacer,
    QuicPacketRecovery,
    QuicPacketSpace,
)

from .utils import ack_eliciting_packet


def send_one_rtt_packets(
    recovery: QuicPacketRecovery, space: QuicPacketSpace, sent_times: dict[int, float]
) -> None:
    """
    Send 1-RTT packets, given as a mapping of packet numbers to send times.
    """
    for packet_number, sent_time in sent_times.items():
        recovery.on_packet_sent(
            packet=ack_eliciting_packet(
                packet_number=packet_number, sent_time=sent_time
            ),
            space=space,
        )


def send_probe():
    """
    Stand in for the connection, which would send an ack-eliciting packet
    when the PTO fires.
    """


def send_watched_packets(
    recovery: QuicPacketRecovery, space: QuicPacketSpace, sent_times: dict[int, float]
) -> list[tuple[QuicDeliveryState, int]]:
    """
    Send ack-eliciting packets, given as a mapping of packet numbers to send
    times, and return the list in which their deliveries are recorded.
    """
    deliveries = []

    def on_delivery(delivery: QuicDeliveryState, packet_number: int) -> None:
        deliveries.append((delivery, packet_number))

    for packet_number, sent_time in sent_times.items():
        packet = ack_eliciting_packet(packet_number=packet_number, sent_time=sent_time)
        packet.delivery_handlers.append((on_delivery, (packet_number,)))
        recovery.on_packet_sent(packet=packet, space=space)
    return deliveries


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


class QuicPacketNumberWindowTest(TestCase):
    def test_empty(self):
        window = QuicPacketNumberWindow()
        self.assertNotIn(0, window)
        self.assertNotIn(7, window)
        self.assertNotIn(100, window)

    def test_add(self):
        window = QuicPacketNumberWindow()
        window.add(0)
        window.add(2)
        self.assertIn(0, window)
        self.assertNotIn(1, window)
        self.assertIn(2, window)
        self.assertNotIn(3, window)

    def test_slide(self):
        window = QuicPacketNumberWindow()
        size = 2 * MAX_ACK_RANGES
        window.add(1)
        window.add(5)
        window.add(size + 2)

        # packets below the window are considered received
        self.assertIn(0, window)
        self.assertIn(1, window)
        self.assertIn(2, window)

        # packets within the window are tracked individually
        self.assertNotIn(3, window)
        self.assertNotIn(4, window)
        self.assertIn(5, window)
        self.assertNotIn(size + 1, window)
        self.assertIn(size + 2, window)
        self.assertNotIn(size + 3, window)

        # adding a packet below the window is a no-op
        window.add(0)
        self.assertNotIn(3, window)

    def test_slide_beyond_size(self):
        window = QuicPacketNumberWindow()
        size = 2 * MAX_ACK_RANGES
        window.add(3)
        window.add(1000)
        self.assertIn(1000 - size, window)
        self.assertNotIn(1000 - size + 1, window)
        self.assertNotIn(999, window)
        self.assertIn(1000, window)
        self.assertNotIn(1001, window)


class QuicPacketPacerTest(TestCase):
    def setUp(self):
        self.pacer = QuicPacketPacer(max_datagram_size=1280)

    def test_no_measurement(self):
        self.assertIsNone(self.pacer.next_send_time(now=0.0))
        self.pacer.update_after_send(now=0.0)

        self.assertIsNone(self.pacer.next_send_time(now=0.0))
        self.pacer.update_after_send(now=0.0)

    def test_with_measurement(self):
        self.assertIsNone(self.pacer.next_send_time(now=0.0))
        self.pacer.update_after_send(now=0.0)

        self.pacer.update_rate(congestion_window=1280000, smoothed_rtt=0.05)
        self.assertEqual(self.pacer.bucket_max, 0.0008)
        self.assertEqual(self.pacer.bucket_time, 0.0)
        self.assertEqual(self.pacer.packet_time, 0.00005)

        # 16 packets
        for i in range(16):
            self.assertIsNone(self.pacer.next_send_time(now=1.0))
            self.pacer.update_after_send(now=1.0)
        self.assertAlmostEqual(self.pacer.next_send_time(now=1.0), 1.00005)

        # 2 packets
        for i in range(2):
            self.assertIsNone(self.pacer.next_send_time(now=1.00005))
            self.pacer.update_after_send(now=1.00005)
        self.assertAlmostEqual(self.pacer.next_send_time(now=1.00005), 1.0001)

        # 1 packet
        self.assertIsNone(self.pacer.next_send_time(now=1.0001))
        self.pacer.update_after_send(now=1.0001)
        self.assertAlmostEqual(self.pacer.next_send_time(now=1.0001), 1.00015)

        # 2 packets
        for i in range(2):
            self.assertIsNone(self.pacer.next_send_time(now=1.00015))
            self.pacer.update_after_send(now=1.00015)
        self.assertAlmostEqual(self.pacer.next_send_time(now=1.00015), 1.0002)


class QuicPacketRecoveryTest(TestCase):
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
            packet=ack_eliciting_packet(sent_time=1.0),
            space=self.ONE_RTT_SPACE,
        )
        self.assertIsNone(self.recovery.get_loss_detection_time())

        # The PTO is armed once the handshake is confirmed, including max_ack_delay.
        self.recovery.handshake_confirmed = True
        self.recovery.on_packet_sent(
            packet=ack_eliciting_packet(sent_time=2.0),
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

    def test_on_ack_received_with_ranges(self):
        # Packets 1 and 3 were acknowledged and packet 2 lost earlier, so the first
        # two ranges contain no packet in flight.
        deliveries = send_watched_packets(
            self.recovery, self.ONE_RTT_SPACE, dict.fromkeys([0, 4, 5, 6, 7, 8, 9], 1.0)
        )

        # Packets in the ranges are acknowledged, then those at least three below
        # the largest acknowledged one are lost (RFC 9002 section 6.1.1).
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(1, 2), range(3, 4), range(5, 6), range(8, 9)]),
            ack_delay=0.0,
            now=2.0,
            space=self.ONE_RTT_SPACE,
        )
        self.assertEqual(
            deliveries,
            [
                (QuicDeliveryState.ACKED, 5),
                (QuicDeliveryState.ACKED, 8),
                (QuicDeliveryState.LOST, 0),
                (QuicDeliveryState.LOST, 4),
            ],
        )
        self.assertEqual(list(self.ONE_RTT_SPACE.sent_packets), [6, 7, 9])

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

    def test_on_loss_detection_timeout_retransmits_oldest_packet(self):
        self.recovery.handshake_confirmed = True
        deliveries = send_watched_packets(
            self.recovery, self.ONE_RTT_SPACE, {0: 1.0, 1: 1.1}
        )
        congestion_window = self.recovery.congestion_window

        # The oldest packet's data is retransmitted, without a congestion event.
        self.recovery.on_loss_detection_timeout(now=2.0)
        self.assertEqual(deliveries, [(QuicDeliveryState.LOST, 0)])
        self.assertEqual(list(self.ONE_RTT_SPACE.sent_packets), [1])
        self.assertEqual(self.recovery.bytes_in_flight, 1280)
        self.assertEqual(self.recovery.congestion_window, congestion_window)

    def test_on_loss_detection_timeout_retransmits_oldest_packet_unconfirmed(self):
        one_rtt_deliveries = send_watched_packets(
            self.recovery, self.ONE_RTT_SPACE, {0: 1.0}
        )
        handshake_deliveries = send_watched_packets(
            self.recovery, self.HANDSHAKE_SPACE, {0: 1.1}
        )

        # Application data sent before the handshake is confirmed is skipped,
        # even though it is older.
        self.recovery.on_loss_detection_timeout(now=2.0)
        self.assertEqual(one_rtt_deliveries, [])
        self.assertEqual(handshake_deliveries, [(QuicDeliveryState.LOST, 0)])

    def test_on_loss_detection_timeout_with_crypto(self):
        self.recovery.handshake_confirmed = True
        deliveries = send_watched_packets(self.recovery, self.ONE_RTT_SPACE, {0: 1.0})
        self.recovery.on_packet_sent(
            packet=QuicSentPacket(
                epoch=tls.Epoch.HANDSHAKE,
                in_flight=True,
                is_ack_eliciting=True,
                is_crypto_packet=True,
                packet_number=0,
                packet_type=QuicPacketType.HANDSHAKE,
                sent_bytes=1280,
                sent_time=1.1,
            ),
            space=self.HANDSHAKE_SPACE,
        )

        congestion_window = self.recovery.congestion_window

        # Only the CRYPTO data is retransmitted, without a congestion event.
        self.recovery.on_loss_detection_timeout(now=2.0)
        self.assertEqual(deliveries, [])
        self.assertEqual(self.HANDSHAKE_SPACE.sent_packets, {})
        self.assertEqual(self.recovery.bytes_in_flight, 1280)
        self.assertEqual(self.recovery.congestion_window, congestion_window)

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

    def test_on_packets_lost_persistent_congestion(self):
        take_rtt_sample(self.recovery, self.INITIAL_SPACE)

        # Packets 1 and 2 are lost, and sent further apart than the persistent
        # congestion duration of 3 * (0.1 + 4 * 0.0375 + 0.025) = 0.825.
        send_one_rtt_packets(
            self.recovery, self.ONE_RTT_SPACE, {1: 1.0, 2: 2.0, 3: 2.1}
        )
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(3, 4)]),
            ack_delay=0.0,
            now=2.2,
            space=self.ONE_RTT_SPACE,
        )
        self.assertEqual(self.recovery.congestion_window, K_MINIMUM_WINDOW * 1280)

    def test_on_packets_lost_persistent_congestion_acked_in_between(self):
        take_rtt_sample(self.recovery, self.INITIAL_SPACE)

        # Packets 1 and 3 are lost, but packet 2 was acknowledged.
        send_one_rtt_packets(
            self.recovery, self.ONE_RTT_SPACE, {1: 1.0, 2: 1.5, 3: 2.0, 4: 2.1}
        )
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(2, 3), range(4, 5)]),
            ack_delay=0.0,
            now=2.2,
            space=self.ONE_RTT_SPACE,
        )
        self.assertEqual(self.recovery.congestion_window, 7680)

    def test_on_packets_lost_persistent_congestion_before_rtt_sample(self):
        # Packets 0 and 1 are lost, but were sent before the first RTT sample.
        send_one_rtt_packets(
            self.recovery, self.ONE_RTT_SPACE, {0: 0.0, 1: 2.0, 2: 2.1}
        )
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(2, 3)]),
            ack_delay=0.0,
            now=2.2,
            space=self.ONE_RTT_SPACE,
        )
        self.assertEqual(self.recovery.congestion_window, 7040)

    def test_on_packets_lost_persistent_congestion_short_period(self):
        take_rtt_sample(self.recovery, self.INITIAL_SPACE)

        # Packets 1 and 2 are lost, but sent within the persistent congestion
        # duration.
        send_one_rtt_packets(
            self.recovery, self.ONE_RTT_SPACE, {1: 1.5, 2: 2.0, 3: 2.1}
        )
        self.recovery.on_ack_received(
            ack_rangeset=RangeSet([range(3, 4)]),
            ack_delay=0.0,
            now=2.2,
            space=self.ONE_RTT_SPACE,
        )
        self.assertEqual(self.recovery.congestion_window, 7040)

    def test_reschedule_data_speed_up_handshake(self):
        self.recovery.handshake_confirmed = True
        deliveries = send_watched_packets(self.recovery, self.ONE_RTT_SPACE, {0: 1.0})

        # Speeding up handshake completion only retransmits CRYPTO data.
        self.recovery.reschedule_data(now=2.0, speed_up_handshake=True)
        self.assertEqual(deliveries, [])
        self.assertEqual(list(self.ONE_RTT_SPACE.sent_packets), [0])
