from unittest import TestCase

from aioquic.quic.congestion.base import K_INITIAL_WINDOW, K_MINIMUM_WINDOW
from aioquic.quic.congestion.reno import RenoCongestionControl

from .utils import ack_eliciting_packet


class RenoCongestionControlTest(TestCase):
    def setUp(self):
        self.reno = RenoCongestionControl(max_datagram_size=1280)

    def test_congestion_avoidance(self):
        self.reno.ssthresh = self.reno.congestion_window

        # The window grows by one datagram once a full window is acknowledged.
        for i in range(K_INITIAL_WINDOW - 1):
            self.reno.on_packet_acked(
                now=1.0, packet=ack_eliciting_packet(sent_time=0.5)
            )
        self.assertEqual(self.reno.congestion_window, K_INITIAL_WINDOW * 1280)

        self.reno.on_packet_acked(now=1.0, packet=ack_eliciting_packet(sent_time=0.5))
        self.assertEqual(self.reno.congestion_window, (K_INITIAL_WINDOW + 1) * 1280)

    def test_log_data(self):
        self.assertEqual(
            self.reno.get_log_data(),
            {"cwnd": K_INITIAL_WINDOW * 1280, "bytes_in_flight": 0},
        )

        self.reno.ssthresh = 5000
        self.assertEqual(
            self.reno.get_log_data(),
            {"cwnd": K_INITIAL_WINDOW * 1280, "bytes_in_flight": 0, "ssthresh": 5000},
        )

    def test_packet_acked_during_recovery(self):
        self.reno.on_packets_lost(
            now=1.0, packets=[ack_eliciting_packet(sent_time=0.5)]
        )
        self.assertEqual(self.reno.congestion_window, 5 * 1280)

        # The window does not grow for packets sent before recovery started.
        for i in range(5):
            self.reno.on_packet_acked(
                now=2.0, packet=ack_eliciting_packet(sent_time=1.0)
            )
        self.assertEqual(self.reno.congestion_window, 5 * 1280)

        # It grows again for packets sent after.
        for i in range(5):
            self.reno.on_packet_acked(
                now=2.0, packet=ack_eliciting_packet(sent_time=1.5)
            )
        self.assertEqual(self.reno.congestion_window, 6 * 1280)

    def test_packet_expired(self):
        packet = ack_eliciting_packet(sent_time=0.0)
        self.reno.on_packet_sent(packet=packet)
        self.assertEqual(self.reno.bytes_in_flight, 1280)

        self.reno.on_packets_expired(packets=[packet])
        self.assertEqual(self.reno.bytes_in_flight, 0)

    def test_packet_lost(self):
        packet = ack_eliciting_packet(sent_time=0.5)
        self.reno.on_packet_sent(packet=packet)

        # The window is halved and recovery starts.
        self.reno.on_packets_lost(now=1.0, packets=[packet])
        self.assertEqual(self.reno.bytes_in_flight, 0)
        self.assertEqual(self.reno.congestion_window, K_INITIAL_WINDOW * 1280 // 2)
        self.assertEqual(self.reno.ssthresh, self.reno.congestion_window)

        # A packet sent before recovery started does not reduce it again.
        self.reno.on_packets_lost(
            now=2.0, packets=[ack_eliciting_packet(sent_time=0.9)]
        )
        self.assertEqual(self.reno.congestion_window, K_INITIAL_WINDOW * 1280 // 2)

        # A packet sent after recovery started does.
        self.reno.on_packets_lost(
            now=3.0, packets=[ack_eliciting_packet(sent_time=1.5)]
        )
        self.assertEqual(self.reno.congestion_window, K_INITIAL_WINDOW * 1280 // 4)

    def test_packet_lost_minimum_window(self):
        for i in range(10):
            self.reno.on_packets_lost(
                now=i + 1.0, packets=[ack_eliciting_packet(sent_time=i + 0.5)]
            )
        self.assertEqual(self.reno.congestion_window, K_MINIMUM_WINDOW * 1280)

    def test_persistent_congestion(self):
        self.reno.on_packets_lost(
            now=1.0, packets=[ack_eliciting_packet(sent_time=0.5)]
        )

        # The window collapses to the minimum and recovery ends.
        self.reno.on_persistent_congestion()
        self.assertEqual(self.reno.congestion_window, K_MINIMUM_WINDOW * 1280)
        self.assertEqual(self.reno._congestion_recovery_start_time, 0.0)

    def test_rtt_increasing_exits_slow_start(self):
        # Get some low RTT samples.
        for i in range(10):
            self.reno.on_rtt_measurement(now=i + 1, rtt=1)
        self.assertIsNone(self.reno.ssthresh)

        # The RTT increases, for instance because of congestion.
        for i in range(10):
            self.reno.on_rtt_measurement(now=100 + i, rtt=1000)
        self.assertEqual(self.reno.ssthresh, self.reno.congestion_window)

    def test_slow_start(self):
        # The window grows by the size of each acknowledged packet.
        self.reno.on_packet_acked(now=1.0, packet=ack_eliciting_packet(sent_time=0.5))
        self.assertEqual(self.reno.congestion_window, (K_INITIAL_WINDOW + 1) * 1280)
