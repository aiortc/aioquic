import math
from unittest import TestCase

from aioquic import tls
from aioquic.quic.congestion.base import K_INITIAL_WINDOW, K_MINIMUM_WINDOW
from aioquic.quic.congestion.cubic import (
    K_CUBIC_C,
    K_CUBIC_LOSS_REDUCTION_FACTOR,
    CubicCongestionControl,
    better_cube_root,
)
from aioquic.quic.packet import PACKET_TYPE_INITIAL, PACKET_TYPE_ONE_RTT
from aioquic.quic.packet_builder import QuicSentPacket
from aioquic.quic.rangeset import RangeSet
from aioquic.quic.recovery import QuicPacketRecovery, QuicPacketSpace


def send_probe():
    pass


def W_cubic(t, K, W_max):
    return K_CUBIC_C * (t - K) ** 3 + (W_max)


class QuicPacketRecoveryCubicTest(TestCase):
    def setUp(self):
        self.INITIAL_SPACE = QuicPacketSpace()
        self.HANDSHAKE_SPACE = QuicPacketSpace()
        self.ONE_RTT_SPACE = QuicPacketSpace()

        self.recovery = QuicPacketRecovery(
            congestion_control_algorithm="cubic",
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

    def test_better_cube_root(self):
        self.assertAlmostEqual(better_cube_root(8), 2)
        self.assertAlmostEqual(better_cube_root(-8), -2)
        self.assertAlmostEqual(better_cube_root(0), 0)
        self.assertAlmostEqual(better_cube_root(27), 3)

    def test_discard_space(self):
        self.recovery.discard_space(self.INITIAL_SPACE)

    def test_on_ack_received_ack_eliciting(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
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
            packet_type=PACKET_TYPE_ONE_RTT,
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

    def test_on_packet_lost_crypto(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.INITIAL,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=True,
            packet_number=0,
            packet_type=PACKET_TYPE_INITIAL,
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

    def test_packet_expired(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )

        cubic = CubicCongestionControl(1440)
        cubic.on_packet_sent(packet=packet)

        cubic.on_packets_expired(packets=[packet])

        self.assertEqual(cubic.bytes_in_flight, 0)

    def test_log_data(self):
        cubic = CubicCongestionControl(1440)

        self.assertEqual(
            cubic.get_log_data(),
            {
                "cwnd": cubic.congestion_window,
                "bytes_in_flight": cubic.bytes_in_flight,
                "cubic-wmax": cubic._W_max,
            },
        )

        cubic._W_max = 5000
        cubic.ssthresh = 5000

        self.assertEqual(
            cubic.get_log_data(),
            {
                "cwnd": cubic.congestion_window,
                "ssthresh": cubic.ssthresh,
                "bytes_in_flight": cubic.bytes_in_flight,
                "cubic-wmax": cubic._W_max,
            },
        )

    def test_congestion_avoidance(self):
        """
        Check if the cubic implementation respects the mathematical
        formula defined in the rfc 9438
        """

        max_datagram_size = 1440

        n = 400  # number of ms to check

        W_max = 5  # starting W_max
        K = better_cube_root(W_max * (1 - K_CUBIC_LOSS_REDUCTION_FACTOR) / K_CUBIC_C)
        cwnd = W_max * K_CUBIC_LOSS_REDUCTION_FACTOR

        correct = []

        test_range = range(n)

        for i in test_range:
            correct.append(W_cubic(i / 1000, K, W_max) * max_datagram_size)

        cubic = CubicCongestionControl(max_datagram_size)
        cubic.rtt = 0
        cubic._W_max = W_max * max_datagram_size
        cubic._starting_congestion_avoidance = True
        cubic.congestion_window = cwnd * max_datagram_size
        cubic.ssthresh = cubic.congestion_window
        cubic._W_est = 0

        results = []
        for i in test_range:
            cwnd = cubic.congestion_window // max_datagram_size  # number of segments

            # simulate the reception of cwnd packets (a full window of acks)
            for _ in range(int(cwnd)):
                packet = QuicSentPacket(None, True, True, True, 0, 0)
                packet.sent_bytes = 0  # won't affect results

                cubic.on_packet_acked(packet=packet, now=(i / 1000))

            results.append(cubic.congestion_window)

        for i in test_range:
            # check if it is almost equal to the value of W_cubic
            self.assertTrue(
                correct[i] * 0.99 <= results[i] <= 1.01 * correct[i],
                f"Error at {i}ms, Result={results[i]}, Expected={correct[i]}",
            )

    def test_reset_idle(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=10.0,
        )

        max_datagram_size = 1440

        cubic = CubicCongestionControl(1440)
        # set last received at time 1
        cubic.last_ack = 1

        # receive a packet after 9s of idle time
        cubic.on_packet_sent(packet=packet)

        cubic.on_packets_expired(packets=[packet])

        self.assertEqual(cubic.congestion_window, K_INITIAL_WINDOW * max_datagram_size)

        self.assertIsNone(cubic.ssthresh)

        self.assertTrue(cubic._first_slow_start)
        self.assertFalse(cubic._starting_congestion_avoidance)
        self.assertEqual(cubic.K, 0.0)
        self.assertEqual(cubic._W_est, 0)
        self.assertEqual(cubic._cwnd_epoch, 0)
        self.assertEqual(cubic._t_epoch, 0.0)

        self.assertEqual(cubic._W_max, K_INITIAL_WINDOW * max_datagram_size)

    def test_reno_friendly_region(self):
        cubic = CubicCongestionControl(1440)
        cubic._W_max = 5000  # set the target number of bytes to 5000
        cubic._cwnd_epoch = 2880  # a cwnd of 1440 bytes when we had congestion
        cubic._starting_congestion_avoidance = False
        cubic._first_slow_start = False
        cubic.ssthresh = 2880
        cubic._t_epoch = 5

        # set an arbitrarily high W_est,
        # meaning that cubic would underperform compared to reno
        cubic._W_est = 100000

        # calculate K
        W_max_segments = cubic._W_max / cubic._max_datagram_size
        cwnd_epoch_segments = cubic._cwnd_epoch / cubic._max_datagram_size
        cubic.K = better_cube_root((W_max_segments - cwnd_epoch_segments) / K_CUBIC_C)

        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )

        previous_cwnd = cubic.congestion_window

        cubic.on_packet_acked(now=10, packet=packet)

        # congestion window should be equal to W_est (Reno estimated window)
        self.assertAlmostEqual(
            cubic.congestion_window,
            100000
            + cubic.additive_increase_factor * (packet.sent_bytes / previous_cwnd),
        )

    def test_convex_region(self):
        cubic = CubicCongestionControl(1440)
        cubic._W_max = 5000  # set the target number of bytes to 5000
        cubic._cwnd_epoch = 2880  # a cwnd of 1440 bytes when we had congestion
        cubic._starting_congestion_avoidance = False
        cubic._first_slow_start = False
        cubic.ssthresh = 2880
        cubic._t_epoch = 5

        cubic._W_est = 0

        # calculate K
        W_max_segments = cubic._W_max / cubic._max_datagram_size
        cwnd_epoch_segments = cubic._cwnd_epoch / cubic._max_datagram_size
        cubic.K = better_cube_root((W_max_segments - cwnd_epoch_segments) / K_CUBIC_C)

        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )

        previous_cwnd = cubic.congestion_window

        cubic.on_packet_acked(now=10, packet=packet)

        # elapsed time + basic rtt
        target = int(previous_cwnd * 1.5)

        expected = int(
            previous_cwnd
            + ((target - previous_cwnd) * (cubic._max_datagram_size / previous_cwnd))
        )

        # congestion window should be equal to W_est (Reno estimated window)
        self.assertAlmostEqual(cubic.congestion_window, expected)

    def test_concave_region(self):
        cubic = CubicCongestionControl(1440)
        cubic._W_max = 25000  # set the target number of bytes to 25000
        cubic._cwnd_epoch = 2880  # a cwnd of 1440 bytes when we had congestion
        cubic._starting_conges2ion_avoidance = False
        cubic._first_slow_start = False
        cubic.ssthresh = 2880
        cubic._t_epoch = 5

        cubic._W_est = 0

        # calculate K
        W_max_segments = cubic._W_max / cubic._max_datagram_size
        cwnd_epoch_segments = cubic._cwnd_epoch / cubic._max_datagram_size
        cubic.K = better_cube_root((W_max_segments - cwnd_epoch_segments) / K_CUBIC_C)

        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )

        previous_cwnd = cubic.congestion_window

        cubic.on_packet_acked(now=6, packet=packet)

        # elapsed time + basic rtt
        target = cubic.W_cubic(1 + 0.02)

        expected = int(
            previous_cwnd
            + ((target - previous_cwnd) * (cubic._max_datagram_size / previous_cwnd))
        )

        self.assertAlmostEqual(cubic.congestion_window, expected)

    def test_increasing_rtt(self):
        cubic = CubicCongestionControl(1440)

        # get some low rtt
        for i in range(10):
            cubic.on_rtt_measurement(now=i + 1, rtt=1)

        # rtt increase (because of congestion for example)
        for i in range(10):
            cubic.on_rtt_measurement(now=100 + i, rtt=1000)

        self.assertEqual(cubic.ssthresh, cubic.congestion_window)

    def test_increasing_rtt_exiting_slow_start(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=200.0,
        )

        cubic = CubicCongestionControl(1440)

        # get some low rtt
        for i in range(10):
            cubic.on_rtt_measurement(now=i + 1, rtt=1)

        # rtt increase (because of congestion for example)
        for i in range(10):
            cubic.on_rtt_measurement(now=100 + i, rtt=1000)

        previous_cwnd = cubic.congestion_window

        self.assertFalse(cubic._starting_congestion_avoidance)

        cubic.on_packet_acked(packet=packet, now=220)

        self.assertFalse(cubic._first_slow_start)
        self.assertEqual(cubic._W_max, previous_cwnd)
        self.assertEqual(cubic._t_epoch, 220)
        self.assertEqual(cubic._cwnd_epoch, previous_cwnd)
        self.assertEqual(
            cubic._W_est,
            previous_cwnd
            + cubic.additive_increase_factor * (packet.sent_bytes / previous_cwnd),
        )

        # calculate K
        W_max_segments = previous_cwnd / cubic._max_datagram_size
        cwnd_epoch_segments = previous_cwnd / cubic._max_datagram_size
        K = better_cube_root((W_max_segments - cwnd_epoch_segments) / K_CUBIC_C)

        self.assertEqual(cubic.K, K)

    def test_packet_lost(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=200.0,
        )

        packet2 = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=240.0,
        )

        cubic = CubicCongestionControl(1440)

        previous_cwnd = cubic.congestion_window

        cubic.on_packets_lost(now=210, packets=[packet])

        self.assertEqual(cubic._congestion_recovery_start_time, 210)

        self.assertEqual(cubic._W_max, previous_cwnd)
        self.assertEqual(cubic.ssthresh, K_MINIMUM_WINDOW * cubic._max_datagram_size)
        self.assertEqual(
            cubic.congestion_window, K_MINIMUM_WINDOW * cubic._max_datagram_size
        )
        self.assertTrue(cubic._starting_congestion_avoidance)

        previous_cwnd = cubic.congestion_window
        W_max = cubic._W_max

        cubic.on_packet_acked(now=250, packet=packet)

        self.assertFalse(cubic._starting_congestion_avoidance)
        self.assertFalse(cubic._first_slow_start)
        self.assertEqual(cubic._t_epoch, 250)
        self.assertEqual(cubic._cwnd_epoch, previous_cwnd)
        self.assertEqual(
            cubic._W_est,
            previous_cwnd
            + cubic.additive_increase_factor * (packet2.sent_bytes / previous_cwnd),
        )
        # calculate K
        W_max_segments = W_max / cubic._max_datagram_size
        cwnd_epoch_segments = previous_cwnd / cubic._max_datagram_size
        K = better_cube_root((W_max_segments - cwnd_epoch_segments) / K_CUBIC_C)

        self.assertEqual(cubic.K, K)

    def test_lost_with_W_max(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=200.0,
        )

        cubic = CubicCongestionControl(1440)

        cubic._W_max = 100000

        previous_cwnd = cubic.congestion_window

        cubic.on_packets_lost(now=210, packets=[packet])

        # test when W_max was much more than cwnd
        # and a loss occur
        self.assertEqual(
            cubic._W_max, previous_cwnd * (1 + K_CUBIC_LOSS_REDUCTION_FACTOR) / 2
        )

    def test_cwnd_target(self):
        cubic = CubicCongestionControl(1440)
        cubic._W_max = 25000  # set the target number of bytes to 25000
        cubic._cwnd_epoch = 2880  # a cwnd of 1440 bytes when we had congestion
        cubic._starting_conges2ion_avoidance = False
        cubic._first_slow_start = False
        cubic.ssthresh = 2880
        cubic._t_epoch = 5
        cubic.congestion_window = 100000

        cubic._W_est = 0

        # calculate K
        W_max_segments = cubic._W_max / cubic._max_datagram_size
        cwnd_epoch_segments = cubic._cwnd_epoch / cubic._max_datagram_size
        cubic.K = better_cube_root((W_max_segments - cwnd_epoch_segments) / K_CUBIC_C)

        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=PACKET_TYPE_ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )

        previous_cwnd = cubic.congestion_window

        cubic.on_packet_acked(now=6, packet=packet)

        # elapsed time + basic rtt
        target = previous_cwnd

        expected = int(
            previous_cwnd
            + ((target - previous_cwnd) * (cubic._max_datagram_size / previous_cwnd))
        )

        self.assertAlmostEqual(cubic.congestion_window, expected)
