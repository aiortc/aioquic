from unittest import TestCase

from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE
from aioquic.quic.congestion.cubic import (
    K_CUBIC_C,
    K_CUBIC_LOSS_REDUCTION_FACTOR,
    CubicCongestionControl,
    QuicSentPacket,
    cube_root,
)


def W_cubic(t, K, W_max):
    return K_CUBIC_C * (t - K) ** 3 + (W_max)


class CubicCongestionControlTest(TestCase):
    def test_congestion_avoidance(self):
        """
        Check if the cubic implementation respects the mathematical formula
        defined in the RFC 9438.
        """

        n = 400  # number of ms to check

        W_max = 5  # starting W_max
        K = cube_root(W_max * (1 - K_CUBIC_LOSS_REDUCTION_FACTOR) / K_CUBIC_C)
        cwnd = W_max * K_CUBIC_LOSS_REDUCTION_FACTOR
        max_datagram_size = SMALLEST_MAX_DATAGRAM_SIZE

        correct = []

        test_range = range(n)

        for i in test_range:
            correct.append(W_cubic(i / 1000, K, W_max) * max_datagram_size)

        cubic = CubicCongestionControl(max_datagram_size=max_datagram_size)
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
                cubic.on_packet_acked(packet=packet, now=i / 1000)

            results.append(cubic.congestion_window)

        for i in test_range:
            # check if it is almost equal to the value of W_cubic
            self.assertTrue(
                correct[i] * 0.99 <= results[i] <= 1.01 * correct[i],
                f"Error at {i}ms, Result={results[i]}, Expected={correct[i]}",
            )
