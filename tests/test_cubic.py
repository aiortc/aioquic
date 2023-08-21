from aioquic.quic.recovery import CubicCongestionControl, K_CUBIC_C, K_CUBIC_LOSS_REDUCTION_FACTOR, QuicSentPacket
import unittest

def W_cubic(t, K, W_max):
    return K_CUBIC_C * (t - K)**3 + (W_max)

def cube_root(x):
    if (x < 0): return -((-x)**(1/3))
    else: return x**(1/3)

class CubicTests(unittest.TestCase):

    def test_congestion_avoidance(self):

        n = 20

        W_max = 20
        K = cube_root(W_max*(1-K_CUBIC_LOSS_REDUCTION_FACTOR)/K_CUBIC_C)
        cwnd = W_max*K_CUBIC_LOSS_REDUCTION_FACTOR

        correct = []

        for i in range(n):
            correct.append(W_cubic(i, K, W_max))

        cubic = CubicCongestionControl(caller=None)
        cubic._W_max = W_max
        cubic._starting_congestion_avoidance = True
        cubic.congestion_window = cwnd
        cubic.ssthresh = cwnd

        results = []
        for i in range(n):
            packet = QuicSentPacket(None, True, True, True, 0, 0)
            packet.sent_bytes = 10     # won't affect results
            cubic.on_packet_acked_timed(packet, i, 1000000)
            results.append(cubic.congestion_window)

        for i in range(n):
            self.assertAlmostEqual(correct[i], results[i])

        

if __name__ == '__main__':
    unittest.main()
