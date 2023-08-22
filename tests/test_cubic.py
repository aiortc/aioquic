from aioquic.quic.congestion import CubicCongestionControl, K_CUBIC_C, K_CUBIC_LOSS_REDUCTION_FACTOR, QuicSentPacket
import unittest

def W_cubic(t, K, W_max):
    return K_CUBIC_C * (t - K)**3 + (W_max)

def cube_root(x):
    if (x < 0): return -((-x)**(1/3))
    else: return x**(1/3)

class CubicTests(unittest.TestCase):

    def test_congestion_avoidance(self):
        """
        Check if the cubic implementation respects the mathematical formula defined in the rfc 9438
        """

        n = 4000  # number of ms to check

        W_max = 5  # starting W_max
        K = cube_root(W_max*(1-K_CUBIC_LOSS_REDUCTION_FACTOR)/K_CUBIC_C)
        cwnd = W_max*K_CUBIC_LOSS_REDUCTION_FACTOR

        correct = []

        for i in range(n):
            correct.append(W_cubic(i/1000, K, W_max))

        cubic = CubicCongestionControl(caller=None)
        cubic._W_max = W_max
        cubic._starting_congestion_avoidance = True
        cubic.congestion_window = cwnd
        cubic.ssthresh = cwnd

        results = []
        for i in range(n):
            cwnd = cubic.congestion_window # number of segments
            

            # simulate the reception of cwnd packets (a full window of acks)
            for _ in range(int(cwnd)):
                packet = QuicSentPacket(None, True, True, True, 0, 0)
                packet.sent_bytes = 10     # won't affect results
                rtt = 0
                cubic.on_packet_acked_timed(packet, i/1000, rtt)

            results.append(cubic.congestion_window)

        for i in range(n):
            # check if it is almost equal to the value of W_cubic
            self.assertTrue(correct[i]*0.99 <= results[i] <= 1.01*correct[i], F"Error at {i}ms, Result={results[i]}, Expected={correct[i]}")
        

if __name__ == '__main__':
    unittest.main()