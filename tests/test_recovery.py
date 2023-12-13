from unittest import TestCase

from aioquic.quic.congestion.base import QuicRttMonitor, create_congestion_control
from aioquic.quic.recovery import QuicPacketPacer


class QuicCongestionControlTest(TestCase):
    def test_create_unknown_congestion_control(self):
        with self.assertRaises(Exception) as cm:
            create_congestion_control("bogus", max_datagram_size=1280)
        self.assertEqual(
            str(cm.exception), "Unknown congestion control algorithm: bogus"
        )


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


class QuicRttMonitorTest(TestCase):
    def test_monitor(self):
        monitor = QuicRttMonitor()

        self.assertFalse(monitor.is_rtt_increasing(rtt=10, now=1000))
        self.assertEqual(monitor._samples, [10, 0.0, 0.0, 0.0, 0.0])
        self.assertFalse(monitor._ready)

        # not taken into account
        self.assertFalse(monitor.is_rtt_increasing(rtt=11, now=1000))
        self.assertEqual(monitor._samples, [10, 0.0, 0.0, 0.0, 0.0])
        self.assertFalse(monitor._ready)

        self.assertFalse(monitor.is_rtt_increasing(rtt=11, now=1001))
        self.assertEqual(monitor._samples, [10, 11, 0.0, 0.0, 0.0])
        self.assertFalse(monitor._ready)

        self.assertFalse(monitor.is_rtt_increasing(rtt=12, now=1002))
        self.assertEqual(monitor._samples, [10, 11, 12, 0.0, 0.0])
        self.assertFalse(monitor._ready)

        self.assertFalse(monitor.is_rtt_increasing(rtt=13, now=1003))
        self.assertEqual(monitor._samples, [10, 11, 12, 13, 0.0])
        self.assertFalse(monitor._ready)

        # we now have enough samples
        self.assertFalse(monitor.is_rtt_increasing(rtt=14, now=1004))
        self.assertEqual(monitor._samples, [10, 11, 12, 13, 14])
        self.assertTrue(monitor._ready)

        self.assertFalse(monitor.is_rtt_increasing(rtt=20, now=1005))
        self.assertEqual(monitor._increases, 0)

        self.assertFalse(monitor.is_rtt_increasing(rtt=30, now=1006))
        self.assertEqual(monitor._increases, 0)

        self.assertFalse(monitor.is_rtt_increasing(rtt=40, now=1007))
        self.assertEqual(monitor._increases, 0)

        self.assertFalse(monitor.is_rtt_increasing(rtt=50, now=1008))
        self.assertEqual(monitor._increases, 0)

        self.assertFalse(monitor.is_rtt_increasing(rtt=60, now=1009))
        self.assertEqual(monitor._increases, 1)

        self.assertFalse(monitor.is_rtt_increasing(rtt=70, now=1010))
        self.assertEqual(monitor._increases, 2)

        self.assertFalse(monitor.is_rtt_increasing(rtt=80, now=1011))
        self.assertEqual(monitor._increases, 3)

        self.assertFalse(monitor.is_rtt_increasing(rtt=90, now=1012))
        self.assertEqual(monitor._increases, 4)

        self.assertTrue(monitor.is_rtt_increasing(rtt=100, now=1013))
        self.assertEqual(monitor._increases, 5)
