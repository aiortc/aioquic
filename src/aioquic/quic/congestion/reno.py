from .congestion import QuicCongestionControl, K_LOSS_REDUCTION_FACTOR, K_INITIAL_WINDOW, K_MAX_DATAGRAM_SIZE, K_MINIMUM_WINDOW, QuicRttMonitor
from ..packet_builder import QuicSentPacket
from .slow_starts.standard_slow_start import StandardSlowStart
from .slow_starts.slow_start import SlowStart
from typing import Iterable, Optional, Dict, Any

class RenoCongestionControl(QuicCongestionControl):
    """
    New Reno congestion control.
    """

    def __init__(self, callback=None, slow_start : SlowStart = StandardSlowStart()) -> None:
        super().__init__(callback=callback)
        self.bytes_in_flight = 0
        self.congestion_window = K_INITIAL_WINDOW
        self._congestion_recovery_start_time = 0.0
        self._congestion_stash = 0
        self.slow_start = slow_start
        self.slow_start.set_cc(self)

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        super().on_packet_acked(packet)
        self.bytes_in_flight -= packet.sent_bytes

        # don't increase window in congestion recovery
        if packet.sent_time <= self._congestion_recovery_start_time:
            return

        if self.slow_start.is_slow_start():
            # slow start
            self.slow_start.on_ack(packet)
        else:
            # congestion avoidance
            self._congestion_stash += packet.sent_bytes
            count = self._congestion_stash // self.congestion_window
            if count:
                self._congestion_stash -= count * self.congestion_window
                self.congestion_window += count * K_MAX_DATAGRAM_SIZE

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)
        self.slow_start.on_sent(packet)
        self.bytes_in_flight += packet.sent_bytes

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            self.slow_start.on_expired(packet)

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)
        lost_largest_time = 0.0
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            lost_largest_time = packet.sent_time
            self.slow_start.on_lost(packet)

        # start a new congestion event if packet was sent after the
        # start of the previous congestion recovery period.
        if lost_largest_time > self._congestion_recovery_start_time:
            self._congestion_recovery_start_time = now
            self.congestion_window = max(
                int(self.congestion_window * K_LOSS_REDUCTION_FACTOR), K_MINIMUM_WINDOW
            )
            self.slow_start.set_ssthresh(self.congestion_window)
            

        # TODO : collapse congestion window if persistent congestion

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)
        # check whether we should exit slow start
        self.slow_start.on_rtt_measured(latest_rtt, now)

    def get_congestion_window(self) -> int:
        return int(self.congestion_window)
    
    def _set_congestion_window(self, value):
        self.congestion_window = value
    
    def get_ssthresh(self) -> int: 
        return self.slow_start.get_ssthresh()
    
    def get_bytes_in_flight(self) -> int:
        return self.bytes_in_flight
    
    def log_callback(self) -> Dict[str, Any]:
        data = super().log_callback()
        if (self.slow_start.is_slow_start()):
            data["Phase"] = "slow-start"
        else:
            data["Phase"] = "congestion-avoidance"
        return data