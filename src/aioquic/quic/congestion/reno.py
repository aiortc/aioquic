from .congestion import QuicCongestionControl, K_LOSS_REDUCTION_FACTOR, K_INITIAL_WINDOW, K_MAX_DATAGRAM_SIZE, K_MINIMUM_WINDOW, QuicRttMonitor
from ..packet_builder import QuicSentPacket
from typing import Iterable, Optional, Dict, Any

class RenoCongestionControl(QuicCongestionControl):
    """
    New Reno congestion control.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.bytes_in_flight = 0
        self.congestion_window = K_INITIAL_WINDOW
        self._congestion_recovery_start_time = 0.0
        self._congestion_stash = 0
        self._rtt_monitor = QuicRttMonitor()
        self.ssthresh: Optional[int] = None

    def is_slow_start(self) -> bool:
        return self.ssthresh is None or self.congestion_window < self.ssthresh

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        super().on_packet_acked(packet)
        self.bytes_in_flight -= packet.sent_bytes

        # don't increase window in congestion recovery
        if packet.sent_time <= self._congestion_recovery_start_time:
            return

        if self.is_slow_start():
            # slow start
            self.congestion_window += packet.sent_bytes
        else:
            # congestion avoidance
            self._congestion_stash += packet.sent_bytes
            count = self._congestion_stash // self.congestion_window
            if count:
                self._congestion_stash -= count * self.congestion_window
                self.congestion_window += count * K_MAX_DATAGRAM_SIZE

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)
        self.bytes_in_flight += packet.sent_bytes

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)
        lost_largest_time = 0.0
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            lost_largest_time = packet.sent_time

        # start a new congestion event if packet was sent after the
        # start of the previous congestion recovery period.
        if lost_largest_time > self._congestion_recovery_start_time:
            self._congestion_recovery_start_time = now
            self.congestion_window = max(
                int(self.congestion_window * K_LOSS_REDUCTION_FACTOR), K_MINIMUM_WINDOW
            )
            self.ssthresh = self.congestion_window

        # TODO : collapse congestion window if persistent congestion

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)
        # check whether we should exit slow start
        if self.ssthresh is None and self._rtt_monitor.is_rtt_increasing(
            latest_rtt, now
        ):
            self.ssthresh = self.congestion_window

    def get_congestion_window(self) -> int:
        return int(self.congestion_window)
    
    def get_ssthresh(self) -> int: 
        if self.ssthresh == None: return None
        return int(self.ssthresh)
    
    def get_bytes_in_flight(self) -> int:
        return self.bytes_in_flight
    
    def log_callback(self) -> Dict[str, Any]:
        data = super().log_callback()
        if (self.is_slow_start()):
            data["Phase"] = "slow-start"
        else:
            data["Phase"] = "congestion-avoidance"
        return data