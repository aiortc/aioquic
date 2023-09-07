from ..packet_builder import QuicSentPacket
from typing import Iterable, Optional, Dict, Any
from datetime import datetime
from copy import copy
from enum import Enum
import random
from dataclasses import dataclass
from .rs import RateSample

K_GRANULARITY = 0.001  # seconds

# congestion control
K_MAX_DATAGRAM_SIZE = 1280
K_INITIAL_WINDOW_SEGMENTS = 10
K_INITIAL_WINDOW = K_INITIAL_WINDOW_SEGMENTS * K_MAX_DATAGRAM_SIZE
K_MINIMUM_WINDOW_SEGMENTS = 2
K_MINIMUM_WINDOW = K_MINIMUM_WINDOW_SEGMENTS * K_MAX_DATAGRAM_SIZE
K_LOSS_REDUCTION_FACTOR = 0.5

class CongestionEvent(Enum):
    ACK=0
    PACKET_SENT=1
    PACKET_EXPIRED=2
    PACKET_LOST=3
    RTT_MEASURED=4

class QuicRttMonitor:
    """
    Roundtrip time monitor for HyStart.
    """

    def __init__(self) -> None:
        self._increases = 0
        self._last_time = None
        self._ready = False
        self._size = 5

        self._filtered_min: Optional[float] = None

        self._sample_idx = 0
        self._sample_max: Optional[float] = None
        self._sample_min: Optional[float] = None
        self._sample_time = 0.0
        self._samples = [0.0 for i in range(self._size)]

    def add_rtt(self, rtt: float) -> None:
        self._samples[self._sample_idx] = rtt
        self._sample_idx += 1

        if self._sample_idx >= self._size:
            self._sample_idx = 0
            self._ready = True

        if self._ready:
            self._sample_max = self._samples[0]
            self._sample_min = self._samples[0]
            for sample in self._samples[1:]:
                if sample < self._sample_min:
                    self._sample_min = sample
                elif sample > self._sample_max:
                    self._sample_max = sample

    def is_rtt_increasing(self, rtt: float, now: float) -> bool:
        if now > self._sample_time + K_GRANULARITY:
            self.add_rtt(rtt)
            self._sample_time = now

            if self._ready:
                if self._filtered_min is None or self._filtered_min > self._sample_max:
                    self._filtered_min = self._sample_max

                delta = self._sample_min - self._filtered_min
                if delta * 4 >= self._filtered_min:
                    self._increases += 1
                    if self._increases >= self._size:
                        return True
                elif delta > 0:
                    self._increases = 0
        return False
    

def Now():
    return datetime.timestamp(datetime.now())


class QuicCongestionControl:

    def __init__(self, callback=None, fixed_cwnd = 10*1024*1024) -> None:
        self.callback = callback # a callback argument that is called when an event occurs
        # 10 GB window or custom fixed size window (shouldn't be used in real network !, use a real CCA instead)
        self.cwnd = fixed_cwnd
        self.data_in_flight = 0
        self.rs = RateSample()

    def set_recovery(self, recovery):
        # recovery is a QuicPacketRecovery instance
        self.recovery = recovery

    def on_init(self, *args, **kwargs):
        pass

    def on_packet_acked(self, packet: QuicSentPacket):
        if self.callback:
            self.callback(CongestionEvent.ACK, self)
        self.data_in_flight -= packet.sent_bytes
        self.rs.on_ack(packet, Now())
        self.rs.rm_packet_info(packet)

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        if self.callback:
            self.callback(CongestionEvent.PACKET_SENT, self)
        self.data_in_flight += packet.sent_bytes
        self.rs.on_sent(packet, Now())

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        if self.callback:
            self.callback(CongestionEvent.PACKET_EXPIRED, self)
        for packet in packets:
            self.data_in_flight -= packet.sent_bytes
            self.rs.on_expired(packet)

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        if self.callback:
            self.callback(CongestionEvent.PACKET_LOST, self)
        for packet in packets:
            self.data_in_flight -= packet.sent_bytes
            self.rs.on_lost(packet, Now())
            self.rs.rm_packet_info(packet)

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        if self.callback:
            self.callback(CongestionEvent.RTT_MEASURED, self)

    def get_congestion_window(self) -> int:
        # return the cwnd in number of bytes
        return self.cwnd   
    
    def _set_congestion_window(self, value):
        self.cwnd = value

    def get_ssthresh(self) -> Optional[int]: 
        pass

    def get_bytes_in_flight(self) -> int:
        return self.data_in_flight

    def log_callback(self) -> Dict[str, Any]:
        # a callback called when a recovery happens
        # The data object will be saved in the log file, so feel free to add
        # any attribute you want to track
        data: Dict[str, Any] = {
            "bytes_in_flight": self.get_bytes_in_flight(),
            "cwnd": self.get_congestion_window(),
        }
        if self.get_ssthresh() is not None:
            data["ssthresh"] = self.get_ssthresh()

        data["delivery_rate"] = self.rs.delivery_rate

        return data
  

