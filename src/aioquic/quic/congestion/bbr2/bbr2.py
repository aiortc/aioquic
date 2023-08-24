from ..congestion import QuicCongestionControl
from ...packet_builder import QuicSentPacket
from typing import Iterable, Optional

class BBR2CongestionControl(QuicCongestionControl):
    
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.bbr_state = None

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        super().on_packet_acked(packet)

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)

    def get_congestion_window(self) -> int:
        pass
    
    def get_ssthresh(self) -> int: 
        pass
    
    def get_bytes_in_flight(self) -> int:
        pass