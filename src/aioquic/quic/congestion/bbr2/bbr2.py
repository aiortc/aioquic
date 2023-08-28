from ..congestion import QuicCongestionControl, Now
from ...packet_builder import QuicSentPacket
from typing import Iterable, Optional, Dict, Any
from .values import BBR2, BBR2State
from .bbr2_methods import bbr2_init
from .per_transmit import bbr2_on_transmit

# this implementation is heavily based on the one done on the quiche implementation 
# (https://github.com/divyabhat1/quiche/tree/bbr2_enhance/quiche/src/recovery/bbr2)

class BBR2CongestionControl(QuicCongestionControl):
    
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.bbr_state = BBR2()
        self.recovery = kwargs["caller"]
        bbr2_init(self.recovery)

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        super().on_packet_acked(packet)

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)
        self.bbr_state.bytes_in_flight += packet.sent_bytes
        bbr2_on_transmit(self.recovery, Now())
        

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

    def log_callback(self) -> Dict[str, Any]:
        data = super().log_callback()

        if (data.bbr_state.state == BBR2State.Startup):
            data["Phase"] = "Startup"
        if (data.bbr_state.state == BBR2State.Drain):
            data["Phase"] = "Drain"
        if (data.bbr_state.state == BBR2State.ProbeBWUP):
            data["Phase"] = "ProbeBWUP"
        if (data.bbr_state.state == BBR2State.ProbeBWDOWN):
            data["Phase"] = "ProbeBWDOWN"
        if (data.bbr_state.state == BBR2State.ProbeBWREFILL):
            data["Phase"] = "ProbeBWREFILL"
        if (data.bbr_state.state == BBR2State.ProbeBWCRUISE):
            data["Phase"] = "ProbeBWCRUISE"
        if (data.bbr_state.state == BBR2State.ProbeRTT):
            data["Phase"] = "ProbeRTT"
        

        return data