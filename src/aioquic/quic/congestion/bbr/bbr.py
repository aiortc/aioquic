from ..congestion import QuicCongestionControl, Now, K_MAX_DATAGRAM_SIZE
from ...recovery import QuicPacketRecovery, K_MICRO_SECOND
from ...packet_builder import QuicSentPacket
from ...logger import get_dataclass_attr
from typing import Iterable, Optional, Dict, Any
from .values import *
from ..rs import RateSample
from .per_ack import bbr_save_cwnd, bbr_restore_cwnd, bbr_update_model_and_state, bbr_update_control_parameters
from .init import bbr_init
from .per_transmit import bbr_on_transmit


# this implementation is heavily based on the one done on the quiche implementation 
# (https:#github.com/divyabhat1/quiche/tree/bbr_enhance/quiche/src/recovery/bbr)

class BBRCongestionControl(QuicCongestionControl):
    
    def __init__(self, callback=None) -> None:
        super().__init__(callback=callback)
        now = Now()
        self.bbr_state = BBR(start_time=now, cycle_stamp=now, rtprop_stamp=now)

    def on_init(self, *args, **kwargs):
        self.rs = RateSample()
        bbr_init(self.recovery)

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        super().on_packet_acked(packet)
        now = Now()

        self.bbr_state.newly_acked_bytes = packet.sent_bytes
        self.bbr_state.prior_bytes_in_flight = self.rs.inflight

        self.rs.on_ack(packet, now)
        
        bbr_update_model_and_state(self.recovery, packet, now)

        self.rs.inflight = max(self.rs.inflight - packet.sent_bytes, 0)

        if not self.rs.in_congestion_recovery(packet) and self.bbr_state.in_recovery:
            # Upon exiting loss recovery.
            bbr_exit_recovery(self.recovery)

        bbr_update_control_parameters(self.recovery, now)

        self.bbr_state.newly_lost_bytes = 0

        self.rs.rm_packet_info(packet)

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)
        now = Now()
        self.rs.on_sent(packet, now)
        bbr_on_transmit(self.recovery)
        
        
    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)
        for packet in packets:
            self.rs.on_expired(packet)

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)
        now = Now()
        lost_bytes = 0
        largest_packet = None
        for packet in packets:
            self.rs.on_lost(packet, now)
            lost_bytes += packet.sent_bytes
            if largest_packet == None or packet.sent_bytes > largest_packet.sent_bytes:
                largest_packet = packet

        self.bbr_state.newly_lost_bytes = lost_bytes

        if not self.rs.in_congestion_recovery(largest_packet):
            #Upon entering Fast Recovery.
            bbr_enter_recovery(self.recovery, now)

        for packet in packets:
            self.rs.rm_packet_info(packet)


    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)

    def get_congestion_window(self) -> int:
        return int(self.bbr_state.cwnd)
    
    def get_ssthresh(self) -> int: 
        return None
    
    def get_bytes_in_flight(self) -> int:
        return int(self.rs.inflight)

    def log_callback(self) -> Dict[str, Any]:
        data = super().log_callback()

        for attr, value in get_dataclass_attr(self.bbr_state).items():
            data[attr] = value

        if "min_rtt" in data:
            data["min_rtt"] = data["min_rtt"] * 1000 # convert to ms to respect the format of recovery.py

        if (self.bbr_state.state == BBRState.Startup):
            data["Phase"] = "Startup"
        if (self.bbr_state.state == BBRState.Drain):
            data["Phase"] = "Drain"
        if (self.bbr_state.state == BBRState.ProbeBW):
            data["Phase"] = "ProbeBW"
        if (self.bbr_state.state == BBRState.ProbeRTT):
            data["Phase"] = "ProbeRTT"
        
        data["pacing_rate"] = self.recovery._pacer.pacing_rate

        data = self.rs.add_attributes(data)

        return data
    

# When entering the recovery episode.
def bbr_enter_recovery(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    bbr.prior_cwnd = bbr_save_cwnd(r)

    bbr.cwnd = max(r._cc.rs.inflight, K_MAX_DATAGRAM_SIZE)
    r.congestion_recovery_start_time = now

    bbr.packet_conservation = True
    bbr.in_recovery = True

    bbr.newly_lost_bytes = 0

    # Start round now.
    bbr.next_round_delivered = r.delivery_rate.delivered()


# When exiting the recovery episode.
def bbr_exit_recovery(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    r.congestion_recovery_start_time = None

    bbr.packet_conservation = False
    bbr.in_recovery = False

    bbr_restore_cwnd(r)