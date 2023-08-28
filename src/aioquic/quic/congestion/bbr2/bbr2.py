from ..congestion import QuicCongestionControl, Now, K_MAX_DATAGRAM_SIZE
from ...recovery import QuicPacketRecovery
from ...packet_builder import QuicSentPacket
from typing import Iterable, Optional, Dict, Any
from .values import BBR2, BBR2State
from .bbr2_methods import bbr2_init
from .per_transmit import bbr2_on_transmit
from .rs import RateSample
from .bbr2_methods import bbr2_update_model_and_state, bbr2_update_control_parameters, bbr2_update_on_loss, \
    bbr2_restore_cwnd, bbr2_save_cwnd

# this implementation is heavily based on the one done on the quiche implementation 
# (https://github.com/divyabhat1/quiche/tree/bbr2_enhance/quiche/src/recovery/bbr2)

class BBR2CongestionControl(QuicCongestionControl):
    
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.bbr_state = BBR2()
        self.recovery = kwargs["caller"]
        self.rs = RateSample()
        self.in_congestion_recovery = False

    def on_init(self, *args, **kwargs):
        bbr2_init(self.recovery)

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        super().on_packet_acked(packet)

        now = Now()
        

        self.bbr_state.newly_acked_bytes = 0

        time_sent = packet.sent_time

        self.bbr_state.prior_bytes_in_flight = self.rs.inflight

        bbr2_update_model_and_state(self.recovery, packet, now)

        self.rs.on_ack(packet)
        self.bbr_state.newly_acked_bytes += packet.sent_bytes

        if not self.rs.in_congestion_recovery(time_sent):
            # Upon exiting loss recovery.
            bbr2_exit_recovery(self.recovery)

        bbr2_update_control_parameters(self.recovery, now)

        self.bbr_state.newly_lost_bytes = 0

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)
        self.rs.on_sent(packet)
        bbr2_on_transmit(self.recovery, Now())
        

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
            self.rs.on_lost(packet)
            lost_bytes += packet.sent_bytes
            if largest_packet == None or packet.sent_bytes > largest_packet.sent_bytes:
                largest_packet = packet

        self.bbr_state.newly_lost_bytes = lost_bytes

        bbr2_update_on_loss(self.recovery, largest_packet, now)
        if not self.rs.in_congestion_recovery(largest_packet.sent_time):
            #Upon entering Fast Recovery.
            bbr2_enter_recovery(self.recovery, now)

        for packet in packets:
            self.rs.rm_packet_info(packet)


    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)

    def get_congestion_window(self) -> int:
        return self.bbr_state.cwnd
    
    def get_ssthresh(self) -> int: 
        return None
    
    def get_bytes_in_flight(self) -> int:
        return self.rs.inflight

    def log_callback(self) -> Dict[str, Any]:
        data = super().log_callback()

        if (self.bbr_state.state == BBR2State.Startup):
            data["Phase"] = "Startup"
        if (self.bbr_state.state == BBR2State.Drain):
            data["Phase"] = "Drain"
        if (self.bbr_state.state == BBR2State.ProbeBWUP):
            data["Phase"] = "ProbeBWUP"
        if (self.bbr_state.state == BBR2State.ProbeBWDOWN):
            data["Phase"] = "ProbeBWDOWN"
        if (self.bbr_state.state == BBR2State.ProbeBWREFILL):
            data["Phase"] = "ProbeBWREFILL"
        if (self.bbr_state.state == BBR2State.ProbeBWCRUISE):
            data["Phase"] = "ProbeBWCRUISE"
        if (self.bbr_state.state == BBR2State.ProbeRTT):
            data["Phase"] = "ProbeRTT"
        

        return data
    

# When entering the recovery episode.
def bbr2_enter_recovery(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    bbr.prior_cwnd = bbr2_save_cwnd(r)

    bbr.cwnd = r._cc.rs.inflight + max(bbr.newly_acked_bytes, K_MAX_DATAGRAM_SIZE)

    bbr.packet_conservation = True
    bbr.in_recovery = True

    # Start round now.
    bbr.next_round_delivered = r._cc.rs.delivered


# When exiting the recovery episode.
def bbr2_exit_recovery(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.packet_conservation = False
    bbr.in_recovery = False

    bbr2_restore_cwnd(r)