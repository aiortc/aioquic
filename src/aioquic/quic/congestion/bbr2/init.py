from ...recovery import QuicPacketRecovery

from .values import *
from .per_loss import bbr2_reset_congestion_signals, bbr2_reset_lower_bounds
from pacing import bbr2_init_pacing_rate

def bbr2_init(r: QuicPacketRecovery):
    rtt = r._rtt
    now = Now()

    bbr = r._cc.bbr_state # get the bbr state from BBR2CongestionControl
    bbr.min_rtt = rtt
    bbr.min_rtt_stamp = now
    bbr.probe_rtt_done_stamp = None
    bbr.probe_rtt_round_done = False
    bbr.prior_cwnd = 0
    bbr.idle_restart = False
    bbr.extra_acked_interval_start = now
    bbr.extra_acked_delivered = 0
    bbr.bw_lo = MAX_INT
    bbr.bw_hi = MAX_INT
    bbr.inflight_lo = MAX_INT
    bbr.inflight_hi = MAX_INT
    bbr.probe_up_cnt = MAX_INT

    r.send_quantum = r.max_datagram_size

    bbr2_reset_congestion_signals(r)
    bbr2_reset_lower_bounds(r)
    bbr2_init_round_counting(r)
    bbr2_init_full_pipe(r)
    bbr2_init_pacing_rate(r)
    bbr2_enter_startup(r)


# 4.5.1.  BBR.round_count: Tracking Packet-Timed Round Trips
def bbr2_init_round_counting(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.next_round_delivered = 0
    bbr.round_start = False
    bbr.round_count = 0


# 4.3.1.1.  Startup Dynamics
def bbr2_enter_startup(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.state = BBR2State.Startup
    bbr.pacing_gain = K_BBR2_STARTUP_PACING_GAIN
    bbr.cwnd_gain = K_BBR2_STARTUP_CWND_GAIN


# 4.3.1.2.  Exiting Startup Based on Bandwidth Plateau
def bbr2_init_full_pipe(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.filled_pipe = False
    bbr.full_bw = 0
    bbr.full_bw_count = 0
