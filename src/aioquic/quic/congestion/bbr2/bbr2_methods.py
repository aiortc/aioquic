from ...recovery import QuicPacketRecovery
from random import random, randint
from ...packet_builder import QuicSentPacket
from .values import *
from ..congestion import K_MAX_DATAGRAM_SIZE

from .pacing import bbr2_init_pacing_rate, bbr2_set_pacing_rate

# Copyright (C) 2022, Cloudflare, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#  1.2Mbps in bytes/sec
PACING_RATE_1_2MBPS: int = int(1200 * 1000 / 8)

# The minimal cwnd value BBR2 tries to target, in bytes
def bbr2_min_pipe_cwnd(r: QuicPacketRecovery) -> int :
    K_BBR2_MIN_PIPE_CWND_PKTS * K_MAX_DATAGRAM_SIZE

# BBR2 Functions when ACK is received.
#
def bbr2_update_model_and_state(
    r: QuicPacketRecovery, packet: QuicSentPacket, now: float,
):
    bbr2_update_latest_delivery_signals(r)
    bbr2_update_congestion_signals(r, packet)
    bbr2_update_ack_aggregation(r, packet, now)
    bbr2_check_startup_done(r)
    bbr2_check_drain(r, now)
    bbr2_update_probe_bw_cycle_phase(r, now)
    bbr2_update_min_rtt(r, now)
    bbr2_check_probe_rtt(r, now)
    bbr2_advance_latest_delivery_signals(r)
    bbr2_bound_bw_for_model(r)


def bbr2_update_control_parameters(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    bbr2_set_pacing_rate(r)
    bbr2_set_send_quantum(r)

    # Set outgoing packet pacing rate
    # It is called here because send_quantum may be updated too.
    # TODO : set_pacing_rate
    r.set_pacing_rate(bbr.pacing_rate, now)

    bbr2_set_cwnd(r)

# BBR2 Functions while processing ACKs.
#

# 4.3.1.1.  Startup Dynamics
def bbr2_check_startup_done(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    bbr2_check_startup_full_bandwidth(r)
    bbr2_check_startup_high_loss(r)

    if bbr.state == BBR2State.Startup and bbr.filled_pipe:
        bbr2_enter_drain(r)


# 4.3.1.2.  Exiting Startup Based on Bandwidth Plateau
def bbr2_check_startup_full_bandwidth(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    # TODO : app_limited
    if bbr.filled_pipe or not bbr.round_start or r.delivery_rate.sample_is_app_limited():
        # No need to check for a full pipe now.
        return

    # Still growing?
    if bbr.max_bw >= int(bbr.full_bw * K_BBR2_MAX_BW_GROWTH_THRESHOLD):
        # Record new baseline level
        bbr.full_bw = bbr.max_bw
        bbr.full_bw_count = 0
        return

    # Another round w/o much growth
    bbr.full_bw_count += 1

    if bbr.full_bw_count >= K_BBR2_MAX_BW_COUNT:
        bbr.filled_pipe = True

# 4.3.1.3.  Exiting Startup Based on Packet Loss
def bbr2_check_startup_high_loss(r: QuicPacketRecovery):
    # todo: this is not implemented (not in the draft)
    bbr = r._cc.bbr_state
    if bbr.loss_round_start and bbr.in_recovery and bbr.loss_events_in_round >= K_BBR2_FULL_LOSS_COUNT and bbr2_is_inflight_too_high(r):
        bbr2_handle_queue_too_high_in_startup(r)
    if bbr.loss_round_start:
        bbr.loss_events_in_round = 0

def bbr2_handle_queue_too_high_in_startup(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    bbr.filled_pipe = True
    bbr.inflight_hi = bbr2_inflight(r, bbr.max_bw, 1.0)


# 4.3.2.  Drain
def bbr2_enter_drain(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.state = BBR2State.Drain

    # pace slowly
    bbr.pacing_gain = K_BBR2_PACING_GAIN / K_BBR2_STARTUP_CWND_GAIN

    # maintain cwnd
    bbr.cwnd_gain = K_BBR2_STARTUP_CWND_GAIN


def bbr2_check_drain(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    if bbr.state == BBR2State.Drain and bbr.bytes_in_flight <= bbr2_inflight(r, bbr.max_bw, 1.0):
        # BBR estimates the queue was drained
        bbr2_enter_probe_bw(r, now)


# 4.3.3.  ProbeBW
# 4.3.3.5.3.  Design Considerations for Choosing Constant Parameters
def bbr2_check_time_to_probe_bw(r: QuicPacketRecovery, now: float) -> bool:
    bbr = r._cc.bbr_state
    # Is it time to transition from DOWN or CRUISE to REFILL?
    if bbr2_has_elapsed_in_phase(r, bbr.bw_probe_wait, now) or bbr2_is_reno_coexistence_probe_time(r):
        
        bbr2_start_probe_bw_refill(r)
        return True

    return False


# Randomized decision about how long to wait until
# probing for bandwidth, using round count and wall clock.
def bbr2_pick_probe_wait(r: QuicPacketRecovery):

    bbr = r._cc.bbr_state

    # Decide random round-trip bound for wait
    bbr.rounds_since_probe = randint(0,1)

    # Decide the random wall clock bound for wait
    bbr.bw_probe_wait = 2.0 + random()

def bbr2_is_reno_coexistence_probe_time(r: QuicPacketRecovery) -> bool:
    bbr = r._cc.bbr_state
    reno_rounds = bbr2_target_inflight(r)
    rounds = min(reno_rounds, 63)

    return bbr.rounds_since_probe >= rounds




# 4.3.3.6.  ProbeBW Algorithm Details
def bbr2_enter_probe_bw(r: QuicPacketRecovery, now: float):
    bbr2_start_probe_bw_down(r, now)


def bbr2_start_probe_bw_cruise(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.state = BBR2State.ProbeBWCRUISE
    bbr.pacing_gain = K_BBR2_PACING_GAIN
    bbr.cwnd_gain = K_BBR2_CWND_GAIN


def bbr2_start_probe_bw_refill(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    bbr2_reset_lower_bounds(r)

    bbr.bw_probe_up_rounds = 0
    bbr.bw_probe_up_acks = 0
    bbr.ack_phase = BBR2ACKPhase.Refilling

    bbr2_start_round(r)

    bbr.state = BBR2State.ProbeBWREFILL
    bbr.pacing_gain = K_BBR2_PACING_GAIN
    bbr.cwnd_gain = K_BBR2_CWND_GAIN

def bbr2_start_probe_bw_up(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    bbr.ack_phase = BBR2ACKPhase.ProbeStarting

    bbr2_start_round(r)

    # Start wall clock.
    bbr.cycle_stamp = now
    bbr.state = BBR2State.ProbeBWUP
    bbr.pacing_gain = K_BBR2_PROBE_UP_PACING_GAIN
    bbr.cwnd_gain = K_BBR2_CWND_GAIN

    bbr2_raise_inflight_hi_slope(r)


# The core state machine logic for ProbeBW
def bbr2_update_probe_bw_cycle_phase(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    if not bbr.filled_pipe :
        # only handling steady-state behavior here
        return

    bbr2_adapt_upper_bounds(r, now)

    if not bbr2_is_in_a_probe_bw_state(r):
        # only handling ProbeBW states here
        return

    if (bbr.state == BBR2State.ProbeBWDOWN):
        if bbr2_check_time_to_probe_bw(r, now):
            # Already decided state transition.
            return

        if bbr2_check_time_to_cruise(r):
            bbr2_start_probe_bw_cruise(r)
        

    if (bbr.state == BBR2State.ProbeBWCRUISE):
        bbr2_check_time_to_probe_bw(r, now)

    if (bbr.state == BBR2State.ProbeBWREFILL):
        # After one round of REFILL, start UP.
        if bbr.round_start:
            bbr.bw_probe_samples = True

            bbr2_start_probe_bw_up(r, now)

    if (bbr.state == BBR2State.ProbeBWDOWN):
        if bbr2_has_elapsed_in_phase(r, bbr.min_rtt, now) and bbr.bytes_in_flight > bbr2_inflight(r, bbr.max_bw, 1.25):
            bbr2_start_probe_bw_down(r, now)


def bbr2_is_in_a_probe_bw_state(r: QuicPacketRecovery) -> bool:
    bbr = r._cc.bbr_state
    state = bbr.state

    return state == BBR2State.ProbeBWDOWN or \
        state == BBR2State.ProbeBWCRUISE or \
        state == BBR2State.ProbeBWREFILL or \
        state == BBR2State.ProbeBWUP


def bbr2_check_time_to_cruise(r: QuicPacketRecovery) -> bool:
    bbr = r._cc.bbr_state
    if bbr.bytes_in_flight > bbr2_inflight_with_headroom(r):
        # Not enough headroom.
        return False

    if bbr.bytes_in_flight <= bbr2_inflight(r, bbr.max_bw, 1.0):
        # inflight <= estimated BDP
        return True

    return False


def bbr2_has_elapsed_in_phase(
    r: QuicPacketRecovery, interval: float, now: float,
) -> bool:
    bbr = r._cc.bbr_state
    return now > bbr.cycle_stamp + interval


# Return a volume of data that tries to leave free
# headroom in the bottleneck buffer or link for
# other flows, for fairness convergence and lower
# RTTs and loss
def bbr2_inflight_with_headroom(r: QuicPacketRecovery) -> int:
    bbr = r._cc.bbr_state

    if bbr.inflight_hi == MAX_INT:
        return MAX_INT


    headroom = max(int(K_BBR2_HEADROOM * bbr.inflight_hi), 1)

    bbr.inflight_hi = max(max(bbr.inflight_hi - headroom, 0), bbr2_min_pipe_cwnd(r))

# Raise inflight_hi slope if appropriate.
def bbr2_raise_inflight_hi_slope(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    growth_this_round = (1 << bbr.bw_probe_up_rounds) * K_MAX_DATAGRAM_SIZE

    bbr.bw_probe_up_rounds = min(bbr.bw_probe_up_rounds + 1, 30)
    bbr.probe_up_cnt = max(bbr.congestion_window / growth_this_round, 1)

# Increase inflight_hi if appropriate.
def bbr2_probe_inflight_hi_upward(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    # TODO app_limited
    if r.app_limited() or bbr.congestion_window < bbr.inflight_hi:
        # Not fully using inflight_hi, so don't grow it.
        return

    # bw_probe_up_acks is a packet count.
    bbr.bw_probe_up_acks += 1

    if bbr.bw_probe_up_acks >= bbr.probe_up_cnt:
        delta = bbr.bw_probe_up_acks / bbr.probe_up_cnt

        bbr.bw_probe_up_acks -= delta * bbr.probe_up_cnt

        bbr.inflight_hi += delta * K_MAX_DATAGRAM_SIZE

    if bbr.round_start:
        bbr2_raise_inflight_hi_slope(r)


# Track ACK state and update bbr.max_bw window and
# bbr.inflight_hi and bbr.bw_hi.
def bbr2_adapt_upper_bounds(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    if bbr.ack_phase == BBR2ACKPhase.ProbeStarting and bbr.round_start:
        # Starting to get bw probing samples.
        bbr.ack_phase = BBR2ACKPhase.ProbeFeedback

    if bbr.ack_phase == BBR2ACKPhase.ProbeStopping and bbr.round_start:
        bbr.bw_probe_samples = False
        bbr.ack_phase = BBR2ACKPhase.Init

        # End of samples from bw probing phase.
        # TODO app_limited
        if bbr2_is_in_a_probe_bw_state(r) and not r.delivery_rate.sample_is_app_limited():
            bbr2_advance_max_bw_filter(r)

    if not bbr2_check_inflight_too_high(r, now):
        # Loss rate is safe. Adjust upper bounds upward.
        if bbr.inflight_hi == MAX_INT or bbr.bw_hi == MAX_INT:
            # No upper bounds to raise.
            return

        if bbr.tx_in_flight > bbr.inflight_hi:
            bbr.inflight_hi = bbr.tx_in_flight

        # TODO delivery_rate
        if r.delivery_rate() > bbr.bw_hi:
            bbr.bw_hi = r.delivery_rate()

        if bbr.state == BBR2State.ProbeBWUP:
            bbr2_probe_inflight_hi_upward(r)


# 4.3.4. ProbeRTT
# 4.3.4.4.  ProbeRTT Logic
def bbr2_update_min_rtt(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state

    bbr.probe_rtt_expired = now > bbr.probe_rtt_min_stamp + K_BBR2_PROBE_RTT_INTERVAL

    # TODO sample rtt
    rs_rtt = r.delivery_rate.sample_rtt()

    if not rs_rtt == 0 and (rs_rtt < bbr.probe_rtt_min_delay or bbr.probe_rtt_expired):
        bbr.probe_rtt_min_delay = rs_rtt
        bbr.probe_rtt_min_stamp = now

    min_rtt_expired = now > bbr.min_rtt_stamp + rs_rtt * K_BBR2_MIN_RTT_FILTER_LEN

    # To do: Figure out Probe RTT logic
    # if bbr.probe_rtt_min_delay < bbr.min_rtt ||  bbr.min_rtt == INITIAL_RTT ||
    # min_rtt_expired {
    if bbr.min_rtt == K_BBR2_INITIAL_RTT or min_rtt_expired:
        # bbr.min_rtt = bbr.probe_rtt_min_delay;
        # bbr.min_rtt_stamp = bbr.probe_rtt_min_stamp;
        bbr.min_rtt = rs_rtt
        bbr.min_rtt_stamp = now

def bbr2_check_probe_rtt(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    if bbr.state != BBR2State.ProbeRTT and bbr.probe_rtt_expired and not bbr.idle_restart:
        bbr2_enter_probe_rtt(r)

        bbr.prior_cwnd = bbr2_save_cwnd(r)
        bbr.probe_rtt_done_stamp = None
        bbr.ack_phase = BBR2ACKPhase.ProbeStopping

        bbr2_start_round(r)

    if bbr.state ==  BBR2State.ProbeRTT:
        bbr2_handle_probe_rtt(r, now)

    # TODO : sample delivered
    if r.delivery_rate.sample_delivered() > 0:
        bbr.idle_restart = False

def bbr2_enter_probe_rtt(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.state = BBR2State.ProbeRTT
    bbr.pacing_gain = K_BBR2_PACING_GAIN
    bbr.cwnd_gain = K_BBR2_PROBE_RTT_CWND_GAIN

def bbr2_handle_probe_rtt(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    # TODO update app limited
    # Ignore low rate samples during ProbeRTT.
    r.delivery_rate.update_app_limited(True)

    if bbr.probe_rtt_done_stamp != None:
        if bbr.round_start:
            bbr.probe_rtt_round_done = True

        if bbr.probe_rtt_round_done:
            bbr2_check_probe_rtt_done(r, now)
        
    elif bbr.bytes_in_flight <= bbr2_probe_rtt_cwnd(r):
        # Wait for at least ProbeRTTDuration to elapse.
        bbr.probe_rtt_done_stamp = now + K_BBR2_PROBE_RTT_DURATION

        # Wait for at lease one round to elapse.
        bbr.probe_rtt_round_done = False

        bbr2_start_round(r)


def bbr2_check_probe_rtt_done(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state

    if bbr.probe_rtt_done_stamp != None:
        if now > bbr.probe_rtt_done_stamp:
            # Schedule next ProbeRTT.
            bbr.probe_rtt_min_stamp = now

            bbr2_restore_cwnd(r)
            bbr2_exit_probe_rtt(r, now)

# 4.3.4.5.  Exiting ProbeRTT
def bbr2_exit_probe_rtt(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    bbr2_reset_lower_bounds(r)

    if bbr.filled_pipe:
        bbr2_start_probe_bw_down(r, now)
        bbr2_start_probe_bw_cruise(r)
    else:
        bbr2_enter_startup(r)

# 4.5.1.  BBR.round_count: Tracking Packet-Timed Round Trips
def bbr2_update_round(r: QuicPacketRecovery, packet: QuicSentPacket):
    bbr = r._cc.bbr_state
    # TODO : packet.delivered
    if packet.delivered >= bbr.next_round_delivered:
        bbr2_start_round(r)

        bbr.round_count += 1
        bbr.rounds_since_probe += 1
        bbr.round_start = True
    else:
        bbr.round_start = False


def bbr2_start_round(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    # TODO : delivered
    bbr.next_round_delivered = r.delivery_rate.delivered()


# 4.5.2.5.  Tracking Time for the BBR.max_bw Max Filter
def bbr2_advance_max_bw_filter(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    bbr.cycle_count += 1

# 4.5.4.  BBR.offload_budget
def bbr2_update_offload_budget(r: QuicPacketRecovery):
    # TODO : send_quantum
    bbr = r._cc.bbr_state
    bbr.offload_budget = 3 * r.send_quantum

# 4.5.5.  BBR.extra_acked
def bbr2_update_ack_aggregation(r: QuicPacketRecovery, packet: QuicSentPacket, now: float):
    bbr = r._cc.bbr_state

    # Find excess ACKed beyond expected amount over this interval.
    interval = now - bbr.extra_acked_interval_start
    expected_delivered = int(bbr.bw * interval)

    # Reset interval if ACK rate is below expected rate.
    if bbr.extra_acked_delivered <= expected_delivered:
        bbr.extra_acked_delivered = 0
        bbr.extra_acked_interval_start = now
        expected_delivered = 0

    bbr.extra_acked_delivered += packet.sent_bytes

    extra = max(bbr.extra_acked_delivered - expected_delivered, 0)
    extra = min(extra, bbr.congestion_window)

    # TODO : understand what this does...
    extra_acked_filter_len = r.delivery_rate.sample_rtt().saturating_mul(K_BBR2_MIN_RTT_FILTER_LEN)

    bbr.extra_acked = bbr.extra_acked_filter.running_max(extra_acked_filter_len, bbr.start_time + bbr.round_count, extra)


# 4.6.3.  Send Quantum: BBR.send_quantum
def bbr2_set_send_quantum(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    rate = bbr.pacing_rate
    floor = K_MAX_DATAGRAM_SIZE if rate < PACING_RATE_1_2MBPS else 2 * K_MAX_DATAGRAM_SIZE

    # TODO : send_quantum
    r.send_quantum = min(int(rate / 1000), 64 * 1024); # Assumes send buffer is limited to 64KB
    r.send_quantum = max(r.send_quantum, floor)


# 4.6.4.1.  Initial cwnd
# 4.6.4.2.  Computing BBR.max_inflight
def bbr2_bdp_multiple(r: QuicPacketRecovery, bw: int, gain: float) -> int: 
    bbr = r._cc.bbr_state

    if bbr.min_rtt == float("inf"):
        # No valid RTT samples yet.
        return  K_INITIAL_WINDOW

    bbr.bdp = int(bw * bbr.min_rtt)

    return int(gain * bbr.bdp)


def bbr2_quantization_budget(r: QuicPacketRecovery, inflight: int) -> int:
    bbr = r._cc.bbr_state
    bbr2_update_offload_budget(r)

    inflight = max(inflight, bbr.offload_budget)
    inflight = max(inflight, bbr2_min_pipe_cwnd(r))

    # TODO: cycle_idx is unused
    if bbr.state == BBR2State.ProbeBWUP:
        return inflight + 2 * K_MAX_DATAGRAM_SIZE

    return inflight

def bbr2_inflight(r: QuicPacketRecovery, bw: int, gain: float) -> int:
    inflight = bbr2_bdp_multiple(r, bw, gain)

    return bbr2_quantization_budget(r, inflight)

def bbr2_update_max_inflight(r: QuicPacketRecovery):
    # TODO: not implemented (not in the draft)
    # bbr2_update_aggregation_budget(r);

    bbr = r._cc.bbr_state

    inflight = bbr2_bdp_multiple(r, bbr.max_bw, bbr.cwnd_gain)
    inflight = inflight + bbr.extra_acked

    bbr.max_inflight = bbr2_quantization_budget(r, inflight)


# 4.6.4.4.  Modulating cwnd in Loss Recovery
def bbr2_save_cwnd(r: QuicPacketRecovery) -> int:
    bbr = r._cc.bbr_state

    if not bbr.in_recovery and bbr.state != BBR2State.ProbeRTT:
        return bbr.cwnd
    else:
        max(bbr.cwnd, bbr.prior_cwnd)

def bbr2_restore_cwnd(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    bbr.cwnd = max(bbr.cwnd, bbr.prior_cwnd)

def bbr2_modulate_cwnd_for_recovery(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    acked_bytes = bbr.newly_acked_bytes
    lost_bytes = bbr.newly_lost_bytes

    if lost_bytes > 0:
        # QUIC mininum cwnd is 2 x MSS.
        bbr.cwnd = max(r.cwnd - lost_bytes, K_MINIMUM_WINDOW)

    if bbr.packet_conservation:
        bbr.cwnd = max(bbr.cwnd, bbr.bytes_in_flight + acked_bytes)


# 4.6.4.5.  Modulating cwnd in ProbeRTT
def bbr2_probe_rtt_cwnd(r: QuicPacketRecovery) -> int:
    bbr = r._cc.bbr_state
    probe_rtt_cwnd = bbr2_bdp_multiple(r, bbr.bw, K_BBR2_PROBE_RTT_CWND_GAIN)

    return max(probe_rtt_cwnd, bbr2_min_pipe_cwnd(r))


def bbr2_bound_cwnd_for_probe_rtt(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    if bbr.state == BBR2State.ProbeRTT:
        bbr.cwnd = min(bbr.cwnd, bbr2_probe_rtt_cwnd(r))

# 4.6.4.6.  Core cwnd Adjustment Mechanism
def bbr2_set_cwnd(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    acked_bytes = bbr.newly_acked_bytes

    bbr2_update_max_inflight(r)
    bbr2_modulate_cwnd_for_recovery(r)

    if not bbr.packet_conservation:
        if bbr.filled_pipe:
            bbr.cwnd = min(bbr.cwnd + acked_bytes, bbr.max_inflight)
        # TODO delivery rate
        elif bbr.cwnd < bbr.max_inflight or r.delivery_rate.delivered() < K_INITIAL_WINDOW:
            bbr.cwnd += acked_bytes
        bbr.cwnd = max(bbr.cwnd, bbr2_min_pipe_cwnd(r))

    bbr2_bound_cwnd_for_probe_rtt(r)
    bbr2_bound_cwnd_for_model(r)

# 4.6.4.7.  Bounding cwnd Based on Recent Congestion
def bbr2_bound_cwnd_for_model(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    cap = MAX_INT

    if bbr2_is_in_a_probe_bw_state(r) and bbr.state != BBR2State.ProbeBWCRUISE:
        cap = bbr.inflight_hi
    elif bbr.state == BBR2State.ProbeRTT or bbr.state == BBR2State.ProbeBWCRUISE:
        cap = bbr2_inflight_with_headroom(r)

    # Apply inflight_lo (possibly infinite).
    cap = min(cap, bbr.inflight_lo)
    cap = max(cap, bbr2_min_pipe_cwnd(r))

    bbr.cwnd = min(bbr.cwnd, cap)

# BBR2 Functions on every packet loss event.
#
# 4.2.4.  Per-Loss Steps
def bbr2_update_on_loss(r: QuicPacketRecovery, packet: QuicSentPacket, now: float):
    bbr2_handle_lost_packet(r, packet, now)

# 4.5.6.  Updating the Model Upon Packet Loss
# 4.5.6.2.  Probing for Bandwidth In ProbeBW
def bbr2_check_inflight_too_high(r: QuicPacketRecovery, now: float) -> bool:
    bbr = r._cc.bbr_state

    if bbr2_is_inflight_too_high(r):
        if bbr.bw_probe_samples:
            bbr2_handle_inflight_too_high(r, now)

        # inflight too high.
        return True

    # inflight not too high.
    return False

def bbr2_is_inflight_too_high(r: QuicPacketRecovery) -> bool:
    bbr = r._cc.bbr_state
    return bbr.lost > int(bbr.tx_in_flight * K_BBR2_LOSS_THRESH)


def bbr2_handle_inflight_too_high(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state

    # Only react once per bw probe.
    bbr.bw_probe_samples = False

    # TODO app limited
    if not r.delivery_rate.sample_is_app_limited():
        bbr.inflight_hi = max(bbr.tx_in_flight, bbr2_target_inflight(r) * K_BBR2_BETA)

    if bbr.state == BBR2State.ProbeBWUP:
        bbr2_start_probe_bw_down(r, now)

def bbr2_handle_lost_packet(r: QuicPacketRecovery, packet: QuicSentPacket, now: float):
    bbr = r._cc.bbr_state
    if not bbr.bw_probe_samples:
        return

    # TODO : packets don't have tx_in_flight
    bbr.tx_in_flight = packet.tx_in_flight
    bbr.lost = int(bbr.bytes_lost - packet.lost)

    # TODO app_limited
    # r.delivery_rate_update_app_limited(packet.is_app_limited)

    if bbr2_is_inflight_too_high(r):
        bbr.tx_in_flight = bbr2_inflight_hi_from_lost_packet(r, packet)

        bbr2_handle_inflight_too_high(r, now)

def bbr2_inflight_hi_from_lost_packet(r: QuicPacketRecovery, packet: QuicSentPacket) -> int:
    bbr = r._cc.bbr_state
    size = packet.sent_bytes
    inflight_prev = bbr.tx_in_flight - size
    lost_prev = bbr.lost - size
    lost_prefix = (K_BBR2_LOSS_THRESH * inflight_prev - lost_prev) / (1.0 - K_BBR2_LOSS_THRESH)

    return int(inflight_prev + lost_prefix)

# 4.5.6.3.  When not Probing for Bandwidth
def bbr2_update_latest_delivery_signals(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    # Near start of ACK processing.
    bbr.loss_round_start = False
    # TODO sample_delivery_rate
    bbr.bw_latest = max(bbr.bw_latest, r.delivery_rate.sample_delivery_rate())
    bbr.inflight_latest = max(bbr.inflight_latest, r.delivery_rate.sample_delivered())

    if r.delivery_rate.sample_prior_delivered() >= bbr.loss_round_delivered:
        # TODO delivered
        bbr.loss_round_delivered = r.delivery_rate.delivered()
        bbr.loss_round_start = True

def bbr2_advance_latest_delivery_signals(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    # Near end of ACK processing.
    if bbr.loss_round_start:
        # TODO sample_delivery_rate
        bbr.bw_latest = r.delivery_rate.sample_delivery_rate()
        bbr.inflight_latest = r.delivery_rate.sample_delivered()

def bbr2_reset_congestion_signals(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.loss_in_round = False
    bbr.loss_events_in_round = 0
    bbr.bw_latest = 0
    bbr.inflight_latest = 0

def bbr2_update_congestion_signals(r: QuicPacketRecovery, packet: QuicSentPacket):
    bbr = r._cc.bbr_state

    # Update congestion state on every ACK.
    bbr2_update_max_bw(r, packet)

    if bbr.lost > 0:
        bbr.loss_in_round = True
        bbr.loss_events_in_round += 1

    if not bbr.loss_round_start:
        # Wait until end of round trip.
        return

    bbr2_adapt_lower_bounds_from_congestion(r)

    bbr.loss_in_round = False
    bbr.loss_events_in_round = 0


def bbr2_adapt_lower_bounds_from_congestion(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    # Once per round-trip respond to congestion.
    if bbr2_is_probing_bw(r):
        return


    if bbr.loss_in_round:
        bbr2_init_lower_bounds(r)
        bbr2_loss_lower_bounds(r)
    
def bbr2_init_lower_bounds(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    # Handle the first congestion episode in this cycle.
    if bbr.bw_lo == MAX_INT:
        bbr.bw_lo = bbr.max_bw

    if bbr.inflight_lo == MAX_INT:
        bbr.inflight_lo = bbr.cwnd

def bbr2_loss_lower_bounds(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    # Adjust model once per round based on loss.
    bbr.bw_lo = max(bbr.bw_latest, int(bbr.bw_lo * K_BBR2_BETA))
    bbr.inflight_lo = max(bbr.inflight_latest, int(bbr.inflight_lo * K_BBR2_BETA))

def bbr2_reset_lower_bounds(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.bw_lo = MAX_INT
    bbr.inflight_lo = MAX_INT

def bbr2_bound_bw_for_model(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    temp = min(bbr.bw_lo, bbr.bw_hi)
    bbr.bw = min(bbr.max_bw, temp)

# This function is not defined in the draft but used.
def bbr2_is_probing_bw(r: QuicPacketRecovery) -> bool:
    bbr = r._cc.bbr_state
    state = bbr.state

    return state == BBR2State.Startup or \
        state == BBR2State.ProbeBWREFILL or \
        state == BBR2State.ProbeBWUP

# How much data do we want in flight?
# Our estimated BDP, unless congestion cut cwnd.
def bbr2_target_inflight(r: QuicPacketRecovery) -> int:
    bbr = r._cc.bbr_state
    return min(bbr.bdp, bbr.cwnd)

def bbr2_start_probe_bw_down(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    bbr2_reset_congestion_signals(r)

    # not growing inflight_hi
    bbr.probe_up_cnt = MAX_INT

    bbr2_pick_probe_wait(r)

    # start wall clock
    bbr.cycle_stamp = now
    bbr.ack_phase = BBR2ACKPhase.ProbeStopping

    bbr2_start_round(r)

    bbr.state = BBR2State.ProbeBWDOWN
    bbr.pacing_gain = K_BBR2_PROBE_DOWN_PACING_GAIN
    bbr.cwnd_gain = K_BBR2_CWND_GAIN

# 4.5.2.4.  Updating the BBR.max_bw Max Filter
def bbr2_update_max_bw(r: QuicPacketRecovery, packet: QuicSentPacket):
    bbr = r._cc.bbr_state
    bbr2_update_round(r, packet)

    # TODO : delivery rate + app_limited
    if r.delivery_rate() >= bbr.max_bw or not r.delivery_rate.sample_is_app_limited():
        # TODO : understant what this does...
        max_bw_filter_len = r.delivery_rate.sample_rtt().saturating_mul(K_BBR2_MIN_RTT_FILTER_LEN)

        bbr.max_bw = bbr.max_bw_filter.running_max(max_bw_filter_len, bbr.start_time + bbr.cycle_count, r.delivery_rate())

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
