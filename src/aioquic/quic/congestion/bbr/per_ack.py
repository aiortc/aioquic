import random
from ...recovery import QuicPacketRecovery, K_MIN_RTT
from ..congestion import K_MINIMUM_WINDOW
from ...packet_builder import QuicSentPacket
from .pacing import bbr_set_pacing_rate
from .values import *
from .init import bbr_enter_startup

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


#/ 1.2Mbps in bytes/sec
PACING_RATE_1_2MBPS: int = 1200 * 1000 / 8

#/ 24Mbps in bytes/sec
PACING_RATE_24MBPS: int = 24 * 1000 * 1000 / 8

#/ The minimal cwnd value BBR tries to target, in bytes
def bbr_min_pipe_cwnd(r: QuicPacketRecovery) -> int:
    return BBR_MIN_PIPE_CWND_PKTS * K_MAX_DATAGRAM_SIZE

# BBR Functions when ACK is received.
#
def bbr_update_model_and_state(
    r: QuicPacketRecovery, packet: QuicSentPacket, now: float,
):
    bbr_update_btlbw(r, packet)
    bbr_check_cycle_phase(r, now)
    bbr_check_full_pipe(r)
    bbr_check_drain(r, now)
    bbr_update_rtprop(r, now)
    bbr_check_probe_rtt(r, now)


def bbr_update_control_parameters(r: QuicPacketRecovery, now: float):
    bbr_set_pacing_rate(r)
    bbr_set_send_quantum(r)

    bbr = r._cc.bbr_state
    # Set outgoing packet pacing rate
    # It is called here because send_quantum may be updated too.
    r._pacer.set_pacing_rate(bbr.pacing_rate)

    bbr_set_cwnd(r)

# BBR Functions while processing ACKs.
#

# 4.1.1.5.  Updating the BBR.BtlBw Max Filter
def bbr_update_btlbw(r: QuicPacketRecovery, packet: QuicSentPacket):
    bbr = r._cc.bbr_state
    bbr_update_round(r, packet)

    if r._cc.rs.delivery_rate >= bbr.btlbw or not r._cc.rs.app_limited:
        # Since minmax filter is based on time,
        # start_time + (round_count as seconds) is used instead.
        bbr.btlbw = bbr.btlbwfilter.running_max(
            BTLBW_FILTER_LEN,
            bbr.start_time + bbr.round_count,
            r._cc.rs.delivery_rate,
        )

# 4.1.1.3 Tracking Time for the BBR.BtlBw Max Filter
def bbr_update_round(r: QuicPacketRecovery, packet: QuicSentPacket):
    bbr = r._cc.bbr_state

    if r._cc.rs.get_packet_info(packet)["delivered"] >= bbr.next_round_delivered:
        # TODO idea : adding the size of cwnd to make sure it is a whole round
        #bbr.next_round_delivered = r._cc.rs.delivered
        bbr.next_round_delivered = r._cc.rs.delivered + bbr.cwnd
        bbr.round_count += 1
        bbr.round_start = True
        bbr.packet_conservation = False
    else:
        bbr.round_start = False

# 4.1.2.3. Updating the BBR.RTprop Min Filter
def bbr_update_rtprop(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    rs_rtt = r._rtt_smoothed if r._rtt_smoothed >= 0.001 else float("inf")

    bbr.rtprop_expired = now > bbr.rtprop_stamp + RTPROP_FILTER_LEN

    if rs_rtt != 0 and (rs_rtt <= bbr.rtprop or bbr.rtprop_expired):
        bbr.rtprop = rs_rtt
        bbr.rtprop_stamp = now

# 4.2.2 Send Quantum
def bbr_set_send_quantum(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    rate = bbr.pacing_rate

    if rate < PACING_RATE_1_2MBPS:
        r.send_quantum = K_MAX_DATAGRAM_SIZE
    elif rate < PACING_RATE_24MBPS:
        r.send_quantum = 2*K_MAX_DATAGRAM_SIZE
    else:
        r.send_quantum = min(int(rate / 1000), 64 * 1024)

# 4.2.3.2 Target cwnd
def bbr_inflight(r: QuicPacketRecovery, gain: float) -> int:
    bbr = r._cc.bbr_state

    if bbr.rtprop == float("inf"):
        return K_MINIMUM_WINDOW

    quanta = 3 * r.send_quantum
    estimated_bdp = bbr.btlbw * bbr.rtprop

    return int(gain * estimated_bdp) + quanta

def bbr_update_target_cwnd(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    bbr.target_cwnd = bbr_inflight(r, bbr.cwnd_gain)

# 4.2.3.4 Modulating cwnd in Loss Recovery
def bbr_save_cwnd(r: QuicPacketRecovery) -> int:
    bbr = r._cc.bbr_state
    if not bbr.in_recovery and bbr.state != BBRState.ProbeRTT:
        return bbr.cwnd
    else :
        return max(bbr.cwnd, bbr.prior_cwnd)

def bbr_restore_cwnd(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    bbr.cwnd = max(bbr.cwnd, bbr.prior_cwnd)

def bbr_modulate_cwnd_for_recovery(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    acked_bytes = bbr.newly_acked_bytes
    lost_bytes = bbr.newly_lost_bytes

    if lost_bytes > 0:
        # QUIC mininum cwnd is 2 x MSS.
        bbr.cwnd = max(bbr.cwnd - lost_bytes, K_MINIMUM_WINDOW)

    if bbr.packet_conservation:
        bbr.cwnd = max(bbr.cwnd, r._cc.rs.inflight + acked_bytes)


# 4.2.3.5 Modulating cwnd in ProbeRTT
def bbr_modulate_cwnd_for_probe_rtt(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    if bbr.state == BBRState.ProbeRTT:
        bbr.cwnd = min(bbr.cwnd, bbr_min_pipe_cwnd(r))
    
# 4.2.3.6 Core cwnd Adjustment Mechanism
def bbr_set_cwnd(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    acked_bytes = bbr.newly_acked_bytes

    bbr_update_target_cwnd(r)
    bbr_modulate_cwnd_for_recovery(r)

    if not bbr.packet_conservation:
        if bbr.filled_pipe:
            bbr.cwnd = min(bbr.cwnd + acked_bytes,bbr.target_cwnd)
        elif bbr.cwnd < bbr.target_cwnd or r._cc.rs.delivered < K_MINIMUM_WINDOW:
            bbr.cwnd += acked_bytes
        

        bbr.cwnd = max(bbr.cwnd, bbr_min_pipe_cwnd(r))

    bbr_modulate_cwnd_for_probe_rtt(r)


# 4.3.2.2.  Estimating When Startup has Filled the Pipe
def bbr_check_full_pipe(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state
    # No need to check for a full pipe now.
    if bbr.filled_pipe or not bbr.round_start or r._cc.rs.app_limited:
        return

    # BBR.BtlBw still growing?
    if bbr.btlbw >= (bbr.full_bw * BTLBW_GROWTH_TARGET):
        # record new baseline level
        bbr.full_bw = bbr.btlbw
        bbr.full_bw_count = 0
        return

    # another round w/o much growth
    bbr.full_bw_count += 1

    if bbr.full_bw_count >= 3:
        bbr.filled_pipe = True

# 4.3.3.  Drain
def bbr_enter_drain(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.state = BBRState.Drain

    # pace slowly
    bbr.pacing_gain = 1.0 / BBR_HIGH_GAIN

    # maintain cwnd
    bbr.cwnd_gain = BBR_HIGH_GAIN


def bbr_check_drain(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    if bbr.state == BBRState.Startup and bbr.filled_pipe:
        bbr_enter_drain(r)

    if bbr.state == BBRState.Drain and r._cc.rs.inflight <= bbr_inflight(r, 1.0):
        # we estimate queue is drained
        bbr_enter_probe_bw(r, now)


# 4.3.4.3.  Gain Cycling Algorithm
def bbr_enter_probe_bw(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state

    bbr.state = BBRState.ProbeBW
    bbr.pacing_gain = 1.0
    bbr.cwnd_gain = 2.0

    # cycle_index will be one of (1, 2, 3, 4, 5, 6, 7). Since
    # bbr_advance_cycle_phase() is called right next and it will
    # increase cycle_index by 1, the actual cycle_index in the
    # beginning of ProbeBW will be one of (2, 3, 4, 5, 6, 7, 0)
    # to avoid index 1 (pacing_gain=3/4). See 4.3.4.2 for details.
    bbr.cycle_index = BBR_GAIN_CYCLE_LEN - 1 - random.randint(0, BBR_GAIN_CYCLE_LEN - 2)

    bbr_advance_cycle_phase(r, now)


def bbr_check_cycle_phase(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state

    if bbr.state == BBRState.ProbeBW and bbr_is_next_cycle_phase(r, now):
        bbr_advance_cycle_phase(r, now)

def bbr_advance_cycle_phase(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state

    bbr.cycle_stamp = now
    bbr.cycle_index = (bbr.cycle_index + 1) % BBR_GAIN_CYCLE_LEN
    bbr.pacing_gain = PACING_GAIN_CYCLE[bbr.cycle_index]


def bbr_is_next_cycle_phase(r: QuicPacketRecovery, now: float) -> bool:
    bbr = r._cc.bbr_state
    lost_bytes = bbr.newly_lost_bytes
    pacing_gain = bbr.pacing_gain
    prior_in_flight = bbr.prior_bytes_in_flight

    is_full_length = (now - bbr.cycle_stamp) > bbr.rtprop + K_BBR_MIN_CYCLE_DURATION

    # pacing_gain == 1.0
    if abs(pacing_gain - 1.0) < 10e-12:
        return is_full_length

    if pacing_gain > 1.0:
        return is_full_length and (lost_bytes > 0 or prior_in_flight >= bbr_inflight(r, pacing_gain))

    return is_full_length or prior_in_flight <= bbr_inflight(r, 1.0)


# 4.3.5.  ProbeRTT
def bbr_check_probe_rtt(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    if bbr.state != BBRState.ProbeRTT and bbr.rtprop_expired and not bbr.idle_restart:
        bbr_enter_probe_rtt(r)

        bbr.prior_cwnd = bbr_save_cwnd(r)
        bbr.probe_rtt_done_stamp = None

    if bbr.state == BBRState.ProbeRTT:
        bbr_handle_probe_rtt(r, now)

    bbr.idle_restart = False


def bbr_enter_probe_rtt(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.state = BBRState.ProbeRTT
    bbr.pacing_gain = 1.0
    bbr.cwnd_gain = 1.0

def bbr_handle_probe_rtt(r: QuicPacketRecovery, now: float):
    # Ignore low rate samples during ProbeRTT.
    bbr = r._cc.bbr_state
    r._cc.rs.update_app_limited(True)

    if bbr.probe_rtt_done_stamp != None:
        probe_rtt_done_stamp = bbr.probe_rtt_done_stamp
        if bbr.round_start:
            bbr.probe_rtt_round_done = True

        if bbr.probe_rtt_round_done and now > probe_rtt_done_stamp:
            bbr.rtprop_stamp = now

            bbr_restore_cwnd(r)
            bbr_exit_probe_rtt(r, now)
    
    elif r._cc.rs.inflight <= bbr_min_pipe_cwnd(r):
        bbr.probe_rtt_done_stamp = now + PROBE_RTT_DURATION
        bbr.probe_rtt_round_done = False
        bbr.next_round_delivered = r._cc.rs.delivered

def bbr_exit_probe_rtt(r: QuicPacketRecovery, now: float):
    bbr = r._cc.bbr_state
    if bbr.filled_pipe:
        bbr_enter_probe_bw(r, now)
    else:
        bbr_enter_startup(r)
