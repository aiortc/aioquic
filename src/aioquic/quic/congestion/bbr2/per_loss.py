from ...recovery import QuicPacketRecovery
from ...packet_builder import QuicSentPacket
from .values import K_BBR2_LOSS_THRESH, K_BBR2_BETA, BBR2State, MAX_INT
from .per_ack import bbr2_target_inflight, bbr2_start_probe_bw_down, bbr2_update_max_bw

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
