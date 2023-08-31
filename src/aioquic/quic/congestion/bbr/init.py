from ...recovery import QuicPacketRecovery, K_MICRO_SECOND
from ..congestion import Now, K_MAX_DATAGRAM_SIZE
from .values import *

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


# BBR Functions at Initialization.
#

# 4.3.1.  Initialization Steps
def bbr_init(r: QuicPacketRecovery):
    now = Now()

    bbr = r._cc.bbr_state
    bbr.rtprop = float("inf")
    bbr.rtprop_stamp = now
    bbr.next_round_delivered = r._cc.rs.delivered

    r.send_quantum = K_MAX_DATAGRAM_SIZE

    bbr_init_round_counting(r)
    bbr_init_full_pipe(r)
    bbr_init_pacing_rate(r)
    bbr_enter_startup(r)


# 4.1.1.3.  Tracking Time for the BBR.BtlBw Max Filter
def bbr_init_round_counting(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.next_round_delivered = 0
    bbr.round_start = False
    bbr.round_count = 0

# 4.2.1.  Pacing Rate
def bbr_init_pacing_rate(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    srtt = max(r._rtt_smoothed, K_MICRO_SECOND)

    # At init, cwnd is initcwnd.
    nominal_bandwidth = bbr.cwnd / srtt

    bbr.pacing_rate = int(bbr.pacing_gain * nominal_bandwidth)


# 4.3.2.1.  Startup Dynamics
def bbr_enter_startup(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.state = BBRState.Startup
    bbr.pacing_gain = BBR_HIGH_GAIN
    bbr.cwnd_gain = BBR_HIGH_GAIN


# 4.3.2.2.  Estimating When Startup has Filled the Pipe
def bbr_init_full_pipe(r: QuicPacketRecovery):
    bbr = r._cc.bbr_state

    bbr.filled_pipe = False
    bbr.full_bw = 0
    bbr.full_bw_count = 0