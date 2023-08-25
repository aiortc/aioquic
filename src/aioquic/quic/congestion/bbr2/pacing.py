from ...recovery import QuicPacketRecovery
from .values import BBR2, K_BBR2_STARTUP_PACING_GAIN, K_BBR2_PACING_MARGIN_PERCENT

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

# BBR2 Transmit Packet Pacing Functions
#

# 4.6.2.  Pacing Rate: BBR.pacing_rate
def bbr2_init_pacing_rate(r: QuicPacketRecovery):
    bbr : BBR2 = r._cc.bbr_state

    srtt = r._rtt_smoothed

    # At init, cwnd is initcwnd.
    nominal_bandwidth = bbr.cwnd / srtt

    bbr.pacing_rate = int(K_BBR2_STARTUP_PACING_GAIN * nominal_bandwidth)
    bbr.init_pacing_rate = int(K_BBR2_STARTUP_PACING_GAIN * nominal_bandwidth)


def bbr2_set_pacing_rate_with_gain(r: QuicPacketRecovery, pacing_gain: float):
    bbr = r._cc.bbr_state
    rate = int(pacing_gain * bbr.bw * (1.0 - K_BBR2_PACING_MARGIN_PERCENT))

    if bbr.filled_pipe or rate > bbr.pacing_rate or bbr.pacing_rate == bbr.init_pacing_rate:
        bbr.pacing_rate = rate

def bbr2_set_pacing_rate(r: QuicPacketRecovery):
    bbr2_set_pacing_rate_with_gain(r, r._cc.bbr_state.pacing_gain)