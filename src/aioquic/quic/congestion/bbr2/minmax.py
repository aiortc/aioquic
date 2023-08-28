from dataclasses import dataclass
from typing import Any
from datetime import datetime

# Copyright (C) 2020, Cloudflare, Inc.
# Copyright (C) 2017, Google, Inc.
#
# Use of this source code is governed by the following BSD-style license:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#    * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#
#    * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# lib/minmax.c: windowed min/max tracker
#
# Kathleen Nichols' algorithm for tracking the minimum (or maximum)
# value of a data stream over some fixed time interval.  (E.g.,
# the minimum RTT over the past five minutes.) It uses constant
# space and constant time per update yet almost always delivers
# the same minimum as an implementation that has to keep all the
# data in the window.
#
# The algorithm keeps track of the best, 2nd best & 3rd best min
# values, maintaining an invariant that the measurement time of
# the n'th best >= n-1'th best. It also makes sure that the three
# values are widely separated in the time window since that bounds
# the worse case error when that data is monotonically increasing
# over the window.
#
# Upon getting a new min, we can forget everything earlier because
# it has no value - the new min is <= everything else in the window
# by definition and it's the most recent. So we restart fresh on
# every new min and overwrites 2nd & 3rd choices. The same property
# holds for 2nd & 3rd best.

def Now():
    return datetime.timestamp(datetime.now())

@dataclass
class MinmaxSample:
    time : float = 0
    value : Any = None

class Minmax:
    def __init__(self, value):
        self.estimates = [MinmaxSample(Now(), value) for i in range(3)]


    # Resets the estimates to the given value.
    def reset(self, time, meas):
        v = MinmaxSample(time, meas)
        for i in range(len(self.estimates)):
            self.estimates[i] = v
        
        return self.estimates[0].value
    

    # Updates the min estimate based on the given measurement, and returns it.
    def running_min(self, win, time, meas):
        val = MinmaxSample(time, meas)
        delta_time = Now() - self.estimates[2].time

        # Reset if there's nothing in the window or a new min value is found.
        if val.value <= self.estimates[0].value or delta_time > win:
            return self.reset(time, meas)

        if val.value <= self.estimates[1].value:
            self.estimates[2] = val
            self.estimates[1] = val
        elif val.value <= self.estimates[2].value:
            self.estimates[2] = val

        return self.subwin_update(win, time, meas)
    
    # Updates the max estimate based on the given measurement, and returns it.
    def running_max(self, win, time, meas):
        val = MinmaxSample(time, meas)

        delta_time = Now() - self.estimates[2].time

        # Reset if there's nothing in the window or a new max value is found.
        if val.value >= self.estimates[0].value or delta_time > win:
            return self.reset(time, meas)

        if val.value >= self.estimates[1].value:
            self.estimates[2] = val
            self.estimates[1] = val
        elif val.value >= self.estimates[2].value:
            self.estimates[2] = val

        return self.subwin_update(win, time, meas)
    
    # As time advances, update the 1st, 2nd and 3rd estimates.
    def subwin_update(self, win, time, meas):
        val = MinmaxSample(time, meas)

        delta_time = Now() - self.estimates[2].time

        if delta_time > win: 
            # Passed entire window without a new val so make 2nd estimate the
            # new val & 3rd estimate the new 2nd choice. we may have to iterate
            # this since our 2nd estimate may also be outside the window (we
            # checked on entry that the third estimate was in the window).
            self.estimates[0] = self.estimates[1]
            self.estimates[1] = self.estimates[2]
            self.estimates[2] = val

            if Now() - self.estimates[0].time > win:
                self.estimates[0] = self.estimates[1]
                self.estimates[1] = self.estimates[2]
                self.estimates[2] = val

        elif self.estimates[1].time == self.estimates[0].time and delta_time > win / 4.0:

            # We've passed a quarter of the window without a new val so take a
            # 2nd estimate from the 2nd quarter of the window.
            self.estimates[2] = val
            self.estimates[1] = val
        elif self.estimates[2].time == self.estimates[1].time and delta_time > win / 2.0:
        
            # We've passed half the window without finding a new val so take a
            # 3rd estimate from the last half of the window.
            self.estimates[2] = val
        

        return self.estimates[0].value
    