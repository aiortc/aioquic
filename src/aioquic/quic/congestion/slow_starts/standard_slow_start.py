from .slow_start import SlowStart
from ..congestion import K_MAX_DATAGRAM_SIZE, QuicRttMonitor
from typing import Optional


class StandardSlowStart(SlowStart):

    # Classic HyStart slow start

    def __init__(self):
        self.reset()

    def reset(self):
        self.ssthresh: Optional[int] = None
        self._rtt_monitor = QuicRttMonitor()

    def set_cc(self, cc):
        self.cc = cc

    def cwnd(self):
        return self.cc.get_congestion_window()

    def is_slow_start(self):
        # return True if it is time for slow start
        return self.ssthresh is None or self.cwnd() < self.ssthresh
    
    def on_ack(self, acked_packet):
        # return the new cwnd after an ack was received
        self.cc._set_congestion_window(self.cwnd() + acked_packet.sent_bytes)

    def set_ssthresh(self, value):
        self.ssthresh = value

    def on_rtt_measured(self, latest_rtt, now):
        # update state on rtt received
        if self.ssthresh is None and self._rtt_monitor.is_rtt_increasing(
            latest_rtt, now
        ):
            # enter congestion avoidance
            print("RTT = ", latest_rtt)
            self.ssthresh = self.cwnd()   
            return True
        return False

    def get_ssthresh(self):
        if self.ssthresh == None: return None
        return int(self.ssthresh)
    