from .slow_start import SlowStart
from ..congestion import K_MAX_DATAGRAM_SIZE


class StandardSlowStart(SlowStart):

    def __init__(self):
        pass

    def set_cc(self, cc):
        self.cc = cc

    def is_slow_start(self):
        # return True if it is time for slow start
        return self.cc.get_ssthresh() is None or self.cc.get_congestion_window() < self.cc.get_ssthresh()

    def get_new_cwnd(self, acked_packet):
        # return the new cwnd after an ack was received
        return self.cc.get_congestion_window() + acked_packet.sent_bytes
    
    def get_new_cwnd_segments(self, acked_packet):
        # return the new cwnd after an ack was received (in number of segments, used by cubic)
        return (self.cc.get_congestion_window() + acked_packet.sent_bytes) / K_MAX_DATAGRAM_SIZE # converts to segments at the end

    def on_rtt_increased(self):
        # update state if rtt has increased
        pass
    