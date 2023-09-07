

class SlowStart:

    def __init__(self):
        pass

    def set_cc(self, cc):
        self.cc = cc

    def is_slow_start(self):
        # return True if it is time for slow start
        pass

    def get_new_cwnd(self, acked_packet):
        # return the new cwnd after an ack was received
        pass

    def get_new_cwnd_segments(self, acked_packet):
        # return the new cwnd after an ack was received (in number of segments, used by cubic)
        pass

    def on_rtt_increased(self):
        # update state if rtt has increased
        pass
    