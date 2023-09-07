

class SlowStart:

    def __init__(self):
        pass

    def reset(self):
        pass

    def set_cc(self, cc):
        self.cc = cc

    def is_slow_start(self):
        # return True if it is time for slow start
        pass

    def on_sent(self, packet):
        pass

    def on_ack(self, acked_packet):
        # return the new cwnd after an ack was received
        pass

    def on_lost(self, packet):
        pass

    def on_expired(self, packet):
        pass

    def set_ssthresh(self, value):
        # update ssthresh when a packet is lost to value
        pass

    def on_rtt_measured(self, latest_rtt, now) -> bool:
        # update state on rtt received, return True if rtt has increased
        pass

    def get_ssthresh(self):
        pass
    