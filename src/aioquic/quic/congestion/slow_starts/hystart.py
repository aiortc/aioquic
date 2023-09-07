from .slow_start import SlowStart
from ..congestion import K_MAX_DATAGRAM_SIZE, Now, QuicRttMonitor
from enum import Enum

MIN_RTT_THRESH = 0.004 # sec
MAX_RTT_THRESH = 0.016 #sec
MIN_RTT_DIVISOR = 8
N_RTT_SAMPLE = 8
CSS_GROWTH_DIVISOR = 4
CSS_ROUNDS = 5
L = float("inf") # paced

class HyStartState(Enum):
    SlowStart=0
    ConservativeSlowStart=1
    CongestionAvoidance=2


class HyStart(SlowStart):

    # HyStart++ implementation
    # https://datatracker.ietf.org/doc/html/rfc9406#name-hystart-algorithm

    def __init__(self):
        self.reset()

    def reset(self):
        self.lastRoundMinRTT = float("inf")
        self.currentRoundMinRTT = float("inf")
        self.currRTT = float("inf")
        self.rttSampleCount = 0
        self.rttThresh = 0
        self.rounds_in_CSS = 0

        self.state = HyStartState.SlowStart

        self.bytes_remaining_until_next_round = 0
        self.cache = {}

        self.ssthresh = None
        self._rtt_monitor = QuicRttMonitor()

    def set_cc(self, cc):
        self.cc = cc
        self.bytes_remaining_until_next_round = cc.get_congestion_window()

    def cwnd(self):
        return self.cc.get_congestion_window()
    
    def set_cwnd(self, value):
        self.cc._set_congestion_window(value)

    def start_round(self):
        self.lastRoundMinRTT = self.currentRoundMinRTT
        self.currentRoundMinRTT = float("inf")
        self.rttSampleCount = 0
        if self.state == HyStartState.ConservativeSlowStart:
            self.rounds_in_CSS += 1

    def is_slow_start(self):
        # return True if it is time for slow start
        return self.state != HyStartState.CongestionAvoidance
    
    def on_sent(self, packet):
        self.cache[packet.packet_number] = Now()

    def on_ack(self, acked_packet):
        # return the new cwnd after an ack was received
        N = acked_packet.sent_bytes
        if self.state == HyStartState.SlowStart:
            self.set_cwnd(self.cwnd() + min(N, L*K_MAX_DATAGRAM_SIZE))
        elif self.state == HyStartState.ConservativeSlowStart:
            self.set_cwnd(self.cwnd() + (min(N, L * K_MAX_DATAGRAM_SIZE) / CSS_GROWTH_DIVISOR))

        self.bytes_remaining_until_next_round -= N
        if self.bytes_remaining_until_next_round <= 0:  # window fully acked
            self.start_round()
            self.bytes_remaining_until_next_round = self.cwnd()  # consider this new round down when 1 entire cwnd was acked

        now = Now()
        if acked_packet.packet_number in self.cache:
            rtt = now - self.cache[acked_packet.packet_number]
            del self.cache[acked_packet.packet_number]

            self.on_rtt_measured(rtt, now)

    def on_lost(self, packet):
        self.state = HyStartState.CongestionAvoidance # change to congestion avoidance as there was losses
        try:
            del self.cache[packet.packet_number]
        except:
            pass
        self.cache = {} # delete the cache, as slow start has now ended

    def on_expired(self, packet):
        try:
            del self.cache[packet.packet_number]
        except:
            pass

    def on_rtt_measured(self, latest_rtt, now) -> bool:
        # update state on rtt received
        self.currentRoundMinRTT = min(self.currentRoundMinRTT, latest_rtt)
        self.rttSampleCount += 1

        if self.state == HyStartState.SlowStart:
            if ((self.rttSampleCount >= N_RTT_SAMPLE) and (self.currentRoundMinRTT != float("inf")) and (self.lastRoundMinRTT != float("inf"))):
                self.rttThresh = max(MIN_RTT_THRESH, min(self.lastRoundMinRTT / MIN_RTT_DIVISOR, MAX_RTT_THRESH))
                if (self.currentRoundMinRTT >= (self.lastRoundMinRTT + self.rttThresh)) :
                    self.cssBaselineMinRtt = self.currentRoundMinRTT
                    self.state = HyStartState.ConservativeSlowStart

        elif self.state == HyStartState.ConservativeSlowStart:
            if (self.currentRoundMinRTT < self.cssBaselineMinRtt):
                self.cssBaselineMinRtt = float("inf")
                self.state = HyStartState.SlowStart
                self.rounds_in_CSS = 0

            elif self.rounds_in_CSS > CSS_ROUNDS:
                self.state = HyStartState.CongestionAvoidance
                self.ssthresh = self.cwnd()

        if self.ssthresh is None and self._rtt_monitor.is_rtt_increasing(
            latest_rtt, now
        ):
            return True
        
        return False

    def get_ssthresh(self):
        if self.ssthresh == None: return None
        return int(self.ssthresh)
    
    def set_ssthresh(self, value):
        # update ssthresh when a packet is lost to value
        self.ssthresh = value