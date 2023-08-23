from datetime import datetime
from .packet_builder import QuicSentPacket
from typing import Iterable, Optional
from enum import Enum
import random
from dataclasses import dataclass

K_GRANULARITY = 0.001  # seconds

# congestion control
K_MAX_DATAGRAM_SIZE = 1280
K_INITIAL_WINDOW_SEGMENTS = 10
K_INITIAL_WINDOW = K_INITIAL_WINDOW_SEGMENTS * K_MAX_DATAGRAM_SIZE
K_MINIMUM_WINDOW_SEGMENTS = 2
K_MINIMUM_WINDOW = K_MINIMUM_WINDOW_SEGMENTS * K_MAX_DATAGRAM_SIZE
K_LOSS_REDUCTION_FACTOR = 0.5

# cubic specific variables (see https://www.rfc-editor.org/rfc/rfc9438.html#name-definitions)
K_CUBIC_K = 1    
K_CUBIC_C = 0.4
K_CUBIC_LOSS_REDUCTION_FACTOR = 0.7
K_CUBIC_ADDITIVE_INCREASE = 1  # in number of segments 

# BBR specific variables (see https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-core-algorithm-design-param)
K_BBR_LOSS_THRESHOLD = 0.02
K_BBR_BETA = 0.7
K_BBR_HEADROOM=0.85
K_BBR_MIN_PIPE_CWND=4*K_MAX_DATAGRAM_SIZE
K_BBR_STARTUP_PACING_GAIN = 2.77
K_BBR_STARTUP_CWND_GAIN = 2
K_BRR_MIN_RTT_FILTER_LEN = 10
K_BRR_PROBE_RTT_INTERVAL = 5
K_BBR_PROBE_RTT_CWND_GAIN = 0.5
K_BBR_PROBE_RTT_DURATION = 0.2  # in seconds
K_BBR_MAX_BW_FILTER_LEN = 2
K_BBR_EW_EXTRA_ACKED_FILTER_LEN = 10
K_BBR_PACING_MARGIN_PERCENT = 1

class CongestionEvent(Enum):
    ACK=0
    PACKET_SENT=1
    PACKET_EXPIRED=2
    PACKET_LOST=3
    RTT_MEASURED=4



class QuicRttMonitor:
    """
    Roundtrip time monitor for HyStart.
    """

    def __init__(self) -> None:
        self._increases = 0
        self._last_time = None
        self._ready = False
        self._size = 5

        self._filtered_min: Optional[float] = None

        self._sample_idx = 0
        self._sample_max: Optional[float] = None
        self._sample_min: Optional[float] = None
        self._sample_time = 0.0
        self._samples = [0.0 for i in range(self._size)]

    def add_rtt(self, rtt: float) -> None:
        self._samples[self._sample_idx] = rtt
        self._sample_idx += 1

        if self._sample_idx >= self._size:
            self._sample_idx = 0
            self._ready = True

        if self._ready:
            self._sample_max = self._samples[0]
            self._sample_min = self._samples[0]
            for sample in self._samples[1:]:
                if sample < self._sample_min:
                    self._sample_min = sample
                elif sample > self._sample_max:
                    self._sample_max = sample

    def is_rtt_increasing(self, rtt: float, now: float) -> bool:
        if now > self._sample_time + K_GRANULARITY:
            self.add_rtt(rtt)
            self._sample_time = now

            if self._ready:
                if self._filtered_min is None or self._filtered_min > self._sample_max:
                    self._filtered_min = self._sample_max

                delta = self._sample_min - self._filtered_min
                if delta * 4 >= self._filtered_min:
                    self._increases += 1
                    if self._increases >= self._size:
                        return True
                elif delta > 0:
                    self._increases = 0
        return False
    

def Now():
    return datetime.timestamp(datetime.now())


class QuicCongestionControl:

    def __init__(self, *args, **kwargs) -> None:
        if ("callback" in kwargs):
            self.callback = kwargs["callback"] # a callback argument that is called when an event occurs
        else:
            self.callback = None

    def on_packet_acked(self, packet: QuicSentPacket):
        if self.callback:
            self.callback(CongestionEvent.ACK, self)

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        if self.callback:
            self.callback(CongestionEvent.PACKET_SENT, self)

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        if self.callback:
            self.callback(CongestionEvent.PACKET_EXPIRED, self)

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        if self.callback:
            self.callback(CongestionEvent.PACKET_LOST, self)

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        if self.callback:
            self.callback(CongestionEvent.RTT_MEASURED, self)

    def get_congestion_window(self) -> int:
        pass

    def get_ssthresh(self) -> Optional[int]: 
        pass

    def get_bytes_in_flight(self) -> int:
        pass


class RenoCongestionControl(QuicCongestionControl):
    """
    New Reno congestion control.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.bytes_in_flight = 0
        self.congestion_window = K_INITIAL_WINDOW
        self._congestion_recovery_start_time = 0.0
        self._congestion_stash = 0
        self._rtt_monitor = QuicRttMonitor()
        self.ssthresh: Optional[int] = None

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        super().on_packet_acked(packet)
        self.bytes_in_flight -= packet.sent_bytes

        # don't increase window in congestion recovery
        if packet.sent_time <= self._congestion_recovery_start_time:
            return

        if self.ssthresh is None or self.congestion_window < self.ssthresh:
            # slow start
            self.congestion_window += packet.sent_bytes
        else:
            # congestion avoidance
            self._congestion_stash += packet.sent_bytes
            count = self._congestion_stash // self.congestion_window
            if count:
                self._congestion_stash -= count * self.congestion_window
                self.congestion_window += count * K_MAX_DATAGRAM_SIZE

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)
        self.bytes_in_flight += packet.sent_bytes

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)
        lost_largest_time = 0.0
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            lost_largest_time = packet.sent_time

        # start a new congestion event if packet was sent after the
        # start of the previous congestion recovery period.
        if lost_largest_time > self._congestion_recovery_start_time:
            self._congestion_recovery_start_time = now
            self.congestion_window = max(
                int(self.congestion_window * K_LOSS_REDUCTION_FACTOR), K_MINIMUM_WINDOW
            )
            self.ssthresh = self.congestion_window

        # TODO : collapse congestion window if persistent congestion

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)
        # check whether we should exit slow start
        if self.ssthresh is None and self._rtt_monitor.is_rtt_increasing(
            latest_rtt, now
        ):
            self.ssthresh = self.congestion_window

    def get_congestion_window(self) -> int:
        return int(self.congestion_window)
    
    def get_ssthresh(self) -> int: 
        if self.ssthresh == None: return None
        return int(self.ssthresh)
    
    def get_bytes_in_flight(self) -> int:
        return self.bytes_in_flight



class CubicCongestionControl(QuicCongestionControl):
    """
    Cubic congestion control implementation for aioquic
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.bytes_in_flight = 0
        self.congestion_window = K_INITIAL_WINDOW_SEGMENTS
        self._congestion_stash = 0
        self._congestion_recovery_start_time = 0.0
        self._rtt_monitor = QuicRttMonitor()
        self.ssthresh: Optional[int] = None

        self.caller = kwargs["caller"]   # the parent, allowing to get the smoothed rtt

        self._cwnd_prior = None
        self._cwnd_epoch = None
        self._t_epoch = None
        self._W_max = None
        self._W_est = None
        self._first_slow_start = True
        self._starting_congestion_avoidance = False
        

    def better_cube_root(self, x):
        if (x < 0):
            # avoid precision errors that make the cube root returns an imaginary number
            return -((-x)**(1./3.))
        else:
            return (x)**(1./3.)
        
    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        self.on_packet_acked_timed(packet, Now(), self.caller._rtt_smoothed)
        super().on_packet_acked(packet)

    def on_packet_acked_timed(self, packet: QuicSentPacket, now: float, rtt : float) -> None:
        self.bytes_in_flight -= packet.sent_bytes

        if self.ssthresh is None or self.congestion_window < self.ssthresh:
            # slow start
            self.congestion_window += packet.sent_bytes // K_MAX_DATAGRAM_SIZE
        else:
            # congestion avoidance
            if (self._first_slow_start and not self._starting_congestion_avoidance):
                self._first_slow_start = False
                self._cwnd_prior = self.congestion_window
                self._W_max = self.congestion_window
                self._t_epoch = now
                self._cwnd_epoch = self.congestion_window
                self._W_est = self._cwnd_epoch

            # initialize the variables used at start of congestion avoidance
            if self._starting_congestion_avoidance:
                self._starting_congestion_avoidance = False
                self._first_slow_start = False
                self._t_epoch = now
                self._cwnd_epoch = self.congestion_window
                self._W_est = self._cwnd_epoch

            seg_ack = packet.sent_bytes // K_MAX_DATAGRAM_SIZE
            self._W_est = self._W_est + K_CUBIC_ADDITIVE_INCREASE*(seg_ack/self.congestion_window)

            t = now - self._t_epoch

            # calculate K by converting W_max in term of number of segments
            K = self.better_cube_root((self._W_max - self._cwnd_epoch)/K_CUBIC_C)

            def W_cubic(t):
                return K_CUBIC_C * (t - K)**3 + (self._W_max)
            
            target = None
            if (W_cubic(t + rtt) < self.congestion_window):
                target = self.congestion_window
            elif (W_cubic(t + rtt) > 1.5*self.congestion_window):
                target = self.congestion_window*1.5
            else:
                target = W_cubic(t + rtt)


            if W_cubic(t) < self._W_est:
                # reno friendly region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-reno-friendly-region)
                self.congestion_window = self._W_est
            elif self.congestion_window < self._W_max:
                # concave region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-concave-region)
                self.congestion_window = self.congestion_window + ((target - self.congestion_window)/self.congestion_window)
            else:
                # convex region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-convex-region)
                self.congestion_window = self.congestion_window + ((target - self.congestion_window)/self.congestion_window)

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)
        self.bytes_in_flight += packet.sent_bytes

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)
        lost_largest_time = 0.0
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            lost_largest_time = packet.sent_time

        # start a new congestion event if packet was sent after the
        # start of the previous congestion recovery period.
        if lost_largest_time > self._congestion_recovery_start_time:

            self._congestion_recovery_start_time = now

            # Normal congestion handle, can't be used in same time as fast convergence
            # self._W_max = self.congestion_window

            # fast convergence
            if (self._W_max != None and self.congestion_window < self._W_max):
                self._W_max = self.congestion_window * (1 + K_CUBIC_LOSS_REDUCTION_FACTOR) / 2
            else:
                self._W_max = self.congestion_window

            # normal congestion MD
            flight_size = self.bytes_in_flight // K_MAX_DATAGRAM_SIZE
            self.ssthresh = int(flight_size*K_CUBIC_LOSS_REDUCTION_FACTOR)
            self._cwnd_prior = self.congestion_window
            self.congestion_window = max(self.ssthresh, K_MINIMUM_WINDOW_SEGMENTS)
            self.ssthresh = max(self.ssthresh, K_MINIMUM_WINDOW_SEGMENTS)
            

            self._starting_congestion_avoidance = True  # restart a new congestion avoidance phase


    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)
        # check whether we should exit slow start
        if self.ssthresh is None and self._rtt_monitor.is_rtt_increasing(
            latest_rtt, now
        ):
            self.ssthresh = self.congestion_window
            self._cwnd_prior = self.congestion_window

    def get_congestion_window(self) -> int:
        return int(self.congestion_window * K_MAX_DATAGRAM_SIZE)
    
    def get_ssthresh(self) -> int:
        if self.ssthresh == None: return None
        return int(self.ssthresh * K_MAX_DATAGRAM_SIZE)
    
    def get_bytes_in_flight(self) -> int:
        return self.bytes_in_flight
    

class BBRStates(Enum):
    Startup=0
    Drain=1
    ProbeBW_DOWN=2
    ProbeBW_CRUISE=3
    ProbeBW_REFILL=4
    ProbeBW_UP=5
    ProbeRTT=6


def is_ProbeBW(state):
    return state == BBRStates.ProbeBW_CRUISE or state == BBRStates.ProbeBW_DOWN or state == BBRStates.ProbeBW_UP or state == BBRStates.ProbeBW_REFILL

class ACKPhase(Enum):
    ACKS_PROBE_STOPPING=0
    ACKS_REFILLING=1
    ACKS_PROBE_STARTING=2

@dataclass
class BBRRateSample:
    delivered: int = 0
    delivery_rate : float = 0.0
    rtt : float = 0.0
    newly_acked : int = 0
    newly_lost : int = 0
    tx_in_flight : int = 0
    lost: int = 0
    is_app_limited : bool = False

@dataclass
class BBRGlobalStats:
    delivered: int = 0
    lost: int = 0
    app_limited: int = 0

class BBRCongestionControl(QuicCongestionControl):

    def __init__(self, *args, **kwargs) -> None:

        super().__init__(*args, **kwargs)

        """
        self.bytes_in_flight = 0
        self._congestion_recovery_start_time = 0.0
        self._congestion_stash = 0
        self._rtt_monitor = QuicRttMonitor()
        self.ssthresh: Optional[int] = None

        # BBR specific variables
        self.state = BBRStates.Startup
        self.round_count = 0
        self.round_start = True
        self.next_round_delivered = None
        self.idle_restart = False
        """

        self.lost_table = {}            # a table containing for each packet number as key the number of lost bytes
        self.inflight_table = {}        # a table containing for each packet number as key the number of inflight bytes
        self.delivered_table = {}       # a table containing for each packet number as key the number of delivered bytes
        self.cwnd = K_INITIAL_WINDOW
        self.rs = BBRRateSample()
        self.C = BBRGlobalStats()

        self.inflight = 0
        self.packets_in_flight = 0
        self.fast_recovery_counts = 0
        self.loss_rate = 0
        self.sequence_ranges_lost = 0

        self.packet = None
        self.max_bw = 0
        self.bw = 0
        self.probe_rtt_min_stamp = 0
        self.probe_rtt_min_delay = 0

        # BBROnInit
        now = Now()
        self.caller = kwargs["caller"]   # the parent, allowing to get the smoothed rtt
        self.SRTT = self.caller._rtt_smoothed

        # TODO
        #init_windowed_max_filter(filter=BBR.MaxBwFilter, value=0, time=0)
        self.min_rtt = self.SRTT if self.SRTT else float('inf')
        self.min_rtt_stamp = now
        self.probe_rtt_done_stamp = 0
        self.probe_rtt_round_done = False
        self.prior_cwnd = 0
        self.idle_restart = False
        self.extra_acked_interval_start = now
        self.extra_acked_delivered = 0
        self.BBRResetCongestionSignals()
        self.BBRResetLowerBounds()
        self.BBRInitRoundCounting()
        self.BBRInitFullPipe()
        self.BBRInitPacingRate()
        self.BBREnterStartup()

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        super().on_packet_acked(packet)
        self.packet = packet
        self.C.delivered += packet.sent_bytes
        self.inflight -= packet.sent_bytes
        self.packets_in_flight -= 1
        self.BBRUpdateModelAndState()
        self.BBRUpdateControlParameters()

        del self.lost_table[packet.packet_number]     
        del self.inflight_table[packet.packet_number]
        del self.delivered_table[packet.packet_number]


    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)

        self.inflight += packet.sent_bytes
        self.packets_in_flight += 1

        self.inflight_table[packet.packet_number] = self.inflight
        self.lost_table[packet.packet_number] = self.C.lost # total number of lost saved when sending packet
        self.delivered_table[packet.packet_number] = self.C.delivered
        # BBROnTransmit
        self.BBRHandleRestartFromIdle()

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)

        for packet in packets:
            self.inflight -= packet.sent_bytes
            # delete the entries for this packet number in tables
            del self.lost_table[packet.packet_number]     
            del self.inflight_table[packet.packet_number]
            del self.delivered_table[packet.packet_number]
            self.packets_in_flight -= 1

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)

        for packet in packets:
            self.C.lost += packet.sent_bytes

        self.BBRHandleLostPacket(packets)

        for packet in packets:
            self.inflight -= packet.sent_bytes
            del self.lost_table[packet.packet_number]     
            del self.inflight_table[packet.packet_number]
            del self.delivered_table[packet.packet_number]
            self.packets_in_flight -= 1


    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)
        # check whether we should exit slow start

        """
        if self.ssthresh is None and self._rtt_monitor.is_rtt_increasing(
            latest_rtt, now
        ):
            self.ssthresh = self.congestion_window
        """

    def get_congestion_window(self) -> int:
        return int(self.cwnd)
    
    def get_ssthresh(self) -> int: 
        return None
    
    def get_bytes_in_flight(self) -> int:
        return self.inflight
    
    def BBRUpdateModelAndState(self):
        self.BBRUpdateLatestDeliverySignals()
        self.BBRUpdateCongestionSignals()
        self.BBRUpdateACKAggregation()
        self.BBRCheckStartupDone()
        self.BBRCheckDrain()
        self.BBRUpdateProbeBWCyclePhase()
        self.BBRUpdateMinRTT()
        self.BBRCheckProbeRTT()
        self.BBRAdvanceLatestDeliverySignals()
        self.BBRBoundBWForModel()

    def BBRUpdateControlParameters(self):
        self.BBRSetPacingRate()
        self.BBRSetSendQuantum()
        self.BBRSetCwnd()
    
    def BBREnterStartup(self):
        self.state = BBRStates.Startup
        self.pacing_gain = K_BBR_STARTUP_PACING_GAIN
        self.cwnd_gain = K_BBR_STARTUP_CWND_GAIN

    def BBRInitFullPipe(self):
        self.filled_pipe = False
        self.full_bw = 0
        self.full_bw_count = 0

    def BBRCheckStartupDone(self):
        self.BBRCheckStartupFullBandwidth()
        self.BBRCheckStartupHighLoss()
        if (self.state == BBRStates.Startup and self.filled_pipe):
            self.BBREnterDrain()

    def BBRCheckStartupFullBandwidth(self):
        if self.filled_pipe or not self.round_start or self.rs.is_app_limited:
            return  # no need to check for a full pipe now 
        if (self.max_bw >= self.full_bw * 1.25):  # still growing ? 
            self.full_bw = self.max_bw    # record new baseline level 
            self.full_bw_count = 0
            return
        self.full_bw_count += 1 # another round w/o much growth 
        if (self.full_bw_count >= 3):
            self.filled_pipe = True

    def BBRCheckStartupHighLoss(self):
        # TODO make sure this function is working !!!!!
        if (self.fast_recovery_counts >= 1 and self.loss_rate >= K_BBR_LOSS_THRESHOLD and self.sequence_ranges_lost >= 3):
            self.filled_pipe = True

    def BBREnterDrain(self):
        self.state = BBRStates.Drain
        self.pacing_gain = 1/K_BBR_STARTUP_PACING_GAIN  # pace slowly 
        self.cwnd_gain = K_BBR_STARTUP_CWND_GAIN      # maintain cwnd
    
    def BBRCheckDrain(self):
        if (self.state == BBRStates.Drain and self.packets_in_flight <= self.BBRInflight(1.0)):
            self.BBREnterProbeBW()  # BBR estimates the queue was drained 

    
    def BBRCheckTimeToProbeBW(self):
        """ Is it time to transition from DOWN or CRUISE to REFILL? """
        if (self.BBRHasElapsedInPhase(self.bw_probe_wait) or self.BBRIsRenoCoexistenceProbeTime()):
            self.BBRStartProbeBW_REFILL()
            return True
        return False
    

    def BBRPickProbeWait(self):
        """
        Randomized decision about how long to wait until
        probing for bandwidth, using round count and wall clock.
        """
        # Decide random round-trip bound for wait: 
        self.rounds_since_bw_probe = random.randint(0, 1); # 0 or 1 
        # Decide the random wall clock bound for wait: 
        self.bw_probe_wait = 2 + random.random()     # 2 + 0..1 sec

    def BBRIsRenoCoexistenceProbeTime(self):
        reno_rounds = self.BBRTargetInflight()
        rounds = min(reno_rounds, 63)
        return self.rounds_since_bw_probe >= rounds
    
    def BBRTargetInflight(self):
        """
        How much data do we want in flight?
        Our estimated BDP, unless congestion cut cwnd.
        """
        return min(self.bdp, self.cwnd)
    
    def BBREnterProbeBW(self):
        self.BBRStartProbeBW_DOWN()

    def BBRStartProbeBW_DOWN(self):
        self.BBRResetCongestionSignals()
        self.probe_up_cnt = float("inf")  # not growing inflight_hi
        self.BBRPickProbeWait()
        self.cycle_stamp = Now()  # start wall clock 
        self.ack_phase  = ACKPhase.ACKS_PROBE_STOPPING
        self.BBRStartRound()
        self.state = BBRStates.ProbeBW_DOWN

    def BBRStartProbeBW_CRUISE(self):
        self.state = BBRStates.ProbeBW_CRUISE

    def BBRStartProbeBW_REFILL(self):
        self.BBRResetLowerBounds()
        self.bw_probe_up_rounds = 0
        self.bw_probe_up_acks = 0
        self.ack_phase = ACKPhase.ACKS_REFILLING
        self.BBRStartRound()
        self.state = BBRStates.ProbeBW_REFILL

    def BBRStartProbeBW_UP(self):
        self.ack_phase = ACKPhase.ACKS_PROBE_STARTING
        self.BBRStartRound()
        self.cycle_stamp = Now() # start wall clock 
        self.state = BBRStates.ProbeBW_UP
        self.BBRRaiseInflightHiSlope()

    def BBRUpdateProbeBWCyclePhase(self):
        """The core state machine logic for ProbeBW"""
        if (not self.filled_pipe):
            return  # only handling steady-state behavior here
        self.BBRAdaptUpperBounds()
        if (not self.IsInAProbeBWState()):
            return # only handling ProbeBW states here: 

        if self.state == BBRStates.ProbeBW_DOWN:

            if (self.BBRCheckTimeToProbeBW()):
                return # already decided state transition
            if (self.BBRCheckTimeToCruise()):
                self.BBRStartProbeBW_CRUISE()

        if self.state == BBRStates.ProbeBW_CRUISE:        
            if (self.BBRCheckTimeToProbeBW()):
                return # already decided state transition

        if self.state == BBRStates.ProbeBW_REFILL: 
            # After one round of REFILL, start UP
            if (self.round_start):
                self.bw_probe_samples = 1
                self.BBRStartProbeBW_UP()

        if self.state == BBRStates.ProbeBW_UP: 
            if (self.BBRHasElapsedInPhase(self.min_rtt) and self.inflight > self.BBRInflight(self.max_bw, 1.25)):
                self.BBRStartProbeBW_DOWN()

    def IsInAProbeBWState(self):
        state = self.state
        return (state == BBRStates.ProbeBW_DOWN or
                state == BBRStates.ProbeBW_CRUISE or
                state == BBRStates.ProbeBW_REFILL or
                state == BBRStates.ProbeBW_UP)
    
      
    def BBRCheckTimeToCruise(self):
        """Time to transition from DOWN to CRUISE?"""
        if (self.inflight > self.BBRInflightWithHeadroom()):
            return False  # not enough headroom 
        if (self.inflight <= self.BBRInflight(self.max_bw, 1.0)):
            return True   # inflight <= estimated BDP
        
    
    def BBRHasElapsedInPhase(self, interval):
        return Now() > self.cycle_stamp + interval
    

    def BBRInflightWithHeadroom(self ):
        """
        Return a volume of data that tries to leave free
        headroom in the bottleneck buffer or link for
        other flows, for fairness convergence and lower
        RTTs and loss */
        """
        if (self.inflight_hi == float("inf")):
            return float("inf")
        headroom = max(1, K_BBR_HEADROOM * self.inflight_hi)
        return max(self.inflight_hi - headroom,  K_BBR_MIN_PIPE_CWND)
    
      
    def BBRProbeInflightHiUpward(self):
        """
        Increase inflight_hi if appropriate.
        """
        if (not self.is_cwnd_limited or self.cwnd < self.inflight_hi):
            return  # not fully using inflight_hi, so don't grow it 
        self.bw_probe_up_acks += self.rs.newly_acked
        if (self.bw_probe_up_acks >= self.probe_up_cnt):
            delta = self.bw_probe_up_acks / self.probe_up_cnt
            self.bw_probe_up_acks -= delta * self.bw_probe_up_cnt
            self.inflight_hi += delta
        if (self.round_start):
            self.BBRRaiseInflightHiSlope()


    def BBRAdaptUpperBounds(self):
        """
        Track ACK state and update BBR.max_bw window and
        BBR.inflight_hi and BBR.bw_hi. */
        """
        if (self.ack_phase == ACKPhase.ACKS_PROBE_STARTING and self.round_start):
            # starting to get bw probing samples 
            self.ack_phase = ACKPhase.ACKS_PROBE_FEEDBACK
        if (self.ack_phase == ACKPhase.ACKS_PROBE_STOPPING and self.round_start):
            # end of samples from bw probing phase 
            if (self.IsInAProbeBWState() and not self.rs.is_app_limited):
                self.BBRAdvanceMaxBwFilter()

        if (not self.CheckInflightTooHigh()):
            # Loss rate is safe. Adjust upper bounds upward.
            if (self.inflight_hi == float("inf") or self.bw_hi == float("inf")):
                return # no upper bounds to raise
            if (self.rs.tx_in_flight > self.inflight_hi):
                self.inflight_hi = self.rs.tx_in_flight
            if (self.rs.delivery_rate > self.bw_hi):
                self.bw_hi = self.rs.bw
            if (self.state == BBRStates.ProbeBW_UP):
                self.BBRProbeInflightHiUpward()
    
    def BBRRaiseInflightHiSlope(self):
        # Raise inflight_hi slope if appropriate.
        growth_this_round = K_MAX_DATAGRAM_SIZE << self.bw_probe_up_rounds
        self.bw_probe_up_rounds = min(self.bw_probe_up_rounds + 1, 30)
        self.probe_up_cnt = max(self.cwnd / growth_this_round, 1)

    def BBRUpdateMinRTT(self):
        self.probe_rtt_expired = Now() > self.probe_rtt_min_stamp + K_BRR_PROBE_RTT_INTERVAL
        if (self.rs.rtt >= 0 and (self.rs.rtt < self.probe_rtt_min_delay or self.probe_rtt_expired)):
            self.probe_rtt_min_delay = self.rs.rtt
            self.probe_rtt_min_stamp = Now()

        min_rtt_expired = Now() > self.min_rtt_stamp + K_BRR_MIN_RTT_FILTER_LEN 
        if (self.probe_rtt_min_delay < self.min_rtt or min_rtt_expired):
            self.min_rtt       = self.probe_rtt_min_delay
            self.min_rtt_stamp = self.probe_rtt_min_stamp

    def BBRCheckProbeRTT(self):
        if (self.state != BBRStates.ProbeRTT and self.probe_rtt_expired and not self.idle_restart):
            self.BBREnterProbeRTT()
            self.BBRSaveCwnd()
            self.probe_rtt_done_stamp = 0
            self.ack_phase = ACKPhase.ACKS_PROBE_STOPPING
            self.BBRStartRound()
        if (self.state == BBRStates.ProbeRTT):
            self.BBRHandleProbeRTT()
        if (self.rs.delivered > 0):
            self.idle_restart = False

    def BBREnterProbeRTT(self):
        self.state = BBRStates.ProbeRTT
        self.pacing_gain = 1
        self.cwnd_gain = K_BBR_PROBE_RTT_CWND_GAIN  # 0.5 

    def BBRHandleProbeRTT(self):
        """ Ignore low rate samples during ProbeRTT """
        self.MarkConnectionAppLimited()
        if (self.probe_rtt_done_stamp == 0 and self.packets_in_flight <= self.BBRProbeRTTCwnd()):
            # Wait for at least ProbeRTTDuration to elapse:
            self.probe_rtt_done_stamp = Now() + K_BBR_PROBE_RTT_DURATION
            # Wait for at least one round to elapse:
            self.probe_rtt_round_done = False
            self.BBRStartRound()
        elif (self.probe_rtt_done_stamp != 0):
            if (self.round_start):
                self.probe_rtt_round_done = True
            if (self.probe_rtt_round_done):
                self.BBRCheckProbeRTTDone()

    def BBRCheckProbeRTTDone(self):
        if (self.probe_rtt_done_stamp != 0 and Now() > self.probe_rtt_done_stamp):
            # schedule next ProbeRTT: 
            self.probe_rtt_min_stamp = Now()
            self.BBRRestoreCwnd()
            self.BBRExitProbeRTT()

    def MarkConnectionAppLimited(self):
        # TODO : not sure if it was meant to be like that
        # self.C.app_limited = (self.C.delivered + self.packets_in_flight) ? : 1
        if (self.C.delivered + self.packets_in_flight):
            self.C.app_limited = (self.C.delivered + self.packets_in_flight)
        else:
            self.C.app_limited = 1
        pass

    def BBRExitProbeRTT(self):
        self.BBRResetLowerBounds()
        if (self.filled_pipe):
            self.BBRStartProbeBW_DOWN()
            self.BBRStartProbeBW_CRUISE()
        else:
            self.BBREnterStartup()

    def BBRHandleRestartFromIdle(self):
        if (self.packets_in_flight == 0 and self.C.app_limited):
            self.idle_restart = True
            self.extra_acked_interval_start = Now()
            if (self.IsInAProbeBWState()):
                self.BBRSetPacingRateWithGain(1)
            elif (self.state == BBRStates.ProbeRTT):
                self.BBRCheckProbeRTTDone()

    def BBRInitRoundCounting(self):
        self.next_round_delivered = 0
        self.round_start = False
        self.round_count = 0

    def BBRUpdateRound(self):
        if (self.delivered_table[self.packet.packet_number] >= self.next_round_delivered):
            self.BBRStartRound()
            self.round_count += 1
            self.rounds_since_probe += 1
            self.round_start = True
        else:
            self.round_start = False

    def BBRStartRound(self):
        self.next_round_delivered = self.C.delivered

    def BBRUpdateMaxBw(self):
        self.BBRUpdateRound()
        if (self.rs.delivery_rate >= self.max_bw or not self.rs.is_app_limited):
            # TODO
            pass
            """
            self.max_bw = update_windowed_max_filter(
                        filter=self.MaxBwFilter,
                        value=self.rs.delivery_rate,
                        time=self.cycle_count,
                        window_length=K_BBR_MAX_BW_FILTER_LEN)
            """
            
    def BBRAdvanceMaxBwFilter(self):
        self.cycle_count += 1

    def BBRUpdateOffloadBudget(self):
        self.offload_budget = 3 * self.send_quantum

    def BBRUpdateACKAggregation(self):
        """ Find excess ACKed beyond expected amount over this interval """
        interval = (Now() - self.extra_acked_interval_start)
        expected_delivered = self.bw * interval
        # Reset interval if ACK rate is below expected rate:
        if (self.extra_acked_delivered <= expected_delivered):
            self.extra_acked_delivered = 0
            self.extra_acked_interval_start = Now()
            expected_delivered = 0
        self.extra_acked_delivered += self.rs.newly_acked
        extra = self.extra_acked_delivered - expected_delivered
        extra = min(extra, self.cwnd)
        # TODO
        """
        self.extra_acked = update_windowed_max_filter(
                            filter=self.ExtraACKedFilter,
                            value=extra,
                            time=self.round_count,
                            window_length=K_BBR_EW_EXTRA_ACKED_FILTER_LEN)
        """
        

    def CheckInflightTooHigh(self):
        """
        Do loss signals suggest inflight is too high?
        If so, react.
        """
        if (self.IsInflightTooHigh()):
            if (self.bw_probe_samples):
                self.BBRHandleInflightTooHigh()
            return True  # inflight too high
        else:
            return False # inflight not too high
        
    def IsInflightTooHigh(self):
        return (self.rs.lost > self.rs.tx_in_flight * K_BBR_LOSS_THRESHOLD)
    
    def BBRHandleInflightTooHigh(self):
        self.bw_probe_samples = 0;   # only react once per bw probe 
        if (not self.rs.is_app_limited):
            self.inflight_hi = max(self.rs.tx_in_flight, self.BBRTargetInflight() * K_BBR_BETA)
        if (self.state == BBRStates.ProbeBW_UP):
            self.BBRStartProbeBW_DOWN()

    def  BBRHandleLostPacket(self, packets : Iterable[QuicSentPacket]):
        if (not self.bw_probe_samples):
            return # not a packet sent while probing bandwidth 
        for packet in packets:
            self.rs.tx_in_flight = self.inflight_table[packet.packet_number]  # inflight at transmit
            self.rs.lost = self.C.lost - self.lost_table[packet.packet_number] # data lost since transmit 
            #self.rs.is_app_limited = packet.is_app_limited
        if (self.IsInflightTooHigh()):
            self.rs.tx_in_flight = self.BBRInflightHiFromLostPacket(self.rs, packets)
            self.BBRHandleInflightTooHigh()

    def BBRInflightHiFromLostPacket(self, rs : BBRRateSample, packets : QuicSentPacket):
        """
        At what prefix of packet did losses exceed BBRLossThresh?
        """
        size = 0
        for packet in packets:
            size += packet.sent_bytes
        # What was in flight before this packet?
        inflight_prev = rs.tx_in_flight - size
        # What was lost before this packet? 
        lost_prev = rs.lost - size
        lost_prefix = (K_BBR_LOSS_THRESHOLD * inflight_prev - lost_prev) / (1 - K_BBR_LOSS_THRESHOLD)
        # At what inflight value did losses cross BBRLossThresh? 
        inflight = inflight_prev + lost_prefix
        return inflight
    
    
    def BBRUpdateLatestDeliverySignals(self):
        """
        Near start of ACK processing
        """
        self.loss_round_start = 0
        self.bw_latest       = max(self.bw_latest,       self.rs.delivery_rate)
        self.inflight_latest = max(self.inflight_latest, self.rs.delivered)

        # TODO
        """
        if (self.rs.prior_delivered >= self.loss_round_delivered):
            self.loss_round_delivered = self.C.delivered
            self.loss_round_start = 1
        """


   
    def BBRAdvanceLatestDeliverySignals(self):
        """
         Near end of ACK processing
        """
        if (self.loss_round_start):
            self.bw_latest       = self.rs.delivery_rate
            self.inflight_latest = self.rs.delivered

    def BBRResetCongestionSignals(self):
        self.loss_in_round = 0
        self.bw_latest = 0
        self.inflight_latest = 0

    def BBRUpdateCongestionSignals(self):
        """
        Update congestion state on every ACK
        """
        self.BBRUpdateMaxBw()
        # TODO verify rs.losses
        if (self.rs.lost > 0):
            self.loss_in_round = 1
        if (not self.loss_round_start):
            return  # wait until end of round trip 
        self.BBRAdaptLowerBoundsFromCongestion()
        self.loss_in_round = 0

    def BBRAdaptLowerBoundsFromCongestion(self):
        """
        Once per round-trip respond to congestion
        """
        if (self.BBRIsProbingBW()):
            return
        if (self.loss_in_round()):
            self.BBRInitLowerBounds()
            self.BBRLossLowerBounds()

    def BBRInitLowerBounds(self):
        """
        Handle the first congestion episode in this cycle
        """
        if (self.bw_lo == float("inf")):
            self.bw_lo = self.max_bw
        if (self.inflight_lo == float("inf")):
            self.inflight_lo = self.cwnd

    def BBRLossLowerBounds(self):
        """
        Adjust model once per round based on loss
        """
        self.bw_lo       = max(self.bw_latest,
                            K_BBR_BETA * self.bw_lo)
        self.inflight_lo = max(self.inflight_latest,
                            K_BBR_BETA * self.infligh_lo)

    def BBRResetLowerBounds(self):
        self.bw_lo       = float("inf")
        self.inflight_lo = float("inf")

    def BBRBoundBWForModel(self):
        self.bw = min(self.max_bw, self.bw_lo, self.bw_hi)  

    def BBRInitPacingRate(self):
        nominal_bandwidth = K_MINIMUM_WINDOW / (self.SRTT if self.SRTT else 0.001)
        self.pacing_rate =  K_BBR_STARTUP_PACING_GAIN * nominal_bandwidth

    def BBRSetPacingRateWithGain(self, pacing_gain):
        rate = pacing_gain * self.bw * (100 - K_BBR_PACING_MARGIN_PERCENT) / 100
        if (self.filled_pipe or rate > self.pacing_rate):
            self.pacing_rate = rate

    def BBRSetPacingRate(self):
        self.BBRSetPacingRateWithGain(self.pacing_gain)
     

    def BBRSetSendQuantum(self):
        if (self.pacing_rate < 1.2e6):  # less than 1.2 Mbps
            floor = 1 * K_MAX_DATAGRAM_SIZE
        else:
            floor = 2 * K_MAX_DATAGRAM_SIZE
        self.send_quantum = min(self.pacing_rate * 0.001, 64e3)  # 1ms, 64 KBytes
        self.send_quantum = max(self.send_quantum, floor)

    def BBRBDPMultiple(self, gain):
        if (self.min_rtt == float("inf")):
            return K_MINIMUM_WINDOW  # no valid RTT samples yet */
        self.bdp = self.bw * self.min_rtt
        return gain * self.bdp

    def BBRQuantizationBudget(self, inflight):
        self.BBRUpdateOffloadBudget()
        inflight = max(inflight, self.offload_budget)
        inflight = max(inflight, K_BBR_MIN_PIPE_CWND)
        if (is_ProbeBW(self.state) and self.cycle_idx == BBRStates.ProbeBW_UP):
            inflight += 2
        return inflight

    def BBRInflight(self, gain):
        inflight = self.BBRBDPMultiple(gain)
        return self.BBRQuantizationBudget(inflight)

    def BBRUpdateMaxInflight(self):
        self.BBRUpdateAggregationBudget()
        inflight = self.BBRBDPMultiple(self.cwnd_gain)
        inflight += self.extra_acked
        self.max_inflight = self.BBRQuantizationBudget(inflight)

    def BBROnEnterRTO(self):
        self.prior_cwnd = self.BBRSaveCwnd()
        self.cwnd = self.packets_in_flight + 1

    def BBROnEnterFastRecovery(self):
        self.prior_cwnd = self.BBRSaveCwnd()
        self.cwnd = self.packets_in_flight + max(self.rs.newly_acked, 1)
        self.packet_conservation = True

    def BBRModulateCwndForRecovery(self):
        if (self.rs.newly_lost > 0):
            self.cwnd = max(self.cwnd - self.rs.newly_lost, 1)
        if (self.packet_conservation):
            self.cwnd = max(self.cwnd, self.packets_in_flight + self.rs.newly_acked)

    def BBRSaveCwnd(self):
        if (not self.InLossRecovery() and self.state != BBRStates.ProbeRTT):
            return self.cwnd
        else:
            return max(self.prior_cwnd, self.cwnd)

    def BBRRestoreCwnd(self):
        self.cwnd = max(self.cwnd, self.prior_cwnd)

    def BBRProbeRTTCwnd(self):
        probe_rtt_cwnd = self.BBRBDPMultiple(K_BBR_PROBE_RTT_CWND_GAIN)
        probe_rtt_cwnd = max(probe_rtt_cwnd, K_BBR_MIN_PIPE_CWND)
        return probe_rtt_cwnd

    def BBRBoundCwndForProbeRTT(self):
        if (self.state == BBRStates.ProbeRTT):
            self.cwnd = min(self.cwnd, self.BBRProbeRTTCwnd())

    def BBRSetCwnd(self):
        self.BBRUpdateMaxInflight()
        self.BBRModulateCwndForRecovery()
        if (not self.packet_conservation):
            if (self.filled_pipe):
                self.cwnd = min(self.cwnd + self.rs.newly_acked, self.max_inflight)
            elif (self.cwnd < self.max_inflight or self.C.delivered < K_MINIMUM_WINDOW):
                self.cwnd = self.cwnd + self.rs.newly_acked
            self.cwnd = max(self.cwnd, K_BBR_MIN_PIPE_CWND)
        self.BBRBoundCwndForProbeRTT()
        self.BBRBoundCwndForModel()

    def BBRBoundCwndForModel(self):
        cap = float("inf")
        if (self.IsInAProbeBWState() and self.state != BBRStates.ProbeBW_CRUISE):
            cap = self.inflight_hi
        elif (self.state == BBRStates.ProbeRTT or self.state == BBRStates.ProbeBW_CRUISE):
            cap = self.BBRInflightWithHeadroom()

        # apply inflight_lo (possibly infinite):
        cap = min(cap, self.inflight_lo)
        cap = max(cap, K_BBR_MIN_PIPE_CWND)
        self.cwnd = min(self.cwnd, cap)