


def is_ProbeBW(state):
    return state == BBRStates.ProbeBW_CRUISE or state == BBRStates.ProbeBW_DOWN or state == BBRStates.ProbeBW_UP or state == BBRStates.ProbeBW_REFILL


class BBRCongestionControl(QuicCongestionControl):

    def __init__(self, *args, **kwargs) -> None:

        super().__init__(*args, **kwargs)
        
        # BBR variables
        # 2.1
        self.C = BBRGlobalStats()

        # 2.2
        self.packet = None
        self.packet_table = {}     # a table containing for each packet number as key the value of C when this packet was sent

        # 2.3
        self.rs = BBRRateSample()

        # 2.4
        self.cwnd = K_INITIAL_WINDOW
        self.pacing_rate = 0
        self.send_quantum = 0

        # 2.5
        self.pacing_gain = 0
        self.next_departure_time = 0

        # 2.6
        self.cwnd_gain = 0
        self.packet_conservation = False
        

        # 2.7
        self.state = None
        self.round_count = 0
        self.round_start = True
        self.next_round_delivered = 0
        self.idle_restart = False

        # 2.9.1
        self.max_bw = 0
        self.bw_hi = 0
        self.bw_lo = 0
        self.bw = 0

        # 2.9.2
        self.min_rtt = 0
        self.bdp = 0
        self.extra_acked = 0
        self.offload_budget = 0
        self.max_inflight = 0
        self.inflight_hi = 0
        self.inflight_lo = 0

        # 2.10
        self.bw_latest = 0
        self.inflight_latest = 0

        # 2.11
        self.MaxBwFilter = 0
        self.cycle_count = 0

        # 2.12
        self.extra_acked_interval_start = 0
        self.extra_acked_delivered = 0
        self.ExtraACKedFilter = 0

        # 2.13
        self.filled_pipe = False
        self.full_bw = 0
        self.full_bw_count = 0

        # 2.14.1
        self.min_rtt_stamp = 0

        # 2.14.2
        self.probe_rtt_min_delay = 0
        self.probe_rtt_min_stamp = 0
        self.probe_rtt_expired = False

        # Others
        self.fast_recovery_counts = 0
        self.loss_rate = 0
        self.sequence_ranges_lost = 0
        self.rounds_since_probe = 0
        self.bw_probe_samples = 0
        self.is_cwnd_limited = False
        self.cycle_idx = 0


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
        self.rs.tx_in_flight -= packet.sent_bytes
        self.C.packets_in_flight -= 1
        self.rs.newly_acked = packet.sent_bytes
        self.BBRUpdateModelAndState()
        self.BBRUpdateControlParameters()

        del self.packet_table[packet.packet_number]    
        self.rs.newly_acked = 0  # resetting the number of bytes acked 


    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)

        self.rs.tx_in_flight += packet.sent_bytes
        self.C.packets_in_flight += 1

        self.packet_table[packet.packet_number] = copy(self.C)
        self.packet_table[packet.packet_number].inflight = self.rs.inflight  # copy the number of bytes in flight at sending time
        # BBROnTransmit
        self.BBRHandleRestartFromIdle()

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)

        for packet in packets:
            self.rs.tx_in_flight -= packet.sent_bytes
            # delete the entries for this packet number in tables
            del self.packet_table[packet.packet_number]     
            self.C.packets_in_flight -= 1

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)

        for packet in packets:
            self.C.lost += packet.sent_bytes
            self.rs.newly_lost += packet.sent_bytes
            self.rs.tx_in_flight -= packet.sent_bytes

        self.fast_recovery_counts += 1

        self.BBRHandleLostPacket(packets)

        for packet in packets:
            del self.packet_table[packet.packet_number]  
            self.C.packets_in_flight -= 1
        self.rs.newly_lost = 0 # reset newly lost number of bytes


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
        return self.rs.inflight
    
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
        self.loss_rate = self.rs.lost / (self.rs.tx_in_flight)
        if (self.fast_recovery_counts >= 1 and self.loss_rate >= K_BBR_LOSS_THRESHOLD): # and self.sequence_ranges_lost >= 3):
            self.filled_pipe = True

    def BBREnterDrain(self):
        self.state = BBRStates.Drain
        self.pacing_gain = 1/K_BBR_STARTUP_PACING_GAIN  # pace slowly 
        self.cwnd_gain = K_BBR_STARTUP_CWND_GAIN      # maintain cwnd
    
    def BBRCheckDrain(self):
        if (self.state == BBRStates.Drain and self.C.packets_in_flight <= self.BBRInflight(self.bw, 1.0)):
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
        self.cycle_idx = BBRStates.ProbeBW_REFILL
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
            if (self.BBRHasElapsedInPhase(self.min_rtt) and self.rs.inflight > self.BBRInflight(self.max_bw, 1.25)):
                self.BBRStartProbeBW_DOWN()

    def IsInAProbeBWState(self):
        state = self.state
        return (state == BBRStates.ProbeBW_DOWN or
                state == BBRStates.ProbeBW_CRUISE or
                state == BBRStates.ProbeBW_REFILL or
                state == BBRStates.ProbeBW_UP)
    
      
    def BBRCheckTimeToCruise(self):
        """Time to transition from DOWN to CRUISE?"""
        if (self.rs.inflight > self.BBRInflightWithHeadroom()):
            return False  # not enough headroom 
        if (self.rs.inflight <= self.BBRInflight(self.max_bw, 1.0)):
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
            self.prior_cwnd = self.BBRSaveCwnd()
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
        if (self.probe_rtt_done_stamp == 0 and self.C.packets_in_flight <= self.BBRProbeRTTCwnd()):
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
        # self.C.app_limited = (self.C.delivered + self.C.packets_in_flight) ? : 1
        if (self.C.delivered + self.C.packets_in_flight):
            self.C.app_limited = (self.C.delivered + self.C.packets_in_flight)
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
        if (self.C.packets_in_flight == 0 and self.C.app_limited):
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
        if (self.packet_table[self.packet.packet_number].delivered >= self.next_round_delivered):
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
            self.rs.tx_in_flight = self.packet_table[packet.packet_number].inflight  # inflight at transmit
            self.rs.lost = self.C.lost - self.packet_table[packet.packet_number].lost # data lost since transmit 
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

    def BBRBDPMultiple(self, bw, gain):
        if (self.min_rtt == float("inf")):
            return K_MINIMUM_WINDOW  # no valid RTT samples yet */
        self.bdp = bw * self.min_rtt
        return gain * self.bdp

    def BBRQuantizationBudget(self, inflight):
        self.BBRUpdateOffloadBudget()
        inflight = max(inflight, self.offload_budget)
        inflight = max(inflight, K_BBR_MIN_PIPE_CWND)
        if (is_ProbeBW(self.state) and self.cycle_idx == BBRStates.ProbeBW_UP):
            inflight += 2
        return inflight

    def BBRInflight(self, bw, gain):
        inflight = self.BBRBDPMultiple(bw, gain)
        return self.BBRQuantizationBudget(inflight)

    def BBRUpdateMaxInflight(self):
        # TODO
        # self.BBRUpdateAggregationBudget()
        inflight = self.BBRBDPMultiple(self.bw, self.cwnd_gain)
        inflight += self.extra_acked
        self.max_inflight = self.BBRQuantizationBudget(inflight)

    def BBROnEnterRTO(self):
        self.prior_cwnd = self.BBRSaveCwnd()
        self.cwnd = self.C.packets_in_flight + 1

    def BBROnEnterFastRecovery(self):
        self.prior_cwnd = self.BBRSaveCwnd()
        self.cwnd = self.C.packets_in_flight + max(self.rs.newly_acked, 1)
        self.packet_conservation = True

    def BBRModulateCwndForRecovery(self):
        if (self.rs.newly_lost > 0):
            self.cwnd = max(self.cwnd - self.rs.newly_lost, 1)
        if (self.packet_conservation):
            self.cwnd = max(self.cwnd, self.C.packets_in_flight + self.rs.newly_acked)

    def BBRSaveCwnd(self):
        if (not self.InLossRecovery() and self.state != BBRStates.ProbeRTT):
            return self.cwnd
        else:
            return max(self.prior_cwnd, self.cwnd)
        
    def InLossRecovery(self):
        # TODO
        return False

    def BBRRestoreCwnd(self):
        self.cwnd = max(self.cwnd, self.prior_cwnd)

    def BBRProbeRTTCwnd(self):
        probe_rtt_cwnd = self.BBRBDPMultiple(self.bw, K_BBR_PROBE_RTT_CWND_GAIN)
        probe_rtt_cwnd = max(probe_rtt_cwnd, K_BBR_MIN_PIPE_CWND)
        return probe_rtt_cwnd

    def BBRBoundCwndForProbeRTT(self):
        if (self.state == BBRStates.ProbeRTT):
            self.cwnd = min(self.cwnd, self.BBRProbeRTTCwnd())

    def BBRSetCwnd(self):
        self.BBRUpdateMaxInflight()
        self.BBRModulateCwndForRecovery()
        if (not self.packet_conservation):
            print(F"Max inflight = {self.max_inflight}")
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