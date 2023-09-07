from .congestion import QuicCongestionControl, K_INITIAL_WINDOW, K_MAX_DATAGRAM_SIZE, K_MINIMUM_WINDOW, QuicRttMonitor, Now
from ..packet_builder import QuicSentPacket
from typing import Iterable, Optional, Dict, Any
from .slow_starts.standard_slow_start import StandardSlowStart
from .slow_starts.slow_start import SlowStart
from .rs import RateSample

# cubic specific variables (see https://www.rfc-editor.org/rfc/rfc9438.html#name-definitions)
K_CUBIC_K = 1    
K_CUBIC_C = 0.4
K_CUBIC_LOSS_REDUCTION_FACTOR = 0.7
K_CUBIC_ADDITIVE_INCREASE = K_MAX_DATAGRAM_SIZE  # bytes corresponding to 1 segment 
K_CUBIC_MAX_IDLE_TIME = 2   # reset the cwnd after 2 seconds of inactivity

class CubicCongestionControl(QuicCongestionControl):
    """
    Cubic congestion control implementation for aioquic
    """

    def __init__(self, callback=None, slow_start : SlowStart = StandardSlowStart(), reno_friendly_activated = True) -> None:
        super().__init__(callback=callback)
        self.bytes_in_flight = 0
        self.congestion_window = K_INITIAL_WINDOW
        self._congestion_recovery_start_time = 0.0
        self.ssthresh: Optional[int] = None
        self.slow_start = slow_start
        self.slow_start.set_cc(self)
        self.reno_friendly_activated = reno_friendly_activated

        self.reset()

        self.last_ack = None
        self.rs = RateSample()

    def better_cube_root(self, x):
        if (x < 0):
            # avoid precision errors that make the cube root returns an imaginary number
            return -((-x)**(1./3.))
        else:
            return (x)**(1./3.)
        
    def W_cubic(self, t):
        W_max_segments = self._W_max / K_MAX_DATAGRAM_SIZE
        target_segments = K_CUBIC_C * (t - self.K)**3 + (W_max_segments)
        return target_segments * K_MAX_DATAGRAM_SIZE
    
    def is_reno_friendly(self, t) -> bool:
        return self.reno_friendly_activated and self.W_cubic(t) < self._W_est
    
    def is_concave(self):
        return self.congestion_window < self._W_max
    
    def is_convex(self):
        return self.congestion_window >= self._W_max
    
    def reset(self):
        self.congestion_window = K_INITIAL_WINDOW

        self._cwnd_prior = None
        self._cwnd_epoch = None
        self._t_epoch = None
        self._W_max = None
        self._first_slow_start = True
        self._starting_congestion_avoidance = False
        self.K = 0
        self._W_est = 0
        self._cwnd_epoch = 0
        self._t_epoch = 0
        self._W_max = self.congestion_window

        self.slow_start.reset()
        
    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        self.on_packet_acked_timed(packet, Now(), self.recovery._rtt_smoothed)
        super().on_packet_acked(packet)

    def on_packet_acked_timed(self, packet: QuicSentPacket, now: float, rtt : float) -> None:
        self.bytes_in_flight -= packet.sent_bytes
        self.last_ack = now
        self.rs.on_ack(packet, Now())

        if self.slow_start.is_slow_start():
            # slow start
            self.slow_start.on_ack(packet)
        else:
            # congestion avoidance
            if (self._first_slow_start and not self._starting_congestion_avoidance):
                # exiting slow start without having a loss
                self._first_slow_start = False
                self._cwnd_prior = self.congestion_window
                self._W_max = self.congestion_window
                self._t_epoch = now
                self._cwnd_epoch = self.congestion_window
                self._W_est = self._cwnd_epoch
                # calculate K
                W_max_segments = self._W_max / K_MAX_DATAGRAM_SIZE
                cwnd_epoch_segments = self._cwnd_epoch / K_MAX_DATAGRAM_SIZE
                self.K = self.better_cube_root((W_max_segments - cwnd_epoch_segments)/K_CUBIC_C)

            # initialize the variables used at start of congestion avoidance
            if self._starting_congestion_avoidance:
                self._starting_congestion_avoidance = False
                self._first_slow_start = False
                self._t_epoch = now
                self._cwnd_epoch = self.congestion_window
                self._W_est = self._cwnd_epoch
                # calculate K
                W_max_segments = self._W_max / K_MAX_DATAGRAM_SIZE
                cwnd_epoch_segments = self._cwnd_epoch / K_MAX_DATAGRAM_SIZE
                self.K = self.better_cube_root((W_max_segments - cwnd_epoch_segments)/K_CUBIC_C)


            self._W_est = self._W_est + K_CUBIC_ADDITIVE_INCREASE*(packet.sent_bytes/self.congestion_window)

            t = now - self._t_epoch
            
            target = None
            if (self.W_cubic(t + rtt) < self.congestion_window):
                target = self.congestion_window
            elif (self.W_cubic(t + rtt) > 1.5*self.congestion_window):
                target = self.congestion_window*1.5
            else:
                target = self.W_cubic(t + rtt)


            if self.is_reno_friendly(t):
                # reno friendly region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-reno-friendly-region)
                self.congestion_window = self._W_est
            elif self.is_concave():
                # concave region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-concave-region)
                self.congestion_window = self.congestion_window + ((target - self.congestion_window)*(K_MAX_DATAGRAM_SIZE/self.congestion_window))
            else:
                # convex region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-convex-region)
                self.congestion_window = self.congestion_window + ((target - self.congestion_window)*(K_MAX_DATAGRAM_SIZE/self.congestion_window))

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        super().on_packet_sent(packet)
        self.rs.on_sent(packet, Now())
        self.slow_start.on_sent(packet)
        self.bytes_in_flight += packet.sent_bytes
        if self.last_ack == None:
            return
        elapsed_idle = Now() - self.last_ack
        if (elapsed_idle >= K_CUBIC_MAX_IDLE_TIME):
            self.reset()

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        super().on_packets_expired(packets)
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            self.slow_start.on_expired(packet)
            self.rs.on_expired(packet)

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        super().on_packets_lost(packets, now)
        lost_largest_time = 0.0
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            lost_largest_time = packet.sent_time
            self.slow_start.on_lost(packet)
            self.rs.on_lost(packet, Now())
            self.rs.rm_packet_info(packet)

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
            flight_size = self.bytes_in_flight
            new_ssthresh = max(int(flight_size*K_CUBIC_LOSS_REDUCTION_FACTOR), K_MINIMUM_WINDOW)
            self.slow_start.set_ssthresh(new_ssthresh)
            self._cwnd_prior = self.congestion_window
            self.congestion_window = max(self.slow_start.get_ssthresh(), K_MINIMUM_WINDOW)
            

            self._starting_congestion_avoidance = True  # restart a new congestion avoidance phase


    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        super().on_rtt_measurement(latest_rtt, now)
        # check whether we should exit slow start
        rtt_increased = self.slow_start.on_rtt_measured(latest_rtt, now)
            
        if rtt_increased:
            self._cwnd_prior = self.congestion_window
            

    def get_congestion_window(self) -> int:
        return int(self.congestion_window)
    
    def _set_congestion_window(self, value):
        self.congestion_window = value
    
    def get_ssthresh(self) -> int:
        return self.slow_start.get_ssthresh()
    
    def get_bytes_in_flight(self) -> int:
        return self.bytes_in_flight
    
    def log_callback(self) -> Dict[str, Any]:
        data = super().log_callback()

        if self._W_max == None:
            data["W_max"] = None
        else:
            data["W_max"] = int(self._W_max)

        # saving the phase
        if not self.slow_start.is_slow_start():
            now = Now()
            t = now - self._t_epoch
        
        if (self.slow_start.is_slow_start()):
            data["Phase"] = "slow-start"
        elif (self.is_reno_friendly(t)):
            data["Phase"] = "reno-friendly region"
        else:
            data["Phase"] = "cubic-growth"

        data["delivery_rate"] = self.rs.delivery_rate
        return data