from .congestion import QuicCongestionControl, K_INITIAL_WINDOW_SEGMENTS, K_MAX_DATAGRAM_SIZE, K_MINIMUM_WINDOW_SEGMENTS, QuicRttMonitor, Now
from ..packet_builder import QuicSentPacket
from typing import Iterable, Optional, Dict, Any

# cubic specific variables (see https://www.rfc-editor.org/rfc/rfc9438.html#name-definitions)
K_CUBIC_K = 1    
K_CUBIC_C = 0.4
K_CUBIC_LOSS_REDUCTION_FACTOR = 0.7
K_CUBIC_ADDITIVE_INCREASE = 1  # in number of segments 

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
        self.K = 0
        self._W_est = 0
        self._cwnd_epoch = 0
        self._t_epoch = 0
        

    def better_cube_root(self, x):
        if (x < 0):
            # avoid precision errors that make the cube root returns an imaginary number
            return -((-x)**(1./3.))
        else:
            return (x)**(1./3.)
        
    def W_cubic(self, t):
        return K_CUBIC_C * (t - self.K)**3 + (self._W_max)
        
    def is_slow_start(self) -> bool:
        return self.ssthresh is None or self.congestion_window < self.ssthresh
    
    def is_reno_friendly(self, t) -> bool:
        return self.W_cubic(t) < self._W_est
    
    def is_concave(self):
        return self.congestion_window < self._W_max
    
    def is_convex(self):
        return self.congestion_window >= self._W_max
        
    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        self.on_packet_acked_timed(packet, Now(), self.caller._rtt_smoothed)
        super().on_packet_acked(packet)

    def on_packet_acked_timed(self, packet: QuicSentPacket, now: float, rtt : float) -> None:
        self.bytes_in_flight -= packet.sent_bytes

        if self.is_slow_start():
            # slow start
            self.congestion_window += packet.sent_bytes // K_MAX_DATAGRAM_SIZE
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
                self.K = self.better_cube_root((self._W_max - self._cwnd_epoch)/K_CUBIC_C)

            # initialize the variables used at start of congestion avoidance
            if self._starting_congestion_avoidance:
                self._starting_congestion_avoidance = False
                self._first_slow_start = False
                self._t_epoch = now
                self._cwnd_epoch = self.congestion_window
                self._W_est = self._cwnd_epoch
                # calculate K
                self.K = self.better_cube_root((self._W_max - self._cwnd_epoch)/K_CUBIC_C)

            seg_ack = packet.sent_bytes // K_MAX_DATAGRAM_SIZE
            self._W_est = self._W_est + K_CUBIC_ADDITIVE_INCREASE*(seg_ack/self.congestion_window)

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
    
    def log_callback(self) -> Dict[str, Any]:
        data = super().log_callback()

        if self._W_max == None:
            data["W_max"] = None
        else:
            data["W_max"] = int(self._W_max * K_MAX_DATAGRAM_SIZE)

        # saving the phase
        if not self.is_slow_start():
            now = Now()
            t = now - self._t_epoch
        
        if (self.is_slow_start()):
            data["Phase"] = "slow-start"
        elif (self.is_reno_friendly(t)):
            data["Phase"] = "reno-friendly region"
        else:
            data["Phase"] = "cubic-growth"

        return data