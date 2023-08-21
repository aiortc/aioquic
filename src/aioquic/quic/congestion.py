from datetime import datetime
from .packet_builder import QuicSentPacket
from typing import Iterable, Optional

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


class QuicCongestionControl:

    def __init__(self, *args, **kwargs) -> None:
        if ("callback" in kwargs):
            self.callback = kwargs["callback"] # a callback argument that is called when an event occurs
        else:
            self.callback = None

    def on_packet_acked(self, packet: QuicSentPacket):
        if self.callback:
            self.callback("ack", self)

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        if self.callback:
            self.callback("packet_sent", self)

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        if self.callback:
            self.callback("packet_expired", self)

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        if self.callback:
            self.callback("packet_lost", self)

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        if self.callback:
            self.callback("rtt_measured", self)

    def get_congestion_window(self) -> int:
        pass

    def get_ssthresh(self) -> int: 
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
        self.on_packet_acked_timed(packet, datetime.timestamp(datetime.now()), self.caller._rtt_smoothed)
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