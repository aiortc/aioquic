from typing import Any, Dict, Iterable

from ..packet_builder import QuicSentPacket
from .base import (
    K_INITIAL_WINDOW,
    K_MINIMUM_WINDOW,
    QuicCongestionControl,
    QuicRttMonitor,
    register_congestion_control,
)

# cubic specific variables (see https://www.rfc-editor.org/rfc/rfc9438.html#name-definitions)
K_CUBIC_K = 1
K_CUBIC_C = 0.4
K_CUBIC_LOSS_REDUCTION_FACTOR = 0.7
K_CUBIC_MAX_IDLE_TIME = 2  # reset the cwnd after 2 seconds of inactivity


def cube_root(x: float) -> float:
    # Avoid precision errors that make the cube root return an imaginary number.
    if x < 0:
        return -((-x) ** (1 / 3))
    else:
        return x ** (1 / 3)


class CubicCongestionControl(QuicCongestionControl):
    """
    Cubic congestion control implementation for aioquic
    """

    def __init__(self, max_datagram_size: int) -> None:
        super().__init__(max_datagram_size=max_datagram_size)
        self.additive_increase_factor = max_datagram_size  # increase by one segment

        self._congestion_recovery_start_time = 0.0
        self._max_datagram_size = max_datagram_size
        self._reno_friendly_activated = True
        self._rtt_monitor = QuicRttMonitor()

        self.reset()

        self.last_ack = None

    def W_cubic(self, t: float) -> float:
        W_max_segments = self._W_max / self._max_datagram_size
        target_segments = K_CUBIC_C * (t - self._K) ** 3 + (W_max_segments)
        return target_segments * self._max_datagram_size

    def is_reno_friendly(self, t: float) -> bool:
        return self._reno_friendly_activated and self.W_cubic(t) < self._W_est

    def is_concave(self) -> bool:
        return self.congestion_window < self._W_max

    def is_convex(self) -> bool:
        return self.congestion_window >= self._W_max

    def reset(self) -> None:
        self.congestion_window = K_INITIAL_WINDOW * self._max_datagram_size

        self._cwnd_prior = None
        self._cwnd_epoch = None
        self._t_epoch = None
        self._W_max = None
        self._first_slow_start = True
        self._starting_congestion_avoidance = False
        self._K = 0
        self._W_est = 0
        self._cwnd_epoch = 0
        self._t_epoch = 0
        self._W_max = self.congestion_window

    def on_packet_acked(self, *, now: float, packet: QuicSentPacket) -> None:
        rtt = self.recovery._rtt_smoothed
        self.bytes_in_flight -= packet.sent_bytes
        self.last_ack = now

        if self.ssthresh is None or self.congestion_window < self.ssthresh:
            # slow start
            self.congestion_window += packet.sent_bytes
        else:
            # congestion avoidance
            if self._first_slow_start and not self._starting_congestion_avoidance:
                # exiting slow start without having a loss
                self._first_slow_start = False
                self._cwnd_prior = self.congestion_window
                self._W_max = self.congestion_window
                self._t_epoch = now
                self._cwnd_epoch = self.congestion_window
                self._W_est = self._cwnd_epoch
                # calculate K
                W_max_segments = self._W_max / self._max_datagram_size
                cwnd_epoch_segments = self._cwnd_epoch / self._max_datagram_size
                self._K = cube_root((W_max_segments - cwnd_epoch_segments) / K_CUBIC_C)

            # initialize the variables used at start of congestion avoidance
            if self._starting_congestion_avoidance:
                self._starting_congestion_avoidance = False
                self._first_slow_start = False
                self._t_epoch = now
                self._cwnd_epoch = self.congestion_window
                self._W_est = self._cwnd_epoch
                # calculate K
                W_max_segments = self._W_max / self._max_datagram_size
                cwnd_epoch_segments = self._cwnd_epoch / self._max_datagram_size
                self._K = cube_root((W_max_segments - cwnd_epoch_segments) / K_CUBIC_C)

            self._W_est = self._W_est + self.additive_increase_factor * (
                packet.sent_bytes / self.congestion_window
            )

            t = now - self._t_epoch

            target = self.W_cubic(t + rtt)
            if target < self.congestion_window:
                target = min(self.congestion_window, target)
            elif target > 1.5 * self.congestion_window:
                target = self.congestion_window * 1.5

            if self.is_reno_friendly(t):
                # reno friendly region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-reno-friendly-region)
                self.congestion_window = self._W_est
            elif self.is_concave():
                # concave region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-concave-region)
                self.congestion_window = self.congestion_window + (
                    (target - self.congestion_window)
                    * (self._max_datagram_size / self.congestion_window)
                )
            else:
                # convex region of cubic (https://www.rfc-editor.org/rfc/rfc9438.html#name-convex-region)
                self.congestion_window = self.congestion_window + (
                    (target - self.congestion_window)
                    * (self._max_datagram_size / self.congestion_window)
                )

    def on_packet_sent(self, *, packet: QuicSentPacket) -> None:
        self.bytes_in_flight += packet.sent_bytes
        if self.last_ack is None:
            return
        elapsed_idle = packet.sent_time - self.last_ack
        if elapsed_idle >= K_CUBIC_MAX_IDLE_TIME:
            self.reset()

    def on_packets_expired(self, *, packets: Iterable[QuicSentPacket]) -> None:
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes

    def on_packets_lost(self, *, now: float, packets: Iterable[QuicSentPacket]) -> None:
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
            if self._W_max is not None and self.congestion_window < self._W_max:
                self._W_max = (
                    self.congestion_window * (1 + K_CUBIC_LOSS_REDUCTION_FACTOR) / 2
                )
            else:
                self._W_max = self.congestion_window

            # normal congestion MD
            flight_size = self.bytes_in_flight
            new_ssthresh = max(
                int(flight_size * K_CUBIC_LOSS_REDUCTION_FACTOR),
                K_MINIMUM_WINDOW * self._max_datagram_size,
            )
            self.ssthresh = new_ssthresh
            self._cwnd_prior = self.congestion_window
            self.congestion_window = max(
                self.ssthresh, K_MINIMUM_WINDOW * self._max_datagram_size
            )

            self._starting_congestion_avoidance = (
                True  # restart a new congestion avoidance phase
            )

    def on_rtt_measurement(self, *, now: float, rtt: float) -> None:
        # check whether we should exit slow start
        if self.ssthresh is None and self._rtt_monitor.is_rtt_increasing(rtt, now):
            self._cwnd_prior = self.congestion_window

    def log_callback(self, now: float) -> Dict[str, Any]:
        data = super().log_callback()

        if self._W_max is None:
            data["cubic_wmax"] = None
        else:
            data["cubic_wmax"] = int(self._W_max)

        # saving the phase
        if self.ssthresh is None:
            data["cubic_phase"] = "slow-start"
        elif self.is_reno_friendly(now - self._t_epoch):
            data["cubic_phase"] = "reno-friendly region"
        else:
            data["cubic_phase"] = "cubic-growth"

        return data


register_congestion_control("cubic", CubicCongestionControl)
