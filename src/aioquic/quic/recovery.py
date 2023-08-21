import logging
import math
from typing import Any, Callable, Dict, Iterable, List, Optional
from datetime import datetime

from .logger import QuicLoggerTrace
from .packet_builder import QuicDeliveryState, QuicSentPacket
from .rangeset import RangeSet

# loss detection
K_PACKET_THRESHOLD = 3
K_GRANULARITY = 0.001  # seconds
K_TIME_THRESHOLD = 9 / 8
K_MICRO_SECOND = 0.000001
K_SECOND = 1.0

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


class QuicPacketSpace:
    def __init__(self) -> None:
        self.ack_at: Optional[float] = None
        self.ack_queue = RangeSet()
        self.discarded = False
        self.expected_packet_number = 0
        self.largest_received_packet = -1
        self.largest_received_time: Optional[float] = None

        # sent packets and loss
        self.ack_eliciting_in_flight = 0
        self.largest_acked_packet = 0
        self.loss_time: Optional[float] = None
        self.sent_packets: Dict[int, QuicSentPacket] = {}


class QuicPacketPacer:
    def __init__(self) -> None:
        self.bucket_max: float = 0.0
        self.bucket_time: float = 0.0
        self.evaluation_time: float = 0.0
        self.packet_time: Optional[float] = None

    def next_send_time(self, now: float) -> float:
        if self.packet_time is not None:
            self.update_bucket(now=now)
            if self.bucket_time <= 0:
                return now + self.packet_time
        return None

    def update_after_send(self, now: float) -> None:
        if self.packet_time is not None:
            self.update_bucket(now=now)
            if self.bucket_time < self.packet_time:
                self.bucket_time = 0.0
            else:
                self.bucket_time -= self.packet_time

    def update_bucket(self, now: float) -> None:
        if now > self.evaluation_time:
            self.bucket_time = min(
                self.bucket_time + (now - self.evaluation_time), self.bucket_max
            )
            self.evaluation_time = now

    def update_rate(self, congestion_window: int, smoothed_rtt: float) -> None:
        pacing_rate = congestion_window / max(smoothed_rtt, K_MICRO_SECOND)
        self.packet_time = max(
            K_MICRO_SECOND, min(K_MAX_DATAGRAM_SIZE / pacing_rate, K_SECOND)
        )

        self.bucket_max = (
            max(
                2 * K_MAX_DATAGRAM_SIZE,
                min(congestion_window // 4, 16 * K_MAX_DATAGRAM_SIZE),
            )
            / pacing_rate
        )
        if self.bucket_time > self.bucket_max:
            self.bucket_time = self.bucket_max


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

        self.caller : QuicPacketRecovery = kwargs["caller"]

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
        super().on_packet_acked(packet)
        return self.on_packet_acked_timed(packet, datetime.timestamp(datetime.now()), self.caller._rtt_smoothed)

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

            t = int(now - self._t_epoch)

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
                # TODO: change back to normal reno handle
                #self.congestion_window = self._W_est
                self.congestion_window = self.congestion_window + ((target - self.congestion_window)/self.congestion_window)
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

            # fast convergence
            #if (self._W_max != None and cwnd_segments < self._W_max):
            #    self._W_max = int(cwnd_segments * (1 + K_CUBIC_LOSS_REDUCTION_FACTOR) / 2)
            #else:
            #    self._W_max = cwnd_segments

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

class QuicPacketRecovery:
    """
    Packet loss and congestion controller.
    """

    def __init__(
        self,
        initial_rtt: float,
        peer_completed_address_validation: bool,
        send_probe: Callable[[], None],
        logger: Optional[logging.LoggerAdapter] = None,
        quic_logger: Optional[QuicLoggerTrace] = None,
        congestion_control_algo: QuicCongestionControl = RenoCongestionControl,
        congestion_options = {}
    ) -> None:
        self.max_ack_delay = 0.025
        self.peer_completed_address_validation = peer_completed_address_validation
        self.spaces: List[QuicPacketSpace] = []

        # callbacks
        self._logger = logger
        self._quic_logger = quic_logger
        self._send_probe = send_probe

        # loss detection
        self._pto_count = 0
        self._rtt_initial = initial_rtt
        self._rtt_initialized = False
        self._rtt_latest = 0.0
        self._rtt_min = math.inf
        self._rtt_smoothed = 0.0
        self._rtt_variance = 0.0
        self._time_of_last_sent_ack_eliciting_packet = 0.0

        # congestion control
        if (congestion_options != None):
            self._cc = congestion_control_algo(caller=self, **congestion_options)
        else:
            self._cc = congestion_control_algo(caller=self)
        self._pacer = QuicPacketPacer()

    @property
    def bytes_in_flight(self) -> int:
        return self._cc.bytes_in_flight

    @property
    def congestion_window(self) -> int:
        return self._cc.get_congestion_window()

    def discard_space(self, space: QuicPacketSpace) -> None:
        assert space in self.spaces

        self._cc.on_packets_expired(
            filter(lambda x: x.in_flight, space.sent_packets.values())
        )
        space.sent_packets.clear()

        space.ack_at = None
        space.ack_eliciting_in_flight = 0
        space.loss_time = None

        # reset PTO count
        self._pto_count = 0

        if self._quic_logger is not None:
            self._log_metrics_updated()

    def get_loss_detection_time(self) -> float:
        # loss timer
        loss_space = self._get_loss_space()
        if loss_space is not None:
            return loss_space.loss_time

        # packet timer
        if (
            not self.peer_completed_address_validation
            or sum(space.ack_eliciting_in_flight for space in self.spaces) > 0
        ):
            timeout = self.get_probe_timeout() * (2**self._pto_count)
            return self._time_of_last_sent_ack_eliciting_packet + timeout

        return None

    def get_probe_timeout(self) -> float:
        if not self._rtt_initialized:
            return 2 * self._rtt_initial
        return (
            self._rtt_smoothed
            + max(4 * self._rtt_variance, K_GRANULARITY)
            + self.max_ack_delay
        )

    def on_ack_received(
        self,
        space: QuicPacketSpace,
        ack_rangeset: RangeSet,
        ack_delay: float,
        now: float,
    ) -> None:
        """
        Update metrics as the result of an ACK being received.
        """
        is_ack_eliciting = False
        largest_acked = ack_rangeset.bounds().stop - 1
        largest_newly_acked = None
        largest_sent_time = None

        if largest_acked > space.largest_acked_packet:
            space.largest_acked_packet = largest_acked

        for packet_number in sorted(space.sent_packets.keys()):
            if packet_number > largest_acked:
                break
            if packet_number in ack_rangeset:
                # remove packet and update counters
                packet = space.sent_packets.pop(packet_number)
                if packet.is_ack_eliciting:
                    is_ack_eliciting = True
                    space.ack_eliciting_in_flight -= 1
                if packet.in_flight:
                    self._cc.on_packet_acked(packet)
                largest_newly_acked = packet_number
                largest_sent_time = packet.sent_time

                # trigger callbacks
                for handler, args in packet.delivery_handlers:
                    handler(QuicDeliveryState.ACKED, *args)

        # nothing to do if there are no newly acked packets
        if largest_newly_acked is None:
            return

        if largest_acked == largest_newly_acked and is_ack_eliciting:
            latest_rtt = now - largest_sent_time
            log_rtt = True

            # limit ACK delay to max_ack_delay
            ack_delay = min(ack_delay, self.max_ack_delay)

            # update RTT estimate, which cannot be < 1 ms
            self._rtt_latest = max(latest_rtt, 0.001)
            if self._rtt_latest < self._rtt_min:
                self._rtt_min = self._rtt_latest
            if self._rtt_latest > self._rtt_min + ack_delay:
                self._rtt_latest -= ack_delay

            if not self._rtt_initialized:
                self._rtt_initialized = True
                self._rtt_variance = latest_rtt / 2
                self._rtt_smoothed = latest_rtt
            else:
                self._rtt_variance = 3 / 4 * self._rtt_variance + 1 / 4 * abs(
                    self._rtt_min - self._rtt_latest
                )
                self._rtt_smoothed = (
                    7 / 8 * self._rtt_smoothed + 1 / 8 * self._rtt_latest
                )

            # inform congestion controller
            self._cc.on_rtt_measurement(latest_rtt, now=now)
            self._pacer.update_rate(
                congestion_window=self._cc.get_congestion_window(),
                smoothed_rtt=self._rtt_smoothed,
            )

        else:
            log_rtt = False

        self._detect_loss(space, now=now)

        # reset PTO count
        self._pto_count = 0

        if self._quic_logger is not None:
            self._log_metrics_updated(log_rtt=log_rtt)

    def on_loss_detection_timeout(self, now: float) -> None:
        loss_space = self._get_loss_space()
        if loss_space is not None:
            self._detect_loss(loss_space, now=now)
        else:
            self._pto_count += 1
            self.reschedule_data(now=now)

    def on_packet_sent(self, packet: QuicSentPacket, space: QuicPacketSpace) -> None:
        space.sent_packets[packet.packet_number] = packet

        if packet.is_ack_eliciting:
            space.ack_eliciting_in_flight += 1
        if packet.in_flight:
            if packet.is_ack_eliciting:
                self._time_of_last_sent_ack_eliciting_packet = packet.sent_time

            # add packet to bytes in flight
            self._cc.on_packet_sent(packet)

            if self._quic_logger is not None:
                self._log_metrics_updated()

    def reschedule_data(self, now: float) -> None:
        """
        Schedule some data for retransmission.
        """
        # if there is any outstanding CRYPTO, retransmit it
        crypto_scheduled = False
        for space in self.spaces:
            packets = tuple(
                filter(lambda i: i.is_crypto_packet, space.sent_packets.values())
            )
            if packets:
                self._on_packets_lost(packets, space=space, now=now)
                crypto_scheduled = True
        if crypto_scheduled and self._logger is not None:
            self._logger.debug("Scheduled CRYPTO data for retransmission")

        # ensure an ACK-elliciting packet is sent
        self._send_probe()

    def _detect_loss(self, space: QuicPacketSpace, now: float) -> None:
        """
        Check whether any packets should be declared lost.
        """
        loss_delay = K_TIME_THRESHOLD * (
            max(self._rtt_latest, self._rtt_smoothed)
            if self._rtt_initialized
            else self._rtt_initial
        )
        packet_threshold = space.largest_acked_packet - K_PACKET_THRESHOLD
        time_threshold = now - loss_delay

        lost_packets = []
        space.loss_time = None
        for packet_number, packet in space.sent_packets.items():
            if packet_number > space.largest_acked_packet:
                break

            if packet_number <= packet_threshold or packet.sent_time <= time_threshold:
                lost_packets.append(packet)
            else:
                packet_loss_time = packet.sent_time + loss_delay
                if space.loss_time is None or space.loss_time > packet_loss_time:
                    space.loss_time = packet_loss_time

        self._on_packets_lost(lost_packets, space=space, now=now)

    def _get_loss_space(self) -> Optional[QuicPacketSpace]:
        loss_space = None
        for space in self.spaces:
            if space.loss_time is not None and (
                loss_space is None or space.loss_time < loss_space.loss_time
            ):
                loss_space = space
        return loss_space

    def _log_metrics_updated(self, log_rtt=False) -> None:
        data: Dict[str, Any] = {
            "bytes_in_flight": self._cc.bytes_in_flight,
            "cwnd": self._cc.get_congestion_window(),
        }
        if self._cc.get_ssthresh() is not None:
            data["ssthresh"] = self._cc.get_ssthresh()

        if log_rtt:
            data.update(
                {
                    "latest_rtt": self._quic_logger.encode_time(self._rtt_latest),
                    "min_rtt": self._quic_logger.encode_time(self._rtt_min),
                    "smoothed_rtt": self._quic_logger.encode_time(self._rtt_smoothed),
                    "rtt_variance": self._quic_logger.encode_time(self._rtt_variance),
                }
            )

        self._quic_logger.log_event(
            category="recovery", event="metrics_updated", data=data
        )

    def _on_packets_lost(
        self, packets: Iterable[QuicSentPacket], space: QuicPacketSpace, now: float
    ) -> None:
        lost_packets_cc = []
        for packet in packets:
            del space.sent_packets[packet.packet_number]

            if packet.in_flight:
                lost_packets_cc.append(packet)

            if packet.is_ack_eliciting:
                space.ack_eliciting_in_flight -= 1

            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="recovery",
                    event="packet_lost",
                    data={
                        "type": self._quic_logger.packet_type(packet.packet_type),
                        "packet_number": packet.packet_number,
                    },
                )
                self._log_metrics_updated()

            # trigger callbacks
            for handler, args in packet.delivery_handlers:
                handler(QuicDeliveryState.LOST, *args)

        # inform congestion controller
        if lost_packets_cc:
            self._cc.on_packets_lost(lost_packets_cc, now=now)
            self._pacer.update_rate(
                congestion_window=self._cc.get_congestion_window(),
                smoothed_rtt=self._rtt_smoothed,
            )
            if self._quic_logger is not None:
                self._log_metrics_updated()


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
