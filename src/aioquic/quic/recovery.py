import logging
import math
from bisect import bisect_left
from collections.abc import Callable, Iterable
from typing import Any, Optional

from .congestion import cubic, reno  # noqa
from .congestion.base import K_GRANULARITY, create_congestion_control
from .logger import QuicLoggerTrace
from .packet_builder import QuicDeliveryState, QuicSentPacket
from .rangeset import RangeSet

# loss detection
K_PACKET_THRESHOLD = 3
K_TIME_THRESHOLD = 9 / 8
K_MICRO_SECOND = 0.000001
K_PERSISTENT_CONGESTION_THRESHOLD = 3
K_SECOND = 1.0

# The number of ACK ranges kept. Duplicate detection accepts packets fewer than
# twice this many below the largest received, and each range plus the gap above
# it spans at least two, so the range dropped never holds a packet which was
# just accepted (RFC 9000 section 13.2.1).
MAX_ACK_RANGES = 64


class QuicPacketNumberWindow:
    """
    A sliding window of the most recently received packet numbers, used to
    detect duplicate packets.

    Packet numbers which have fallen out of the window are considered to have
    already been received.
    """

    def __init__(self) -> None:
        self._lower = 0
        self._received: set[int] = set()
        self._size = 2 * MAX_ACK_RANGES

    def add(self, packet_number: int) -> None:
        if packet_number < self._lower:
            return
        self._received.add(packet_number)

        # Slide the window so that the packet number is its upper bound.
        lower = packet_number - self._size + 1
        if lower > self._lower:
            self._lower = lower

            # Prune packet numbers below the window, but only once the set has
            # grown well beyond the window size, so the cost is amortized.
            if len(self._received) > 2 * self._size:
                self._received = {pn for pn in self._received if pn >= lower}

    def __contains__(self, packet_number: int) -> bool:
        return packet_number < self._lower or packet_number in self._received


class QuicPacketSpace:
    def __init__(self, *, is_application_data: bool = False) -> None:
        self.ack_at: Optional[float] = None
        self.ack_queue = RangeSet()
        self.discarded = False
        self.expected_packet_number = 0
        self.is_application_data = is_application_data
        self.largest_received_packet = -1
        self.largest_received_time: Optional[float] = None
        self.received_packets = QuicPacketNumberWindow()

        # sent packets and loss
        self.ack_eliciting_in_flight = 0
        self.largest_acked_packet = 0
        self.loss_time: Optional[float] = None
        self.sent_packets: dict[int, QuicSentPacket] = {}


class QuicPacketPacer:
    def __init__(self, *, max_datagram_size: int) -> None:
        self._max_datagram_size = max_datagram_size
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
            K_MICRO_SECOND, min(self._max_datagram_size / pacing_rate, K_SECOND)
        )

        self.bucket_max = (
            max(
                2 * self._max_datagram_size,
                min(congestion_window // 4, 16 * self._max_datagram_size),
            )
            / pacing_rate
        )
        if self.bucket_time > self.bucket_max:
            self.bucket_time = self.bucket_max


class QuicPacketRecovery:
    """
    Packet loss and congestion controller.
    """

    def __init__(
        self,
        *,
        congestion_control_algorithm: str,
        initial_rtt: float,
        max_datagram_size: int,
        peer_completed_address_validation: bool,
        send_probe: Callable[[], None],
        logger: Optional[logging.LoggerAdapter] = None,
        quic_logger: Optional[QuicLoggerTrace] = None,
    ) -> None:
        self.handshake_confirmed = False
        self.max_ack_delay = 0.025
        self.peer_completed_address_validation = peer_completed_address_validation
        self.spaces: list[QuicPacketSpace] = []

        # callbacks
        self._logger = logger
        self._quic_logger = quic_logger
        self._send_probe = send_probe

        # loss detection
        self._pto_count = 0
        self._rtt_first_sample_time = 0.0
        self._rtt_initial = initial_rtt
        self._rtt_initialized = False
        self._rtt_latest = 0.0
        self._rtt_min = math.inf
        self._rtt_smoothed = 0.0
        self._rtt_variance = 0.0
        self._time_of_last_sent_ack_eliciting_packet = 0.0

        # congestion control
        self._cc = create_congestion_control(
            congestion_control_algorithm, max_datagram_size=max_datagram_size
        )
        self._pacer = QuicPacketPacer(max_datagram_size=max_datagram_size)

    @property
    def bytes_in_flight(self) -> int:
        return self._cc.bytes_in_flight

    @property
    def congestion_window(self) -> int:
        return self._cc.congestion_window

    def discard_space(self, space: QuicPacketSpace) -> None:
        assert space in self.spaces

        self._cc.on_packets_expired(
            packets=filter(lambda x: x.in_flight, space.sent_packets.values())
        )
        space.sent_packets.clear()

        space.ack_at = None
        space.ack_eliciting_in_flight = 0
        space.loss_time = None

        # reset PTO count
        self._pto_count = 0

        if self._quic_logger is not None:
            self._log_metrics_updated()

    def get_loss_detection_time(self) -> Optional[float]:
        """
        Return the time at which the loss detection timer should fire, or None
        if no timer is needed.

        The connection calls this every time it computes its next timer, so the
        result always reflects the current state rather than being re-armed on
        specific events as in RFC 9002 appendix A.8. When the timer fires, the
        connection calls :meth:`on_loss_detection_timeout`.
        """
        # loss timer
        loss_space = self._get_loss_space()
        if loss_space is not None:
            return loss_space.loss_time

        # packet timer
        # Application data does not arm the PTO until the handshake is confirmed
        # (RFC 9002 section 6.2.1).
        ack_eliciting_in_flight = sum(
            space.ack_eliciting_in_flight
            for space in self.spaces
            if self.handshake_confirmed or not space.is_application_data
        )
        if not self.peer_completed_address_validation or ack_eliciting_in_flight:
            # Once the handshake is confirmed, only application data remains,
            # which is the only space whose PTO includes max_ack_delay.
            timeout = self.get_probe_timeout(
                include_max_ack_delay=self.handshake_confirmed
            ) * (2**self._pto_count)
            return self._time_of_last_sent_ack_eliciting_packet + timeout

        return None

    def get_probe_timeout(self, *, include_max_ack_delay: bool = True) -> float:
        """
        Return the PTO period, without backoff.

        The loss detection timer only includes max_ack_delay for application
        data (RFC 9002 section 6.2.1). The connection uses the default, which
        includes it, to size the idle timeout and the closing period.

        Before the first RTT sample, this is twice the initial RTT, regardless
        of `include_max_ack_delay`.
        """
        if not self._rtt_initialized:
            return 2 * self._rtt_initial
        pto = self._rtt_smoothed + max(4 * self._rtt_variance, K_GRANULARITY)
        if include_max_ack_delay:
            pto += self.max_ack_delay
        return pto

    def on_ack_received(
        self,
        *,
        ack_rangeset: RangeSet,
        ack_delay: float,
        now: float,
        space: QuicPacketSpace,
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

        # Only visit the sent packets within the acknowledged ranges, as the peer
        # chooses how many ranges and ACK frames it sends. Packets are stored in
        # the order they are sent, so their numbers are sorted.
        packet_numbers = list(space.sent_packets)
        for r in ack_rangeset:
            start = bisect_left(packet_numbers, r.start)
            stop = bisect_left(packet_numbers, r.stop)
            for packet_number in packet_numbers[start:stop]:
                # Remove the packet and update the counters.
                packet = space.sent_packets.pop(packet_number)
                if packet.is_ack_eliciting:
                    is_ack_eliciting = True
                    space.ack_eliciting_in_flight -= 1
                if packet.in_flight:
                    self._cc.on_packet_acked(packet=packet, now=now)
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
                self._rtt_first_sample_time = now
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
            self._cc.on_rtt_measurement(now=now, rtt=latest_rtt)
            self._pacer.update_rate(
                congestion_window=self._cc.congestion_window,
                smoothed_rtt=self._rtt_smoothed,
            )

        else:
            log_rtt = False

        self._detect_loss(now=now, space=space)

        # Reset the PTO count, unless the client is not yet certain the server
        # has validated its address (RFC 9002 section 6.2.1).
        if self.peer_completed_address_validation:
            self._pto_count = 0

        if self._quic_logger is not None:
            self._log_metrics_updated(log_rtt=log_rtt)

    def on_loss_detection_timeout(self, *, now: float) -> None:
        loss_space = self._get_loss_space()
        if loss_space is not None:
            self._detect_loss(now=now, space=loss_space)
        else:
            self._pto_count += 1
            self.reschedule_data(now=now)

    def on_packet_sent(self, *, packet: QuicSentPacket, space: QuicPacketSpace) -> None:
        space.sent_packets[packet.packet_number] = packet

        if packet.is_ack_eliciting:
            space.ack_eliciting_in_flight += 1
        if packet.in_flight:
            # Application data sent before the handshake is confirmed does not
            # arm the PTO, so it must not delay it either.
            if packet.is_ack_eliciting and (
                self.handshake_confirmed or not space.is_application_data
            ):
                self._time_of_last_sent_ack_eliciting_packet = packet.sent_time

            # add packet to bytes in flight
            self._cc.on_packet_sent(packet=packet)

            if self._quic_logger is not None:
                self._log_metrics_updated()

    def reschedule_data(self, *, now: float, speed_up_handshake: bool = False) -> None:
        """
        Schedule some data for retransmission and request a probe.

        Outstanding CRYPTO data is retransmitted if there is any. Otherwise, so
        that a probe carries data rather than a bare PING (RFC 9002 section
        6.2.4), the oldest ack-eliciting packet is retransmitted, unless
        `speed_up_handshake` is set, as speeding up handshake completion only
        involves CRYPTO data (RFC 9002 section 6.2.3).

        The packets are declared lost, although RFC 9002 section 6.2 says a PTO
        must not mark packets as lost, because delivery handlers expect a packet
        to be either acknowledged or lost, never both. Retransmitting early does
        not imply a loss though, so this is not a congestion event.
        """
        # Retransmit any outstanding CRYPTO data.
        crypto_scheduled = False
        for space in self.spaces:
            packets = tuple(
                filter(lambda i: i.is_crypto_packet, space.sent_packets.values())
            )
            if packets:
                if self._logger is not None:
                    self._logger.debug(
                        "Scheduled CRYPTO data of %s packets %s for retransmission",
                        packets[0].packet_type.name,
                        ", ".join(str(packet.packet_number) for packet in packets),
                    )
                self._on_packets_lost(
                    congestion_event=False, now=now, packets=packets, space=space
                )
                crypto_scheduled = True

        # Otherwise retransmit the oldest ack-eliciting packet. Application data
        # does not arm the PTO before the handshake is confirmed, so it is not
        # retransmitted early either.
        if not crypto_scheduled and not speed_up_handshake:
            oldest: Optional[tuple[QuicSentPacket, QuicPacketSpace]] = None
            for space in self.spaces:
                if space.is_application_data and not self.handshake_confirmed:
                    continue
                for packet in space.sent_packets.values():
                    if packet.is_ack_eliciting:
                        if oldest is None or packet.sent_time < oldest[0].sent_time:
                            oldest = (packet, space)
                        break
            if oldest is not None:
                packet, space = oldest
                if self._logger is not None:
                    self._logger.debug(
                        "Scheduled data of %s packet %d for retransmission",
                        packet.packet_type.name,
                        packet.packet_number,
                    )
                self._on_packets_lost(
                    congestion_event=False, now=now, packets=[packet], space=space
                )

        # Ensure an ACK-eliciting packet is sent.
        self._send_probe()

    def _detect_loss(self, *, now: float, space: QuicPacketSpace) -> None:
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

        self._on_packets_lost(
            now=now,
            packets=lost_packets,
            persistent_congestion=self._in_persistent_congestion(packets=lost_packets),
            space=space,
        )

    def _get_loss_space(self) -> Optional[QuicPacketSpace]:
        loss_space = None
        for space in self.spaces:
            if space.loss_time is not None and (
                loss_space is None or space.loss_time < loss_space.loss_time
            ):
                loss_space = space
        return loss_space

    def _in_persistent_congestion(self, *, packets: list[QuicSentPacket]) -> bool:
        """
        Check whether the loss of `packets` establishes persistent congestion
        (RFC 9002 section 7.6.2).

        The lost packets are a contiguous run of the sent packets, so a gap in
        packet numbers means an intervening packet was acknowledged. It may
        also have belonged to another space or been retransmitted on a PTO, in
        which case we err on the side of not declaring persistent congestion.
        """
        if not self._rtt_initialized:
            return False

        duration = self.get_probe_timeout() * K_PERSISTENT_CONGESTION_THRESHOLD
        previous_packet_number: int | None = None
        start_time: float | None = None
        for packet in packets:
            # A gap in packet numbers ends the current period, as a packet sent
            # in between may have been acknowledged.
            if (
                previous_packet_number is not None
                and packet.packet_number != previous_packet_number + 1
            ):
                start_time = None
            previous_packet_number = packet.packet_number

            # Only ack-eliciting packets sent after the first RTT sample count.
            if (
                packet.is_ack_eliciting
                and packet.sent_time > self._rtt_first_sample_time
            ):
                if start_time is None:
                    start_time = packet.sent_time
                elif packet.sent_time - start_time > duration:
                    return True
        return False

    def _log_metrics_updated(self, log_rtt=False) -> None:
        data: dict[str, Any] = self._cc.get_log_data()

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
        self,
        *,
        congestion_event: bool = True,
        now: float,
        packets: Iterable[QuicSentPacket],
        persistent_congestion: bool = False,
        space: QuicPacketSpace,
    ) -> None:
        """
        Stop tracking the packets and schedule their data for retransmission.

        If `congestion_event` is True, the loss is reported to the congestion
        controller, which may reduce its window, and `persistent_congestion` makes
        it collapse the window. If it is False, the packets are only removed from
        bytes in flight, as when a PTO retransmits data which may not be lost.
        """
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
        if lost_packets_cc and not congestion_event:
            self._cc.on_packets_expired(packets=lost_packets_cc)
        elif lost_packets_cc:
            self._cc.on_packets_lost(now=now, packets=lost_packets_cc)
            if persistent_congestion:
                self._cc.on_persistent_congestion()
            self._pacer.update_rate(
                congestion_window=self._cc.congestion_window,
                smoothed_rtt=self._rtt_smoothed,
            )
            if self._quic_logger is not None:
                self._log_metrics_updated()
