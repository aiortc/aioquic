import binascii
import contextlib
import io
import os
import time
from typing import Optional
from unittest import TestCase, skipIf

from aioquic import tls
from aioquic.buffer import UINT_VAR_MAX, Buffer, encode_uint_var
from aioquic.quic import events
from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE, QuicConfiguration
from aioquic.quic.connection import (
    MAX_LOCAL_CHALLENGES,
    MAX_NETWORK_PATHS,
    MAX_PENDING_CRYPTO,
    MAX_REMOTE_CHALLENGES,
    STREAM_COUNT_MAX,
    NetworkAddress,
    QuicConnection,
    QuicConnectionError,
    QuicConnectionId,
    QuicConnectionState,
    QuicNetworkPath,
    QuicReceiveContext,
    dump_cid,
)
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import (
    QuicErrorCode,
    QuicFrameType,
    QuicPacketType,
    QuicPreferredAddress,
    QuicProtocolVersion,
    QuicTransportParameters,
    QuicVersionInformation,
    encode_quic_retry,
    encode_quic_version_negotiation,
    get_spin_bit,
    pull_quic_header,
    pull_quic_transport_parameters,
    push_quic_transport_parameters,
)
from aioquic.quic.packet_builder import QuicDeliveryState, QuicPacketBuilder
from aioquic.quic.recovery import K_GRANULARITY, QuicPacketPacer

from .utils import (
    SERVER_CACERTFILE,
    SERVER_CERTFILE,
    SERVER_CERTFILE_WITH_CHAIN,
    SERVER_KEYFILE,
    SKIP_TESTS,
)

CLIENT_ADDR = ("1.2.3.4", 1234)
NEW_CLIENT_ADDR = ("1.2.3.4", 2345)
CLIENT_HANDSHAKE_DATAGRAM_SIZES = [1200]

SERVER_ADDR = ("2.3.4.5", 4433)
SERVER_PREFERRED_ADDR = ("3.4.5.6", 4433)
SERVER_PREFERRED_ADDRESS = QuicPreferredAddress(
    ipv4_address=SERVER_PREFERRED_ADDR,
    ipv6_address=None,
    connection_id=bytes(8),
    stateless_reset_token=bytes(16),
)
SPOOFED_ADDR = ("6.7.8.9", 1234)
SERVER_INITIAL_DATAGRAM_SIZES = [1200, 1162]

HANDSHAKE_COMPLETED_EVENTS = [
    events.HandshakeCompleted,
    events.ConnectionIdIssued,
    events.ConnectionIdIssued,
    events.ConnectionIdIssued,
    events.ConnectionIdIssued,
    events.ConnectionIdIssued,
    events.ConnectionIdIssued,
    events.ConnectionIdIssued,
]
TICK = 0.05  # seconds


class SessionTicketStore:
    def __init__(self):
        self.tickets = {}

    def add(self, ticket):
        self.tickets[ticket.ticket] = ticket

    def pop(self, label):
        return self.tickets.pop(label, None)


def advertise_preferred_address(server):
    """
    Make `server` advertise SERVER_PREFERRED_ADDR as its preferred address.
    """
    connection_id = QuicConnectionId(
        cid=os.urandom(8),
        sequence_number=1,
        stateless_reset_token=os.urandom(16),
        was_sent=True,
    )
    server._host_cids.append(connection_id)
    server._host_cid_seq = 2

    serialize_transport_parameters = server._serialize_transport_parameters

    def patched_serialize_transport_parameters():
        parameters = pull_quic_transport_parameters(
            Buffer(data=serialize_transport_parameters())
        )
        parameters.preferred_address = QuicPreferredAddress(
            ipv4_address=SERVER_PREFERRED_ADDR,
            ipv6_address=None,
            connection_id=connection_id.cid,
            stateless_reset_token=connection_id.stateless_reset_token,
        )
        return encode_transport_parameters(parameters)

    server._serialize_transport_parameters = patched_serialize_transport_parameters


def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
    return QuicReceiveContext(
        epoch=epoch,
        host_cid=client.host_cid,
        network_path=client._network_paths[0],
        quic_logger_frames=[],
        time=time.time(),
        version=None,
    )


def consume_events(connection: QuicConnection) -> None:
    while True:
        event = connection.next_event()
        if event is None:
            break


def create_standalone_client(self, **client_options):
    client = QuicConnection(
        configuration=QuicConfiguration(
            is_client=True, quic_logger=QuicLogger(), **client_options
        )
    )
    client._ack_delay = 0

    # kick-off handshake
    client.connect(SERVER_ADDR, now=time.time())
    self.assertEqual(drop(client), 1)

    return client


def create_standalone_server(self, original_destination_connection_id=bytes(8)):
    server_configuration = QuicConfiguration(is_client=False, quic_logger=QuicLogger())
    server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)

    server = QuicConnection(
        configuration=server_configuration,
        original_destination_connection_id=original_destination_connection_id,
    )
    server._ack_delay = 0

    return server


def datagram_sizes(items: list[tuple[bytes, NetworkAddress]]) -> list[int]:
    return [len(x[0]) for x in items]


def new_connection_id(
    *,
    sequence_number: int,
    retire_prior_to: int = 0,
    connection_id: bytes = bytes(8),
    capacity: int = 100,
):
    buf = Buffer(capacity=capacity)
    buf.push_uint_var(sequence_number)
    buf.push_uint_var(retire_prior_to)
    buf.push_uint_var(len(connection_id))
    buf.push_bytes(connection_id)
    buf.push_bytes(bytes(16))  # stateless reset token
    buf.seek(0)
    return buf


@contextlib.contextmanager
def client_and_server(
    client_kwargs={},
    client_options={},
    client_patch=lambda x: None,
    handshake=True,
    server_kwargs={},
    server_certfile=SERVER_CERTFILE,
    server_keyfile=SERVER_KEYFILE,
    server_options={},
    server_patch=lambda x: None,
):
    client_configuration = QuicConfiguration(
        is_client=True, quic_logger=QuicLogger(), **client_options
    )
    client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)

    client = QuicConnection(configuration=client_configuration, **client_kwargs)
    client._ack_delay = 0
    disable_packet_pacing(client)
    client_patch(client)

    server_configuration = QuicConfiguration(
        is_client=False, quic_logger=QuicLogger(), **server_options
    )
    server_configuration.load_cert_chain(server_certfile, server_keyfile)

    server = QuicConnection(
        configuration=server_configuration,
        original_destination_connection_id=client.original_destination_connection_id,
        **server_kwargs,
    )
    server._ack_delay = 0
    disable_packet_pacing(server)
    server_patch(server)

    # perform handshake
    if handshake:
        client.connect(SERVER_ADDR, now=time.time())
        for i in range(3):
            roundtrip(client, server)

    yield client, server

    # close
    client.close()
    server.close()


def disable_packet_pacing(connection):
    class DummyPacketPacer(QuicPacketPacer):
        def __init__(self):
            super().__init__(max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE)

        def next_send_time(self, now):
            return None

    connection._loss._pacer = DummyPacketPacer()


def encode_transport_parameters(parameters: QuicTransportParameters) -> bytes:
    buf = Buffer(capacity=512)
    push_quic_transport_parameters(buf, parameters)
    return buf.data


def sequence_numbers(connection_ids):
    return list(map(lambda x: x.sequence_number, connection_ids))


def drop(sender):
    """
    Drop datagrams from `sender`.
    """
    return len(sender.datagrams_to_send(now=time.time()))


def receive_from(sender, receiver, from_addr):
    """
    Send datagrams from `sender` to `receiver`, as if they came from `from_addr`.

    Returns the destination addresses of the datagrams.
    """
    addrs = []
    for data, addr in sender.datagrams_to_send(now=time.time()):
        addrs.append(addr)
        receiver.receive_datagram(data, from_addr, now=time.time())
    return addrs


def roundtrip(sender, receiver):
    """
    Send datagrams from `sender` to `receiver` and back.
    """
    return (transfer(sender, receiver), transfer(receiver, sender))


def roundtrip_until_done(sender, receiver):
    """
    Send datagrams from `sender` to `receiver` and back
    repeatedly until no more datagrams are exchanged.
    """
    rounds = 0
    while roundtrip(sender, receiver) != (0, 0):
        rounds += 1
        assert rounds < 10, "Too many roundtrips!"


def transfer(sender, receiver):
    """
    Send datagrams from `sender` to `receiver`.
    """
    datagrams = 0
    from_addr = CLIENT_ADDR if sender._is_client else SERVER_ADDR
    for data, addr in sender.datagrams_to_send(now=time.time()):
        datagrams += 1
        receiver.receive_datagram(data, from_addr, now=time.time())
    return datagrams


class QuicConnectionTestCase(TestCase):
    def assertEvents(self, connection: QuicConnection, expected: list):
        types = []
        while True:
            event = connection.next_event()
            if event is not None:
                types.append(type(event))
            else:
                break
        self.assertEqual(types, expected)

    def assertPacketDropped(self, connection: QuicConnection, trigger: str):
        log = connection.configuration.quic_logger.to_dict()
        found_trigger = None
        for event in log["traces"][0]["events"]:
            if event["name"] == "transport:packet_dropped":
                found_trigger = event["data"]["trigger"]
                break
        self.assertEqual(found_trigger, trigger)

    def assertSentPackets(self, connection: QuicConnection, expected: list[int]):
        counts = [len(space.sent_packets) for space in connection._loss.spaces]
        self.assertEqual(counts, expected)


class QuicConnectionLossTest(QuicConnectionTestCase):
    """
    Check how connections recover when packets are lost or delayed.
    """

    def acked_ranges(self, connection: QuicConnection) -> list[list[list[int]]]:
        """
        Return the ranges of the ACK frames sent by `connection`.
        """
        log = connection.configuration.quic_logger.to_dict()
        return [
            frame["acked_ranges"]
            for event in log["traces"][0]["events"]
            if event["name"] == "transport:packet_sent"
            for frame in event["data"]["frames"]
            if frame["frame_type"] == "ack"
        ]

    def advance_by_tick(self, now: float) -> float:
        """
        Move time forward by one network hop, checking no timer is skipped.
        """
        now += TICK
        self.assertNoTimerDueBefore(now)
        return now

    def advance_to_timer(self, now: float, connection: QuicConnection) -> float:
        """
        Move time forward to the connection's timer, checking it is not in the
        past and that no other timer is due before it.
        """
        timer = connection.get_timer()
        self.assertIsNotNone(timer)
        self.assertGreaterEqual(timer, now)
        self.assertNoTimerDueBefore(timer)
        return timer

    def assertNoTimerDueBefore(self, when: float) -> None:
        for connection in self._watched_connections:
            timer = connection.get_timer()
            if timer is not None:
                role = "client" if connection._is_client else "server"
                self.assertGreaterEqual(timer, when, f"The {role}'s timer is overdue.")

    def create_session_ticket(self):
        """
        Perform a handshake and return the client's session ticket, along with
        the server's ticket store.
        """
        client_tickets = []
        ticket_store = SessionTicketStore()
        with client_and_server(
            client_kwargs={"session_ticket_handler": client_tickets.append},
            server_kwargs={"session_ticket_handler": ticket_store.add},
        ):
            pass
        return client_tickets[0], ticket_store

    def handshake(
        self, client: QuicConnection, server: QuicConnection, now: float
    ) -> float:
        """
        Perform the handshake without loss and return the time it completes.
        """
        client.connect(SERVER_ADDR, now=now)
        sender, receiver = client, server
        idle_turns = 0
        while idle_turns < 2:
            items = sender.datagrams_to_send(now=now)
            idle_turns = 0 if items else idle_turns + 1
            now = self.advance_by_tick(now)
            from_addr = CLIENT_ADDR if sender is client else SERVER_ADDR
            for data, addr in items:
                receiver.receive_datagram(data, from_addr, now=now)
            sender, receiver = receiver, sender
        consume_events(client)
        consume_events(server)
        return now

    def path_challenges(self, connection: QuicConnection) -> list[str]:
        """
        Return the data of the PATH_CHALLENGE frames sent by `connection`.
        """
        log = connection.configuration.quic_logger.to_dict()
        return [
            frame["data"]
            for event in log["traces"][0]["events"]
            if event["name"] == "transport:packet_sent"
            for frame in event["data"]["frames"]
            if frame["frame_type"] == "path_challenge"
        ]

    def probing_datagram(
        self,
        client: QuicConnection,
        connection_id: QuicConnectionId,
        frame_type: int,
        data: bytes,
        max_total_bytes: Optional[int] = None,
    ) -> bytes:
        """
        Build a datagram with which the client probes a new path, using a
        connection ID reserved for that path, as a client which supports
        migration would.
        """
        builder = QuicPacketBuilder(
            host_cid=client.host_cid,
            is_client=True,
            max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
            packet_number=client._packet_number,
            peer_cid=connection_id.cid,
            version=client._version,
        )
        builder.max_total_bytes = max_total_bytes
        builder.start_packet(QuicPacketType.ONE_RTT, client._cryptos[tls.Epoch.ONE_RTT])
        buf = builder.start_frame(frame_type, capacity=9)
        buf.push_bytes(data)
        datagrams, packets = builder.flush()
        client._packet_number = builder.packet_number
        return datagrams[0]

    def test_connect_with_0rtt_and_lost_client_first_flight(self):
        """
        Check the client pads datagrams carrying INITIAL packets to 1200 bytes
        when its congestion window is nearly full (RFC 9000 section 14.1).

        The client's first flight of INITIAL and 0-RTT data is lost, so when the
        server acknowledges the retransmitted INITIAL, the congestion window has
        room for less than a full datagram. The padding after the INITIAL and
        HANDSHAKE packets is not in flight, but 1-RTT data would have to be padded
        with PADDING frames, so it is sent in a datagram of its own. The server
        delays its ACK of the 0-RTT data, which would make the client detect the
        loss of its first flight and free the congestion window.
        """
        client_ticket, ticket_store = self.create_session_ticket()

        def patch(server):
            server._ack_delay = K_GRANULARITY

        with client_and_server(
            client_options={"session_ticket": client_ticket},
            handshake=False,
            server_kwargs={"session_ticket_fetcher": ticket_store.pop},
            server_patch=patch,
        ) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL and 0-RTT data, which fill the congestion window.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            stream_id = client.get_next_available_stream_id()
            client.send_stream_data(stream_id, bytes(20000), end_stream=True)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200] * 10)
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 10])
            self.assertEvents(client, [])
            self.assertEqual(client._loss.bytes_in_flight, 12000)
            self.assertEqual(client._loss.congestion_window, 12000)

            # The first flight is lost, client's PTO fires and it retransmits
            # INITIAL with 0-RTT data.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.6)
            self.assertSentPackets(client, [1, 0, 11])
            self.assertEvents(client, [])

            # Server receives INITIAL and 0-RTT data, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(server.get_timer(), 0.251)
            self.assertSentPackets(server, [1, 1, 0])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # Server's ACK timer fires, it sends an ACK for the 0-RTT data, which
            # arrives after INITIAL + HANDSHAKE.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            ack_items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(ack_items), [33])
            self.assertAlmostEqual(server.get_timer(), 0.45)
            self.assertSentPackets(server, [1, 1, 1])
            self.assertEvents(server, [])

            # Client receives INITIAL + HANDSHAKE, sends a padded datagram with
            # INITIAL + HANDSHAKE, and 1-RTT data in a datagram of its own.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            self.assertEqual(
                client._loss.congestion_window - client._loss.bytes_in_flight, 684
            )
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200, 580])
            self.assertAlmostEqual(client.get_timer(), 0.604)
            self.assertSentPackets(client, [0, 1, 12])
            self.assertEvents(
                client, [events.ProtocolNegotiated] + HANDSHAKE_COMPLETED_EVENTS
            )

    def test_connect_with_0rtt_without_loss(self):
        """
        Check the server acknowledges 0-RTT data in 1-RTT packets before the
        handshake completes (RFC 9000 sections 7 and 13.2.1).
        """
        client_ticket, ticket_store = self.create_session_ticket()

        with client_and_server(
            client_options={"session_ticket": client_ticket},
            handshake=False,
            server_kwargs={"session_ticket_fetcher": ticket_store.pop},
        ) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL + 0-RTT data.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            stream_id = client.get_next_available_stream_id()
            client.send_stream_data(stream_id, b"hello", end_stream=True)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 1])
            self.assertEvents(client, [])

            # Server receives INITIAL + 0-RTT data, sends INITIAL + HANDSHAKE and
            # an ACK for the 0-RTT data.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 1, 1])
            self.assertEvents(
                server, [events.ProtocolNegotiated, events.StreamDataReceived]
            )

            # Client receives INITIAL + HANDSHAKE and the ACK, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.35)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(
                client, [events.ProtocolNegotiated] + HANDSHAKE_COMPLETED_EVENTS
            )

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [231])
            self.assertAlmostEqual(server.get_timer(), 0.425)
            self.assertSentPackets(server, [0, 0, 2])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)

            # Client receives HANDSHAKE_DONE, sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(client.get_timer(), 60.2)  # idle timeout
            self.assertSentPackets(client, [0, 0, 1])
            self.assertEvents(client, [])

    def test_connect_with_delayed_client_finished_and_session_ticket(self):
        """
        Check the server does not send a session ticket before the client's
        FINISHED is received, as 1-RTT packets cannot be acknowledged until then.
        """
        client_tickets = []
        ticket_store = SessionTicketStore()

        with client_and_server(
            client_kwargs={"session_ticket_handler": client_tickets.append},
            handshake=False,
            server_kwargs={"session_ticket_handler": ticket_store.add},
        ) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)

            # Server receives INITIAL, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertSentPackets(server, [1, 2, 0])

            # Client receives INITIAL + HANDSHAKE, sends FINISHED which is delayed.
            now = self.advance_by_tick(now)
            for data, addr in items:
                client.receive_datagram(data, SERVER_ADDR, now=now)
            delayed_items = client.datagrams_to_send(now=now)

            # Server's PTO fires, it retransmits INITIAL + HANDSHAKE.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])

            # No session ticket has been issued or sent.
            self.assertEqual(ticket_store.tickets, {})
            self.assertFalse(
                any(
                    packet.is_crypto_packet
                    for packet in server._spaces[
                        tls.Epoch.ONE_RTT
                    ].sent_packets.values()
                )
            )

            # Server receives the delayed FINISHED, sends session ticket.
            now = self.advance_by_tick(now)
            for data, addr in delayed_items:
                server.receive_datagram(data, CLIENT_ADDR, now=now)
            self.assertEqual(len(ticket_store.tickets), 1)
            items = server.datagrams_to_send(now=now)

            # Client receives session ticket.
            now = self.advance_by_tick(now)
            for data, addr in items:
                client.receive_datagram(data, SERVER_ADDR, now=now)
            self.assertEqual(len(client_tickets), 1)
            self.assertEqual(
                client_tickets[0].ticket, list(ticket_store.tickets.keys())[0]
            )

    def test_connect_with_late_server_handshake(self):
        """
        Check the client does not speed up handshake completion when a HANDSHAKE
        packet arrives after it discarded its handshake keys.

        Only a packet which arrives before the client obtains handshake keys
        suggests the server's INITIAL was lost (RFC 9002 section 6.2.3).
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # Server receives INITIAL, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            server_items = server.datagrams_to_send(now=now)
            self.assertEqual(
                datagram_sizes(server_items), SERVER_INITIAL_DATAGRAM_SIZES
            )
            self.assertAlmostEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # Client receives INITIAL + HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(server_items[0][0], SERVER_ADDR, now=now)
            client.receive_datagram(server_items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), CLIENT_HANDSHAKE_DATAGRAM_SIZES)
            self.assertAlmostEqual(client.get_timer(), 0.4)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(
                client, [events.ProtocolNegotiated] + HANDSHAKE_COMPLETED_EVENTS
            )

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertAlmostEqual(server.get_timer(), 0.425)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)

            # Client receives HANDSHAKE_DONE, discards its handshake keys and
            # sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(client.get_timer(), 60.2)  # idle timeout
            self.assertSentPackets(client, [0, 0, 1])
            self.assertEvents(client, [])

            # Client receives a late copy of the server's second HANDSHAKE packet,
            # which it cannot decrypt, and sends nothing.
            now = self.advance_by_tick(now)
            client.receive_datagram(server_items[1][0], SERVER_ADDR, now=now)
            self.assertEqual(client.datagrams_to_send(now=now), [])
            self.assertAlmostEqual(client.get_timer(), 60.2)  # idle timeout
            self.assertSentPackets(client, [0, 0, 1])
            self.assertEvents(client, [])

    def test_connect_with_lost_client_initial(self):
        """
        Check the handshake completes if the client's INITIAL is lost.

        The client's PTO fires and it retransmits its INITIAL.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # INITIAL is lost, client's PTO fires and it retransmits INITIAL.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.6)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # Server receives INITIAL, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertAlmostEqual(server.get_timer(), 0.45)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # Client receives INITIAL + HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), CLIENT_HANDSHAKE_DATAGRAM_SIZES)
            self.assertAlmostEqual(client.get_timer(), 0.6)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(
                client, [events.ProtocolNegotiated] + HANDSHAKE_COMPLETED_EVENTS
            )

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertAlmostEqual(server.get_timer(), 0.625)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)

            # Client receives HANDSHAKE_DONE, sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(client.get_timer(), 60.4)  # idle timeout
            self.assertSentPackets(client, [0, 0, 1])
            self.assertEvents(client, [])

    def test_connect_with_lost_client_stream_data(self):
        """
        Check the client's PTO probe retransmits stream data which is lost once
        the handshake is confirmed, rather than a bare PING whose ACK would only
        then reveal the loss (RFC 9002 section 6.2.4). This is not a congestion
        event.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])

            # Server receives INITIAL, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertEvents(server, [events.ProtocolNegotiated])

            # Client receives INITIAL + HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), CLIENT_HANDSHAKE_DATAGRAM_SIZES)

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)

            # Client receives HANDSHAKE_DONE, sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            self.assertTrue(client._handshake_confirmed)
            ack_items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(ack_items), [32])
            self.assertSentPackets(client, [0, 0, 1])

            # Client sends stream data, which is lost.
            client.send_stream_data(0, b"GET /index.html\r\n", end_stream=True)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [48])
            self.assertAlmostEqual(client.get_timer(), 0.475)
            self.assertSentPackets(client, [0, 0, 2])

            # Server receives ACK, nothing remains in flight.
            now = self.advance_by_tick(now)
            server.receive_datagram(ack_items[0][0], CLIENT_ADDR, now=now)
            self.assertEqual(server.datagrams_to_send(now=now), [])
            self.assertAlmostEqual(server.get_timer(), 60.25)  # idle timeout
            self.assertSentPackets(server, [0, 0, 0])

            # Client's PTO fires, it retransmits the stream data without reducing
            # its congestion window.
            congestion_window = client._loss.congestion_window
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [49])
            self.assertAlmostEqual(client.get_timer(), 1.025)
            self.assertSentPackets(client, [0, 0, 2])
            self.assertEqual(client._loss.congestion_window, congestion_window)

            # Server receives stream data, sends ACK.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            self.assertEvents(server, [events.StreamDataReceived])
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [34])
            self.assertAlmostEqual(server.get_timer(), 60.525)  # idle timeout
            self.assertSentPackets(server, [0, 0, 1])

            # Client receives ACK, nothing remains in flight.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            self.assertEqual(client.datagrams_to_send(now=now), [])
            self.assertAlmostEqual(client.get_timer(), 60.575)  # idle timeout
            self.assertSentPackets(client, [0, 0, 0])

    def test_connect_with_lost_server_encrypted_extensions(self):
        """
        Check the client acknowledges the server's HANDSHAKE packets even if the
        one carrying EncryptedExtensions is lost, so that the server can detect
        the loss without waiting for its PTO.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)

            # Server receives INITIAL, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 2, 0])

            # Client receives the INITIAL but not the HANDSHAKE packet which
            # follows it, then receives the second HANDSHAKE packet.
            now = self.advance_by_tick(now)
            data = items[0][0]
            header = pull_quic_header(Buffer(data=data), host_cid_length=8)
            self.assertEqual(header.packet_type, QuicPacketType.INITIAL)
            client.receive_datagram(data[: header.packet_length], SERVER_ADDR, now=now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            self.assertEqual(
                client.tls.state, tls.State.CLIENT_EXPECT_ENCRYPTED_EXTENSIONS
            )

            # Client acknowledges the HANDSHAKE packet.
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertSentPackets(client, [0, 1, 0])

            # Server receives the ACK for a later HANDSHAKE packet, so it arms its
            # loss timer, which expires before its PTO.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            self.assertEqual(server.datagrams_to_send(now=now), [])
            self.assertAlmostEqual(server.get_timer(), 0.1625)

            # Server's loss timer fires, it retransmits the lost HANDSHAKE packet.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1024])

            # Client completes the handshake.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            self.assertTrue(client._handshake_complete)

    def test_connect_with_lost_server_finished(self):
        """
        Check the handshake completes if the server's second datagram is lost.

        This datagram carries the end of the server's HANDSHAKE data: the rest of
        its Certificate, its CertificateVerify and its FINISHED. The client's ACKs
        are lost too, so the client's address is not validated when the server's
        PTO fires, and the anti-amplification limit only lets the server
        retransmit data the client mostly already has. The client's ACK and PING
        then validate its address, and the server sends the rest of its HANDSHAKE
        data.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # Server receives INITIAL, sends INITIAL + HANDSHAKE but the second
            # datagram is lost.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # Client only receives the first datagram and sends ACKs, which are
            # lost.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.3)
            self.assertSentPackets(client, [0, 1, 0])
            self.assertEvents(client, [events.ProtocolNegotiated])

            # Server's PTO fires, it retransmits INITIAL + HANDSHAKE but its
            # anti-amplification budget only allows one datagram, which mostly
            # carries data the client already has.
            now = self.advance_to_timer(now, server)
            with self.assertLogs("quic", level="DEBUG") as cm:
                server.handle_timer(now=now)
            self.assertIn(
                "Scheduled CRYPTO data of HANDSHAKE packets 1, 2 for retransmission",
                "\n".join(cm.output),
            )
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(server.get_timer(), 0.65)
            self.assertSentPackets(server, [1, 1, 0])
            self.assertEvents(server, [])

            # Client receives the datagram and sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            ack_items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(ack_items), [50])
            self.assertAlmostEqual(client.get_timer(), 0.3)
            self.assertSentPackets(client, [0, 2, 0])
            self.assertEvents(client, [])

            # Client's PTO fires, it sends a HANDSHAKE PING.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            ping_items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(ping_items), [45])
            self.assertAlmostEqual(client.get_timer(), 0.9)
            self.assertSentPackets(client, [0, 3, 0])
            self.assertEvents(client, [])

            # Server receives ACK + PING, which validate the client's address, so
            # it discards INITIAL and sends the rest of HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(ack_items[0][0], CLIENT_ADDR, now=now)
            server.receive_datagram(ping_items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1162])
            self.assertAlmostEqual(server.get_timer(), 0.65)
            self.assertSentPackets(server, [0, 1, 0])
            self.assertEvents(server, [])

            # Client receives HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [327])
            self.assertAlmostEqual(client.get_timer(), 0.65)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(client, HANDSHAKE_COMPLETED_EVENTS)

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertAlmostEqual(server.get_timer(), 0.725)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)

            # Client receives HANDSHAKE_DONE, sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(client.get_timer(), 60.5)  # idle timeout
            self.assertSentPackets(client, [0, 0, 1])
            self.assertEvents(client, [])

    def test_connect_with_lost_server_handshake_and_full_congestion_window(self):
        """
        Check the server resends lost HANDSHAKE data when its congestion window
        is full of 1-RTT data.

        The server's certificate chain makes its HANDSHAKE data span three
        packets, and the second one is lost. The client cannot process the 1-RTT
        data which follows until the handshake completes. Once the server
        declares the HANDSHAKE packet lost, its congestion window is below bytes
        in flight, and no PTO is armed: the client acknowledged the other
        HANDSHAKE packets, and 1-RTT data does not arm the PTO before the
        handshake is confirmed (RFC 9002 section 6.2.1).
        """
        with client_and_server(
            handshake=False, server_certfile=SERVER_CERTFILE_WITH_CHAIN
        ) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # Server receives INITIAL, sends INITIAL + HANDSHAKE and 1-RTT data, up
            # to the anti-amplification limit.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            server.send_stream_data(3, bytes(20000))
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200, 1200, 1155, 45])
            self.assertAlmostEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 3, 1])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # The second datagram is lost. Client receives the others, drops the
            # 1-RTT data and sends ACKs.
            now = self.advance_by_tick(now)
            for data, addr in [items[0], items[2], items[3]]:
                client.receive_datagram(data, SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.3)
            self.assertSentPackets(client, [0, 1, 0])
            self.assertEvents(client, [events.ProtocolNegotiated])

            # Server receives ACKs, which validate the client's address, so it
            # sends 1-RTT data which fills the congestion window. It arms its loss
            # timer for the second HANDSHAKE packet.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200] * 10 + [1110])
            self.assertAlmostEqual(server.get_timer(), 0.1625)
            self.assertSentPackets(server, [0, 1, 12])
            self.assertEvents(server, [])
            self.assertEqual(server._loss.bytes_in_flight, 14355)
            self.assertEqual(server._loss.congestion_window, 14355)

            # Server's loss timer fires, it declares the HANDSHAKE packet lost
            # and resends its data although the congestion window is full.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            self.assertEqual(server._loss.bytes_in_flight, 13155)
            self.assertEqual(server._loss.congestion_window, 7177)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(server.get_timer(), 0.4125)
            self.assertSentPackets(server, [0, 1, 12])
            self.assertEvents(server, [])

            # Client receives HANDSHAKE, completes the handshake.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            self.assertEvents(client, [events.HandshakeCompleted])

    def test_connect_with_lost_server_handshake_done(self):
        """
        Check the handshake is confirmed if the server's HANDSHAKE_DONE is lost.

        The server's PTO probe retransmits HANDSHAKE_DONE, without which the
        client cannot confirm the handshake, rather than a bare PING whose ACK
        would only then reveal the loss (RFC 9002 section 6.2.4). This is not a
        congestion event. Meanwhile, the client's PTO fires for its FINISHED,
        which the server never acknowledges as it discards its Handshake keys on
        receiving it.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)

            # Server receives INITIAL, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # Client receives INITIAL + HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), CLIENT_HANDSHAKE_DATAGRAM_SIZES)
            self.assertAlmostEqual(client.get_timer(), 0.4)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(
                client, [events.ProtocolNegotiated] + HANDSHAKE_COMPLETED_EVENTS
            )

            # Server receives FINISHED, discards its Handshake keys and sends
            # HANDSHAKE_DONE which is lost.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            self.assertTrue(server._handshake_confirmed)
            self.assertTrue(server._spaces[tls.Epoch.HANDSHAKE].discarded)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertAlmostEqual(server.get_timer(), 0.425)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)
            self.assertFalse(client._handshake_confirmed)

            # Client's PTO fires as its FINISHED was not acknowledged, it
            # retransmits FINISHED which is lost.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [99])
            self.assertAlmostEqual(client.get_timer(), 1.0)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(client, [])

            # Server's PTO fires, it retransmits HANDSHAKE_DONE without reducing
            # its congestion window.
            congestion_window = server._loss.congestion_window
            now = self.advance_to_timer(now, server)
            with self.assertLogs("quic", level="DEBUG") as cm:
                server.handle_timer(now=now)
            self.assertIn(
                "Scheduled data of ONE_RTT packet 3 for retransmission",
                "\n".join(cm.output),
            )
            self.assertTrue(server._handshake_done_pending)
            items = server.datagrams_to_send(now=now)
            self.assertFalse(server._handshake_done_pending)
            self.assertEqual(datagram_sizes(items), [225])
            self.assertAlmostEqual(server.get_timer(), 0.975)
            self.assertSentPackets(server, [0, 0, 1])
            # FIXME: the server re-emits the ConnectionIdIssued events.
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS[1:])
            self.assertEqual(server._loss.congestion_window, congestion_window)

            # Client receives HANDSHAKE_DONE, confirms the handshake and sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            self.assertTrue(client._handshake_confirmed)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(client.get_timer(), 0.725)
            self.assertSentPackets(client, [0, 0, 2])
            self.assertEvents(client, [])

            # Server receives ACK, nothing remains in flight.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [])
            self.assertAlmostEqual(server.get_timer(), 60.525)  # idle timeout
            self.assertSentPackets(server, [0, 0, 0])
            self.assertEvents(server, [])

    def test_connect_with_lost_server_initial(self):
        """
        Check the handshake completes if the server's first datagram is lost.

        This datagram carries the server's INITIAL, so the client cannot decrypt
        the HANDSHAKE packet in the second datagram. It retransmits its INITIAL
        to speed up the handshake, and the server retransmits its INITIAL and
        HANDSHAKE on receiving duplicate CRYPTO data.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # Server receives INITIAL, sends INITIAL + HANDSHAKE but the first
            # datagram is lost.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # Client only receives the second datagram, which it cannot decrypt,
            # and retransmits INITIAL.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.3)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            self.assertPacketDropped(client, "key_unavailable")

            # Server receives duplicate INITIAL, retransmits INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertAlmostEqual(server.get_timer(), 0.35)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [])

            # Client receives INITIAL + HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), CLIENT_HANDSHAKE_DATAGRAM_SIZES)
            self.assertAlmostEqual(client.get_timer(), 0.5)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(
                client, [events.ProtocolNegotiated] + HANDSHAKE_COMPLETED_EVENTS
            )

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertAlmostEqual(server.get_timer(), 0.525)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)

            # Client receives HANDSHAKE_DONE, sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(client.get_timer(), 60.3)  # idle timeout
            self.assertSentPackets(client, [0, 0, 1])
            self.assertEvents(client, [])

    def test_connect_with_lost_server_initial_and_handshake(self):
        """
        Check the handshake completes if both of the server's datagrams are lost.

        The client's PTO fires and it retransmits its INITIAL. The server receives
        duplicate CRYPTO data and retransmits its INITIAL and HANDSHAKE to speed
        up the handshake.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # Server receives INITIAL, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # INITIAL + HANDSHAKE are lost, client's PTO fires and it retransmits
            # INITIAL.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.6)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # Server receives duplicate INITIAL, retransmits INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertEqual(server.get_timer(), 0.45)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [])

            # Client receives INITIAL + HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), CLIENT_HANDSHAKE_DATAGRAM_SIZES)
            self.assertAlmostEqual(client.get_timer(), 0.6)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(
                client, [events.ProtocolNegotiated] + HANDSHAKE_COMPLETED_EVENTS
            )

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertAlmostEqual(server.get_timer(), 0.625)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)

            # Client receives HANDSHAKE_DONE, sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(client.get_timer(), 60.4)  # idle timeout
            self.assertSentPackets(client, [0, 0, 1])
            self.assertEvents(client, [])

    def test_connect_with_lost_server_initial_and_handshake_amplification_limited(
        self,
    ):
        """
        Check the server stops retransmitting once it has sent three times the
        data it received from the client, whose address is not validated (RFC
        9000 section 8.1).

        The server's datagrams and the client's retransmitted INITIALs are lost,
        so the server's PTO fires twice having only received the client's first
        INITIAL. The second time, there is no room left for even a PING. The
        handshake completes once the client's next INITIAL gets through.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)

            # Server receives INITIAL, sends INITIAL + HANDSHAKE which are lost.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            network_path = server._network_paths[0]
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertFalse(network_path.is_validated)

            # Client's PTO fires, it retransmits INITIAL which is lost.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.6)

            # Server's PTO fires, it only has enough anti-amplification budget left
            # to retransmit one datagram, which is lost.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(server.get_timer(), 0.65)
            self.assertSentPackets(server, [1, 1, 0])
            self.assertEqual(network_path.bytes_received, 1200)
            self.assertEqual(network_path.bytes_sent, 3562)

            # Client's PTO fires, it retransmits INITIAL which is lost.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 1.4)

            # Server's PTO fires, but its anti-amplification budget does not even
            # allow a PING, so it sends nothing and only the idle timeout remains.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [])
            self.assertAlmostEqual(server.get_timer(), 60.05)
            self.assertSentPackets(server, [0, 0, 0])
            self.assertEqual(network_path.bytes_sent, 3562)

            # Client's PTO fires, it retransmits INITIAL.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 3.0)

            # Server receives INITIAL, which raises its anti-amplification budget,
            # and retransmits INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200, 1164])
            self.assertAlmostEqual(server.get_timer(), 2.25)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEqual(network_path.bytes_received, 2400)

            # Client receives INITIAL + HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), CLIENT_HANDSHAKE_DATAGRAM_SIZES)
            self.assertAlmostEqual(client.get_timer(), 1.8)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertTrue(client._handshake_complete)

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertAlmostEqual(server.get_timer(), 1.825)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertTrue(server._handshake_complete)

            # Client receives HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            self.assertTrue(client._handshake_confirmed)

    def test_connect_with_missing_client_finished_and_stream_data(self):
        """
        Check the server does not arm its PTO for 1-RTT data before the handshake
        is confirmed, as it cannot process acknowledgments for it until then.
        """

        def patch(client):
            """
            Patch client to never send its FINISHED.
            """
            push_crypto_data = client._push_crypto_data

            def push_crypto_data_without_finished():
                client._crypto_buffers[tls.Epoch.HANDSHAKE].seek(0)
                push_crypto_data()

            client._push_crypto_data = push_crypto_data_without_finished

        with client_and_server(client_patch=patch, handshake=False) as (
            client,
            server,
        ):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)

            # Server receives INITIAL, sends INITIAL + HANDSHAKE + 1-RTT.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            server.send_stream_data(3, b"settings")
            items = server.datagrams_to_send(now=now)
            self.assertSentPackets(server, [1, 2, 1])

            # Client receives INITIAL + HANDSHAKE + 1-RTT, sends ACKs but no FINISHED.
            now = self.advance_by_tick(now)
            for data, addr in items:
                client.receive_datagram(data, SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)

            # Server receives ACKs, only 1-RTT data remains in flight.
            now = self.advance_by_tick(now)
            for data, addr in items:
                server.receive_datagram(data, CLIENT_ADDR, now=now)
            self.assertSentPackets(server, [0, 0, 1])

            # The PTO is not armed, only the idle timeout remains.
            self.assertEqual(server.get_timer(), server._close_at)

    def test_connect_without_loss(self):
        """
        Check the handshake completes in the absence of loss.

        This is the reference sequence for the tests with lost packets.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)

            # Client sends INITIAL.
            now = 0.0
            client.connect(SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertEqual(client.get_timer(), 0.2)
            self.assertSentPackets(client, [1, 0, 0])
            self.assertEvents(client, [])

            # Server receives INITIAL, sends INITIAL + HANDSHAKE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), SERVER_INITIAL_DATAGRAM_SIZES)
            self.assertAlmostEqual(server.get_timer(), 0.25)
            self.assertSentPackets(server, [1, 2, 0])
            self.assertEvents(server, [events.ProtocolNegotiated])

            # Client receives INITIAL + HANDSHAKE, sends FINISHED.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            client.receive_datagram(items[1][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), CLIENT_HANDSHAKE_DATAGRAM_SIZES)
            self.assertAlmostEqual(client.get_timer(), 0.4)
            self.assertSentPackets(client, [0, 1, 1])
            self.assertEvents(
                client, [events.ProtocolNegotiated] + HANDSHAKE_COMPLETED_EVENTS
            )

            # Server receives FINISHED, sends HANDSHAKE_DONE.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [229])
            self.assertAlmostEqual(server.get_timer(), 0.425)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, HANDSHAKE_COMPLETED_EVENTS)

            # Client receives HANDSHAKE_DONE, sends ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(client.get_timer(), 60.2)  # idle timeout
            self.assertSentPackets(client, [0, 0, 1])
            self.assertEvents(client, [])

    def test_idle_timeout_restarted_on_send(self):
        """
        Check the idle timer restarts when sending the first ack-eliciting packet
        since the last packet was received, but not when sending later ones, so
        PTO probes do not keep an unresponsive connection open (RFC 9000 section
        10.1).
        """
        with client_and_server(
            client_options={"idle_timeout": 2.0}, handshake=False
        ) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)
            self.assertAlmostEqual(client.get_timer(), 2.2)  # idle timeout
            self.assertAlmostEqual(server.get_timer(), 2.25)  # idle timeout

            # Client sends stream data after a pause, which is lost. This restarts
            # its idle timer.
            now += 0.5
            client.send_stream_data(0, b"ping")
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [35])
            self.assertAlmostEqual(client.get_timer(), 1.125)
            self.assertSentPackets(client, [0, 0, 2])

            # Client's PTO fires, its probe is lost.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [36])
            self.assertAlmostEqual(client.get_timer(), 1.675)
            self.assertSentPackets(client, [0, 0, 2])
            self.assertEvents(client, [])

            # Client's PTO fires again, its probe is lost.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [36])
            self.assertAlmostEqual(client.get_timer(), 2.775)
            self.assertSentPackets(client, [0, 0, 2])
            self.assertEvents(client, [])

            # Server's idle timer expires, as it received nothing since the
            # handshake.
            now = self.advance_to_timer(now, server)
            self.assertAlmostEqual(now, 2.25)
            server.handle_timer(now=now)
            self.assertEqual(server.datagrams_to_send(now=now), [])
            self.assertIsNone(server.get_timer())
            self.assertEvents(server, [events.ConnectionTerminated])

            # Client's PTO fires again, its probe is lost. The idle timer was not
            # restarted by the probes.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [36])
            self.assertAlmostEqual(client.get_timer(), 2.85)  # idle timeout
            self.assertSentPackets(client, [0, 0, 2])
            self.assertEvents(client, [])

            # Client's idle timer expires.
            now = self.advance_to_timer(now, client)
            client.handle_timer(now=now)
            self.assertEqual(client.datagrams_to_send(now=now), [])
            self.assertIsNone(client.get_timer())
            self.assertEvents(client, [events.ConnectionTerminated])

    def test_migrate_after_probing(self):
        """
        Check the server answers a client probing a new path, and validates the
        path before the client migrates to it.

        The server sends PATH_RESPONSE and its own PATH_CHALLENGE on the probed
        path (RFC 9000 sections 8.2.2 and 9.6.3), using a connection ID reserved
        for that path, without changing the one used on the active path (RFC
        9000 section 9.5). When the client migrates, the server switches to the
        reserved connection ID and is not limited by anti-amplification.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)

            # Client probes a new path with a new connection ID.
            probe_cid = client._peer_cid_available.pop(0)
            challenge = os.urandom(8)
            client._network_paths[0].local_challenges.append(challenge)
            data = self.probing_datagram(
                client, probe_cid, QuicFrameType.PATH_CHALLENGE, challenge
            )
            self.assertEqual(len(data), 1200)

            # Server receives the probe, sends ACK on the active path and
            # PATH_RESPONSE + PATH_CHALLENGE on the probed path.
            now = self.advance_by_tick(now)
            server.receive_datagram(data, NEW_CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(
                [(len(data), addr) for data, addr in items],
                [(32, CLIENT_ADDR), (1200, NEW_CLIENT_ADDR)],
            )
            self.assertAlmostEqual(server.get_timer(), 0.6375)
            self.assertSentPackets(server, [0, 0, 2])
            self.assertEvents(server, [])
            self.assertEqual(server.get_peer_address(), CLIENT_ADDR)
            self.assertEqual(server._peer_cid.sequence_number, 0)
            self.assertEqual(server._network_paths[1].peer_cid.sequence_number, 1)
            self.assertEqual(len(self.path_challenges(server)), 1)

            # Client receives ACK, PATH_RESPONSE matching its challenge and
            # PATH_CHALLENGE. It sends ACK on its active path and PATH_RESPONSE on
            # the probed path.
            now = self.advance_by_tick(now)
            for data, addr in items:
                client.receive_datagram(data, SERVER_ADDR, now=now)
            self.assertEqual(len(client._network_paths[0].local_challenges), 0)
            server_challenge = client._network_paths[0].remote_challenges.popleft()
            data = self.probing_datagram(
                client, probe_cid, QuicFrameType.PATH_RESPONSE, server_challenge
            )
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])

            # Server receives ACK and PATH_RESPONSE, the probed path is validated.
            now = self.advance_by_tick(now)
            for item in items:
                server.receive_datagram(item[0], CLIENT_ADDR, now=now)
            server.receive_datagram(data, NEW_CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(
                [(len(data), addr) for data, addr in items], [(32, CLIENT_ADDR)]
            )
            self.assertAlmostEqual(server.get_timer(), 60.5)  # idle timeout
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [])
            self.assertEqual(server.get_peer_address(), CLIENT_ADDR)
            self.assertTrue(server._network_paths[1].is_validated)

            # Client receives ACK, migrates to the probed path and sends data.
            now = self.advance_by_tick(now)
            for data, addr in items:
                client.receive_datagram(data, SERVER_ADDR, now=now)
            client._peer_cid = probe_cid
            client.send_stream_data(0, bytes(3000))
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200, 1200, 697])

            # Server receives the data on the probed path, switches to it with the
            # reserved connection ID, and is not limited by anti-amplification.
            now = self.advance_by_tick(now)
            for data, addr in items:
                server.receive_datagram(data, NEW_CLIENT_ADDR, now=now)
            self.assertEqual(server.get_peer_address(), NEW_CLIENT_ADDR)
            self.assertEqual(server._peer_cid.sequence_number, 1)
            self.assertEqual(server._retire_connection_ids, [0])
            server.send_stream_data(1, bytes(3000))
            items = server.datagrams_to_send(now=now)
            self.assertEqual(
                [(len(data), addr) for data, addr in items],
                [
                    (1200, NEW_CLIENT_ADDR),
                    (1200, NEW_CLIENT_ADDR),
                    (704, NEW_CLIENT_ADDR),
                ],
            )
            self.assertEqual(server._retire_connection_ids, [])
            self.assertEvents(server, [events.StreamDataReceived] * 3)

    def test_migrate_after_probing_with_lost_path_challenge(self):
        """
        Check the server validates the client's new address when the client
        migrates after its PATH_CHALLENGE was answered, but the server's own
        PATH_CHALLENGE on the probed path was lost.

        A PATH_CHALLENGE on a path which is not the active one is not sent
        again, so the server starts validating the path afresh when the client
        migrates to it (RFC 9000 section 9.3).
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)

            # Client probes a new path with a new connection ID.
            probe_cid = client._peer_cid_available.pop(0)
            challenge = os.urandom(8)
            client._network_paths[0].local_challenges.append(challenge)
            data = self.probing_datagram(
                client, probe_cid, QuicFrameType.PATH_CHALLENGE, challenge
            )

            # Server receives the probe, sends ACK on the active path and
            # PATH_RESPONSE + PATH_CHALLENGE on the probed path, which is lost.
            now = self.advance_by_tick(now)
            server.receive_datagram(data, NEW_CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(
                [(len(data), addr) for data, addr in items],
                [(32, CLIENT_ADDR), (1200, NEW_CLIENT_ADDR)],
            )
            self.assertEqual(len(self.path_challenges(server)), 1)

            # Client receives ACK, migrates to the probed path and sends data.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            client._peer_cid = probe_cid
            client.send_stream_data(0, b"01234567")
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [39])

            # Server receives the data on the probed path, switches to it with the
            # reserved connection ID and sends a new PATH_CHALLENGE, padded up to
            # the anti-amplification limit.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], NEW_CLIENT_ADDR, now=now)
            self.assertEqual(server.get_peer_address(), NEW_CLIENT_ADDR)
            self.assertFalse(server._network_paths[0].is_validated)
            self.assertEqual(server._peer_cid.sequence_number, 1)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(len(self.path_challenges(server)), 2)
            self.assertEqual(
                [addr for data, addr in items], [NEW_CLIENT_ADDR] * len(items)
            )
            self.assertIsNotNone(server._path_validation_deadline())

            # Client receives PATH_CHALLENGE, sends PATH_RESPONSE.
            now = self.advance_by_tick(now)
            for data, addr in items:
                client.receive_datagram(data, SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])

            # Server receives PATH_RESPONSE, the path is validated.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], NEW_CLIENT_ADDR, now=now)
            self.assertTrue(server._network_paths[0].is_validated)
            self.assertIsNone(server._path_validation_deadline())

    def test_migrate_to_spoofed_address(self):
        """
        Check the server sends no more than three times the data received from
        an address it cannot validate, then reverts to the client's address.

        An attacker rewrites the source address of a client packet and drops the
        client's subsequent packets. The server's PATH_CHALLENGE exhausts the
        anti-amplification limit of the spoofed address, so its PTO cannot send
        another one. Validation is abandoned after three times the PTO (RFC 9000
        section 8.2.4), and the server reverts to the last validated address
        (RFC 9000 section 9.3.2).
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)
            self.watch_timers(server)

            # Client sends some data.
            client.send_stream_data(0, b"01234567")
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [39])

            # Server receives the data from the spoofed address, sends a
            # PATH_CHALLENGE padded up to the anti-amplification limit.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], SPOOFED_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [3 * 39])
            self.assertEqual(items[0][1], SPOOFED_ADDR)
            self.assertAlmostEqual(server.get_timer(), 0.6375)
            self.assertAlmostEqual(server._path_validation_deadline(), 1.1125)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [events.StreamDataReceived])
            self.assertEqual(len(self.path_challenges(server)), 1)

            # Server's PTO fires, it cannot send anything to the spoofed address.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [])
            self.assertAlmostEqual(server.get_timer(), 1.1125)
            self.assertSentPackets(server, [0, 0, 0])
            self.assertEvents(server, [])
            self.assertEqual(len(self.path_challenges(server)), 1)

            # Server abandons path validation and reverts to the client's
            # address, where it sends its probe.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            self.assertEqual(
                [path.addr for path in server._network_paths], [CLIENT_ADDR]
            )
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [29])
            self.assertEqual(items[0][1], CLIENT_ADDR)
            self.assertAlmostEqual(server.get_timer(), 1.5875)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [])

    def test_migrate_to_spoofed_address_with_many_ack_ranges(self):
        """
        Check the server limits the number of ACK ranges it keeps and the size of
        its ACK frames (RFC 9000 section 13.2.3), so a client which skips packet
        numbers cannot make it exceed the anti-amplification limit of an address
        it cannot validate (RFC 9000 section 8).
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)
            self.watch_timers(server)

            # Client sends PINGs, skipping a packet number after each one, which
            # the server receives. Only the newest ACK ranges are kept.
            for uid in range(100):
                client.send_ping(uid)
                items = client.datagrams_to_send(now=now)
                client._packet_number += 1
                server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            ack_queue = server._spaces[tls.Epoch.ONE_RTT].ack_queue
            self.assertEqual(len(ack_queue), 64)
            self.assertEqual(ack_queue[0], range(77, 78))
            self.assertEqual(ack_queue[-1], range(203, 204))

            # Client sends some data.
            client.send_stream_data(0, b"01234567")
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [39])

            # Server receives the data from the spoofed address as its ACK timer
            # fires, sends an ACK which omits the oldest ranges and a
            # PATH_CHALLENGE, within the anti-amplification limit.
            now = self.advance_to_timer(now, server)
            server.receive_datagram(items[0][0], SPOOFED_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [3 * 39])
            self.assertEqual(items[0][1], SPOOFED_ADDR)
            self.assertAlmostEqual(server.get_timer(), 0.5875)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [events.StreamDataReceived])
            acked_ranges = self.acked_ranges(server)[-1]
            self.assertEqual(len(acked_ranges), 21)
            self.assertEqual(acked_ranges[0], [165, 165])
            self.assertEqual(acked_ranges[-1], [205, 205])
            self.assertEqual(len(self.path_challenges(server)), 1)

    def test_migrate_with_lost_path_challenge(self):
        """
        Check the server sends a new PATH_CHALLENGE when one is lost.

        The server's PTO declares the packet carrying the PATH_CHALLENGE lost,
        and its probe carries a new PATH_CHALLENGE with new data (RFC 9000
        section 8.2.1), padded up to the anti-amplification limit.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)

            # Client changes address and sends some data.
            client.send_stream_data(0, b"01234567")
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [39])

            # Server receives the data, sends a PATH_CHALLENGE which is lost.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], NEW_CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [3 * 39])
            self.assertAlmostEqual(server.get_timer(), 0.6375)
            self.assertAlmostEqual(server._path_validation_deadline(), 1.1125)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [events.StreamDataReceived])

            # Client sends more data.
            client.send_stream_data(0, b"89abcdef")
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [40])

            # Server receives the data, sends ACK.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], NEW_CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(server.get_timer(), 0.6375)
            self.assertSentPackets(server, [0, 0, 2])
            self.assertEvents(server, [events.StreamDataReceived])

            # Client receives ACK.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [])
            self.assertSentPackets(client, [0, 0, 0])

            # Server's PTO fires, it sends a new PATH_CHALLENGE padded up to the
            # anti-amplification limit.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [3 * (39 + 40) - 3 * 39 - 32])
            self.assertAlmostEqual(server.get_timer(), 1.1125)
            self.assertSentPackets(server, [0, 0, 2])
            self.assertEvents(server, [])
            challenges = self.path_challenges(server)
            self.assertEqual(len(challenges), 2)
            self.assertNotEqual(challenges[0], challenges[1])

            # Client receives PATH_CHALLENGE, sends PATH_RESPONSE.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.925)
            self.assertSentPackets(client, [0, 0, 1])

            # Server receives PATH_RESPONSE, the path is validated.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], NEW_CLIENT_ADDR, now=now)
            self.assertTrue(server._network_paths[0].is_validated)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(server.get_timer(), 60.7375)  # idle timeout
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [])

    def test_migrate_with_small_datagram_and_ack_due(self):
        """
        Check the server only reserves room for the first ACK range, so it can
        send an ACK in a datagram with little room left.

        The server's ACK timer fires as it receives a small datagram from an
        address it cannot validate. Its anti-amplification limit leaves room for
        an ACK and a PATH_CHALLENGE (RFC 9000 section 8).
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)
            self.watch_timers(server)

            # Client sends some data.
            client.send_stream_data(0, b"01234567")
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [39])

            # Server receives the data, arms its ACK timer.
            server.receive_datagram(items[0][0], CLIENT_ADDR, now=now)
            self.assertAlmostEqual(server.get_timer(), 0.35)
            self.assertEvents(server, [events.StreamDataReceived])

            # Client sends a PING.
            client.send_ping(1)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [29])

            # Server receives the PING from a new address as its ACK timer fires,
            # sends an ACK and a PATH_CHALLENGE.
            now = self.advance_to_timer(now, server)
            server.receive_datagram(items[0][0], SPOOFED_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [3 * 29])
            self.assertEqual(items[0][1], SPOOFED_ADDR)
            self.assertAlmostEqual(server.get_timer(), 0.5875)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [])
            self.assertEqual(self.acked_ranges(server)[-1], [[4, 6]])
            self.assertEqual(len(self.path_challenges(server)), 1)

    def test_migrate_without_loss(self):
        """
        Check the server validates the client's new address in the absence of
        loss.

        This is the reference sequence for the tests with lost packets.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)

            # Client changes address and sends some data.
            client.send_stream_data(0, b"01234567")
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [39])

            # Server receives the data, sends a PATH_CHALLENGE padded up to the
            # anti-amplification limit.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], NEW_CLIENT_ADDR, now=now)
            self.assertEqual(server.get_peer_address(), NEW_CLIENT_ADDR)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [3 * 39])
            self.assertEqual(items[0][1], NEW_CLIENT_ADDR)
            self.assertAlmostEqual(server.get_timer(), 0.6375)
            self.assertAlmostEqual(server._path_validation_deadline(), 1.1125)
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [events.StreamDataReceived])

            # Client receives PATH_CHALLENGE, sends PATH_RESPONSE.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [1200])
            self.assertAlmostEqual(client.get_timer(), 0.6875)
            self.assertSentPackets(client, [0, 0, 1])

            # Server receives PATH_RESPONSE, the path is validated.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], NEW_CLIENT_ADDR, now=now)
            self.assertTrue(server._network_paths[0].is_validated)
            self.assertIsNone(server._path_validation_deadline())
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [32])
            self.assertAlmostEqual(server.get_timer(), 60.5)  # idle timeout
            self.assertSentPackets(server, [0, 0, 1])
            self.assertEvents(server, [])

            # Client receives ACK, nothing remains in flight.
            now = self.advance_by_tick(now)
            client.receive_datagram(items[0][0], SERVER_ADDR, now=now)
            items = client.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [])
            self.assertAlmostEqual(client.get_timer(), 60.55)  # idle timeout
            self.assertSentPackets(client, [0, 0, 0])

    def test_migrate_without_validated_path(self):
        """
        Check the server closes the connection silently when path validation
        fails and it has no validated address to revert to (RFC 9000 section
        9.3.2).
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)
            self.watch_timers(server)

            # Client changes address and sends some data.
            client.send_stream_data(0, b"01234567")
            items = client.datagrams_to_send(now=now)

            # Server receives the data, sends a PATH_CHALLENGE which is lost.
            now = self.advance_by_tick(now)
            server.receive_datagram(items[0][0], NEW_CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [3 * 39])
            self.assertAlmostEqual(server._path_validation_deadline(), 1.1125)
            self.assertEvents(server, [events.StreamDataReceived])

            # Server has no state about its previous address.
            server._network_paths.pop(1)

            # Server's PTO fires, it cannot send anything to the new address.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [])
            self.assertAlmostEqual(server.get_timer(), 1.1125)

            # Server abandons path validation and closes the connection without
            # sending anything.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(datagram_sizes(items), [])
            self.assertIsNone(server.get_timer())
            event = server.next_event()
            self.assertEqual(type(event), events.ConnectionTerminated)
            self.assertEqual(event.error_code, QuicErrorCode.NO_VIABLE_PATH)
            self.assertEqual(event.reason_phrase, "No validated network path")

    def test_probe_from_spoofed_address(self):
        """
        Check the server sends no more than three times the data received from
        a new address when answering a probe, and only probes it once.

        An attacker rewrites the source address of a small probing packet. The
        server's PATH_RESPONSE and PATH_CHALLENGE are padded only up to the
        anti-amplification limit, and a lost PATH_CHALLENGE is not sent again on
        a path which is not the active one.
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)
            self.watch_timers(server)

            # Client sends a small probe, whose source address is rewritten.
            probe_cid = client._peer_cid_available.pop(0)
            challenge = os.urandom(8)
            client._network_paths[0].local_challenges.append(challenge)
            data = self.probing_datagram(
                client,
                probe_cid,
                QuicFrameType.PATH_CHALLENGE,
                challenge,
                max_total_bytes=60,
            )
            self.assertEqual(len(data), 60)

            # Server receives the probe, sends ACK on the active path and
            # PATH_RESPONSE + PATH_CHALLENGE within the anti-amplification limit.
            now = self.advance_by_tick(now)
            server.receive_datagram(data, SPOOFED_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(
                [(len(data), addr) for data, addr in items],
                [(32, CLIENT_ADDR), (3 * 60, SPOOFED_ADDR)],
            )
            self.assertAlmostEqual(server.get_timer(), 0.6375)
            self.assertSentPackets(server, [0, 0, 2])
            self.assertEqual(server.get_peer_address(), CLIENT_ADDR)
            self.assertEqual(server._peer_cid.sequence_number, 0)

            # Server's PTO fires, it probes the active path only.
            now = self.advance_to_timer(now, server)
            server.handle_timer(now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(
                [(len(data), addr) for data, addr in items], [(29, CLIENT_ADDR)]
            )
            self.assertEqual(len(self.path_challenges(server)), 1)

    def test_probe_without_spare_connection_id(self):
        """
        Check the server sends nothing on a probed path when the client has not
        provided a spare connection ID for it (RFC 9000 section 9.5).
        """
        with client_and_server(handshake=False) as (client, server):
            self.watch_timers(client, server)
            now = self.handshake(client, server, now=0.0)

            # Server has no spare connection ID.
            server._peer_cid_available.clear()

            # Client probes a new path with a new connection ID.
            probe_cid = client._peer_cid_available.pop(0)
            challenge = os.urandom(8)
            client._network_paths[0].local_challenges.append(challenge)
            data = self.probing_datagram(
                client, probe_cid, QuicFrameType.PATH_CHALLENGE, challenge
            )

            # Server receives the probe, sends ACK on the active path only.
            now = self.advance_by_tick(now)
            server.receive_datagram(data, NEW_CLIENT_ADDR, now=now)
            items = server.datagrams_to_send(now=now)
            self.assertEqual(
                [(len(data), addr) for data, addr in items], [(32, CLIENT_ADDR)]
            )
            self.assertAlmostEqual(server.get_timer(), 60.4)  # idle timeout
            self.assertSentPackets(server, [0, 0, 1])
            self.assertIsNone(server._network_paths[1].peer_cid)
            self.assertEqual(len(server._network_paths[1].remote_challenges), 1)
            self.assertEqual(self.path_challenges(server), [])

    def watch_timers(self, *connections: QuicConnection) -> None:
        """
        Register the connections whose timers the advance_* helpers check.
        """
        self._watched_connections = connections


class QuicConnectionTest(QuicConnectionTestCase):
    def check_handshake(self, client, server, alpn_protocol=None):
        """
        Check handshake completed.
        """
        event = client.next_event()
        self.assertEqual(type(event), events.ProtocolNegotiated)
        self.assertEqual(event.alpn_protocol, alpn_protocol)
        event = client.next_event()
        self.assertEqual(type(event), events.HandshakeCompleted)
        self.assertEqual(event.alpn_protocol, alpn_protocol)
        self.assertEqual(event.early_data_accepted, False)
        self.assertEqual(event.session_resumed, False)
        for i in range(7):
            self.assertEqual(type(client.next_event()), events.ConnectionIdIssued)
        self.assertIsNone(client.next_event())

        event = server.next_event()
        self.assertEqual(type(event), events.ProtocolNegotiated)
        self.assertEqual(event.alpn_protocol, alpn_protocol)
        event = server.next_event()
        self.assertEqual(type(event), events.HandshakeCompleted)
        self.assertEqual(event.alpn_protocol, alpn_protocol)
        for i in range(7):
            self.assertEqual(type(server.next_event()), events.ConnectionIdIssued)
        self.assertIsNone(server.next_event())

    def test_connect(self):
        with client_and_server() as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # check each endpoint has available connection IDs for the peer
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [1, 2, 3, 4, 5, 6, 7]
            )
            self.assertEqual(
                sequence_numbers(server._peer_cid_available), [1, 2, 3, 4, 5, 6, 7]
            )

            # client closes the connection
            client.close()
            self.assertEqual(transfer(client, server), 1)

            # check connection closes on the client side
            client.handle_timer(client.get_timer())
            event = client.next_event()
            self.assertEqual(type(event), events.ConnectionTerminated)
            self.assertEqual(event.error_code, QuicErrorCode.NO_ERROR)
            self.assertEqual(event.frame_type, None)
            self.assertEqual(event.reason_phrase, "")
            self.assertIsNone(client.next_event())

            # check connection closes on the server side
            server.handle_timer(server.get_timer())
            event = server.next_event()
            self.assertEqual(type(event), events.ConnectionTerminated)
            self.assertEqual(event.error_code, QuicErrorCode.NO_ERROR)
            self.assertEqual(event.frame_type, None)
            self.assertEqual(event.reason_phrase, "")
            self.assertIsNone(server.next_event())

            # check client log
            client_log = client.configuration.quic_logger.to_dict()
            self.assertGreater(len(client_log["traces"][0]["events"]), 20)

            # check server log
            server_log = server.configuration.quic_logger.to_dict()
            self.assertGreater(len(server_log["traces"][0]["events"]), 20)

    def test_connect_as_server(self):
        server = create_standalone_server(self)

        with self.assertRaises(RuntimeError) as cm:
            server.connect(CLIENT_ADDR, now=time.time())
        self.assertEqual(
            str(cm.exception),
            "connect() can only be called for clients and a single time",
        )

    def test_connect_twice(self):
        client = create_standalone_client(self)

        with self.assertRaises(RuntimeError) as cm:
            client.connect(SERVER_ADDR, now=time.time())
        self.assertEqual(
            str(cm.exception),
            "connect() can only be called for clients and a single time",
        )

    def test_connect_with_alpn(self):
        with client_and_server(
            client_options={"alpn_protocols": ["h3", "hq-interop"]},
            server_options={"alpn_protocols": ["hq-interop"]},
        ) as (client, server):
            # check handshake completed
            self.check_handshake(
                client=client, server=server, alpn_protocol="hq-interop"
            )

    def test_connect_with_alpn_fail(self):
        with client_and_server(
            client_options={"alpn_protocols": ["hq-interop"]},
            server_options={"alpn_protocols": ["h3"]},
        ) as (client, server):
            self.assertEqual(
                server._close_event,
                events.ConnectionTerminated(
                    error_code=QuicErrorCode.CRYPTO_ERROR
                    + tls.AlertDescription.no_application_protocol,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="No common ALPN protocols",
                ),
            )

    def test_connect_with_secrets_log(self):
        client_log_file = io.StringIO()
        server_log_file = io.StringIO()
        with client_and_server(
            client_options={"secrets_log_file": client_log_file},
            server_options={"secrets_log_file": server_log_file},
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # check secrets were logged
            client_log = client_log_file.getvalue()
            server_log = server_log_file.getvalue()
            self.assertEqual(client_log, server_log)
            labels = []
            for line in client_log.splitlines():
                labels.append(line.split()[0])
            self.assertEqual(
                labels,
                [
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                    "SERVER_TRAFFIC_SECRET_0",
                    "CLIENT_TRAFFIC_SECRET_0",
                ],
            )

    def test_connect_with_cert_chain(self):
        with client_and_server(server_certfile=SERVER_CERTFILE_WITH_CHAIN) as (
            client,
            server,
        ):
            # check handshake completed
            self.check_handshake(client=client, server=server)

    def test_connect_with_cipher_suite_aes128(self):
        with client_and_server(
            client_options={"cipher_suites": [tls.CipherSuite.AES_128_GCM_SHA256]}
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # check selected cipher suite
            self.assertEqual(
                client.tls.key_schedule.cipher_suite, tls.CipherSuite.AES_128_GCM_SHA256
            )
            self.assertEqual(
                server.tls.key_schedule.cipher_suite, tls.CipherSuite.AES_128_GCM_SHA256
            )

    def test_connect_with_cipher_suite_aes256(self):
        with client_and_server(
            client_options={"cipher_suites": [tls.CipherSuite.AES_256_GCM_SHA384]}
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # check selected cipher suite
            self.assertEqual(
                client.tls.key_schedule.cipher_suite, tls.CipherSuite.AES_256_GCM_SHA384
            )
            self.assertEqual(
                server.tls.key_schedule.cipher_suite, tls.CipherSuite.AES_256_GCM_SHA384
            )

    @skipIf("chacha20" in SKIP_TESTS, "Skipping chacha20 tests")
    def test_connect_with_cipher_suite_chacha20(self):
        with client_and_server(
            client_options={"cipher_suites": [tls.CipherSuite.CHACHA20_POLY1305_SHA256]}
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # check selected cipher suite
            self.assertEqual(
                client.tls.key_schedule.cipher_suite,
                tls.CipherSuite.CHACHA20_POLY1305_SHA256,
            )
            self.assertEqual(
                server.tls.key_schedule.cipher_suite,
                tls.CipherSuite.CHACHA20_POLY1305_SHA256,
            )

    def test_connect_with_custom_packet_size(self):
        """
        Check that the size of the initial QUIC packet corresponds to the
        packet size configuration.
        """

        client_configuration = QuicConfiguration(is_client=True, max_datagram_size=1480)
        client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)

        client = QuicConnection(configuration=client_configuration)

        now = 0.0
        client.connect(SERVER_ADDR, now=now)
        items = client.datagrams_to_send(now=now)
        self.assertEqual(datagram_sizes(items), [1480])

    def test_connect_with_large_packet_size(self):
        """
        Check that packets larger than 1500 bytes can be exchanged.
        """
        with client_and_server(
            client_options={"max_datagram_size": 3000},
            server_options={"max_datagram_size": 3000},
        ) as (client, server):
            self.check_handshake(client=client, server=server)

            stream_id = client.get_next_available_stream_id()
            client.send_stream_data(stream_id, bytes(2500), end_stream=True)
            items = client.datagrams_to_send(now=time.time())
            self.assertEqual(datagram_sizes(items), [2531])

            for data, addr in items:
                server.receive_datagram(data, CLIENT_ADDR, now=time.time())
            event = server.next_event()
            self.assertEqual(type(event), events.StreamDataReceived)
            self.assertEqual(event.data, bytes(2500))
            self.assertTrue(event.end_stream)

    def test_connect_with_legacy_session_id(self):
        def patch(client):
            """
            Patch client's TLS initialization to send a legacy_session_id.
            """
            real_initialize = client._initialize

            def patched_initialize(peer_cid: bytes):
                real_initialize(peer_cid)
                client.tls.legacy_session_id = bytes(32)

            client._initialize = patched_initialize

        with client_and_server(client_patch=patch) as (client, server):
            self.assertEqual(
                server._close_event,
                events.ConnectionTerminated(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="ClientHello has a non-empty legacy_session_id",
                ),
            )

    def test_init_with_invalid_arguments(self):
        def server_configuration(**kwargs):
            configuration = QuicConfiguration(is_client=False, **kwargs)
            configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
            return configuration

        for configuration, kwargs, message in [
            (
                QuicConfiguration(is_client=True, max_datagram_size=1000),
                {},
                "The smallest allowed maximum datagram size is 1200 bytes",
            ),
            (
                QuicConfiguration(is_client=True),
                {"original_destination_connection_id": bytes(8)},
                "Cannot set original_destination_connection_id for a client",
            ),
            (
                QuicConfiguration(is_client=True),
                {"retry_source_connection_id": bytes(8)},
                "Cannot set retry_source_connection_id for a client",
            ),
            (
                server_configuration(),
                {
                    "original_destination_connection_id": bytes(8),
                    "token_handler": lambda token: None,
                },
                "Cannot set `token_handler` for a server",
            ),
            (
                server_configuration(token=b"token"),
                {"original_destination_connection_id": bytes(8)},
                "Cannot set `configuration.token` for a server",
            ),
            (
                QuicConfiguration(is_client=False),
                {"original_destination_connection_id": bytes(8)},
                "SSL certificate is required for a server",
            ),
            (
                QuicConfiguration(
                    is_client=False, certificate=server_configuration().certificate
                ),
                {"original_destination_connection_id": bytes(8)},
                "SSL private key is required for a server",
            ),
            (
                server_configuration(),
                {},
                "original_destination_connection_id is required for a server",
            ),
        ]:
            with self.subTest(message=message):
                with self.assertRaises(ValueError) as cm:
                    QuicConnection(configuration=configuration, **kwargs)
                self.assertEqual(str(cm.exception), message)

    def test_initial_that_is_too_small(self):
        """
        Check that a too-small initial datagram from the client is dropped by the
        server.
        """
        client = create_standalone_client(self)
        server = create_standalone_server(
            self,
            original_destination_connection_id=client.original_destination_connection_id,
        )

        builder = QuicPacketBuilder(
            host_cid=client._peer_cid.cid,
            is_client=False,
            max_datagram_size=1000,  # too small!
            peer_cid=client.host_cid,
            version=client._version,
        )
        crypto = CryptoPair()
        crypto.setup_initial(
            client._peer_cid.cid, is_client=False, version=client._version
        )
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        buf = builder.start_frame(QuicFrameType.PADDING)
        buf.push_bytes(bytes(builder.remaining_flight_space))

        for datagram in builder.flush()[0]:
            server.receive_datagram(datagram, SERVER_ADDR, now=time.time())

        # Look for the drop event.
        self.assertPacketDropped(server, "initial_packet_datagram_too_small")

    def test_connect_with_no_crypto_frame(self):
        def patch(client):
            """
            Patch client to send PING instead of CRYPTO.
            """
            client._push_crypto_data = client._send_probe

        with client_and_server(client_patch=patch) as (client, server):
            self.assertEqual(
                server._close_event.reason_phrase,
                "Packet contains no CRYPTO frame",
            )

    def test_connect_with_no_transport_parameters(self):
        def patch(client):
            """
            Patch client's TLS initialization to clear TLS extensions.
            """
            real_initialize = client._initialize

            def patched_initialize(peer_cid: bytes):
                real_initialize(peer_cid)
                client.tls.handshake_extensions = []

            client._initialize = patched_initialize

        with client_and_server(client_patch=patch) as (client, server):
            self.assertEqual(
                server._close_event.reason_phrase,
                "No QUIC transport parameters received",
            )

    def test_connect_with_compatible_version_negotiation_1(self):
        """
        The client only supports version 1.

        The server sets the Negotiated Version to version 1.
        """
        with client_and_server(
            client_options={
                "supported_versions": [QuicProtocolVersion.VERSION_1],
            },
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)
            self.assertEqual(client._version, QuicProtocolVersion.VERSION_1)
            self.assertEqual(server._version, QuicProtocolVersion.VERSION_1)

    def test_connect_with_compatible_version_negotiation_1_to_2(self):
        """
        The client originally connects using version 1 but prefers version 2.

        The server sets the Negotiated Version to version 2.
        """
        with client_and_server(
            client_options={
                "original_version": QuicProtocolVersion.VERSION_1,
                "supported_versions": [
                    QuicProtocolVersion.VERSION_2,
                    QuicProtocolVersion.VERSION_1,
                ],
            },
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)
            self.assertEqual(client._version, QuicProtocolVersion.VERSION_2)
            self.assertEqual(server._version, QuicProtocolVersion.VERSION_2)

    def test_connect_with_compatible_version_negotiation_2(self):
        """
        The client only supports version 2.

        The server sets the Negotiated Version to version 2.
        """
        with client_and_server(
            client_options={
                "supported_versions": [QuicProtocolVersion.VERSION_2],
            },
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)
            self.assertEqual(client._version, QuicProtocolVersion.VERSION_2)
            self.assertEqual(server._version, QuicProtocolVersion.VERSION_2)

    def test_connect_with_compatible_version_negotiation_2_to_1(self):
        """
        The client originally connects using version 2 but prefers version 1.

        The server sets the Negotiated Version to version 1.
        """
        with client_and_server(
            client_options={
                "original_version": QuicProtocolVersion.VERSION_2,
                "supported_versions": [
                    QuicProtocolVersion.VERSION_1,
                    QuicProtocolVersion.VERSION_2,
                ],
            },
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)
            self.assertEqual(client._version, QuicProtocolVersion.VERSION_1)
            self.assertEqual(server._version, QuicProtocolVersion.VERSION_1)

    def test_connect_with_quantum_readiness(self):
        with client_and_server(client_options={"quantum_readiness_test": True}) as (
            client,
            server,
        ):
            stream_id = client.get_next_available_stream_id()
            client.send_stream_data(stream_id, b"hello")

            self.assertEqual(roundtrip(client, server), (1, 1))

            received = None
            while True:
                event = server.next_event()
                if isinstance(event, events.StreamDataReceived):
                    received = event.data
                elif event is None:
                    break

            self.assertEqual(received, b"hello")

    def test_connect_with_0rtt(self):
        client_ticket = None
        ticket_store = SessionTicketStore()

        def save_session_ticket(ticket):
            nonlocal client_ticket
            client_ticket = ticket

        with client_and_server(
            client_kwargs={"session_ticket_handler": save_session_ticket},
            server_kwargs={"session_ticket_handler": ticket_store.add},
        ) as (client, server):
            pass

        with client_and_server(
            client_options={"session_ticket": client_ticket},
            server_kwargs={"session_ticket_fetcher": ticket_store.pop},
            handshake=False,
        ) as (client, server):
            client.connect(SERVER_ADDR, now=time.time())
            stream_id = client.get_next_available_stream_id()
            client.send_stream_data(stream_id, b"hello")

            self.assertEqual(roundtrip(client, server), (1, 1))

            event = server.next_event()
            self.assertEqual(type(event), events.ProtocolNegotiated)

            event = server.next_event()
            self.assertEqual(type(event), events.StreamDataReceived)
            self.assertEqual(event.data, b"hello")

    def test_connect_with_0rtt_bad_max_early_data(self):
        client_ticket = None
        ticket_store = SessionTicketStore()

        def patch(server):
            """
            Patch server's TLS initialization to set an invalid
            max_early_data value.
            """
            real_initialize = server._initialize

            def patched_initialize(peer_cid: bytes):
                real_initialize(peer_cid)
                server.tls._max_early_data = 12345

            server._initialize = patched_initialize

        def save_session_ticket(ticket):
            nonlocal client_ticket
            client_ticket = ticket

        with client_and_server(
            client_kwargs={"session_ticket_handler": save_session_ticket},
            server_kwargs={"session_ticket_handler": ticket_store.add},
            server_patch=patch,
        ) as (client, server):
            # The client rejects the session ticket.
            self.assertEqual(
                client._close_event,
                events.ConnectionTerminated(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="Invalid max_early_data value 12345",
                ),
            )

    def test_change_connection_id(self):
        with client_and_server() as (client, server):
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [1, 2, 3, 4, 5, 6, 7]
            )

            # the client changes connection ID
            client.change_connection_id()
            self.assertEqual(transfer(client, server), 1)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [2, 3, 4, 5, 6, 7]
            )

            # the server provides a new connection ID
            self.assertEqual(transfer(server, client), 1)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [2, 3, 4, 5, 6, 7, 8]
            )

    def test_change_connection_id_resets_spin_bit(self):
        with client_and_server() as (client, server):
            client._spin_bit = True
            client.send_ping(1)
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertTrue(get_spin_bit(datagrams[0][0][0]))

            # The spin value is reset when the client changes connection ID.
            client.change_connection_id()
            client.send_ping(2)
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertFalse(get_spin_bit(datagrams[0][0][0]))

    def test_change_connection_id_retransmit_new_connection_id(self):
        with client_and_server() as (client, server):
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [1, 2, 3, 4, 5, 6, 7]
            )

            # the client changes connection ID
            client.change_connection_id()
            self.assertEqual(transfer(client, server), 1)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [2, 3, 4, 5, 6, 7]
            )

            # the server provides a new connection ID, NEW_CONNECTION_ID is lost
            self.assertEqual(drop(server), 1)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [2, 3, 4, 5, 6, 7]
            )

            # NEW_CONNECTION_ID is retransmitted
            server._on_new_connection_id_delivery(
                QuicDeliveryState.LOST, server._host_cids[-1]
            )
            self.assertEqual(transfer(server, client), 1)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [2, 3, 4, 5, 6, 7, 8]
            )

    def test_change_connection_id_retransmit_retire_connection_id(self):
        with client_and_server() as (client, server):
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [1, 2, 3, 4, 5, 6, 7]
            )

            # the client changes connection ID, RETIRE_CONNECTION_ID is lost
            client.change_connection_id()
            self.assertEqual(drop(client), 1)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [2, 3, 4, 5, 6, 7]
            )

            # RETIRE_CONNECTION_ID is retransmitted
            client._on_retire_connection_id_delivery(QuicDeliveryState.LOST, 0)
            self.assertEqual(transfer(client, server), 1)

            # the server provides a new connection ID
            self.assertEqual(transfer(server, client), 1)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [2, 3, 4, 5, 6, 7, 8]
            )

    def test_get_next_available_stream_id(self):
        with client_and_server() as (client, server):
            # client
            stream_id = client.get_next_available_stream_id()
            self.assertEqual(stream_id, 0)
            client.send_stream_data(stream_id, b"hello")

            stream_id = client.get_next_available_stream_id()
            self.assertEqual(stream_id, 4)
            client.send_stream_data(stream_id, b"hello")

            stream_id = client.get_next_available_stream_id(is_unidirectional=True)
            self.assertEqual(stream_id, 2)
            client.send_stream_data(stream_id, b"hello")

            stream_id = client.get_next_available_stream_id(is_unidirectional=True)
            self.assertEqual(stream_id, 6)
            client.send_stream_data(stream_id, b"hello")

            # server
            stream_id = server.get_next_available_stream_id()
            self.assertEqual(stream_id, 1)
            server.send_stream_data(stream_id, b"hello")

            stream_id = server.get_next_available_stream_id()
            self.assertEqual(stream_id, 5)
            server.send_stream_data(stream_id, b"hello")

            stream_id = server.get_next_available_stream_id(is_unidirectional=True)
            self.assertEqual(stream_id, 3)
            server.send_stream_data(stream_id, b"hello")

            stream_id = server.get_next_available_stream_id(is_unidirectional=True)
            self.assertEqual(stream_id, 7)
            server.send_stream_data(stream_id, b"hello")

    def test_get_peer_address(self):
        # The address is unknown before the first datagram.
        client = QuicConnection(configuration=QuicConfiguration(is_client=True))
        self.assertIsNone(client.get_peer_address())
        server = create_standalone_server(self)
        self.assertIsNone(server.get_peer_address())

        with client_and_server() as (client, server):
            self.assertEqual(client.get_peer_address(), SERVER_ADDR)
            self.assertEqual(server.get_peer_address(), CLIENT_ADDR)

            # The address is kept after the connection is terminated.
            client.close()
            self.assertEqual(transfer(client, server), 1)
            client.handle_timer(client.get_timer())
            server.handle_timer(server.get_timer())
            self.assertEqual(client._state, QuicConnectionState.TERMINATED)
            self.assertEqual(server._state, QuicConnectionState.TERMINATED)
            self.assertEqual(client.get_peer_address(), SERVER_ADDR)
            self.assertEqual(server.get_peer_address(), CLIENT_ADDR)

    def test_datagram_frame(self):
        with client_and_server(
            client_options={"max_datagram_frame_size": 65536},
            server_options={"max_datagram_frame_size": 65536},
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server, alpn_protocol=None)

            # send datagram
            client.send_datagram_frame(b"hello")
            self.assertEqual(transfer(client, server), 1)

            event = server.next_event()
            self.assertEqual(type(event), events.DatagramFrameReceived)
            self.assertEqual(event.data, b"hello")

    def test_datagram_frame_2(self):
        # payload which exactly fills an entire packet
        payload = b"Z" * 1170

        with client_and_server(
            client_options={"max_datagram_frame_size": 65536},
            server_options={"max_datagram_frame_size": 65536},
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server, alpn_protocol=None)

            # queue 20 datagrams
            for i in range(20):
                client.send_datagram_frame(payload)

            # client can only 11 datagrams are sent due to congestion control
            self.assertEqual(transfer(client, server), 11)
            for i in range(11):
                event = server.next_event()
                self.assertEqual(type(event), events.DatagramFrameReceived)
                self.assertEqual(event.data, payload)

            # server sends ACK
            self.assertEqual(transfer(server, client), 1)

            # client sends remaining datagrams
            self.assertEqual(transfer(client, server), 9)
            for i in range(9):
                event = server.next_event()
                self.assertEqual(type(event), events.DatagramFrameReceived)
                self.assertEqual(event.data, payload)

    def test_decryption_error(self):
        with client_and_server() as (client, server):
            # mess with encryption key
            server._cryptos[tls.Epoch.ONE_RTT].send.setup(
                cipher_suite=tls.CipherSuite.AES_128_GCM_SHA256,
                secret=bytes(48),
                version=server._version,
            )

            # server sends close
            server.close(error_code=QuicErrorCode.NO_ERROR)
            for data, addr in server.datagrams_to_send(now=time.time()):
                client.receive_datagram(data, SERVER_ADDR, now=time.time())

    def test_tls_error(self):
        def patch(client):
            """
            Patch the client's TLS initialization to send invalid TLS version.
            """
            real_initialize = client._initialize

            def patched_initialize(peer_cid: bytes):
                real_initialize(peer_cid)
                client.tls._supported_versions = [tls.TLS_VERSION_1_3_DRAFT_28]

            client._initialize = patched_initialize

        # handshake fails
        with client_and_server(client_patch=patch) as (client, server):
            timer_at = server.get_timer()
            server.handle_timer(timer_at)

            event = server.next_event()
            self.assertEqual(type(event), events.ConnectionTerminated)
            self.assertEqual(event.error_code, 326)
            self.assertEqual(event.frame_type, QuicFrameType.CRYPTO)
            self.assertEqual(event.reason_phrase, "No supported protocol version")

    def test_receive_datagram_different_source_cid(self):
        client = create_standalone_client(self)
        crypto = CryptoPair()
        crypto.setup_initial(
            client._peer_cid.cid, is_client=False, version=client._version
        )

        def send_initial(source_cid: bytes, packet_number: int) -> None:
            builder = QuicPacketBuilder(
                host_cid=source_cid,
                is_client=False,
                max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
                packet_number=packet_number,
                peer_cid=client.host_cid,
                version=client._version,
            )
            builder.start_packet(QuicPacketType.INITIAL, crypto)
            buf = builder.start_frame(QuicFrameType.PADDING)
            buf.push_bytes(bytes(builder.remaining_flight_space))
            for datagram in builder.flush()[0]:
                client.receive_datagram(datagram, SERVER_ADDR, now=time.time())

        # The first valid INITIAL packet sets the server's Source Connection ID.
        send_initial(source_cid=bytes(8), packet_number=0)
        self.assertEqual(client._remote_initial_source_connection_id, bytes(8))

        # A packet with a different Source Connection ID is discarded.
        send_initial(source_cid=bytes([1] * 8), packet_number=1)
        self.assertPacketDropped(client, "unexpected_source_connection_id")
        self.assertNotIn(1, client._spaces[tls.Epoch.INITIAL].received_packets)

    def test_receive_datagram_duplicate(self):
        with client_and_server() as (client, server):
            while server.next_event() is not None:
                pass

            # client sends some data
            client.send_stream_data(0, b"01234567")
            datagrams = [
                data for data, addr in client.datagrams_to_send(now=time.time())
            ]
            for data in datagrams:
                server.receive_datagram(data, CLIENT_ADDR, now=time.time())
            self.assertEqual(type(server.next_event()), events.StreamDataReceived)
            self.assertIsNone(server.next_event())

            # the same datagrams are replayed
            for data in datagrams:
                server.receive_datagram(data, CLIENT_ADDR, now=time.time())

            # the duplicates are discarded
            self.assertIsNone(server.next_event())
            log = server.configuration.quic_logger.to_dict()
            triggers = [
                event["data"]["trigger"]
                for event in log["traces"][0]["events"]
                if event["name"] == "transport:packet_dropped"
            ]
            self.assertEqual(triggers.count("duplicate"), len(datagrams))

    def test_receive_datagram_first_not_initial(self):
        server = create_standalone_server(self)

        # Server receives a 1-RTT packet before any INITIAL packet.
        datagram = bytes([0x40]) + bytes(8) + bytes(40)
        server.receive_datagram(datagram, CLIENT_ADDR, now=time.time())

        # The packet is dropped.
        log = server.configuration.quic_logger.to_dict()
        triggers = [
            event["data"]["trigger"]
            for event in log["traces"][0]["events"]
            if event["name"] == "transport:packet_dropped"
        ]
        self.assertEqual(triggers, ["key_unavailable"])

    def test_receive_datagram_garbage(self):
        client = create_standalone_client(self)

        datagram = binascii.unhexlify("c00000000080")
        client.receive_datagram(datagram, SERVER_ADDR, now=time.time())

    def test_receive_datagram_reserved_bits_non_zero(self):
        client = create_standalone_client(self)

        builder = QuicPacketBuilder(
            host_cid=client._peer_cid.cid,
            is_client=False,
            max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
            peer_cid=client.host_cid,
            version=client._version,
        )
        crypto = CryptoPair()
        crypto.setup_initial(
            client._peer_cid.cid, is_client=False, version=client._version
        )
        crypto.encrypt_packet_real = crypto.encrypt_packet

        def encrypt_packet(plain_header, plain_payload, packet_number):
            # mess with reserved bits
            plain_header = bytes([plain_header[0] | 0x0C]) + plain_header[1:]
            return crypto.encrypt_packet_real(
                plain_header, plain_payload, packet_number
            )

        crypto.encrypt_packet = encrypt_packet

        builder.start_packet(QuicPacketType.INITIAL, crypto)
        buf = builder.start_frame(QuicFrameType.PADDING)
        buf.push_bytes(bytes(builder.remaining_flight_space))

        for datagram in builder.flush()[0]:
            client.receive_datagram(datagram, SERVER_ADDR, now=time.time())
        self.assertEqual(drop(client), 1)
        self.assertEqual(
            client._close_event,
            events.ConnectionTerminated(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=QuicFrameType.PADDING,
                reason_phrase="Reserved bits must be zero",
            ),
        )

    def test_receive_datagram_unknown_server_address(self):
        with client_and_server() as (client, server):
            while client.next_event() is not None:
                pass

            # The server sends some data.
            server.send_stream_data(3, b"01234567")
            datagrams = [
                data for data, addr in server.datagrams_to_send(now=time.time())
            ]

            # The datagrams are received from an unknown server address.
            for data in datagrams:
                client.receive_datagram(data, ("6.7.8.9", 4433), now=time.time())

            # The datagrams are discarded.
            self.assertIsNone(client.next_event())
            self.assertEqual(
                [path.addr for path in client._network_paths], [SERVER_ADDR]
            )
            log = client.configuration.quic_logger.to_dict()
            triggers = [
                event["data"]["trigger"]
                for event in log["traces"][0]["events"]
                if event["name"] == "transport:packet_dropped"
            ]
            self.assertEqual(triggers.count("unknown_server_address"), len(datagrams))

            # The same datagrams are received from the known server address.
            for data in datagrams:
                client.receive_datagram(data, SERVER_ADDR, now=time.time())
            self.assertEqual(type(client.next_event()), events.StreamDataReceived)

    def test_receive_datagram_wrong_version(self):
        client = create_standalone_client(self)

        builder = QuicPacketBuilder(
            host_cid=client._peer_cid.cid,
            is_client=False,
            max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
            peer_cid=client.host_cid,
            version=0x1A2A3A4A,
        )
        crypto = CryptoPair()
        crypto.setup_initial(
            client._peer_cid.cid, is_client=False, version=client._version
        )
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        buf = builder.start_frame(QuicFrameType.PADDING)
        buf.push_bytes(bytes(builder.remaining_flight_space))

        for datagram in builder.flush()[0]:
            client.receive_datagram(datagram, SERVER_ADDR, now=time.time())
        self.assertEqual(drop(client), 0)

        self.assertPacketDropped(client, "unsupported_version")

    def test_receive_datagram_retry(self):
        client = create_standalone_client(self)

        client.receive_datagram(
            encode_quic_retry(
                version=client._version,
                source_cid=binascii.unhexlify("85abb547bf28be97"),
                destination_cid=client.host_cid,
                original_destination_cid=client._peer_cid.cid,
                retry_token=bytes(16),
            ),
            SERVER_ADDR,
            now=time.time(),
        )
        self.assertEqual(drop(client), 1)

    def test_receive_datagram_retry_same_source_cid(self):
        client = create_standalone_client(self)

        # The client discards a retry whose source CID is its original destination CID.
        client.receive_datagram(
            encode_quic_retry(
                version=client._version,
                source_cid=client._peer_cid.cid,
                destination_cid=client.host_cid,
                original_destination_cid=client._peer_cid.cid,
                retry_token=bytes(16),
            ),
            SERVER_ADDR,
            now=time.time(),
        )
        self.assertEqual(drop(client), 0)

        self.assertPacketDropped(client, "unexpected_packet")

    def test_receive_datagram_retry_wrong_destination_cid(self):
        client = create_standalone_client(self)

        # The client does not reply to a retry packet with a wrong destination CID.
        client.receive_datagram(
            encode_quic_retry(
                version=client._version,
                source_cid=binascii.unhexlify("85abb547bf28be97"),
                destination_cid=binascii.unhexlify("c98343fe8f5f0ff4"),
                original_destination_cid=client._peer_cid.cid,
                retry_token=bytes(16),
            ),
            SERVER_ADDR,
            now=time.time(),
        )
        self.assertEqual(drop(client), 0)

        self.assertPacketDropped(client, "unknown_connection_id")

    def test_receive_datagram_retry_wrong_integrity_tag(self):
        client = create_standalone_client(self)

        client.receive_datagram(
            encode_quic_retry(
                version=client._version,
                source_cid=binascii.unhexlify("85abb547bf28be97"),
                destination_cid=client.host_cid,
                original_destination_cid=client._peer_cid.cid,
                retry_token=bytes(16),
            )[0:-16]
            + bytes(16),
            SERVER_ADDR,
            now=time.time(),
        )
        self.assertEqual(drop(client), 0)

    def test_request_key_update_before_handshake(self):
        with client_and_server(handshake=False) as (client, server):
            # The key update is deferred until the handshake is confirmed.
            client.request_key_update()

            client.connect(SERVER_ADDR, now=time.time())
            for i in range(3):
                roundtrip(client, server)
            self.assertTrue(client._handshake_confirmed)

            # The server follows the key update.
            client.send_ping(1)
            self.assertEqual(roundtrip(client, server), (1, 1))
            self.assertEqual(client._cryptos[tls.Epoch.ONE_RTT].send.key_phase, 1)
            self.assertEqual(server._cryptos[tls.Epoch.ONE_RTT].send.key_phase, 1)

    def test_request_key_update_before_handshake_confirmed(self):
        with client_and_server(handshake=False) as (client, server):
            client.connect(SERVER_ADDR, now=time.time())

            # The client completes the handshake, but has not received
            # HANDSHAKE_DONE yet.
            roundtrip(client, server)
            self.assertTrue(client._handshake_complete)
            self.assertFalse(client._handshake_confirmed)

            # The key update is deferred until the handshake is confirmed.
            client.request_key_update()
            self.assertEqual(transfer(client, server), 1)
            self.assertEqual(client._cryptos[tls.Epoch.ONE_RTT].send.key_phase, 0)

            # The client receives HANDSHAKE_DONE.
            transfer(server, client)
            self.assertTrue(client._handshake_confirmed)

            # The server follows the key update.
            client.send_ping(1)
            self.assertEqual(roundtrip(client, server), (1, 1))
            self.assertEqual(client._cryptos[tls.Epoch.ONE_RTT].send.key_phase, 1)
            self.assertEqual(server._cryptos[tls.Epoch.ONE_RTT].send.key_phase, 1)

    def test_request_key_update_server_before_handshake(self):
        with client_and_server(handshake=False) as (client, server):
            # The key update is deferred until the handshake is confirmed.
            server.request_key_update()

            client.connect(SERVER_ADDR, now=time.time())
            for i in range(3):
                roundtrip(client, server)
            self.assertTrue(server._handshake_confirmed)

            # The client follows the key update.
            server.send_ping(1)
            self.assertEqual(roundtrip(server, client), (1, 1))
            self.assertEqual(client._cryptos[tls.Epoch.ONE_RTT].send.key_phase, 1)
            self.assertEqual(server._cryptos[tls.Epoch.ONE_RTT].send.key_phase, 1)

    def test_handle_ack_frame_ecn(self):
        client = create_standalone_client(self)

        client._handle_ack_frame(
            client_receive_context(client),
            QuicFrameType.ACK_ECN,
            Buffer(data=b"\x00\x02\x00\x00\x00\x00\x00"),
        )

    def test_handle_ack_frame_negative_packet_number(self):
        client = create_standalone_client(self)

        # Client receives an ACK frame whose first range goes below zero.
        with self.assertRaises(QuicConnectionError) as cm:
            client._handle_ack_frame(
                client_receive_context(client),
                QuicFrameType.ACK,
                Buffer(data=b"\x00\x02\x00\x01"),
            )
        self.assertEqual(cm.exception.error_code, QuicErrorCode.FRAME_ENCODING_ERROR)
        self.assertEqual(cm.exception.frame_type, QuicFrameType.ACK)
        self.assertEqual(
            cm.exception.reason_phrase, "ACK range contains a negative packet number"
        )

    def test_handle_connection_close_frame(self):
        with client_and_server() as (client, server):
            server.close(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=QuicFrameType.ACK,
                reason_phrase="illegal ACK frame",
            )
            self.assertEqual(roundtrip(server, client), (1, 0))

            self.assertEqual(
                client._close_event,
                events.ConnectionTerminated(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=QuicFrameType.ACK,
                    reason_phrase="illegal ACK frame",
                ),
            )

    def test_handle_connection_close_frame_app(self):
        with client_and_server() as (client, server):
            server.close(error_code=QuicErrorCode.NO_ERROR, reason_phrase="goodbye")
            self.assertEqual(roundtrip(server, client), (1, 0))

            self.assertEqual(
                client._close_event,
                events.ConnectionTerminated(
                    error_code=QuicErrorCode.NO_ERROR,
                    frame_type=None,
                    reason_phrase="goodbye",
                ),
            )

    def test_handle_connection_close_frame_app_not_utf8(self):
        client = create_standalone_client(self)

        client._handle_connection_close_frame(
            client_receive_context(client),
            QuicFrameType.APPLICATION_CLOSE,
            Buffer(data=binascii.unhexlify("0008676f6f6462798200")),
        )

        self.assertEqual(
            client._close_event,
            events.ConnectionTerminated(
                error_code=QuicErrorCode.NO_ERROR,
                frame_type=None,
                reason_phrase="",
            ),
        )

    def test_handle_crypto_frame_over_largest_offset(self):
        with client_and_server() as (client, server):
            # client receives offset + length > 2^62 - 1
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_crypto_frame(
                    client_receive_context(client),
                    QuicFrameType.CRYPTO,
                    Buffer(data=encode_uint_var(UINT_VAR_MAX) + encode_uint_var(1)),
                )
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.FRAME_ENCODING_ERROR
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
            self.assertEqual(
                cm.exception.reason_phrase, "offset + length cannot exceed 2^62 - 1"
            )

    def test_excessive_crypto_buffering(self):
        with client_and_server() as (client, server):
            # Client receives data that causes more than 512K of buffering; note that
            # because the stream buffer is a single buffer and not a set of fragments,
            # the total buffering size depends not on how much data is received, but
            # how much buffering is needed.  We send fragments of only 100 bytes
            # at offsets 10000, 20000, 30000 etc.
            highest_good_offset = 0
            with self.assertRaises(QuicConnectionError) as cm:
                # We don't start at zero as we want to force buffering, not cause
                # a TLS error.
                for offset in range(10000, 1000000, 10000):
                    client._handle_crypto_frame(
                        client_receive_context(client),
                        QuicFrameType.CRYPTO,
                        Buffer(
                            data=encode_uint_var(offset)
                            + encode_uint_var(100)
                            + b"\x00" * 100
                        ),
                    )
                    highest_good_offset = offset
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.CRYPTO_BUFFER_EXCEEDED
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
            self.assertEqual(highest_good_offset, (MAX_PENDING_CRYPTO // 10000) * 10000)

    def test_handle_data_blocked_frame(self):
        with client_and_server() as (client, server):
            # client receives DATA_BLOCKED: 12345
            client._handle_data_blocked_frame(
                client_receive_context(client),
                QuicFrameType.DATA_BLOCKED,
                Buffer(data=encode_uint_var(12345)),
            )

    def test_handle_datagram_frame(self):
        client = create_standalone_client(self, max_datagram_frame_size=6)

        client._handle_datagram_frame(
            client_receive_context(client),
            QuicFrameType.DATAGRAM,
            Buffer(data=b"hello"),
        )

        self.assertEqual(
            client.next_event(), events.DatagramFrameReceived(data=b"hello")
        )

    def test_handle_datagram_frame_not_allowed(self):
        client = create_standalone_client(self, max_datagram_frame_size=None)

        with self.assertRaises(QuicConnectionError) as cm:
            client._handle_datagram_frame(
                client_receive_context(client),
                QuicFrameType.DATAGRAM,
                Buffer(data=b"hello"),
            )
        self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
        self.assertEqual(cm.exception.frame_type, QuicFrameType.DATAGRAM)
        self.assertEqual(cm.exception.reason_phrase, "Unexpected DATAGRAM frame")

    def test_handle_datagram_frame_too_large(self):
        client = create_standalone_client(self, max_datagram_frame_size=5)

        with self.assertRaises(QuicConnectionError) as cm:
            client._handle_datagram_frame(
                client_receive_context(client),
                QuicFrameType.DATAGRAM,
                Buffer(data=b"hello"),
            )
        self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
        self.assertEqual(cm.exception.frame_type, QuicFrameType.DATAGRAM)
        self.assertEqual(cm.exception.reason_phrase, "Unexpected DATAGRAM frame")

    def test_handle_datagram_frame_with_length(self):
        client = create_standalone_client(self, max_datagram_frame_size=7)

        client._handle_datagram_frame(
            client_receive_context(client),
            QuicFrameType.DATAGRAM_WITH_LENGTH,
            Buffer(data=b"\x05hellojunk"),
        )

        self.assertEqual(
            client.next_event(), events.DatagramFrameReceived(data=b"hello")
        )

    def test_handle_datagram_frame_with_length_not_allowed(self):
        client = create_standalone_client(self, max_datagram_frame_size=None)

        with self.assertRaises(QuicConnectionError) as cm:
            client._handle_datagram_frame(
                client_receive_context(client),
                QuicFrameType.DATAGRAM_WITH_LENGTH,
                Buffer(data=b"\x05hellojunk"),
            )
        self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
        self.assertEqual(cm.exception.frame_type, QuicFrameType.DATAGRAM_WITH_LENGTH)
        self.assertEqual(cm.exception.reason_phrase, "Unexpected DATAGRAM frame")

    def test_handle_datagram_frame_with_length_too_large(self):
        client = create_standalone_client(self, max_datagram_frame_size=6)

        with self.assertRaises(QuicConnectionError) as cm:
            client._handle_datagram_frame(
                client_receive_context(client),
                QuicFrameType.DATAGRAM_WITH_LENGTH,
                Buffer(data=b"\x05hellojunk"),
            )
        self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
        self.assertEqual(cm.exception.frame_type, QuicFrameType.DATAGRAM_WITH_LENGTH)
        self.assertEqual(cm.exception.reason_phrase, "Unexpected DATAGRAM frame")

    def test_handle_handshake_done_not_allowed(self):
        with client_and_server() as (client, server):
            # server receives HANDSHAKE_DONE frame
            with self.assertRaises(QuicConnectionError) as cm:
                server._handle_handshake_done_frame(
                    client_receive_context(server),
                    QuicFrameType.HANDSHAKE_DONE,
                    Buffer(data=b""),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.HANDSHAKE_DONE)
            self.assertEqual(
                cm.exception.reason_phrase,
                "Clients must not send HANDSHAKE_DONE frames",
            )

    def test_handle_max_data_frame(self):
        with client_and_server() as (client, server):
            self.assertEqual(client._remote_max_data, 1048576)

            # client receives MAX_DATA raising limit
            client._handle_max_data_frame(
                client_receive_context(client),
                QuicFrameType.MAX_DATA,
                Buffer(data=encode_uint_var(1048577)),
            )
            self.assertEqual(client._remote_max_data, 1048577)

    def test_handle_max_stream_data_frame(self):
        with client_and_server() as (client, server):
            # client creates bidirectional stream 0
            stream = client._get_or_create_stream_for_send(stream_id=0)
            self.assertEqual(stream.max_stream_data_remote, 1048576)

            # client receives MAX_STREAM_DATA raising limit
            client._handle_max_stream_data_frame(
                client_receive_context(client),
                QuicFrameType.MAX_STREAM_DATA,
                Buffer(data=b"\x00" + encode_uint_var(1048577)),
            )
            self.assertEqual(stream.max_stream_data_remote, 1048577)

            # client receives MAX_STREAM_DATA lowering limit
            client._handle_max_stream_data_frame(
                client_receive_context(client),
                QuicFrameType.MAX_STREAM_DATA,
                Buffer(data=b"\x00" + encode_uint_var(1048575)),
            )
            self.assertEqual(stream.max_stream_data_remote, 1048577)

    def test_handle_max_stream_data_frame_receive_only(self):
        with client_and_server() as (client, server):
            # server creates unidirectional stream 3
            server.send_stream_data(stream_id=3, data=b"hello")

            # client receives MAX_STREAM_DATA: 3, 1
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_max_stream_data_frame(
                    client_receive_context(client),
                    QuicFrameType.MAX_STREAM_DATA,
                    Buffer(data=b"\x03\x01"),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.STREAM_STATE_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.MAX_STREAM_DATA)
            self.assertEqual(cm.exception.reason_phrase, "Stream is receive-only")

    def test_handle_max_streams_bidi_frame(self):
        with client_and_server() as (client, server):
            self.assertEqual(client._remote_max_streams_bidi, 128)

            # client receives MAX_STREAMS_BIDI raising limit
            client._handle_max_streams_bidi_frame(
                client_receive_context(client),
                QuicFrameType.MAX_STREAMS_BIDI,
                Buffer(data=encode_uint_var(129)),
            )
            self.assertEqual(client._remote_max_streams_bidi, 129)

            # client receives MAX_STREAMS_BIDI lowering limit
            client._handle_max_streams_bidi_frame(
                client_receive_context(client),
                QuicFrameType.MAX_STREAMS_BIDI,
                Buffer(data=encode_uint_var(127)),
            )
            self.assertEqual(client._remote_max_streams_bidi, 129)

            # client receives invalid MAX_STREAMS_BIDI
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_max_streams_bidi_frame(
                    client_receive_context(client),
                    QuicFrameType.MAX_STREAMS_BIDI,
                    Buffer(data=encode_uint_var(STREAM_COUNT_MAX + 1)),
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.FRAME_ENCODING_ERROR,
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.MAX_STREAMS_BIDI)
            self.assertEqual(
                cm.exception.reason_phrase, "Maximum Streams cannot exceed 2^60"
            )

    def test_handle_max_streams_uni_frame(self):
        with client_and_server() as (client, server):
            self.assertEqual(client._remote_max_streams_uni, 128)

            # client receives MAX_STREAMS_UNI raising limit
            client._handle_max_streams_uni_frame(
                client_receive_context(client),
                QuicFrameType.MAX_STREAMS_UNI,
                Buffer(data=encode_uint_var(129)),
            )
            self.assertEqual(client._remote_max_streams_uni, 129)

            # client receives MAX_STREAMS_UNI raising limit
            client._handle_max_streams_uni_frame(
                client_receive_context(client),
                QuicFrameType.MAX_STREAMS_UNI,
                Buffer(data=encode_uint_var(127)),
            )
            self.assertEqual(client._remote_max_streams_uni, 129)

            # client receives invalid MAX_STREAMS_UNI
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_max_streams_uni_frame(
                    client_receive_context(client),
                    QuicFrameType.MAX_STREAMS_UNI,
                    Buffer(data=encode_uint_var(STREAM_COUNT_MAX + 1)),
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.FRAME_ENCODING_ERROR,
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.MAX_STREAMS_UNI)
            self.assertEqual(
                cm.exception.reason_phrase, "Maximum Streams cannot exceed 2^60"
            )

    def test_handle_new_connection_id_duplicate(self):
        with client_and_server() as (client, server):
            buf = new_connection_id(sequence_number=7)

            # client receives NEW_CONNECTION_ID
            client._handle_new_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.NEW_CONNECTION_ID,
                buf,
            )

            self.assertEqual(client._peer_cid.sequence_number, 0)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [1, 2, 3, 4, 5, 6, 7]
            )

    def test_handle_new_connection_id_over_limit(self):
        with client_and_server() as (client, server):
            buf = new_connection_id(sequence_number=8)

            # client receives NEW_CONNECTION_ID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.CONNECTION_ID_LIMIT_ERROR
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.NEW_CONNECTION_ID)
            self.assertEqual(
                cm.exception.reason_phrase, "Too many active connection IDs"
            )

    def test_handle_new_connection_id_with_retire_prior_to(self):
        with client_and_server() as (client, server):
            buf = new_connection_id(sequence_number=8, retire_prior_to=2, capacity=42)
            client._spin_bit = True

            # client receives NEW_CONNECTION_ID
            client._handle_new_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.NEW_CONNECTION_ID,
                buf,
            )

            self.assertEqual(client._peer_cid.sequence_number, 2)
            self.assertFalse(client._spin_bit)
            self.assertEqual(
                sequence_numbers(client._peer_cid_available), [3, 4, 5, 6, 7, 8]
            )

    def test_handle_new_connection_id_with_retire_prior_to_lower(self):
        with client_and_server() as (client, server):
            buf = new_connection_id(sequence_number=80, retire_prior_to=80)

            # client receives NEW_CONNECTION_ID
            client._handle_new_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.NEW_CONNECTION_ID,
                buf,
            )

            self.assertEqual(client._peer_cid.sequence_number, 80)
            self.assertEqual(sequence_numbers(client._peer_cid_available), [])

            buf = new_connection_id(sequence_number=30, retire_prior_to=30)

            # client receives NEW_CONNECTION_ID
            client._handle_new_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.NEW_CONNECTION_ID,
                buf,
            )

            self.assertEqual(client._peer_cid.sequence_number, 80)
            self.assertEqual(sequence_numbers(client._peer_cid_available), [])

    def test_handle_new_connection_id_with_retire_prior_to_rotation(self):
        with client_and_server() as (client, server):
            for sequence_number in range(8, 108):
                buf = new_connection_id(
                    sequence_number=sequence_number, retire_prior_to=sequence_number
                )

                # client receives NEW_CONNECTION_ID
                client._handle_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_CONNECTION_ID,
                    buf,
                )

                # Simulate the RETIRE_CONNECTION_ID frames being acknowledged.
                client._retire_connection_ids.clear()

            # Sequence numbers of retired CIDs are forgotten.
            self.assertEqual(client._peer_cid.sequence_number, 107)
            self.assertEqual(client._peer_cid_sequence_numbers, {107})

    def test_handle_excessive_new_connection_id_retires(self):
        with client_and_server() as (client, server):
            for i in range(25):
                sequence_number = 8 + i
                buf = new_connection_id(
                    sequence_number=sequence_number, retire_prior_to=sequence_number
                )

                # client receives NEW_CONNECTION_ID
                client._handle_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_CONNECTION_ID,
                    buf,
                )

            # So far, so good!  We should be at the (default) limit of 4*8 pending
            # retirements.
            self.assertEqual(len(client._retire_connection_ids), 32)

            # Now we will go one too many!
            sequence_number = 8 + 25
            buf = new_connection_id(
                sequence_number=sequence_number, retire_prior_to=sequence_number
            )
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.CONNECTION_ID_LIMIT_ERROR
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.NEW_CONNECTION_ID)
            self.assertEqual(
                cm.exception.reason_phrase, "Too many pending retired connection IDs"
            )

    def test_handle_new_connection_id_with_connection_id_invalid(self):
        with client_and_server() as (client, server):
            buf = new_connection_id(
                sequence_number=8, retire_prior_to=2, connection_id=bytes(21)
            )

            # client receives NEW_CONNECTION_ID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.FRAME_ENCODING_ERROR,
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.NEW_CONNECTION_ID)
            self.assertEqual(
                cm.exception.reason_phrase,
                "Length must be greater than 0 and less than 20",
            )

    def test_handle_new_connection_id_with_retire_prior_to_invalid(self):
        with client_and_server() as (client, server):
            buf = new_connection_id(sequence_number=8, retire_prior_to=9)

            # client receives NEW_CONNECTION_ID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.PROTOCOL_VIOLATION,
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.NEW_CONNECTION_ID)
            self.assertEqual(
                cm.exception.reason_phrase,
                "Retire Prior To is greater than Sequence Number",
            )

    def test_handle_new_token_frame(self):
        new_token = None

        def token_handler(token):
            nonlocal new_token
            new_token = token

        with client_and_server(client_kwargs={"token_handler": token_handler}) as (
            client,
            server,
        ):
            # client receives NEW_TOKEN
            client._handle_new_token_frame(
                client_receive_context(client),
                QuicFrameType.NEW_TOKEN,
                Buffer(data=binascii.unhexlify("080102030405060708")),
            )

        self.assertEqual(new_token, binascii.unhexlify("0102030405060708"))

    def test_handle_new_token_frame_from_client(self):
        with client_and_server() as (client, server):
            # server receives NEW_TOKEN
            with self.assertRaises(QuicConnectionError) as cm:
                server._handle_new_token_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_TOKEN,
                    Buffer(data=binascii.unhexlify("080102030405060708")),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.NEW_TOKEN)
            self.assertEqual(
                cm.exception.reason_phrase, "Clients must not send NEW_TOKEN frames"
            )

    def test_handle_path_challenge_frame(self):
        with client_and_server() as (client, server):
            # client changes address and sends some data
            client.send_stream_data(0, b"01234567")
            for data, addr in client.datagrams_to_send(now=time.time()):
                server.receive_datagram(data, ("1.2.3.4", 2345), now=time.time())

            # check paths
            self.assertEqual(len(server._network_paths), 2)
            self.assertEqual(server._network_paths[0].addr, ("1.2.3.4", 2345))
            self.assertFalse(server._network_paths[0].is_validated)
            self.assertEqual(server._network_paths[1].addr, ("1.2.3.4", 1234))
            self.assertTrue(server._network_paths[1].is_validated)

            # server sends PATH_CHALLENGE and receives PATH_RESPONSE
            for data, addr in server.datagrams_to_send(now=time.time()):
                client.receive_datagram(data, SERVER_ADDR, now=time.time())
            for data, addr in client.datagrams_to_send(now=time.time()):
                server.receive_datagram(data, ("1.2.3.4", 2345), now=time.time())

            # check paths
            self.assertEqual(server._network_paths[0].addr, ("1.2.3.4", 2345))
            self.assertTrue(server._network_paths[0].is_validated)
            self.assertEqual(server._network_paths[1].addr, ("1.2.3.4", 1234))
            self.assertTrue(server._network_paths[1].is_validated)

    def test_handle_path_challenge_frame_padding(self):
        with client_and_server() as (client, server):
            # client changes address and sends some data
            client.send_stream_data(0, b"01234567")
            bytes_received = 0
            for data, addr in client.datagrams_to_send(now=time.time()):
                bytes_received += len(data)
                server.receive_datagram(data, ("1.2.3.4", 2345), now=time.time())

            # The server's PATH_CHALLENGE is padded up to the anti-amplification
            # limit of the new path.
            datagrams = server.datagrams_to_send(now=time.time())
            self.assertEqual(datagram_sizes(datagrams), [3 * bytes_received])

            # The client's PATH_RESPONSE is padded to 1200 bytes.
            for data, addr in datagrams:
                client.receive_datagram(data, SERVER_ADDR, now=time.time())
            self.assertEqual(
                datagram_sizes(client.datagrams_to_send(now=time.time())), [1200]
            )

    def test_handle_path_challenge_response_on_different_path(self):
        with client_and_server() as (client, server):
            # client changes address and sends some data
            client.send_stream_data(0, b"01234567")
            for data, addr in client.datagrams_to_send(now=time.time()):
                server.receive_datagram(data, ("1.2.3.4", 2345), now=time.time())

            # check paths
            self.assertEqual(len(server._network_paths), 2)
            self.assertEqual(server._network_paths[0].addr, ("1.2.3.4", 2345))
            self.assertFalse(server._network_paths[0].is_validated)
            self.assertEqual(server._network_paths[1].addr, ("1.2.3.4", 1234))
            self.assertTrue(server._network_paths[1].is_validated)

            # server sends PATH_CHALLENGE and receives PATH_RESPONSE on the 1234
            # path instead of the expected 2345 path.
            for data, addr in server.datagrams_to_send(now=time.time()):
                client.receive_datagram(data, SERVER_ADDR, now=time.time())
            for data, addr in client.datagrams_to_send(now=time.time()):
                server.receive_datagram(data, ("1.2.3.4", 1234), now=time.time())

            # check paths; note that the order is backwards from the prior test
            # as receiving on 1234 promotes it to first in the list
            self.assertEqual(server._network_paths[0].addr, ("1.2.3.4", 1234))
            self.assertTrue(server._network_paths[0].is_validated)
            self.assertEqual(server._network_paths[1].addr, ("1.2.3.4", 2345))
            self.assertTrue(server._network_paths[1].is_validated)

    def test_local_path_challenges_are_bounded(self):
        network_path = QuicNetworkPath(("1.2.3.4", 2345))
        for i in range(MAX_LOCAL_CHALLENGES + 2):
            network_path.local_challenges.append(int.to_bytes(i, 8, "big"))
        self.assertEqual(
            list(network_path.local_challenges),
            [int.to_bytes(i, 8, "big") for i in range(2, MAX_LOCAL_CHALLENGES + 2)],
        )

    def test_network_paths_are_bounded(self):
        with client_and_server() as (client, server):
            # client sends a fresh packet from many different ports
            for port in range(2000, 2000 + MAX_NETWORK_PATHS + 10):
                client.send_ping(port)
                for data, addr in client.datagrams_to_send(now=time.time()):
                    server.receive_datagram(data, ("1.2.3.4", port), now=time.time())

            # check paths
            self.assertEqual(len(server._network_paths), MAX_NETWORK_PATHS)
            self.assertEqual(
                server._network_paths[0].addr, ("1.2.3.4", 2000 + MAX_NETWORK_PATHS + 9)
            )

    def test_network_paths_eviction_prefers_unvalidated(self):
        with client_and_server() as (client, server):
            server._add_network_path(QuicNetworkPath(("1.2.3.4", 2000)))
            server._add_network_path(
                QuicNetworkPath(("1.2.3.4", 2001), is_validated=True)
            )
            for port in range(2002, 2002 + MAX_NETWORK_PATHS):
                server._add_network_path(QuicNetworkPath(("1.2.3.4", port)))

            # the active path and validated path are kept
            self.assertEqual(len(server._network_paths), MAX_NETWORK_PATHS)
            self.assertEqual(server._network_paths[0].addr, ("1.2.3.4", 1234))
            self.assertEqual(server._network_paths[1].addr, ("1.2.3.4", 2001))
            self.assertEqual(
                server._network_paths[-1].addr, ("1.2.3.4", 2001 + MAX_NETWORK_PATHS)
            )

    def test_network_paths_eviction_all_validated(self):
        with client_and_server() as (client, server):
            for port in range(2000, 2000 + MAX_NETWORK_PATHS - 1):
                server._add_network_path(
                    QuicNetworkPath(("1.2.3.4", port), is_validated=True)
                )

            # the oldest non-active path is evicted, not the one being added
            server._add_network_path(QuicNetworkPath(("1.2.3.4", 3000)))
            self.assertEqual(len(server._network_paths), MAX_NETWORK_PATHS)
            self.assertEqual(server._network_paths[0].addr, ("1.2.3.4", 1234))
            self.assertEqual(server._network_paths[1].addr, ("1.2.3.4", 2001))
            self.assertEqual(server._network_paths[-1].addr, ("1.2.3.4", 3000))

    def test_network_paths_eviction_retires_connection_id(self):
        with client_and_server() as (client, server):
            # A path has a connection ID reserved for it.
            network_path = QuicNetworkPath(("1.2.3.4", 2000))
            network_path.peer_cid = server._peer_cid_available.pop(0)
            server._add_network_path(network_path)
            for port in range(2001, 2001 + MAX_NETWORK_PATHS - 1):
                server._add_network_path(QuicNetworkPath(("1.2.3.4", port)))

            # The path is evicted and its connection ID is retired.
            self.assertNotIn(network_path, server._network_paths)
            self.assertEqual(server._retire_connection_ids, [1])

    def test_remote_path_challenges_are_bounded(self):
        with client_and_server() as (client, server):
            challenges = [os.urandom(8) for i in range(MAX_REMOTE_CHALLENGES + 2)]
            for challenge in challenges:
                client._handle_path_challenge_frame(
                    client_receive_context(client),
                    QuicFrameType.PATH_CHALLENGE,
                    Buffer(data=challenge),
                )
            self.assertEqual(
                list(client._network_paths[0].remote_challenges),
                challenges[0:MAX_REMOTE_CHALLENGES],
            )

    def test_handle_path_response_frame_after_other_challenges(self):
        with client_and_server() as (client, server):
            network_path = QuicNetworkPath(("1.2.3.4", 2345))
            server._add_network_path(network_path)
            network_path.local_challenges.append(bytes(8))

            # Every other path sends more challenges than it keeps before the
            # response arrives.
            for port in range(3000, 3000 + MAX_NETWORK_PATHS - 2):
                server._add_network_path(QuicNetworkPath(("1.2.3.4", port)))
            self.assertEqual(len(server._network_paths), MAX_NETWORK_PATHS)
            for i, other_path in enumerate(server._network_paths):
                if other_path is not network_path:
                    for j in range(MAX_LOCAL_CHALLENGES + 1):
                        other_path.local_challenges.append(
                            bytes([i + 1, j, 0, 0, 0, 0, 0, 0])
                        )

            # The response still validates the path, and its challenges are cleared.
            server._handle_path_response_frame(
                client_receive_context(client),
                QuicFrameType.PATH_RESPONSE,
                Buffer(data=bytes(8)),
            )
            self.assertTrue(network_path.is_validated)
            self.assertEqual(len(network_path.local_challenges), 0)

    def test_handle_path_response_frame_unknown(self):
        with client_and_server() as (client, server):
            # The server sent more challenges on a path than it keeps, so the first
            # one was dropped.
            network_path = QuicNetworkPath(("1.2.3.4", 2345))
            server._add_network_path(network_path)
            for i in range(MAX_LOCAL_CHALLENGES + 1):
                network_path.local_challenges.append(int.to_bytes(i, 8, "big"))

            # The response to the evicted challenge is ignored.
            server._handle_path_response_frame(
                client_receive_context(client),
                QuicFrameType.PATH_RESPONSE,
                Buffer(data=int.to_bytes(0, 8, "big")),
            )
            self.assertFalse(network_path.is_validated)

            # A response to a challenge which is still kept validates the path.
            server._handle_path_response_frame(
                client_receive_context(client),
                QuicFrameType.PATH_RESPONSE,
                Buffer(data=int.to_bytes(1, 8, "big")),
            )
            self.assertTrue(network_path.is_validated)

    def test_handle_padding_frame(self):
        client = create_standalone_client(self)

        # no more padding
        buf = Buffer(data=b"")
        client._handle_padding_frame(
            client_receive_context(client), QuicFrameType.PADDING, buf
        )
        self.assertEqual(buf.tell(), 0)

        # padding until end
        buf = Buffer(data=bytes(10))
        client._handle_padding_frame(
            client_receive_context(client), QuicFrameType.PADDING, buf
        )
        self.assertEqual(buf.tell(), 10)

        # padding then something else
        buf = Buffer(data=bytes(10) + b"\x01")
        client._handle_padding_frame(
            client_receive_context(client), QuicFrameType.PADDING, buf
        )
        self.assertEqual(buf.tell(), 10)

    def test_handle_reset_stream_frame(self):
        stream_id = 0
        with client_and_server() as (client, server):
            # client creates bidirectional stream
            client.send_stream_data(stream_id=stream_id, data=b"hello")
            consume_events(client)

            # client receives RESET_STREAM
            client._handle_reset_stream_frame(
                client_receive_context(client),
                QuicFrameType.RESET_STREAM,
                Buffer(
                    data=encode_uint_var(stream_id)
                    + encode_uint_var(QuicErrorCode.INTERNAL_ERROR)
                    + encode_uint_var(0)
                ),
            )

            event = client.next_event()
            self.assertEqual(type(event), events.StreamReset)
            self.assertEqual(event.error_code, QuicErrorCode.INTERNAL_ERROR)
            self.assertEqual(event.stream_id, stream_id)

    def test_handle_reset_stream_frame_final_size_error(self):
        stream_id = 0
        with client_and_server() as (client, server):
            # client creates bidirectional stream
            client.send_stream_data(stream_id=stream_id, data=b"hello")
            consume_events(client)

            # client receives RESET_STREAM at offset 8
            client._handle_reset_stream_frame(
                client_receive_context(client),
                QuicFrameType.RESET_STREAM,
                Buffer(
                    data=encode_uint_var(stream_id)
                    + encode_uint_var(QuicErrorCode.NO_ERROR)
                    + encode_uint_var(8)
                ),
            )

            event = client.next_event()
            self.assertEqual(type(event), events.StreamReset)
            self.assertEqual(event.error_code, QuicErrorCode.NO_ERROR)
            self.assertEqual(event.stream_id, stream_id)

            # client receives RESET_STREAM at offset 5
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_reset_stream_frame(
                    client_receive_context(client),
                    QuicFrameType.RESET_STREAM,
                    Buffer(
                        data=encode_uint_var(stream_id)
                        + encode_uint_var(QuicErrorCode.NO_ERROR)
                        + encode_uint_var(5)
                    ),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.FINAL_SIZE_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.RESET_STREAM)
            self.assertEqual(cm.exception.reason_phrase, "Cannot change final size")

    def test_handle_reset_stream_frame_flow_control(self):
        stream_id = 0
        reset_stream_data = (
            encode_uint_var(stream_id)
            + encode_uint_var(QuicErrorCode.NO_ERROR)
            + encode_uint_var(8)
        )
        with client_and_server() as (client, server):
            # client creates bidirectional stream
            client.send_stream_data(stream_id=stream_id, data=b"hello")
            consume_events(client)
            used = client._local_max_data.used

            # client receives RESET_STREAM at offset 8
            client._handle_reset_stream_frame(
                client_receive_context(client),
                QuicFrameType.RESET_STREAM,
                Buffer(data=reset_stream_data),
            )
            self.assertEqual(client._local_max_data.used, used + 8)

            # client receives the same RESET_STREAM again
            client._handle_reset_stream_frame(
                client_receive_context(client),
                QuicFrameType.RESET_STREAM,
                Buffer(data=reset_stream_data),
            )
            self.assertEqual(client._local_max_data.used, used + 8)

            # client receives data which was sent before the reset
            client._handle_stream_frame(
                client_receive_context(client),
                QuicFrameType.STREAM_BASE | 6,
                Buffer(
                    data=encode_uint_var(stream_id)
                    + encode_uint_var(0)
                    + encode_uint_var(8)
                    + b"01234567"
                ),
            )
            self.assertEqual(client._local_max_data.used, used + 8)

    def test_handle_reset_stream_frame_over_max_data(self):
        stream_id = 0
        with client_and_server() as (client, server):
            # client creates bidirectional stream
            client.send_stream_data(stream_id=stream_id, data=b"hello")
            consume_events(client)

            # artificially raise received data counter
            client._local_max_data.used = client._local_max_data.value

            # client receives RESET_STREAM frame
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_reset_stream_frame(
                    client_receive_context(client),
                    QuicFrameType.RESET_STREAM,
                    Buffer(
                        data=encode_uint_var(stream_id)
                        + encode_uint_var(QuicErrorCode.NO_ERROR)
                        + encode_uint_var(1)
                    ),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.FLOW_CONTROL_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.RESET_STREAM)
            self.assertEqual(cm.exception.reason_phrase, "Over connection data limit")

    def test_handle_reset_stream_frame_over_max_stream_data(self):
        stream_id = 0
        with client_and_server() as (client, server):
            # client creates bidirectional stream
            client.send_stream_data(stream_id=stream_id, data=b"hello")
            consume_events(client)

            # client receives STREAM frame
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_reset_stream_frame(
                    client_receive_context(client),
                    QuicFrameType.RESET_STREAM,
                    Buffer(
                        data=encode_uint_var(stream_id)
                        + encode_uint_var(QuicErrorCode.NO_ERROR)
                        + encode_uint_var(client._local_max_stream_data_bidi_local + 1)
                    ),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.FLOW_CONTROL_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.RESET_STREAM)
            self.assertEqual(cm.exception.reason_phrase, "Over stream data limit")

    def test_handle_reset_stream_frame_send_only(self):
        with client_and_server() as (client, server):
            # client creates unidirectional stream 2
            client.send_stream_data(stream_id=2, data=b"hello")

            # client receives RESET_STREAM
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_reset_stream_frame(
                    client_receive_context(client),
                    QuicFrameType.RESET_STREAM,
                    Buffer(data=binascii.unhexlify("021100")),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.STREAM_STATE_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.RESET_STREAM)
            self.assertEqual(cm.exception.reason_phrase, "Stream is send-only")

    def test_handle_reset_stream_frame_twice(self):
        stream_id = 3
        reset_stream_data = (
            encode_uint_var(QuicFrameType.RESET_STREAM)
            + encode_uint_var(stream_id)
            + encode_uint_var(QuicErrorCode.INTERNAL_ERROR)
            + encode_uint_var(0)
        )
        with client_and_server() as (client, server):
            # server creates unidirectional stream
            server.send_stream_data(stream_id=stream_id, data=b"hello")
            roundtrip(server, client)
            consume_events(client)

            # client receives RESET_STREAM
            client._payload_received(client_receive_context(client), reset_stream_data)

            event = client.next_event()
            self.assertEqual(type(event), events.StreamReset)
            self.assertEqual(event.error_code, QuicErrorCode.INTERNAL_ERROR)
            self.assertEqual(event.stream_id, stream_id)

            # stream gets discarded
            self.assertEqual(drop(client), 0)

            # client receives RESET_STREAM again
            client._payload_received(client_receive_context(client), reset_stream_data)

            event = client.next_event()
            self.assertIsNone(event)

    def test_handle_retire_connection_id_frame(self):
        with client_and_server() as (client, server):
            self.assertEqual(
                sequence_numbers(client._host_cids), [0, 1, 2, 3, 4, 5, 6, 7]
            )

            # client receives RETIRE_CONNECTION_ID
            client._handle_retire_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.RETIRE_CONNECTION_ID,
                Buffer(data=b"\x02"),
            )
            self.assertEqual(
                sequence_numbers(client._host_cids), [0, 1, 3, 4, 5, 6, 7, 8]
            )

    def test_handle_retire_connection_id_frame_current_cid(self):
        with client_and_server() as (client, server):
            self.assertEqual(
                sequence_numbers(client._host_cids), [0, 1, 2, 3, 4, 5, 6, 7]
            )

            # client receives RETIRE_CONNECTION_ID for the current CID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_retire_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.RETIRE_CONNECTION_ID,
                    Buffer(data=b"\x00"),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.RETIRE_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase, "Cannot retire current connection ID"
            )
            self.assertEqual(
                sequence_numbers(client._host_cids), [0, 1, 2, 3, 4, 5, 6, 7]
            )

    def test_handle_retire_connection_id_frame_invalid_sequence_number(self):
        with client_and_server() as (client, server):
            self.assertEqual(
                sequence_numbers(client._host_cids), [0, 1, 2, 3, 4, 5, 6, 7]
            )

            # client receives RETIRE_CONNECTION_ID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_retire_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.RETIRE_CONNECTION_ID,
                    Buffer(data=b"\x08"),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.RETIRE_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase, "Cannot retire unknown connection ID"
            )
            self.assertEqual(
                sequence_numbers(client._host_cids), [0, 1, 2, 3, 4, 5, 6, 7]
            )

    def test_handle_stop_sending_frame(self):
        with client_and_server() as (client, server):
            # client creates bidirectional stream 0
            client.send_stream_data(stream_id=0, data=b"hello")

            # client receives STOP_SENDING
            client._handle_stop_sending_frame(
                client_receive_context(client),
                QuicFrameType.STOP_SENDING,
                Buffer(data=b"\x00\x11"),
            )

            # check events
            self.assertEqual(type(client.next_event()), events.ProtocolNegotiated)
            self.assertEqual(type(client.next_event()), events.HandshakeCompleted)
            for i in range(7):
                self.assertEqual(type(client.next_event()), events.ConnectionIdIssued)

            event = client.next_event()
            self.assertEqual(type(event), events.StopSendingReceived)
            self.assertEqual(event.stream_id, 0)
            self.assertEqual(event.error_code, 0x11)

            self.assertIsNone(client.next_event())

            # client receives another STOP_SENDING
            client._handle_stop_sending_frame(
                client_receive_context(client),
                QuicFrameType.STOP_SENDING,
                Buffer(data=b"\x00\x12"),
            )

            event = client.next_event()
            self.assertEqual(type(event), events.StopSendingReceived)
            self.assertEqual(event.stream_id, 0)
            self.assertEqual(event.error_code, 0x12)

            self.assertIsNone(client.next_event())

    def test_handle_stop_sending_frame_receive_only(self):
        with client_and_server() as (client, server):
            # server creates unidirectional stream 3
            server.send_stream_data(stream_id=3, data=b"hello")

            # client receives STOP_SENDING
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stop_sending_frame(
                    client_receive_context(client),
                    QuicFrameType.STOP_SENDING,
                    Buffer(data=b"\x03\x11"),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.STREAM_STATE_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.STOP_SENDING)
            self.assertEqual(cm.exception.reason_phrase, "Stream is receive-only")

    def test_handle_stream_frame_fin_only(self):
        frame_type = QuicFrameType.STREAM_BASE | 1
        with client_and_server() as (client, server):
            # The server receives FIN-only STREAM frames on 100 unidirectional
            # streams, which use no flow control credit.
            for i in range(100):
                server._handle_stream_frame(
                    client_receive_context(server),
                    frame_type,
                    Buffer(data=encode_uint_var(i * 4 + 2)),
                )
            consume_events(server)
            self.assertEqual(len(server._streams), 100)

            # The server discards the streams and lets the client open as many.
            self.assertEqual(drop(server), 1)
            self.assertEqual(server._streams, {})
            self.assertEqual(server._local_max_streams_uni.sent, 228)
            self.assertEqual(server._local_max_streams_uni.used, 100)
            self.assertEqual(server._local_max_streams_uni.value, 228)

            # The server receives a FIN-only STREAM frame on a discarded stream,
            # which is ignored.
            server._payload_received(
                client_receive_context(server),
                encode_uint_var(frame_type) + encode_uint_var(2),
            )
            self.assertIsNone(server.next_event())
            self.assertEqual(server._streams, {})

    def test_handle_stream_frame_final_size_error(self):
        with client_and_server() as (client, server):
            frame_type = QuicFrameType.STREAM_BASE | 7
            stream_id = 1

            # client receives FIN at offset 8
            client._handle_stream_frame(
                client_receive_context(client),
                frame_type,
                Buffer(
                    data=encode_uint_var(stream_id)
                    + encode_uint_var(8)
                    + encode_uint_var(0)
                ),
            )

            # client receives FIN at offset 5
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stream_frame(
                    client_receive_context(client),
                    frame_type,
                    Buffer(
                        data=encode_uint_var(stream_id)
                        + encode_uint_var(5)
                        + encode_uint_var(0)
                    ),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.FINAL_SIZE_ERROR)
            self.assertEqual(cm.exception.frame_type, frame_type)
            self.assertEqual(cm.exception.reason_phrase, "Cannot change final size")

    def test_handle_stream_frame_opens_lower_streams(self):
        with client_and_server() as (client, server):
            consume_events(client)

            # The client receives a STREAM frame on unidirectional stream 11,
            # which also opens streams 3 and 7.
            client._handle_stream_frame(
                client_receive_context(client),
                QuicFrameType.STREAM_BASE,
                Buffer(data=encode_uint_var(11) + b"c"),
            )
            self.assertEqual(sorted(client._streams), [3, 7, 11])
            self.assertEqual(client._local_max_streams_uni.used, 3)
            self.assertEqual(
                client.next_event(),
                events.StreamDataReceived(data=b"c", end_stream=False, stream_id=11),
            )

            # The client receives a STREAM frame on stream 3.
            client._handle_stream_frame(
                client_receive_context(client),
                QuicFrameType.STREAM_BASE,
                Buffer(data=encode_uint_var(3) + b"a"),
            )
            self.assertEqual(sorted(client._streams), [3, 7, 11])
            self.assertEqual(client._local_max_streams_uni.used, 3)
            self.assertEqual(
                client.next_event(),
                events.StreamDataReceived(data=b"a", end_stream=False, stream_id=3),
            )

    def test_handle_stream_frame_over_largest_offset(self):
        with client_and_server() as (client, server):
            # client receives offset + length > 2^62 - 1
            frame_type = QuicFrameType.STREAM_BASE | 6
            stream_id = 1
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stream_frame(
                    client_receive_context(client),
                    frame_type,
                    Buffer(
                        data=encode_uint_var(stream_id)
                        + encode_uint_var(UINT_VAR_MAX)
                        + encode_uint_var(1)
                    ),
                )
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.FRAME_ENCODING_ERROR
            )
            self.assertEqual(cm.exception.frame_type, frame_type)
            self.assertEqual(
                cm.exception.reason_phrase, "offset + length cannot exceed 2^62 - 1"
            )

    def test_handle_stream_frame_over_max_data(self):
        with client_and_server() as (client, server):
            # artificially raise received data counter
            client._local_max_data.used = client._local_max_data.value

            # client receives STREAM frame
            frame_type = QuicFrameType.STREAM_BASE | 4
            stream_id = 1
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stream_frame(
                    client_receive_context(client),
                    frame_type,
                    Buffer(data=encode_uint_var(stream_id) + encode_uint_var(1)),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.FLOW_CONTROL_ERROR)
            self.assertEqual(cm.exception.frame_type, frame_type)
            self.assertEqual(cm.exception.reason_phrase, "Over connection data limit")

    def test_handle_stream_frame_over_max_stream_data(self):
        with client_and_server() as (client, server):
            # client receives STREAM frame
            frame_type = QuicFrameType.STREAM_BASE | 4
            stream_id = 1
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stream_frame(
                    client_receive_context(client),
                    frame_type,
                    Buffer(
                        data=encode_uint_var(stream_id)
                        + encode_uint_var(client._local_max_stream_data_bidi_remote + 1)
                    ),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.FLOW_CONTROL_ERROR)
            self.assertEqual(cm.exception.frame_type, frame_type)
            self.assertEqual(cm.exception.reason_phrase, "Over stream data limit")

    def test_handle_stream_frame_over_max_streams(self):
        with client_and_server() as (client, server):
            # client receives STREAM frame
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stream_frame(
                    client_receive_context(client),
                    QuicFrameType.STREAM_BASE,
                    Buffer(
                        data=encode_uint_var(client._local_max_stream_data_uni * 4 + 3)
                    ),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.STREAM_LIMIT_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.STREAM_BASE)
            self.assertEqual(cm.exception.reason_phrase, "Too many streams open")

    def test_handle_stream_frame_over_max_streams_still_open(self):
        frame_type = QuicFrameType.STREAM_BASE
        with client_and_server() as (client, server):
            # The server receives zero-byte STREAM frames on 128 unidirectional
            # streams, which remain open.
            for i in range(128):
                server._handle_stream_frame(
                    client_receive_context(server),
                    frame_type,
                    Buffer(data=encode_uint_var(i * 4 + 2)),
                )
            self.assertEqual(len(server._streams), 128)

            # The server does not let the client open more streams.
            self.assertEqual(drop(server), 0)
            self.assertEqual(server._local_max_streams_uni.sent, 128)
            self.assertEqual(server._local_max_streams_uni.used, 128)
            self.assertEqual(server._local_max_streams_uni.value, 128)

            # The server receives a STREAM frame on one stream too many.
            with self.assertRaises(QuicConnectionError) as cm:
                server._handle_stream_frame(
                    client_receive_context(server),
                    frame_type,
                    Buffer(data=encode_uint_var(128 * 4 + 2)),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.STREAM_LIMIT_ERROR)
            self.assertEqual(cm.exception.frame_type, frame_type)
            self.assertEqual(cm.exception.reason_phrase, "Too many streams open")

    def test_handle_stream_frame_send_only(self):
        with client_and_server() as (client, server):
            # client creates unidirectional stream 2
            client.send_stream_data(stream_id=2, data=b"hello")

            # client receives STREAM frame
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stream_frame(
                    client_receive_context(client),
                    QuicFrameType.STREAM_BASE,
                    Buffer(data=b"\x02"),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.STREAM_STATE_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.STREAM_BASE)
            self.assertEqual(cm.exception.reason_phrase, "Stream is send-only")

    def test_handle_stream_frame_wrong_initiator(self):
        with client_and_server() as (client, server):
            # client receives STREAM frame
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stream_frame(
                    client_receive_context(client),
                    QuicFrameType.STREAM_BASE,
                    Buffer(data=b"\x00"),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.STREAM_STATE_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.STREAM_BASE)
            self.assertEqual(cm.exception.reason_phrase, "Wrong stream initiator")

    def test_handle_stream_data_blocked_frame(self):
        with client_and_server() as (client, server):
            # client creates bidirectional stream 0
            client.send_stream_data(stream_id=0, data=b"hello")

            # client receives STREAM_DATA_BLOCKED
            client._handle_stream_data_blocked_frame(
                client_receive_context(client),
                QuicFrameType.STREAM_DATA_BLOCKED,
                Buffer(data=b"\x00\x01"),
            )

    def test_handle_stream_data_blocked_frame_send_only(self):
        with client_and_server() as (client, server):
            # client creates unidirectional stream 2
            client.send_stream_data(stream_id=2, data=b"hello")

            # client receives STREAM_DATA_BLOCKED
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_stream_data_blocked_frame(
                    client_receive_context(client),
                    QuicFrameType.STREAM_DATA_BLOCKED,
                    Buffer(data=b"\x02\x01"),
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.STREAM_STATE_ERROR)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.STREAM_DATA_BLOCKED)
            self.assertEqual(cm.exception.reason_phrase, "Stream is send-only")

    def test_handle_streams_blocked_uni_frame(self):
        with client_and_server() as (client, server):
            # client receives STREAMS_BLOCKED_UNI: 0
            client._handle_streams_blocked_frame(
                client_receive_context(client),
                QuicFrameType.STREAMS_BLOCKED_UNI,
                Buffer(data=b"\x00"),
            )

            # client receives invalid STREAMS_BLOCKED_UNI
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_streams_blocked_frame(
                    client_receive_context(client),
                    QuicFrameType.STREAMS_BLOCKED_UNI,
                    Buffer(data=encode_uint_var(STREAM_COUNT_MAX + 1)),
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.FRAME_ENCODING_ERROR,
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.STREAMS_BLOCKED_UNI)
            self.assertEqual(
                cm.exception.reason_phrase, "Maximum Streams cannot exceed 2^60"
            )

    def test_parse_transport_parameters(self):
        client = create_standalone_client(self)

        data = encode_transport_parameters(
            QuicTransportParameters(
                original_destination_connection_id=client.original_destination_connection_id
            )
        )
        client._parse_transport_parameters(data)

    def test_parse_transport_parameters_idle_time(self):
        # Remote idle of 10s and local idle of 60s.
        client = create_standalone_client(self)
        data = encode_transport_parameters(
            # Note the timeout parameter here is in milliseconds.
            QuicTransportParameters(
                original_destination_connection_id=client.original_destination_connection_id,
                max_idle_timeout=10000,
            )
        )
        client._parse_transport_parameters(data)
        self.assertAlmostEqual(client._remote_max_idle_timeout, 10.0)
        self.assertAlmostEqual(client._idle_timeout(), 10.0)

        # Remote idle of 120s and local idle of 60s.
        client = create_standalone_client(self)
        data = encode_transport_parameters(
            QuicTransportParameters(
                original_destination_connection_id=client.original_destination_connection_id,
                max_idle_timeout=120000,
            )
        )
        client._parse_transport_parameters(data)
        self.assertAlmostEqual(client._remote_max_idle_timeout, 120.0)
        self.assertAlmostEqual(client._idle_timeout(), 60.0)

        # Remote idle of 1ms and local idle of 60s.
        #
        # Very low values are clamped to 3 * PTO; we use the default initial RTT of 0.1
        # and since RTT is not initialized get_probe_timeout() will return 2 * the
        # initial RTT as the PTO, i.e. 0.2, so 3 * PTO == 0.6.
        client = create_standalone_client(self)
        data = encode_transport_parameters(
            QuicTransportParameters(
                original_destination_connection_id=client.original_destination_connection_id,
                max_idle_timeout=1,
            )
        )
        client._parse_transport_parameters(data)
        self.assertAlmostEqual(client._remote_max_idle_timeout, 0.001)
        self.assertAlmostEqual(client._idle_timeout(), 0.6)

    def test_parse_transport_parameters_malformed(self):
        client = create_standalone_client(self)

        with self.assertRaises(QuicConnectionError) as cm:
            client._parse_transport_parameters(b"0")
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(
            cm.exception.reason_phrase, "Could not parse QUIC transport parameters"
        )

    def test_parse_transport_parameters_with_bad_ack_delay_exponent(self):
        client = create_standalone_client(self)

        data = encode_transport_parameters(
            QuicTransportParameters(
                ack_delay_exponent=21,
                original_destination_connection_id=client.original_destination_connection_id,
            )
        )
        with self.assertRaises(QuicConnectionError) as cm:
            client._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(cm.exception.reason_phrase, "ack_delay_exponent must be <= 20")

    def test_parse_transport_parameters_with_bad_active_connection_id_limit(self):
        client = create_standalone_client(self)

        for active_connection_id_limit in [0, 1]:
            data = encode_transport_parameters(
                QuicTransportParameters(
                    active_connection_id_limit=active_connection_id_limit,
                    original_destination_connection_id=client.original_destination_connection_id,
                )
            )
            with self.assertRaises(QuicConnectionError) as cm:
                client._parse_transport_parameters(data)
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
            self.assertEqual(
                cm.exception.reason_phrase,
                "active_connection_id_limit must be no less than 2",
            )

    def test_parse_transport_parameters_with_bad_max_ack_delay(self):
        client = create_standalone_client(self)

        data = encode_transport_parameters(
            QuicTransportParameters(
                max_ack_delay=2**14,
                original_destination_connection_id=client.original_destination_connection_id,
            )
        )
        with self.assertRaises(QuicConnectionError) as cm:
            client._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(cm.exception.reason_phrase, "max_ack_delay must be < 2^14")

    def test_parse_transport_parameters_with_bad_max_streams_bidi(self):
        client = create_standalone_client(self)

        data = encode_transport_parameters(
            QuicTransportParameters(
                initial_max_streams_bidi=STREAM_COUNT_MAX + 1,
                original_destination_connection_id=client.original_destination_connection_id,
            )
        )
        with self.assertRaises(QuicConnectionError) as cm:
            client._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(
            cm.exception.reason_phrase, "initial_max_streams_bidi cannot exceed 2^60"
        )

    def test_parse_transport_parameters_with_bad_max_streams_uni(self):
        client = create_standalone_client(self)

        data = encode_transport_parameters(
            QuicTransportParameters(
                initial_max_streams_uni=STREAM_COUNT_MAX + 1,
                original_destination_connection_id=client.original_destination_connection_id,
            )
        )
        with self.assertRaises(QuicConnectionError) as cm:
            client._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(
            cm.exception.reason_phrase, "initial_max_streams_uni cannot exceed 2^60"
        )

    def test_parse_transport_parameters_with_bad_max_udp_payload_size(self):
        client = create_standalone_client(self)

        data = encode_transport_parameters(
            QuicTransportParameters(
                max_udp_payload_size=1199,
                original_destination_connection_id=client.original_destination_connection_id,
            )
        )
        with self.assertRaises(QuicConnectionError) as cm:
            client._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(
            cm.exception.reason_phrase, "max_udp_payload_size must be >= 1200"
        )

    def test_parse_transport_parameters_with_bad_initial_source_connection_id(self):
        client = create_standalone_client(self)
        client._initial_source_connection_id = binascii.unhexlify("0011223344556677")

        data = encode_transport_parameters(
            QuicTransportParameters(
                initial_source_connection_id=binascii.unhexlify("1122334455667788"),
                original_destination_connection_id=client.original_destination_connection_id,
            )
        )
        with self.assertRaises(QuicConnectionError) as cm:
            client._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(
            cm.exception.reason_phrase, "initial_source_connection_id does not match"
        )

    def test_parse_transport_parameters_with_bad_version_information_1(self):
        server = create_standalone_server(self)
        data = encode_transport_parameters(
            QuicTransportParameters(
                version_information=QuicVersionInformation(
                    chosen_version=QuicProtocolVersion.VERSION_1,
                    available_versions=[QuicProtocolVersion.VERSION_2],
                )
            )
        )
        with self.assertRaises(QuicConnectionError) as cm:
            server._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(
            cm.exception.reason_phrase,
            "version_information's chosen_version is not included in "
            "available_versions",
        )

    def test_parse_transport_parameters_with_bad_version_information_2(self):
        server = create_standalone_server(self)
        data = encode_transport_parameters(
            QuicTransportParameters(
                version_information=QuicVersionInformation(
                    chosen_version=QuicProtocolVersion.VERSION_1,
                    available_versions=[
                        QuicProtocolVersion.VERSION_1,
                        QuicProtocolVersion.VERSION_2,
                    ],
                )
            )
        )
        server._crypto_packet_version = QuicProtocolVersion.VERSION_2
        with self.assertRaises(QuicConnectionError) as cm:
            server._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.VERSION_NEGOTIATION_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(
            cm.exception.reason_phrase,
            "version_information's chosen_version does not match the version in use",
        )

    def test_parse_transport_parameters_with_preferred_address(self):
        client = create_standalone_client(self)
        client._remote_initial_source_connection_id = bytes(8)
        preferred_address = QuicPreferredAddress(
            ipv4_address=SERVER_PREFERRED_ADDR,
            ipv6_address=None,
            connection_id=b"\x01" * 8,
            stateless_reset_token=b"\x02" * 16,
        )

        data = encode_transport_parameters(
            QuicTransportParameters(
                initial_source_connection_id=bytes(8),
                original_destination_connection_id=client.original_destination_connection_id,
                preferred_address=preferred_address,
            )
        )
        client._parse_transport_parameters(data)
        self.assertEqual(client._remote_preferred_address, preferred_address)
        self.assertEqual(sequence_numbers(client._peer_cid_available), [1])
        self.assertEqual(client._peer_cid_available[0].cid, b"\x01" * 8)
        self.assertEqual(
            client._peer_cid_available[0].stateless_reset_token, b"\x02" * 16
        )
        self.assertIn(1, client._peer_cid_sequence_numbers)

    def test_parse_transport_parameters_with_preferred_address_and_empty_cid(self):
        client = create_standalone_client(self)
        client._remote_initial_source_connection_id = b""

        data = encode_transport_parameters(
            QuicTransportParameters(
                initial_source_connection_id=b"",
                original_destination_connection_id=client.original_destination_connection_id,
                preferred_address=SERVER_PREFERRED_ADDRESS,
            )
        )
        with self.assertRaises(QuicConnectionError) as cm:
            client._parse_transport_parameters(data)
        self.assertEqual(
            cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
        )
        self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
        self.assertEqual(
            cm.exception.reason_phrase,
            "preferred_address is not allowed with a zero-length connection ID",
        )

    def test_parse_transport_parameters_with_preferred_address_from_session_ticket(
        self,
    ):
        client = create_standalone_client(self)

        data = encode_transport_parameters(
            QuicTransportParameters(preferred_address=SERVER_PREFERRED_ADDRESS)
        )
        client._parse_transport_parameters(data, from_session_ticket=True)
        self.assertIsNone(client._remote_preferred_address)
        self.assertEqual(client._peer_cid_available, [])

    def test_parse_transport_parameters_with_server_only_parameter(self):
        server = create_standalone_server(self)
        for active_connection_id_limit in [0, 1]:
            data = encode_transport_parameters(
                QuicTransportParameters(
                    active_connection_id_limit=active_connection_id_limit,
                    original_destination_connection_id=bytes(8),
                )
            )
            with self.assertRaises(QuicConnectionError) as cm:
                server._parse_transport_parameters(data)
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.TRANSPORT_PARAMETER_ERROR
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
            self.assertEqual(
                cm.exception.reason_phrase,
                "original_destination_connection_id is not allowed for clients",
            )

    def test_payload_received_empty(self):
        with client_and_server() as (client, server):
            # client receives empty payload
            with self.assertRaises(QuicConnectionError) as cm:
                client._payload_received(client_receive_context(client), b"")
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.PADDING)
            self.assertEqual(cm.exception.reason_phrase, "Packet contains no frames")

    def test_payload_received_padding_only(self):
        with client_and_server() as (client, server):
            # client receives padding only
            is_ack_eliciting, is_probing = client._payload_received(
                client_receive_context(client), b"\x00" * SMALLEST_MAX_DATAGRAM_SIZE
            )
            self.assertFalse(is_ack_eliciting)
            self.assertTrue(is_probing)

    def test_payload_received_malformed_frame_type(self):
        with client_and_server() as (client, server):
            # client receives a malformed frame type
            with self.assertRaises(QuicConnectionError) as cm:
                client._payload_received(client_receive_context(client), b"\xff")
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.FRAME_ENCODING_ERROR
            )
            self.assertEqual(cm.exception.frame_type, None)
            self.assertEqual(cm.exception.reason_phrase, "Malformed frame type")

    def test_payload_received_unknown_frame_type(self):
        with client_and_server() as (client, server):
            # client receives unknown frame type
            with self.assertRaises(QuicConnectionError) as cm:
                client._payload_received(client_receive_context(client), b"\x1f")
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.FRAME_ENCODING_ERROR
            )
            self.assertEqual(cm.exception.frame_type, 0x1F)
            self.assertEqual(cm.exception.reason_phrase, "Unknown frame type")

    def test_payload_received_unexpected_frame_type(self):
        with client_and_server() as (client, server):
            # client receives CRYPTO frame in 0-RTT
            with self.assertRaises(QuicConnectionError) as cm:
                client._payload_received(
                    client_receive_context(client, epoch=tls.Epoch.ZERO_RTT), b"\x06"
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(cm.exception.frame_type, QuicFrameType.CRYPTO)
            self.assertEqual(cm.exception.reason_phrase, "Unexpected frame type")

    def test_payload_received_malformed_frame(self):
        with client_and_server() as (client, server):
            # client receives malformed TRANSPORT_CLOSE frame
            with self.assertRaises(QuicConnectionError) as cm:
                client._payload_received(
                    client_receive_context(client), b"\x1c\x00\x01"
                )
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.FRAME_ENCODING_ERROR
            )
            self.assertEqual(cm.exception.frame_type, 0x1C)
            self.assertEqual(cm.exception.reason_phrase, "Failed to parse frame")

    def test_preferred_address(self):
        with client_and_server(
            handshake=False, server_patch=advertise_preferred_address
        ) as (client, server):
            client.connect(SERVER_ADDR, now=time.time())
            while not client._handshake_confirmed:
                roundtrip(client, server)
            self.assertEqual(client._peer_cid.sequence_number, 0)

            # The client probes the preferred address with a padded PATH_CHALLENGE,
            # using the connection ID from the preferred address.
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertEqual(
                [addr for data, addr in datagrams],
                [SERVER_ADDR] * (len(datagrams) - 1) + [SERVER_PREFERRED_ADDR],
            )
            self.assertEqual(len(datagrams[-1][0]), 1200)
            self.assertEqual(
                [path.addr for path in client._network_paths],
                [SERVER_ADDR, SERVER_PREFERRED_ADDR],
            )
            self.assertFalse(client._network_paths[1].is_validated)
            self.assertEqual(
                client._network_paths[1].peer_cid.cid, server._host_cids[1].cid
            )

            # The server responds, and the client migrates to the preferred address.
            for data, addr in datagrams:
                server.receive_datagram(data, CLIENT_ADDR, now=time.time())
            receive_from(server, client, SERVER_ADDR)
            self.assertEqual(client.get_peer_address(), SERVER_PREFERRED_ADDR)
            self.assertTrue(client._network_paths[0].is_validated)
            self.assertEqual(client._peer_cid.sequence_number, 1)
            self.assertEqual(client._retire_connection_ids, [0])

            # Further datagrams are sent to the preferred address.
            client.send_stream_data(0, b"hello")
            self.assertEqual(
                set(receive_from(client, server, CLIENT_ADDR)),
                {SERVER_PREFERRED_ADDR},
            )

    def test_preferred_address_challenged_by_server(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS

            # The client's probe is lost.
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertEqual(datagrams[-1][1], SERVER_PREFERRED_ADDR)
            probe_cid = client._network_paths[1].peer_cid

            # The server challenges the client from its preferred address.
            server._network_paths[0].is_validated = False
            server._network_paths[0].local_challenge_sent = False
            server.send_ping(1)
            receive_from(server, client, SERVER_PREFERRED_ADDR)

            # The client responds on that path with a padded datagram, using the
            # connection ID reserved for it, but does not migrate.
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertEqual(
                [
                    (len(data), addr)
                    for data, addr in datagrams
                    if addr == SERVER_PREFERRED_ADDR
                ],
                [(1200, SERVER_PREFERRED_ADDR)],
            )
            log = client.configuration.quic_logger.to_dict()
            packet_sent = [
                event
                for event in log["traces"][0]["events"]
                if event["name"] == "transport:packet_sent"
            ][-1]
            self.assertEqual(
                [frame["frame_type"] for frame in packet_sent["data"]["frames"]],
                ["path_response", "padding"],
            )
            self.assertEqual(
                packet_sent["data"]["header"]["dcid"], dump_cid(probe_cid.cid)
            )
            self.assertEqual(client.get_peer_address(), SERVER_ADDR)

            # The response validates the server's path.
            for data, addr in datagrams:
                server.receive_datagram(data, CLIENT_ADDR, now=time.time())
            self.assertTrue(server._network_paths[0].is_validated)

    def test_preferred_address_challenged_from_original_address(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS
            roundtrip(client, server)
            self.assertEqual(client.get_peer_address(), SERVER_PREFERRED_ADDR)

            # The server challenges the client from its original address.
            server._network_paths[0].is_validated = False
            server._network_paths[0].local_challenge_sent = False
            server.send_ping(1)
            receive_from(server, client, SERVER_ADDR)

            # The client responds on that path with a padded datagram, but does not
            # challenge it, as the handshake validated it.
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertEqual(
                [(len(data), addr) for data, addr in datagrams if addr == SERVER_ADDR],
                [(1200, SERVER_ADDR)],
            )
            log = client.configuration.quic_logger.to_dict()
            packet_sent = [
                event
                for event in log["traces"][0]["events"]
                if event["name"] == "transport:packet_sent"
            ][-1]
            self.assertEqual(
                [frame["frame_type"] for frame in packet_sent["data"]["frames"]],
                ["path_response", "padding"],
            )
            original_path = client._network_paths[1]
            self.assertEqual(original_path.addr, SERVER_ADDR)
            self.assertEqual(
                packet_sent["data"]["header"]["dcid"],
                dump_cid(original_path.peer_cid.cid),
            )

            # The response validates the server's path, and the client stays on the
            # preferred address.
            for data, addr in datagrams:
                server.receive_datagram(data, CLIENT_ADDR, now=time.time())
            self.assertTrue(server._network_paths[0].is_validated)
            receive_from(server, client, SERVER_ADDR)
            self.assertEqual(client.get_peer_address(), SERVER_PREFERRED_ADDR)

    def test_preferred_address_challenged_with_amplification(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS
            drop(client)
            network_path = client._network_paths[1]

            # A small datagram carrying a PATH_CHALLENGE arrives from the
            # preferred address.
            network_path.remote_challenges.append(bytes(8))
            network_path.bytes_received = 100

            # The client does not respond beyond the anti-amplification limit.
            self.assertEqual(client.datagrams_to_send(now=time.time()), [])
            self.assertEqual(len(network_path.remote_challenges), 1)

            # Once more data is received, the response is padded within the limit.
            network_path.bytes_received += 450
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertEqual(
                [(len(data), addr) for data, addr in datagrams],
                [(450, SERVER_PREFERRED_ADDR)],
            )
            self.assertEqual(len(network_path.remote_challenges), 0)

    def test_preferred_address_connection_id_limit(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS
            drop(client)
            self.assertEqual(
                1 + len(client._peer_cid_available) + 1,
                client._local_active_connection_id_limit,
            )

            # The connection ID reserved for the probe counts toward the limit.
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_CONNECTION_ID,
                    new_connection_id(sequence_number=8),
                )
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.CONNECTION_ID_LIMIT_ERROR
            )
            self.assertEqual(cm.exception.frame_type, QuicFrameType.NEW_CONNECTION_ID)
            self.assertEqual(
                cm.exception.reason_phrase, "Too many active connection IDs"
            )

    def test_preferred_address_not_probed_when_closing(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS

            client.close()
            self.assertEqual(
                set(addr for data, addr in client.datagrams_to_send(now=time.time())),
                {SERVER_ADDR},
            )
            self.assertEqual(len(client._network_paths), 1)

    def test_preferred_address_probe_lost(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS

            # The probe is lost.
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertEqual(datagrams[-1][1], SERVER_PREFERRED_ADDR)

            # The client stays on the original address and does not probe again.
            client.send_stream_data(0, b"hello")
            self.assertEqual(
                set(receive_from(client, server, CLIENT_ADDR)), {SERVER_ADDR}
            )
            self.assertEqual(client.get_peer_address(), SERVER_ADDR)
            self.assertEqual(client._peer_cid.sequence_number, 0)

    def test_preferred_address_receive_before_validation(self):
        with client_and_server() as (client, server):
            consume_events(client)
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS
            drop(client)

            # Data from the preferred address is accepted, but the client does not
            # switch to it before validating it.
            server.send_stream_data(3, b"hello")
            receive_from(server, client, SERVER_PREFERRED_ADDR)
            self.assertEqual(type(client.next_event()), events.StreamDataReceived)
            self.assertEqual(client.get_peer_address(), SERVER_ADDR)
            self.assertEqual(client._peer_cid.sequence_number, 0)

    def test_preferred_address_receive_from_original_address(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS
            roundtrip(client, server)
            self.assertEqual(client.get_peer_address(), SERVER_PREFERRED_ADDR)
            consume_events(client)

            # Data from the original address is accepted, and the client stays on
            # the preferred address.
            server.send_stream_data(3, b"hello")
            receive_from(server, client, SERVER_ADDR)
            self.assertEqual(type(client.next_event()), events.StreamDataReceived)
            self.assertEqual(client.get_peer_address(), SERVER_PREFERRED_ADDR)

    def test_preferred_address_retired_before_validation(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = SERVER_PREFERRED_ADDRESS
            datagrams = client.datagrams_to_send(now=time.time())
            self.assertEqual(client._network_paths[1].peer_cid.sequence_number, 1)

            # The server retires the connection ID reserved for the probe.
            client._handle_new_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.NEW_CONNECTION_ID,
                new_connection_id(sequence_number=8, retire_prior_to=2),
            )
            self.assertIsNone(client._network_paths[1].peer_cid)
            self.assertIn(1, client._retire_connection_ids)

            # The path is validated, but the client does not migrate.
            for data, addr in datagrams:
                server.receive_datagram(data, CLIENT_ADDR, now=time.time())
            receive_from(server, client, SERVER_ADDR)
            self.assertTrue(client._network_paths[1].is_validated)
            self.assertEqual(client.get_peer_address(), SERVER_ADDR)
            self.assertEqual(client._peer_cid.sequence_number, 2)

    def test_preferred_address_selection(self):
        client = create_standalone_client(self)

        def preferred_address(ipv4_address=None, ipv6_address=None):
            return QuicPreferredAddress(
                ipv4_address=ipv4_address,
                ipv6_address=ipv6_address,
                connection_id=bytes(8),
                stateless_reset_token=bytes(16),
            )

        dual_stack = preferred_address(
            ipv4_address=("3.4.5.6", 4433), ipv6_address=("2001:db8::1", 4433)
        )

        for description, current_addr, preferred, expected_addr in [
            ("ipv4", ("2.3.4.5", 4433), dual_stack, ("3.4.5.6", 4433)),
            (
                "ipv4-mapped",
                ("::ffff:2.3.4.5", 4433, 0, 0),
                dual_stack,
                ("::ffff:3.4.5.6", 4433, 0, 0),
            ),
            (
                "ipv6",
                ("2001:db8::2", 4433, 0, 0),
                dual_stack,
                ("2001:db8::1", 4433, 0, 0),
            ),
            ("ipv6 2-tuple", ("2001:db8::2", 4433), dual_stack, ("2001:db8::1", 4433)),
            (
                "loopback from loopback",
                ("127.0.0.1", 4433),
                preferred_address(ipv4_address=("127.0.0.2", 4433)),
                ("127.0.0.2", 4433),
            ),
            (
                "loopback from ipv4-mapped loopback",
                ("::ffff:127.0.0.1", 4433, 0, 0),
                preferred_address(ipv4_address=("127.0.0.2", 4433)),
                ("::ffff:127.0.0.2", 4433, 0, 0),
            ),
            (
                "missing family",
                ("2001:db8::2", 4433),
                preferred_address(ipv4_address=("3.4.5.6", 4433)),
                None,
            ),
            ("current address", ("3.4.5.6", 4433), dual_stack, None),
            ("unparsable current address", ("example.com", 4433), dual_stack, None),
            (
                "port 0",
                ("2.3.4.5", 4433),
                preferred_address(ipv4_address=("3.4.5.6", 0)),
                None,
            ),
            (
                "ipv4 multicast",
                ("2.3.4.5", 4433),
                preferred_address(ipv4_address=("224.0.0.1", 4433)),
                None,
            ),
            (
                "ipv6 multicast",
                ("2001:db8::2", 4433),
                preferred_address(ipv6_address=("ff02::1", 4433)),
                None,
            ),
            (
                "ipv4 broadcast",
                ("2.3.4.5", 4433),
                preferred_address(ipv4_address=("255.255.255.255", 4433)),
                None,
            ),
            (
                "ipv4 loopback",
                ("::ffff:2.3.4.5", 4433, 0, 0),
                preferred_address(ipv4_address=("127.0.0.1", 4433)),
                None,
            ),
            (
                "ipv6 loopback",
                ("2001:db8::2", 4433),
                preferred_address(ipv6_address=("::1", 4433)),
                None,
            ),
            (
                "ipv4-mapped ipv6",
                ("2001:db8::2", 4433),
                preferred_address(ipv6_address=("::ffff:3.4.5.6", 4433)),
                None,
            ),
        ]:
            with self.subTest(description):
                client._network_paths[0].addr = current_addr
                client._remote_preferred_address = preferred
                self.assertEqual(client._find_preferred_address(), expected_addr)

    def test_preferred_address_without_matching_family(self):
        with client_and_server() as (client, server):
            client._remote_preferred_address = QuicPreferredAddress(
                ipv4_address=None,
                ipv6_address=("2001:db8::1", 4433),
                connection_id=bytes(8),
                stateless_reset_token=bytes(16),
            )

            # The client has no IPv6 address to probe and stays where it is.
            client.send_stream_data(0, b"hello")
            self.assertEqual(
                set(receive_from(client, server, CLIENT_ADDR)), {SERVER_ADDR}
            )
            self.assertIsNone(client._remote_preferred_address)
            self.assertEqual(len(client._network_paths), 1)

    def test_send_max_data_blocked_by_cc(self):
        with client_and_server() as (client, server):
            # Check congestion control. We do not check the congestion
            # window too strictly as its exact value depends on the size
            # of our ACKs, which depends on the execution time.
            self.assertEqual(client._loss.bytes_in_flight, 0)
            self.assertGreaterEqual(client._loss.congestion_window, 13472)
            self.assertLessEqual(client._loss.congestion_window, 13540)

            # artificially raise received data counter
            client._local_max_data_used = client._local_max_data
            self.assertEqual(server._remote_max_data, 1048576)

            # artificially raise bytes in flight
            client._loss._cc.bytes_in_flight = client._loss.congestion_window

            # MAX_DATA is not sent due to congestion control
            self.assertEqual(drop(client), 0)

    def test_send_max_data_retransmit(self):
        with client_and_server() as (client, server):
            # artificially raise received data counter
            client._local_max_data.used = client._local_max_data.value
            self.assertEqual(client._local_max_data.sent, 1048576)
            self.assertEqual(client._local_max_data.used, 1048576)
            self.assertEqual(client._local_max_data.value, 1048576)
            self.assertEqual(server._remote_max_data, 1048576)

            # MAX_DATA is sent and lost
            self.assertEqual(drop(client), 1)
            self.assertEqual(client._local_max_data.sent, 2097152)
            self.assertEqual(client._local_max_data.used, 1048576)
            self.assertEqual(client._local_max_data.value, 2097152)
            self.assertEqual(server._remote_max_data, 1048576)

            # MAX_DATA loss is detected
            client._on_connection_limit_delivery(
                QuicDeliveryState.LOST, client._local_max_data
            )
            self.assertEqual(client._local_max_data.sent, 0)
            self.assertEqual(client._local_max_data.used, 1048576)
            self.assertEqual(client._local_max_data.value, 2097152)

            # MAX_DATA is retransmitted and acked
            roundtrip_until_done(client, server)
            self.assertEqual(client._local_max_data.sent, 2097152)
            self.assertEqual(client._local_max_data.used, 1048576)
            self.assertEqual(client._local_max_data.value, 2097152)
            self.assertEqual(server._remote_max_data, 2097152)

    def test_send_max_stream_data_retransmit(self):
        with client_and_server() as (client, server):
            # client creates bidirectional stream 0
            stream = client._get_or_create_stream_for_send(stream_id=0)
            client.send_stream_data(0, b"hello")
            self.assertEqual(stream.max_stream_data_local, 1048576)
            self.assertEqual(stream.max_stream_data_local_sent, 1048576)
            self.assertEqual(roundtrip(client, server), (1, 1))

            # server sends data, just before raising MAX_STREAM_DATA
            server.send_stream_data(0, b"Z" * 524288)  # 1048576 // 2
            for i in range(10):
                roundtrip(server, client)
            self.assertEqual(stream.max_stream_data_local, 1048576)
            self.assertEqual(stream.max_stream_data_local_sent, 1048576)

            # server sends one more byte
            server.send_stream_data(0, b"Z")
            self.assertEqual(transfer(server, client), 1)

            # MAX_STREAM_DATA is sent and lost
            self.assertEqual(drop(client), 1)
            self.assertEqual(stream.max_stream_data_local, 2097152)
            self.assertEqual(stream.max_stream_data_local_sent, 2097152)
            client._on_max_stream_data_delivery(QuicDeliveryState.LOST, stream)
            self.assertEqual(stream.max_stream_data_local, 2097152)
            self.assertEqual(stream.max_stream_data_local_sent, 0)

            # MAX_STREAM_DATA is retransmitted and acked
            roundtrip_until_done(client, server)
            self.assertEqual(stream.max_stream_data_local, 2097152)
            self.assertEqual(stream.max_stream_data_local_sent, 2097152)

    def test_send_max_streams_retransmit(self):
        with client_and_server() as (client, server):
            # The client opens and closes 65 unidirectional streams.
            for i in range(65):
                client.send_stream_data(i * 4 + 2, b"", end_stream=True)
            self.assertEqual(transfer(client, server), 1)
            self.assertEqual(client._remote_max_streams_uni, 128)
            self.assertEqual(server._local_max_streams_uni.sent, 128)
            self.assertEqual(server._local_max_streams_uni.used, 65)
            self.assertEqual(server._local_max_streams_uni.value, 128)

            # The server discards the streams, then MAX_STREAMS is sent and lost.
            self.assertEqual(drop(server), 2)
            self.assertEqual(client._remote_max_streams_uni, 128)
            self.assertEqual(server._local_max_streams_uni.sent, 193)
            self.assertEqual(server._local_max_streams_uni.used, 65)
            self.assertEqual(server._local_max_streams_uni.value, 193)

            # MAX_STREAMS loss is detected.
            server._on_connection_limit_delivery(
                QuicDeliveryState.LOST, server._local_max_streams_uni
            )
            self.assertEqual(client._remote_max_streams_uni, 128)
            self.assertEqual(server._local_max_streams_uni.sent, 0)
            self.assertEqual(server._local_max_streams_uni.used, 65)
            self.assertEqual(server._local_max_streams_uni.value, 193)

            # MAX_STREAMS is retransmitted and acked.
            roundtrip_until_done(server, client)
            self.assertEqual(client._remote_max_streams_uni, 193)
            self.assertEqual(server._local_max_streams_uni.sent, 193)
            self.assertEqual(server._local_max_streams_uni.used, 65)
            self.assertEqual(server._local_max_streams_uni.value, 193)

    def test_send_ping(self):
        with client_and_server() as (client, server):
            consume_events(client)

            # client sends ping, server ACKs it
            client.send_ping(uid=12345)
            self.assertEqual(roundtrip(client, server), (1, 1))

            # check event
            event = client.next_event()
            self.assertEqual(type(event), events.PingAcknowledged)
            self.assertEqual(event.uid, 12345)

    def test_send_ping_retransmit(self):
        with client_and_server() as (client, server):
            consume_events(client)

            # client sends another ping, PING is lost
            client.send_ping(uid=12345)
            self.assertEqual(drop(client), 1)

            # PING is retransmitted and acked
            client._on_ping_delivery(QuicDeliveryState.LOST, (12345,))
            self.assertEqual(roundtrip(client, server), (1, 1))

            # check event
            event = client.next_event()
            self.assertEqual(type(event), events.PingAcknowledged)
            self.assertEqual(event.uid, 12345)

    def test_send_reset_stream(self):
        with client_and_server() as (client, server):
            # client creates bidirectional stream
            client.send_stream_data(0, b"hello")
            self.assertEqual(roundtrip(client, server), (1, 1))

            # client resets stream
            client.reset_stream(0, QuicErrorCode.NO_ERROR)
            self.assertEqual(roundtrip(client, server), (1, 1))

    def test_send_stop_sending(self):
        with client_and_server() as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # client creates bidirectional stream
            client.send_stream_data(0, b"hello")
            self.assertEqual(roundtrip(client, server), (1, 1))

            # client sends STOP_SENDING frame
            client.stop_stream(0, 0x11)
            self.assertEqual(roundtrip(client, server), (1, 1))

            # client receives STREAM_RESET frame, with the same error code
            event = client.next_event()
            self.assertEqual(type(event), events.StreamReset)
            self.assertEqual(event.error_code, 0x11)
            self.assertEqual(event.stream_id, 0)

    def test_send_stop_sending_uni_stream(self):
        with client_and_server() as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # client sends STOP_SENDING frame
            with self.assertRaises(ValueError) as cm:
                client.stop_stream(2, QuicErrorCode.NO_ERROR)
            self.assertEqual(
                str(cm.exception),
                "Cannot stop receiving on a local-initiated unidirectional stream",
            )

    def test_send_stop_sending_unknown_stream(self):
        with client_and_server() as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # client sends STOP_SENDING frame
            with self.assertRaises(ValueError) as cm:
                client.stop_stream(0, QuicErrorCode.NO_ERROR)
            self.assertEqual(
                str(cm.exception), "Cannot stop receiving on an unknown stream"
            )

    def test_send_stream_data_finished_stream(self):
        with client_and_server() as (client, server):
            # Client and server exchange data on bidirectional stream 0.
            client.send_stream_data(0, b"hello", end_stream=True)
            self.assertEqual(roundtrip(client, server), (1, 1))
            server.send_stream_data(0, b"world", end_stream=True)
            self.assertEqual(roundtrip(server, client), (1, 1))

            # The client discards the stream.
            self.assertEqual(roundtrip(client, server), (0, 0))
            self.assertNotIn(0, client._streams)

            # The client creates bidirectional stream 4.
            client.send_stream_data(4, b"hello")
            self.assertEqual(client.get_next_available_stream_id(), 8)

            # The client tries to send data on the finished stream.
            with self.assertRaises(ValueError) as cm:
                client.send_stream_data(0, b"hello")
            self.assertEqual(str(cm.exception), "Cannot send data on a finished stream")

            # The client resets the finished stream, which has no effect.
            client.reset_stream(0, QuicErrorCode.NO_ERROR)

            # The stream was not recreated.
            self.assertNotIn(0, client._streams)
            self.assertEqual(client.get_next_available_stream_id(), 8)

    def test_send_stream_data_finished_uni_stream(self):
        with client_and_server() as (client, server):
            # The client sends data on unidirectional stream 2.
            client.send_stream_data(2, b"hello", end_stream=True)
            self.assertEqual(roundtrip(client, server), (1, 1))

            # The client discards the stream once all data is acknowledged.
            self.assertEqual(roundtrip(client, server), (0, 0))
            self.assertNotIn(2, client._streams)

            # The client resets the finished stream, which has no effect.
            client.reset_stream(2, QuicErrorCode.NO_ERROR)
            self.assertNotIn(2, client._streams)
            self.assertEqual(roundtrip(client, server), (0, 0))

    def test_send_stream_data_over_max_streams_bidi(self):
        with client_and_server() as (client, server):
            # create streams
            for i in range(128):
                stream_id = i * 4
                client.send_stream_data(stream_id, b"")
                self.assertFalse(client._streams[stream_id].is_blocked)
            self.assertEqual(len(client._streams_blocked_bidi), 0)
            self.assertEqual(len(client._streams_blocked_uni), 0)
            self.assertEqual(roundtrip(client, server), (0, 0))

            # create one too many -> STREAMS_BLOCKED
            stream_id = 128 * 4
            client.send_stream_data(stream_id, b"")
            self.assertTrue(client._streams[stream_id].is_blocked)
            self.assertEqual(len(client._streams_blocked_bidi), 1)
            self.assertEqual(len(client._streams_blocked_uni), 0)
            self.assertEqual(roundtrip(client, server), (1, 1))

            # peer raises max streams
            client._handle_max_streams_bidi_frame(
                client_receive_context(client),
                QuicFrameType.MAX_STREAMS_BIDI,
                Buffer(data=encode_uint_var(129)),
            )
            self.assertFalse(client._streams[stream_id].is_blocked)

    def test_send_stream_data_over_max_streams_uni(self):
        with client_and_server() as (client, server):
            # create streams
            for i in range(128):
                stream_id = i * 4 + 2
                client.send_stream_data(stream_id, b"")
                self.assertFalse(client._streams[stream_id].is_blocked)
            self.assertEqual(len(client._streams_blocked_bidi), 0)
            self.assertEqual(len(client._streams_blocked_uni), 0)
            self.assertEqual(roundtrip(client, server), (0, 0))

            # create one too many -> STREAMS_BLOCKED
            stream_id = 128 * 4 + 2
            client.send_stream_data(stream_id, b"")
            self.assertTrue(client._streams[stream_id].is_blocked)
            self.assertEqual(len(client._streams_blocked_bidi), 0)
            self.assertEqual(len(client._streams_blocked_uni), 1)
            self.assertEqual(roundtrip(client, server), (1, 1))

            # peer raises max streams
            client._handle_max_streams_uni_frame(
                client_receive_context(client),
                QuicFrameType.MAX_STREAMS_UNI,
                Buffer(data=encode_uint_var(129)),
            )
            self.assertFalse(client._streams[stream_id].is_blocked)

    def test_send_stream_data_peer_initiated(self):
        with client_and_server() as (client, server):
            # server creates bidirectional stream
            server.send_stream_data(1, b"hello")
            self.assertEqual(roundtrip(server, client), (1, 1))

            # server creates unidirectional stream
            server.send_stream_data(3, b"hello")
            self.assertEqual(roundtrip(server, client), (1, 1))

            # client creates bidirectional stream
            client.send_stream_data(0, b"hello")
            self.assertEqual(roundtrip(client, server), (1, 1))

            # client sends data on server-initiated bidirectional stream
            client.send_stream_data(1, b"hello")
            self.assertEqual(roundtrip(client, server), (1, 1))

            # client creates unidirectional stream
            client.send_stream_data(2, b"hello")
            self.assertEqual(roundtrip(client, server), (1, 1))

            # client tries to reset server-initiated unidirectional stream
            with self.assertRaises(ValueError) as cm:
                client.reset_stream(3, QuicErrorCode.NO_ERROR)
            self.assertEqual(
                str(cm.exception),
                "Cannot send data on peer-initiated unidirectional stream",
            )

            # client tries to reset unknown server-initiated bidirectional stream
            with self.assertRaises(ValueError) as cm:
                client.reset_stream(5, QuicErrorCode.NO_ERROR)
            self.assertEqual(
                str(cm.exception), "Cannot send data on unknown peer-initiated stream"
            )

            # client tries to send data on server-initiated unidirectional stream
            with self.assertRaises(ValueError) as cm:
                client.send_stream_data(3, b"hello")
            self.assertEqual(
                str(cm.exception),
                "Cannot send data on peer-initiated unidirectional stream",
            )

            # client tries to send data on unknown server-initiated bidirectional stream
            with self.assertRaises(ValueError) as cm:
                client.send_stream_data(5, b"hello")
            self.assertEqual(
                str(cm.exception), "Cannot send data on unknown peer-initiated stream"
            )

    def test_send_stream_data_skipped_stream(self):
        with client_and_server() as (client, server):
            # The client creates bidirectional stream 8, skipping streams 0 and 4.
            client.send_stream_data(8, b"hello")
            self.assertEqual(client.get_next_available_stream_id(), 12)

            # The client tries to send data on a skipped stream.
            with self.assertRaises(ValueError) as cm:
                client.send_stream_data(0, b"hello")
            self.assertEqual(str(cm.exception), "Cannot send data on a finished stream")
            self.assertEqual(client.get_next_available_stream_id(), 12)

    def test_stream_direction(self):
        with client_and_server() as (client, server):
            for off in [0, 4, 8]:
                # Client-Initiated, Bidirectional
                self.assertTrue(client._stream_can_receive(off))
                self.assertTrue(client._stream_can_send(off))
                self.assertTrue(server._stream_can_receive(off))
                self.assertTrue(server._stream_can_send(off))

                # Server-Initiated, Bidirectional
                self.assertTrue(client._stream_can_receive(off + 1))
                self.assertTrue(client._stream_can_send(off + 1))
                self.assertTrue(server._stream_can_receive(off + 1))
                self.assertTrue(server._stream_can_send(off + 1))

                # Client-Initiated, Unidirectional
                self.assertFalse(client._stream_can_receive(off + 2))
                self.assertTrue(client._stream_can_send(off + 2))
                self.assertTrue(server._stream_can_receive(off + 2))
                self.assertFalse(server._stream_can_send(off + 2))

                # Server-Initiated, Unidirectional
                self.assertTrue(client._stream_can_receive(off + 3))
                self.assertFalse(client._stream_can_send(off + 3))
                self.assertFalse(server._stream_can_receive(off + 3))
                self.assertTrue(server._stream_can_send(off + 3))

    def test_version_negotiation_fail(self):
        client = create_standalone_client(self)

        # no common version, no retry
        client.receive_datagram(
            encode_quic_version_negotiation(
                source_cid=client._peer_cid.cid,
                destination_cid=client.host_cid,
                supported_versions=[0x1A2A3A4A],
            ),
            SERVER_ADDR,
            now=time.time(),
        )
        self.assertEqual(drop(client), 0)

        event = client.next_event()
        self.assertEqual(type(event), events.ConnectionTerminated)
        self.assertEqual(event.error_code, QuicErrorCode.INTERNAL_ERROR)
        self.assertEqual(event.frame_type, QuicFrameType.PADDING)
        self.assertEqual(
            event.reason_phrase, "Could not find a common protocol version"
        )

    def test_version_negotiation_ignore(self):
        client = create_standalone_client(self)

        # version negotiation contains the client's version
        client.receive_datagram(
            encode_quic_version_negotiation(
                source_cid=client._peer_cid.cid,
                destination_cid=client.host_cid,
                supported_versions=[client._version],
            ),
            SERVER_ADDR,
            now=time.time(),
        )
        self.assertEqual(drop(client), 0)

    def test_version_negotiation_ignore_server(self):
        server = create_standalone_server(self)

        # Servers do not expect version negotiation packets.
        server.receive_datagram(
            encode_quic_version_negotiation(
                source_cid=server._peer_cid.cid,
                destination_cid=server.host_cid,
                supported_versions=[QuicProtocolVersion.VERSION_1],
            ),
            CLIENT_ADDR,
            now=time.time(),
        )
        self.assertPacketDropped(server, "unexpected_packet")

    def test_version_negotiation_ok(self):
        client = create_standalone_client(
            self,
            supported_versions=[
                QuicProtocolVersion.VERSION_1,
                0x1A2A3A4A,
            ],
        )

        # found a common version, retry
        client.receive_datagram(
            encode_quic_version_negotiation(
                source_cid=client._peer_cid.cid,
                destination_cid=client.host_cid,
                supported_versions=[0x1A2A3A4A],
            ),
            SERVER_ADDR,
            now=time.time(),
        )
        self.assertEqual(drop(client), 1)

    def test_write_connection_close_early(self):
        client = create_standalone_client(self)

        builder = QuicPacketBuilder(
            host_cid=client.host_cid,
            is_client=True,
            max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
            peer_cid=client._peer_cid.cid,
            version=client._version,
        )
        crypto = CryptoPair()
        crypto.setup_initial(client.host_cid, is_client=True, version=client._version)
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        client._write_connection_close_frame(
            builder=builder,
            epoch=tls.Epoch.INITIAL,
            error_code=123,
            frame_type=None,
            reason_phrase="some reason",
        )

        self.assertEqual(
            builder.quic_logger_frames,
            [
                {
                    "error_code": QuicErrorCode.APPLICATION_ERROR,
                    "error_space": "transport",
                    "frame_type": "connection_close",
                    "raw_error_code": QuicErrorCode.APPLICATION_ERROR,
                    "reason": "",
                    "trigger_frame_type": QuicFrameType.PADDING,
                }
            ],
        )


class QuicNetworkPathTest(TestCase):
    def test_can_send(self):
        path = QuicNetworkPath(("1.2.3.4", 1234))
        self.assertFalse(path.is_validated)

        # initially, cannot send any data
        self.assertTrue(path.can_send(0))
        self.assertFalse(path.can_send(1))

        # receive some data
        path.bytes_received += 1
        self.assertTrue(path.can_send(0))
        self.assertTrue(path.can_send(1))
        self.assertTrue(path.can_send(2))
        self.assertTrue(path.can_send(3))
        self.assertFalse(path.can_send(4))

        # send some data
        path.bytes_sent += 3
        self.assertTrue(path.can_send(0))
        self.assertFalse(path.can_send(1))
