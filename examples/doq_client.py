import argparse
import asyncio
import logging
import pickle
import ssl
import struct
from typing import Optional, cast

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger
from dnslib.dns import QTYPE, DNSHeader, DNSQuestion, DNSRecord

logger = logging.getLogger("client")


class DnsClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[DNSRecord]] = None

    async def query(self, query_name: str, query_type: str) -> None:
        # serialize query
        query = DNSRecord(
            header=DNSHeader(id=0),
            q=DNSQuestion(query_name, getattr(QTYPE, query_type)),
        )
        data = bytes(query.pack())
        data = struct.pack("!H", len(data)) + data

        # send query and wait for answer
        stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data, end_stream=True)
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._ack_waiter is not None:
            if isinstance(event, StreamDataReceived):
                # parse answer
                length = struct.unpack("!H", bytes(event.data[:2]))[0]
                answer = DNSRecord.parse(event.data[2 : 2 + length])

                # return answer
                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(answer)


def save_session_ticket(ticket):
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def main(
    configuration: QuicConfiguration,
    host: str,
    port: int,
    query_name: str,
    query_type: str,
) -> None:
    logger.debug(f"Connecting to {host}:{port}")
    async with connect(
        host,
        port,
        configuration=configuration,
        session_ticket_handler=save_session_ticket,
        create_protocol=DnsClientProtocol,
    ) as client:
        client = cast(DnsClientProtocol, client)
        logger.debug("Sending DNS query")
        answer = await client.query(query_name, query_type)
        logger.info("Received DNS answer\n%s" % answer)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS over QUIC client")
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="The remote peer's host name or IP address",
    )
    parser.add_argument(
        "--port", type=int, default=853, help="The remote peer's port number"
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument("--query-name", required=True, help="Domain to query")
    parser.add_argument("--query-type", default="A", help="The DNS query type to send")
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    configuration = QuicConfiguration(alpn_protocols=["doq"], is_client=True)
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            logger.debug(f"Unable to read {args.session_ticket}")
            pass
    else:
        logger.debug("No session ticket defined...")

    asyncio.run(
        main(
            configuration=configuration,
            host=args.host,
            port=args.port,
            query_name=args.query_name,
            query_type=args.query_type,
        )
    )
