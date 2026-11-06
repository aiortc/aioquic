from unittest import TestCase

from aioquic.buffer import UINT_VAR_MAX
from aioquic.quic.events import StreamDataReceived, StreamReset
from aioquic.quic.packet import QuicErrorCode, QuicStreamFrame
from aioquic.quic.packet_builder import QuicDeliveryState
from aioquic.quic.stream import (
    FinalSizeError,
    QuicStream,
    ReliableSizeError,
    StreamStateError,
)


class QuicStreamTest(TestCase):
    def test_receiver_empty(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 0)

        # empty
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"")), None
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 0)

    def test_receiver_ordered(self) -> None:
        stream = QuicStream(stream_id=0)

        # add data at start
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0),
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 8)
        self.assertEqual(stream.receiver.highest_offset, 8)
        self.assertFalse(stream.receiver.is_finished)

        # add more data
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=8, data=b"89012345")),
            StreamDataReceived(data=b"89012345", end_stream=False, stream_id=0),
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 16)
        self.assertEqual(stream.receiver.highest_offset, 16)
        self.assertFalse(stream.receiver.is_finished)

        # add data and fin
        self.assertEqual(
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=16, data=b"67890123", fin=True)
            ),
            StreamDataReceived(data=b"67890123", end_stream=True, stream_id=0),
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 24)
        self.assertEqual(stream.receiver.highest_offset, 24)
        self.assertTrue(stream.receiver.is_finished)

    def test_receiver_unordered(self) -> None:
        stream = QuicStream(stream_id=0)

        # add data at offset 8
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=8, data=b"89012345")),
            None,
        )
        self.assertEqual(
            bytes(stream.receiver._buffer), b"\x00\x00\x00\x00\x00\x00\x00\x0089012345"
        )
        self.assertEqual(list(stream.receiver._ranges), [range(8, 16)])
        self.assertEqual(stream.receiver._buffer_start, 0)
        self.assertEqual(stream.receiver.highest_offset, 16)

        # add data at offset 0
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            StreamDataReceived(data=b"0123456789012345", end_stream=False, stream_id=0),
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 16)
        self.assertEqual(stream.receiver.highest_offset, 16)

    def test_receiver_offset_only(self) -> None:
        stream = QuicStream(stream_id=0)

        # add data at offset 0
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"")), None
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 0)
        self.assertEqual(stream.receiver.highest_offset, 0)

        # add data at offset 8
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=8, data=b"")), None
        )
        self.assertEqual(
            bytes(stream.receiver._buffer), b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 0)
        self.assertEqual(stream.receiver.highest_offset, 8)

    def test_receiver_already_fully_consumed(self) -> None:
        stream = QuicStream(stream_id=0)

        # add data at offset 0
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0),
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 8)

        # add data again at offset 0
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            None,
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 8)

        # add data again at offset 0
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01")), None
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 8)

    def test_receiver_already_partially_consumed(self) -> None:
        stream = QuicStream(stream_id=0)

        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0),
        )

        self.assertEqual(
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=0, data=b"0123456789012345")
            ),
            StreamDataReceived(data=b"89012345", end_stream=False, stream_id=0),
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 16)

    def test_receiver_already_partially_consumed_2(self) -> None:
        stream = QuicStream(stream_id=0)

        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0),
        )

        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=16, data=b"abcdefgh")),
            None,
        )

        self.assertEqual(
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=2, data=b"23456789012345")
            ),
            StreamDataReceived(data=b"89012345abcdefgh", end_stream=False, stream_id=0),
        )
        self.assertEqual(bytes(stream.receiver._buffer), b"")
        self.assertEqual(list(stream.receiver._ranges), [])
        self.assertEqual(stream.receiver._buffer_start, 24)

    def test_receiver_fin(self) -> None:
        stream = QuicStream(stream_id=0)

        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0),
        )
        self.assertEqual(
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True)
            ),
            StreamDataReceived(data=b"89012345", end_stream=True, stream_id=0),
        )

    def test_receiver_fin_below_received_data(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=4, data=b"4567"))

        # The final size is below data already received.
        with self.assertRaises(FinalSizeError) as cm:
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=0, data=b"01", fin=True)
            )
        self.assertEqual(str(cm.exception), "Data received beyond final size")

    def test_receiver_fin_out_of_order(self) -> None:
        stream = QuicStream(stream_id=0)

        # add data at offset 8 with FIN
        self.assertEqual(
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True)
            ),
            None,
        )
        self.assertEqual(stream.receiver.highest_offset, 16)
        self.assertFalse(stream.receiver.is_finished)

        # add data at offset 0
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            StreamDataReceived(data=b"0123456789012345", end_stream=True, stream_id=0),
        )
        self.assertEqual(stream.receiver.highest_offset, 16)
        self.assertTrue(stream.receiver.is_finished)

    def test_receiver_fin_then_data(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"0123", fin=True))

        # data beyond final size
        with self.assertRaises(FinalSizeError) as cm:
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567"))
        self.assertEqual(str(cm.exception), "Data received beyond final size")

        # final size would be lowered
        with self.assertRaises(FinalSizeError) as cm:
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=0, data=b"01", fin=True)
            )
        self.assertEqual(str(cm.exception), "Cannot change final size")

    def test_receiver_fin_twice(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")),
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0),
        )
        self.assertEqual(
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True)
            ),
            StreamDataReceived(data=b"89012345", end_stream=True, stream_id=0),
        )

        # the duplicate FIN is ignored
        self.assertEqual(
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True)
            ),
            None,
        )

    def test_receiver_fin_without_data(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"", fin=True)),
            StreamDataReceived(data=b"", end_stream=True, stream_id=0),
        )

    def test_receiver_reset(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )
        self.assertEqual(stream.receiver.highest_offset, 4)
        self.assertTrue(stream.receiver.is_finished)

    def test_receiver_reset_after_fin(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"0123", fin=True))

        # all data was received, the reset is ignored
        self.assertEqual(stream.receiver.handle_reset(final_size=4), None)

    def test_receiver_reset_after_fin_out_of_order(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=2, data=b"23", fin=True))

        # some data is missing, the reset is reported
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )

    def test_receiver_reset_after_reset_at_reduces_reliable_size(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_reset_at(
            error_code=QuicErrorCode.NO_ERROR, final_size=4, reliable_size=3
        )
        self.assertEqual(
            stream.receiver.handle_reset(
                error_code=QuicErrorCode.NO_ERROR, final_size=4
            ),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )
        self.assertEqual(stream.receiver._reset_at_reliable_size, 0)

    def test_receiver_reset_at_after_fin(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"data", fin=True))
        self.assertIsNone(
            stream.receiver.handle_reset_at(
                error_code=QuicErrorCode.NO_ERROR,
                final_size=4,
                reliable_size=2,
            )
        )

    def test_receiver_reset_at_error_code_cannot_change(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_reset_at(
            error_code=QuicErrorCode.INTERNAL_ERROR, final_size=4, reliable_size=2
        )
        with self.assertRaises(StreamStateError):
            stream.receiver.handle_reset_at(
                error_code=QuicErrorCode.NO_ERROR, final_size=4, reliable_size=1
            )
        with self.assertRaises(StreamStateError):
            stream.receiver.handle_reset(
                error_code=QuicErrorCode.NO_ERROR, final_size=4
            )

    def test_receiver_reset_at_rejects_invalid_final_size(self) -> None:
        stream = QuicStream(stream_id=0)
        with self.assertRaises(ReliableSizeError):
            stream.receiver.handle_reset_at(
                error_code=QuicErrorCode.NO_ERROR,
                final_size=1,
                reliable_size=2,
            )

        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"data"))
        with self.assertRaises(FinalSizeError):
            stream.receiver.handle_reset_at(
                error_code=QuicErrorCode.NO_ERROR,
                final_size=3,
                reliable_size=2,
            )

        stream = QuicStream(stream_id=0)
        stream.receiver.handle_reset_at(
            error_code=QuicErrorCode.NO_ERROR, final_size=4, reliable_size=0
        )
        with self.assertRaises(FinalSizeError):
            stream.receiver.handle_reset_at(
                error_code=QuicErrorCode.NO_ERROR,
                final_size=5,
                reliable_size=0,
            )

    def test_receiver_reset_at_after_reliable_data(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"0123")),
            StreamDataReceived(data=b"0123", end_stream=False, stream_id=0),
        )
        self.assertEqual(
            stream.receiver.handle_reset_at(
                error_code=QuicErrorCode.INTERNAL_ERROR,
                final_size=8,
                reliable_size=4,
            ),
            StreamReset(error_code=QuicErrorCode.INTERNAL_ERROR, stream_id=0),
        )
        self.assertTrue(stream.receiver.is_finished)
        self.assertIsNone(stream.receiver.take_reset_event())

    def test_receiver_reset_at_uses_smallest_reliable_size(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_reset_at(
            error_code=QuicErrorCode.INTERNAL_ERROR, final_size=8, reliable_size=6
        )
        stream.receiver.handle_reset_at(
            error_code=QuicErrorCode.INTERNAL_ERROR, final_size=8, reliable_size=3
        )
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"012")),
            StreamDataReceived(data=b"012", end_stream=False, stream_id=0),
        )
        self.assertEqual(
            stream.receiver.take_reset_event(),
            StreamReset(error_code=QuicErrorCode.INTERNAL_ERROR, stream_id=0),
        )

    def test_receiver_reset_at_waits_for_reliable_data(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertIsNone(
            stream.receiver.handle_reset_at(
                error_code=QuicErrorCode.INTERNAL_ERROR,
                final_size=8,
                reliable_size=5,
            )
        )

        # Out-of-order data is buffered until the reliable prefix is complete.
        self.assertIsNone(
            stream.receiver.handle_frame(QuicStreamFrame(offset=5, data=b"567"))
        )
        self.assertIsNone(stream.receiver.take_reset_event())
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234")),
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0),
        )
        self.assertEqual(
            stream.receiver.take_reset_event(),
            StreamReset(error_code=QuicErrorCode.INTERNAL_ERROR, stream_id=0),
        )
        self.assertTrue(stream.receiver.is_finished)

    def test_receiver_reset_below_received_data(self) -> None:
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567"))

        # The final size is below data already received.
        with self.assertRaises(FinalSizeError) as cm:
            stream.receiver.handle_reset(final_size=4)
        self.assertEqual(str(cm.exception), "Data received beyond final size")

    def test_receiver_reset_then_data(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )

        # data received after the reset is ignored
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"0123")),
            None,
        )

        # data beyond final size
        with self.assertRaises(FinalSizeError) as cm:
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567"))
        self.assertEqual(str(cm.exception), "Data received beyond final size")

    def test_receiver_reset_twice(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )

        # the duplicate reset is ignored
        self.assertEqual(stream.receiver.handle_reset(final_size=4), None)

    def test_receiver_reset_twice_final_size_error(self) -> None:
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )

        with self.assertRaises(FinalSizeError) as cm:
            stream.receiver.handle_reset(final_size=5)
        self.assertEqual(str(cm.exception), "Cannot change final size")

    def test_receiver_stop(self) -> None:
        stream = QuicStream()

        # stop is requested
        stream.receiver.stop(QuicErrorCode.NO_ERROR)
        self.assertTrue(stream.receiver.stop_pending)

        # stop is sent
        frame = stream.receiver.get_stop_frame()
        self.assertEqual(frame.error_code, QuicErrorCode.NO_ERROR)
        self.assertFalse(stream.receiver.stop_pending)

        # stop is acklowledged
        stream.receiver.on_stop_sending_delivery(QuicDeliveryState.ACKED)
        self.assertFalse(stream.receiver.stop_pending)

    def test_receiver_stop_lost(self) -> None:
        stream = QuicStream()

        # stop is requested
        stream.receiver.stop(QuicErrorCode.NO_ERROR)
        self.assertTrue(stream.receiver.stop_pending)

        # stop is sent
        frame = stream.receiver.get_stop_frame()
        self.assertEqual(frame.error_code, QuicErrorCode.NO_ERROR)
        self.assertFalse(stream.receiver.stop_pending)

        # stop is lost
        stream.receiver.on_stop_sending_delivery(QuicDeliveryState.LOST)
        self.assertTrue(stream.receiver.stop_pending)

        # stop is sent again
        frame = stream.receiver.get_stop_frame()
        self.assertEqual(frame.error_code, QuicErrorCode.NO_ERROR)
        self.assertFalse(stream.receiver.stop_pending)

        # stop is acklowledged
        stream.receiver.on_stop_sending_delivery(QuicDeliveryState.ACKED)
        self.assertFalse(stream.receiver.stop_pending)

    def test_sender_data(self) -> None:
        stream = QuicStream()
        self.assertEqual(stream.sender.next_offset, 0)

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)

        # write data
        stream.sender.write(b"0123456789012345")
        self.assertEqual(list(stream.sender._pending), [range(0, 16)])
        self.assertEqual(stream.sender.next_offset, 0)

        # send a chunk
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"01234567")
        self.assertFalse(frame.fin)
        self.assertEqual(frame.offset, 0)
        self.assertEqual(list(stream.sender._pending), [range(8, 16)])
        self.assertEqual(stream.sender.next_offset, 8)

        # send another chunk
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"89012345")
        self.assertFalse(frame.fin)
        self.assertEqual(frame.offset, 8)
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 16)

        # nothing more to send
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 16)

        # first chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 8, False)
        self.assertFalse(stream.sender.is_finished)

        # second chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 8, 16, False)
        self.assertFalse(stream.sender.is_finished)

    def test_sender_data_and_fin(self) -> None:
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        self.assertEqual(list(stream.sender._pending), [range(0, 16)])
        self.assertEqual(stream.sender.next_offset, 0)

        # send a chunk
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"01234567")
        self.assertFalse(frame.fin)
        self.assertEqual(frame.offset, 0)
        self.assertEqual(stream.sender.next_offset, 8)

        # send another chunk
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"89012345")
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 8)
        self.assertEqual(stream.sender.next_offset, 16)

        # nothing more to send
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)
        self.assertEqual(stream.sender.next_offset, 16)

        # first chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 8, False)
        self.assertFalse(stream.sender.is_finished)

        # second chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 8, 16, True)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_data_and_fin_ack_out_of_order(self) -> None:
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        self.assertEqual(list(stream.sender._pending), [range(0, 16)])
        self.assertEqual(stream.sender.next_offset, 0)

        # send a chunk
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"01234567")
        self.assertFalse(frame.fin)
        self.assertEqual(frame.offset, 0)
        self.assertEqual(stream.sender.next_offset, 8)

        # send another chunk
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"89012345")
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 8)
        self.assertEqual(stream.sender.next_offset, 16)

        # nothing more to send
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)
        self.assertEqual(stream.sender.next_offset, 16)

        # second chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 8, 16, True)
        self.assertFalse(stream.sender.is_finished)

        # first chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 8, False)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_data_lost(self) -> None:
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        self.assertEqual(list(stream.sender._pending), [range(0, 16)])
        self.assertEqual(stream.sender.next_offset, 0)

        # send a chunk
        self.assertEqual(
            stream.sender.get_frame(8),
            QuicStreamFrame(data=b"01234567", fin=False, offset=0),
        )
        self.assertEqual(list(stream.sender._pending), [range(8, 16)])
        self.assertEqual(stream.sender.next_offset, 8)

        # send another chunk
        self.assertEqual(
            stream.sender.get_frame(8),
            QuicStreamFrame(data=b"89012345", fin=True, offset=8),
        )
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 16)

        # nothing more to send
        self.assertIsNone(stream.sender.get_frame(8))
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 16)

        # a chunk gets lost
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 0, 8, False)
        self.assertEqual(list(stream.sender._pending), [range(0, 8)])
        self.assertEqual(stream.sender.next_offset, 0)

        # send chunk again
        self.assertEqual(
            stream.sender.get_frame(8),
            QuicStreamFrame(data=b"01234567", fin=False, offset=0),
        )
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 16)

    def test_sender_data_lost_fin(self) -> None:
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        self.assertEqual(list(stream.sender._pending), [range(0, 16)])
        self.assertEqual(stream.sender.next_offset, 0)

        # send a chunk
        self.assertEqual(
            stream.sender.get_frame(8),
            QuicStreamFrame(data=b"01234567", fin=False, offset=0),
        )
        self.assertEqual(list(stream.sender._pending), [range(8, 16)])
        self.assertEqual(stream.sender.next_offset, 8)

        # send another chunk
        self.assertEqual(
            stream.sender.get_frame(8),
            QuicStreamFrame(data=b"89012345", fin=True, offset=8),
        )
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 16)

        # nothing more to send
        self.assertIsNone(stream.sender.get_frame(8))
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 16)

        # a chunk gets lost
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 8, 16, True)
        self.assertEqual(list(stream.sender._pending), [range(8, 16)])
        self.assertEqual(stream.sender.next_offset, 8)

        # send chunk again
        self.assertEqual(
            stream.sender.get_frame(8),
            QuicStreamFrame(data=b"89012345", fin=True, offset=8),
        )
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 16)

        # first chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 8, False)
        self.assertFalse(stream.sender.is_finished)

        # second chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 8, 16, True)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_blocked(self) -> None:
        stream = QuicStream()
        max_offset = 12

        # nothing to send yet
        frame = stream.sender.get_frame(8, max_offset)
        self.assertIsNone(frame)
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 0)

        # write data, send a chunk
        stream.sender.write(b"0123456789012345")
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"01234567")
        self.assertFalse(frame.fin)
        self.assertEqual(frame.offset, 0)
        self.assertEqual(list(stream.sender._pending), [range(8, 16)])
        self.assertEqual(stream.sender.next_offset, 8)

        # send is limited by peer
        frame = stream.sender.get_frame(8, max_offset)
        self.assertEqual(frame.data, b"8901")
        self.assertFalse(frame.fin)
        self.assertEqual(frame.offset, 8)
        self.assertEqual(list(stream.sender._pending), [range(12, 16)])
        self.assertEqual(stream.sender.next_offset, 12)

        # unable to send, blocked
        frame = stream.sender.get_frame(8, max_offset)
        self.assertIsNone(frame)
        self.assertEqual(list(stream.sender._pending), [range(12, 16)])
        self.assertEqual(stream.sender.next_offset, 12)

        # write more data, still blocked
        stream.sender.write(b"abcdefgh")
        frame = stream.sender.get_frame(8, max_offset)
        self.assertIsNone(frame)
        self.assertEqual(list(stream.sender._pending), [range(12, 24)])
        self.assertEqual(stream.sender.next_offset, 12)

        # peer raises limit, send some data
        max_offset += 8
        frame = stream.sender.get_frame(8, max_offset)
        self.assertEqual(frame.data, b"2345abcd")
        self.assertFalse(frame.fin)
        self.assertEqual(frame.offset, 12)
        self.assertEqual(list(stream.sender._pending), [range(20, 24)])
        self.assertEqual(stream.sender.next_offset, 20)

        # peer raises limit again, send remaining data
        max_offset += 8
        frame = stream.sender.get_frame(8, max_offset)
        self.assertEqual(frame.data, b"efgh")
        self.assertFalse(frame.fin)
        self.assertEqual(frame.offset, 20)
        self.assertEqual(list(stream.sender._pending), [])
        self.assertEqual(stream.sender.next_offset, 24)

        # nothing more to send
        frame = stream.sender.get_frame(8, max_offset)
        self.assertIsNone(frame)

    def test_sender_fin_only(self) -> None:
        stream = QuicStream()

        # nothing to send yet
        self.assertTrue(stream.sender.buffer_is_empty)
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)

        # write EOF
        stream.sender.write(b"", end_stream=True)
        self.assertFalse(stream.sender.buffer_is_empty)
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"")
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 0)

        # nothing more to send
        self.assertFalse(stream.sender.buffer_is_empty)  # FIXME?
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)
        self.assertTrue(stream.sender.buffer_is_empty)

        # EOF is acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 0, True)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_fin_only_despite_blocked(self) -> None:
        stream = QuicStream()

        # nothing to send yet
        self.assertTrue(stream.sender.buffer_is_empty)
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)

        # write EOF
        stream.sender.write(b"", end_stream=True)
        self.assertFalse(stream.sender.buffer_is_empty)
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"")
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 0)

        # nothing more to send
        self.assertFalse(stream.sender.buffer_is_empty)  # FIXME?
        frame = stream.sender.get_frame(8)
        self.assertIsNone(frame)
        self.assertTrue(stream.sender.buffer_is_empty)

    def test_sender_fin_only_without_room(self) -> None:
        """
        A FIN without data waits for a packet with room for the frame header.
        """
        stream = QuicStream()
        stream.sender.write(b"", end_stream=True)

        # No room for the frame header.
        frame = stream.sender.get_frame(-1)
        self.assertIsNone(frame)
        self.assertFalse(stream.sender.buffer_is_empty)

        # Just enough room for the frame header.
        frame = stream.sender.get_frame(0)
        self.assertEqual(frame.data, b"")
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 0)

    def test_sender_fin_then_ack(self) -> None:
        stream = QuicStream()

        # send some data
        stream.sender.write(b"data")
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"data")

        # data is acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 4, False)
        self.assertFalse(stream.sender.is_finished)

        # write EOF
        stream.sender.write(b"", end_stream=True)
        self.assertFalse(stream.sender.buffer_is_empty)
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"")
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 4)

        # EOF is acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 4, 4, True)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_reset(self) -> None:
        stream = QuicStream()

        # send some data and EOF
        stream.sender.write(b"data", end_stream=True)
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"data")
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 0)

        # reset is requested
        stream.sender.reset(QuicErrorCode.NO_ERROR)
        self.assertTrue(stream.sender.buffer_is_empty)
        self.assertTrue(stream.sender.reset_pending)

        # reset is sent
        reset = stream.sender.get_reset_frame()
        self.assertEqual(reset.error_code, QuicErrorCode.NO_ERROR)
        self.assertEqual(reset.final_size, 4)
        self.assertFalse(stream.sender.reset_pending)
        self.assertFalse(stream.sender.is_finished)

        # data and EOF are acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 4, True)
        self.assertTrue(stream.sender.buffer_is_empty)
        self.assertFalse(stream.sender.is_finished)

        # reset is acklowledged
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED)
        self.assertFalse(stream.sender.reset_pending)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_reset_after_fin_acked(self) -> None:
        stream = QuicStream()

        # Data and EOF are sent and acknowledged.
        stream.sender.write(b"data", end_stream=True)
        frame = stream.sender.get_frame(8)
        stream.sender.on_data_delivery(
            QuicDeliveryState.ACKED, frame.offset, frame.offset + 4, frame.fin
        )
        self.assertTrue(stream.sender.is_finished)

        # A reset is requested, which has no effect.
        stream.sender.reset(QuicErrorCode.NO_ERROR)
        self.assertFalse(stream.sender.reset_pending)

    def test_sender_reset_after_reset_at_reduces_reliable_size_to_zero(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"data")
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 3)
        stream.sender.reset(QuicErrorCode.NO_ERROR)
        self.assertEqual(stream.sender.reset_reliable_size, 0)
        self.assertTrue(stream.sender.reset_pending)
        self.assertEqual(stream.sender.get_reset_frame().final_size, 3)

    def test_sender_reset_at_after_reset_has_no_effect(self) -> None:
        stream = QuicStream()
        stream.sender.reset(QuicErrorCode.INTERNAL_ERROR)
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 0)
        self.assertIsNone(stream.sender.reset_reliable_size)
        self.assertTrue(stream.sender.reset_pending)

    def test_sender_reset_at_after_finished_has_no_effect(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"data")
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 4)
        stream.sender.get_reset_frame()
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 4, False)
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED, 4)
        self.assertTrue(stream.sender.is_finished)

        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 2)
        self.assertEqual(stream.sender.reset_reliable_size, 4)
        self.assertFalse(stream.sender.reset_pending)

    def test_sender_reset_at_ignores_stale_reset_ack(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"data")
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 4)
        stream.sender.get_reset_frame()
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 2)
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED, 4)
        self.assertFalse(stream.sender.is_finished)
        self.assertTrue(stream.sender.reset_pending)

    def test_sender_reset_at_preserves_sent_final_size(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"abcdefgh", end_stream=True)
        frame = stream.sender.get_frame(8)
        self.assertTrue(frame.fin)
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 4)
        self.assertEqual(stream.sender.get_reset_frame().final_size, 8)
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 0, 8, True)
        self.assertEqual(list(stream.sender._pending), [range(0, 4)])

    def test_sender_reset_at_reduces_reliable_size(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"abcdefgh")
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 6)
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 3)
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 5)
        self.assertEqual(stream.sender.reset_reliable_size, 3)
        self.assertEqual(list(stream.sender._pending), [range(0, 3)])

    def test_sender_reset_at_reducing_reliable_size_preserves_final_size(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"abcdef")
        stream.sender.get_frame(3)
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 5)
        self.assertEqual(stream.sender.get_reset_frame().final_size, 5)

        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 2)
        self.assertEqual(stream.sender.reset_final_size, 5)
        self.assertEqual(stream.sender.get_reset_frame().final_size, 5)

    def test_sender_reset_at_rejects_invalid_reliable_size(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"data")
        for reliable_size in (-1, UINT_VAR_MAX + 1, 5):
            with self.subTest(reliable_size=reliable_size):
                with self.assertRaises(ValueError):
                    stream.sender.reset_at(QuicErrorCode.NO_ERROR, reliable_size)

    def test_sender_reset_at_retransmits_reliable_prefix(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"abcdefghij")
        stream.sender.reset_at(QuicErrorCode.INTERNAL_ERROR, 4)
        self.assertEqual(list(stream.sender._pending), [range(0, 4)])

        self.assertEqual(
            stream.sender.get_frame(8),
            QuicStreamFrame(data=b"abcd", fin=False, offset=0),
        )
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 0, 4, False)
        self.assertEqual(list(stream.sender._pending), [range(0, 4)])
        self.assertEqual(
            stream.sender.get_frame(8),
            QuicStreamFrame(data=b"abcd", fin=False, offset=0),
        )

        reset = stream.sender.get_reset_frame()
        self.assertEqual(reset.final_size, 4)
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED, 4)
        self.assertFalse(stream.sender.is_finished)
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 4, False)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_reset_lost(self) -> None:
        stream = QuicStream()

        # reset is requested
        stream.sender.reset(QuicErrorCode.NO_ERROR)
        self.assertTrue(stream.sender.buffer_is_empty)
        self.assertTrue(stream.sender.reset_pending)

        # reset is sent
        reset = stream.sender.get_reset_frame()
        self.assertEqual(reset.error_code, QuicErrorCode.NO_ERROR)
        self.assertEqual(reset.final_size, 0)
        self.assertFalse(stream.sender.reset_pending)

        # reset is lost
        stream.sender.on_reset_delivery(QuicDeliveryState.LOST)
        self.assertTrue(stream.sender.reset_pending)
        self.assertFalse(stream.sender.is_finished)

        # reset is sent again
        reset = stream.sender.get_reset_frame()
        self.assertEqual(reset.error_code, QuicErrorCode.NO_ERROR)
        self.assertEqual(reset.final_size, 0)
        self.assertFalse(stream.sender.reset_pending)

        # reset is acklowledged
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED)
        self.assertFalse(stream.sender.reset_pending)
        self.assertTrue(stream.sender.buffer_is_empty)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_reset_with_data_lost(self) -> None:
        stream = QuicStream()

        # send some data and EOF
        stream.sender.write(b"data", end_stream=True)
        frame = stream.sender.get_frame(8)
        self.assertEqual(frame.data, b"data")
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 0)

        # reset is requested
        stream.sender.reset(QuicErrorCode.NO_ERROR)
        self.assertTrue(stream.sender.buffer_is_empty)
        self.assertTrue(stream.sender.reset_pending)

        # reset is sent
        reset = stream.sender.get_reset_frame()
        self.assertEqual(reset.error_code, QuicErrorCode.NO_ERROR)
        self.assertEqual(reset.final_size, 4)
        self.assertFalse(stream.sender.reset_pending)
        self.assertFalse(stream.sender.is_finished)

        # data and EOF are lost
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 0, 4, True)
        self.assertTrue(stream.sender.buffer_is_empty)
        self.assertFalse(stream.sender.is_finished)

        # reset is acklowledged
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED)
        self.assertFalse(stream.sender.reset_pending)
        self.assertTrue(stream.sender.buffer_is_empty)
        self.assertTrue(stream.sender.is_finished)

    def test_sender_write_after_fin(self) -> None:
        stream = QuicStream()
        stream.sender.write(b"data", end_stream=True)

        with self.assertRaises(RuntimeError) as cm:
            stream.sender.write(b"more")
        self.assertEqual(str(cm.exception), "Cannot send data after FIN")

    def test_sender_write_after_reset(self) -> None:
        stream = QuicStream()
        stream.sender.reset(QuicErrorCode.NO_ERROR)

        with self.assertRaises(RuntimeError) as cm:
            stream.sender.write(b"data")
        self.assertEqual(
            str(cm.exception), "Cannot send data after the stream was reset"
        )
