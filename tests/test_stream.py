from unittest import TestCase

from aioquic.quic.events import StreamDataReceived, StreamReset
from aioquic.quic.packet import QuicErrorCode, QuicStreamFrame
from aioquic.quic.packet_builder import QuicDeliveryState
from aioquic.quic.stream import FinalSizeError, QuicStream


class QuicStreamTest(TestCase):
    def test_receiver_empty(self):
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

    def test_receiver_ordered(self):
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

    def test_receiver_unordered(self):
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

    def test_receiver_offset_only(self):
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

    def test_receiver_already_fully_consumed(self):
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

    def test_receiver_already_partially_consumed(self):
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

    def test_receiver_already_partially_consumed_2(self):
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

    def test_receiver_fin(self):
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

    def test_receiver_fin_out_of_order(self):
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

    def test_receiver_fin_then_data(self):
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

    def test_receiver_fin_twice(self):
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

        self.assertEqual(
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True)
            ),
            StreamDataReceived(data=b"", end_stream=True, stream_id=0),
        )

    def test_receiver_fin_without_data(self):
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"", fin=True)),
            StreamDataReceived(data=b"", end_stream=True, stream_id=0),
        )

    def test_receiver_reset(self):
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )
        self.assertTrue(stream.receiver.is_finished)

    def test_receiver_reset_after_fin(self):
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"0123", fin=True))
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )

    def test_receiver_reset_twice(self):
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )

    def test_receiver_reset_twice_final_size_error(self):
        stream = QuicStream(stream_id=0)
        self.assertEqual(
            stream.receiver.handle_reset(final_size=4),
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0),
        )

        with self.assertRaises(FinalSizeError) as cm:
            stream.receiver.handle_reset(final_size=5)
        self.assertEqual(str(cm.exception), "Cannot change final size")

    def test_receiver_stop(self):
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

    def test_receiver_stop_lost(self):
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

    def test_sender_data(self):
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

    def test_sender_data_and_fin(self):
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

    def test_sender_data_and_fin_ack_out_of_order(self):
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

    def test_sender_data_lost(self):
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

    def test_sender_data_lost_fin(self):
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

    def test_sender_blocked(self):
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

    def test_sender_fin_only(self):
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

    def test_sender_fin_only_despite_blocked(self):
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

    def test_sender_fin_then_ack(self):
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

    def test_sender_reset(self):
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

    def test_sender_reset_lost(self):
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

    def test_sender_reset_with_data_lost(self):
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
