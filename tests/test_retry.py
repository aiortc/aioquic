from aioquic.quic.retry import QuicRetryTokenHandler

from .utils import TestCase


class QuicRetryTokenHandlerTest(TestCase):
    def test_retry_token(self) -> None:
        address = ("127.0.0.1", 1234)
        original_destination_connection_id = b"\x08\x07\x06\05\x04\x03\x02\x01"
        retry_source_connection_id = b"abcdefgh"

        handler = QuicRetryTokenHandler()

        # create token
        token = handler.create_token(
            address=address,
            original_destination_connection_id=original_destination_connection_id,
            retry_source_connection_id=retry_source_connection_id,
            now=10.0,
        )
        self.assertIsNotNone(token)
        self.assertEqual(len(token), 61)

        # validate token - ok
        self.assertEqual(
            handler.validate_token(
                address=address,
                destination_cid=retry_source_connection_id,
                token=token,
                now=10.0,
            ),
            original_destination_connection_id,
        )

        # validate token - ok, at the end of its lifetime
        self.assertEqual(
            handler.validate_token(
                address=address,
                destination_cid=retry_source_connection_id,
                token=token,
                now=40.0,
            ),
            original_destination_connection_id,
        )

        # validate token - expired
        with self.assertRaisesMessage(ValueError, "Token has expired."):
            handler.validate_token(
                address=address,
                destination_cid=retry_source_connection_id,
                token=token,
                now=40.001,
            )

        # validate token - empty
        with self.assertRaisesMessage(ValueError, "Token is invalid."):
            handler.validate_token(
                address=address,
                destination_cid=retry_source_connection_id,
                token=b"",
                now=10.0,
            )

        # validate token - truncated
        with self.assertRaisesMessage(ValueError, "Token is invalid."):
            handler.validate_token(
                address=address,
                destination_cid=retry_source_connection_id,
                token=token[:20],
                now=10.0,
            )

        # validate token - tampered
        with self.assertRaisesMessage(ValueError, "Token is invalid."):
            handler.validate_token(
                address=address,
                destination_cid=retry_source_connection_id,
                token=token[:-1] + bytes([token[-1] ^ 1]),
                now=10.0,
            )

        # validate token - issued by another handler
        with self.assertRaisesMessage(ValueError, "Token is invalid."):
            QuicRetryTokenHandler().validate_token(
                address=address,
                destination_cid=retry_source_connection_id,
                token=token,
                now=10.0,
            )

        # validate token - wrong address
        with self.assertRaisesMessage(ValueError, "Remote address does not match."):
            handler.validate_token(
                address=("1.2.3.4", 12345),
                destination_cid=retry_source_connection_id,
                token=token,
                now=10.0,
            )

        # validate token - wrong destination connection ID
        with self.assertRaisesMessage(
            ValueError, "Destination connection ID does not match."
        ):
            handler.validate_token(
                address=address, destination_cid=b"12345678", token=token, now=10.0
            )
