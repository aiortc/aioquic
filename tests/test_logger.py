import json
import os
import tempfile
from unittest import TestCase

from aioquic.quic.logger import QuicFileLogger, QuicLogger

SINGLE_TRACE = {
    "qlog_format": "JSON",
    "qlog_version": "0.3",
    "traces": [
        {
            "common_fields": {
                "ODCID": "0000000000000000",
            },
            "events": [],
            "vantage_point": {"name": "aioquic", "type": "client"},
        }
    ],
}


class QuicLoggerTest(TestCase):
    def test_empty(self):
        logger = QuicLogger()
        self.assertEqual(
            logger.to_dict(),
            {"qlog_format": "JSON", "qlog_version": "0.3", "traces": []},
        )

    def test_single_trace(self):
        logger = QuicLogger()
        trace = logger.start_trace(is_client=True, odcid=bytes(8))
        logger.end_trace(trace)
        self.assertEqual(logger.to_dict(), SINGLE_TRACE)


class QuicFileLoggerTest(TestCase):
    def test_invalid_path(self):
        with self.assertRaises(ValueError) as cm:
            QuicFileLogger("this_path_should_not_exist")
        self.assertEqual(
            str(cm.exception),
            "QUIC log output directory 'this_path_should_not_exist' does not exist",
        )

    def test_single_trace(self):
        with tempfile.TemporaryDirectory() as dirpath:
            logger = QuicFileLogger(dirpath)
            trace = logger.start_trace(is_client=True, odcid=bytes(8))
            logger.end_trace(trace)

            filepath = os.path.join(dirpath, "0000000000000000.qlog")
            self.assertTrue(os.path.exists(filepath))

            with open(filepath, "r") as fp:
                data = json.load(fp)
            self.assertEqual(data, SINGLE_TRACE)
