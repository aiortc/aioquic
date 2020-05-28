import json
import os

from aioquic.quic.logger import QuicLogger, QuicLoggerTrace


class QuicDirectoryLogger(QuicLogger):
    """
    Custom QUIC logger which writes one trace per file.
    """

    def __init__(self, path: str) -> None:
        if not os.path.isdir(path):
            raise ValueError("QUIC log output directory '%s' does not exist" % path)
        self.path = path
        super().__init__()

    def end_trace(self, trace: QuicLoggerTrace) -> None:
        trace_dict = trace.to_dict()
        trace_path = os.path.join(
            self.path, trace_dict["common_fields"]["ODCID"] + ".qlog"
        )
        with open(trace_path, "w") as logger_fp:
            json.dump({"qlog_version": "draft-01", "traces": [trace_dict]}, logger_fp)
        self._traces.remove(trace)
