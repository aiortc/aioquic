from typing import Optional


class BufferReadError(ValueError):
    pass


class BufferWriteError(ValueError):
    pass


class Buffer:
    def __init__(self, capacity: Optional[int] = 0, data: Optional[bytes] = None):
        self._pos = 0
        self._data = memoryview(bytearray(capacity if data is None else data))
        self._capacity = len(self._data)

    def _check_read_bounds(self, len: int) -> None:
        if len < 0 or self._capacity < self._pos + len:
            raise BufferReadError("Read out of bounds")

    def _check_write_bounds(self, len: int) -> None:
        if self._capacity < self._pos + len:
            raise BufferWriteError("Write out of bounds")

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def data(self) -> bytes:
        return bytes(self._data[0 : self._pos])

    def data_slice(self, start: int, end: int) -> bytes:
        if (
            start < 0
            or self._capacity < start
            or end < 0
            or self._capacity < end
            or end < start
        ):
            raise BufferReadError("Read out of bounds")
        return bytes(self._data[start:end])

    def eof(self) -> bool:
        return self._pos == self._capacity

    def seek(self, pos: int) -> None:
        if pos < 0 or pos > self._capacity:
            raise BufferReadError("Seek out of bounds")
        self._pos = pos

    def tell(self) -> int:
        return self._pos

    def pull_bytes(self, length: int) -> bytes:
        self._check_read_bounds(length)
        result = bytes(self._data[self._pos : (self._pos + length)])
        self._pos += length
        return result

    def pull_uint8(self) -> int:
        self._check_read_bounds(1)
        result = self._data[self._pos]
        self._pos += 1
        return result

    def pull_uint16(self) -> int:
        self._check_read_bounds(2)
        result = self._data[self._pos] << 8 | self._data[self._pos + 1]
        self._pos += 2
        return result

    def pull_uint32(self) -> int:
        self._check_read_bounds(4)
        result = (
            self._data[self._pos] << 24
            | self._data[self._pos + 1] << 16
            | self._data[self._pos + 2] << 8
            | self._data[self._pos + 3]
        )
        self._pos += 4
        return result

    def pull_uint64(self) -> int:
        self._check_read_bounds(8)
        result = (
            self._data[self._pos] << 56
            | self._data[self._pos + 1] << 48
            | self._data[self._pos + 2] << 40
            | self._data[self._pos + 3] << 32
            | self._data[self._pos + 4] << 24
            | self._data[self._pos + 5] << 16
            | self._data[self._pos + 6] << 8
            | self._data[self._pos + 7]
        )
        self._pos += 8
        return result

    def pull_uint_var(self) -> int:
        self._check_read_bounds(1)
        type = self._data[self._pos] >> 6
        if type == 0:
            result = self._data[self._pos] & 0x3F
            self._pos += 1
        elif type == 1:
            self._check_read_bounds(2)
            result = (self._data[self._pos] & 0x3F) << 8 | self._data[self._pos + 1]
            self._pos += 2
        elif type == 2:
            self._check_read_bounds(4)
            result = (
                (self._data[self._pos] & 0x3F) << 24
                | self._data[self._pos + 1] << 16
                | self._data[self._pos + 2] << 8
                | self._data[self._pos + 3]
            )
            self._pos += 4
        else:
            self._check_read_bounds(8)
            result = (
                (self._data[self._pos] & 0x3F) << 56
                | self._data[self._pos + 1] << 48
                | self._data[self._pos + 2] << 40
                | self._data[self._pos + 3] << 32
                | self._data[self._pos + 4] << 24
                | self._data[self._pos + 5] << 16
                | self._data[self._pos + 6] << 8
                | self._data[self._pos + 7]
            )
            self._pos += 8
        return result

    def push_bytes(self, value: bytes) -> None:
        length = len(value)
        self._check_write_bounds(length)
        self._data[self._pos : (self._pos + length)] = value
        self._pos += length

    def push_uint8(self, value: int) -> None:
        self._check_write_bounds(1)
        self._data[self._pos] = value
        self._pos += 1

    def push_uint16(self, value: int) -> None:
        self._check_write_bounds(2)
        self._data[self._pos] = value >> 8
        self._data[self._pos + 1] = value & 0xFF
        self._pos += 2

    def push_uint32(self, value: int) -> None:
        self._check_write_bounds(4)
        self._data[self._pos] = value >> 24
        self._data[self._pos + 1] = (value >> 16) & 0xFF
        self._data[self._pos + 2] = (value >> 8) & 0xFF
        self._data[self._pos + 3] = value & 0xFF
        self._pos += 4

    def push_uint64(self, value: int) -> None:
        self._check_write_bounds(8)
        self._data[self._pos] = value >> 56
        self._data[self._pos + 1] = (value >> 48) & 0xFF
        self._data[self._pos + 2] = (value >> 40) & 0xFF
        self._data[self._pos + 3] = (value >> 32) & 0xFF
        self._data[self._pos + 4] = (value >> 24) & 0xFF
        self._data[self._pos + 5] = (value >> 16) & 0xFF
        self._data[self._pos + 6] = (value >> 8) & 0xFF
        self._data[self._pos + 7] = value & 0xFF
        self._pos += 8

    def push_uint_var(self, value: int) -> None:
        if value <= 0x3F:
            self._check_write_bounds(1)
            self._data[self._pos] = value
            self._pos += 1
        elif value <= 0x3FFF:
            self._check_write_bounds(2)
            self._data[self._pos] = (value >> 8) | 0x40
            self._data[self._pos + 1] = value & 0xFF
            self._pos += 2
        elif value <= 0x3FFFFFFF:
            self._check_write_bounds(4)
            self._data[self._pos] = (value >> 24) | 0x80
            self._data[self._pos + 1] = (value >> 16) & 0xFF
            self._data[self._pos + 2] = (value >> 8) & 0xFF
            self._data[self._pos + 3] = value & 0xFF
            self._pos += 4
        elif value <= 0x3FFFFFFFFFFFFFFF:
            self._check_write_bounds(8)
            self._data[self._pos] = (value >> 56) | 0xC0
            self._data[self._pos + 1] = (value >> 48) & 0xFF
            self._data[self._pos + 2] = (value >> 40) & 0xFF
            self._data[self._pos + 3] = (value >> 32) & 0xFF
            self._data[self._pos + 4] = (value >> 24) & 0xFF
            self._data[self._pos + 5] = (value >> 16) & 0xFF
            self._data[self._pos + 6] = (value >> 8) & 0xFF
            self._data[self._pos + 7] = value & 0xFF
            self._pos += 8
        else:
            raise ValueError("Integer is too big for a variable-length integer")
