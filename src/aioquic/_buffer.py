import struct
from typing import Optional

uint16 = struct.Struct(">H")
uint32 = struct.Struct(">L")
uint64 = struct.Struct(">Q")


class BufferReadError(ValueError):
    def __init__(self, message: str = "Read out of bounds") -> None:
        super().__init__(message)


class BufferWriteError(ValueError):
    def __init__(self, message: str = "Write out of bounds") -> None:
        super().__init__(message)


class Buffer:
    def __init__(self, capacity: int = 0, data: Optional[bytes] = None):
        self._pos = 0
        self._data = memoryview(bytearray(capacity if data is None else data))
        self._capacity = len(self._data)

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
            raise BufferReadError()
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
        if length < 0 or self._capacity < self._pos + length:
            raise BufferReadError()
        result = bytes(self._data[self._pos : (self._pos + length)])
        self._pos += length
        return result

    def pull_uint8(self) -> int:
        try:
            result = self._data[self._pos]
        except IndexError:
            raise BufferReadError()
        self._pos += 1
        return result

    def pull_uint16(self) -> int:
        try:
            (result,) = uint16.unpack_from(self._data, self._pos)
        except struct.error:
            raise BufferReadError()
        self._pos += 2
        return result

    def pull_uint32(self) -> int:
        try:
            (result,) = uint32.unpack_from(self._data, self._pos)
        except struct.error:
            raise BufferReadError()
        self._pos += 4
        return result

    def pull_uint64(self) -> int:
        try:
            (result,) = uint64.unpack_from(self._data, self._pos)
        except struct.error:
            raise BufferReadError()
        self._pos += 8
        return result

    def pull_uint_var(self) -> int:
        try:
            first = self._data[self._pos]
        except IndexError:
            raise BufferReadError()
        type = first >> 6
        if type == 0:
            self._pos += 1
            return first
        elif type == 1:
            return self.pull_uint16() & 0x3FFF
        elif type == 2:
            return self.pull_uint32() & 0x3FFFFFFF
        else:
            return self.pull_uint64() & 0x3FFFFFFFFFFFFFFF

    def push_bytes(self, value: bytes) -> None:
        end_pos = self._pos + len(value)
        if self._capacity < end_pos:
            raise BufferWriteError()
        self._data[self._pos : end_pos] = value
        self._pos = end_pos

    def push_uint8(self, value: int) -> None:
        try:
            self._data[self._pos] = value
        except IndexError:
            raise BufferWriteError()
        self._pos += 1

    def push_uint16(self, value: int) -> None:
        try:
            uint16.pack_into(self._data, self._pos, value)
        except struct.error:
            raise BufferWriteError()
        self._pos += 2

    def push_uint32(self, value: int) -> None:
        try:
            uint32.pack_into(self._data, self._pos, value)
        except struct.error:
            raise BufferWriteError()
        self._pos += 4

    def push_uint64(self, value: int) -> None:
        try:
            uint64.pack_into(self._data, self._pos, value)
        except struct.error:
            raise BufferWriteError()
        self._pos += 8

    def push_uint_var(self, value: int) -> None:
        if value <= 0x3F:
            self.push_uint8(value)
        elif value <= 0x3FFF:
            self.push_uint16(value | 0x4000)
        elif value <= 0x3FFFFFFF:
            self.push_uint32(value | 0x80000000)
        elif value <= 0x3FFFFFFFFFFFFFFF:
            self.push_uint64(value | 0xC000000000000000)
        else:
            raise ValueError("Integer is too big for a variable-length integer")
