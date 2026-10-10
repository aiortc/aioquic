import struct
from typing import Optional

_uint16 = struct.Struct("!H")
_uint32 = struct.Struct("!L")
_uint64 = struct.Struct("!Q")


class BufferReadError(ValueError):
    pass


class BufferWriteError(ValueError):
    pass


class Buffer:
    __slots__ = ("_data", "_capacity", "_pos")

    def __init__(self, capacity: Optional[int] = 0, data: Optional[bytes] = None):
        if data is not None:
            self._data = bytearray(data)
        else:
            self._data = bytearray(capacity)
        self._capacity = len(self._data)
        self._pos = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def data(self) -> bytes:
        return bytes(self._data[: self._pos])

    def data_slice(self, start: int, end: int) -> bytes:
        if start < 0 or end > self._capacity or end < start:
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
        """
        Pull bytes.
        """
        end = self._pos + length
        if length < 0 or end > self._capacity:
            raise BufferReadError("Read out of bounds")
        value = bytes(self._data[self._pos : end])
        self._pos = end
        return value

    def pull_uint8(self) -> int:
        """
        Pull an 8-bit unsigned integer.
        """
        if self._pos >= self._capacity:
            raise BufferReadError("Read out of bounds")
        value = self._data[self._pos]
        self._pos += 1
        return value

    def _pull(self, fmt: struct.Struct) -> int:
        try:
            (value,) = fmt.unpack_from(self._data, self._pos)
        except struct.error:
            raise BufferReadError("Read out of bounds") from None
        self._pos += fmt.size
        return value

    def pull_uint16(self) -> int:
        """
        Pull a 16-bit unsigned integer.
        """
        return self._pull(_uint16)

    def pull_uint32(self) -> int:
        """
        Pull a 32-bit unsigned integer.
        """
        return self._pull(_uint32)

    def pull_uint64(self) -> int:
        """
        Pull a 64-bit unsigned integer.
        """
        return self._pull(_uint64)

    def pull_uint_var(self) -> int:
        """
        Pull a QUIC variable-length unsigned integer.
        """
        if self._pos >= self._capacity:
            raise BufferReadError("Read out of bounds")
        kind = self._data[self._pos] >> 6
        if kind == 0:
            value = self._data[self._pos]
            self._pos += 1
            return value
        elif kind == 1:
            return self._pull(_uint16) & 0x3FFF
        elif kind == 2:
            return self._pull(_uint32) & 0x3FFFFFFF
        else:
            return self._pull(_uint64) & 0x3FFFFFFFFFFFFFFF

    def push_bytes(self, value: bytes) -> None:
        """
        Push bytes.
        """
        end = self._pos + len(value)
        if end > self._capacity:
            raise BufferWriteError("Write out of bounds")
        self._data[self._pos : end] = value
        self._pos = end

    def push_uint8(self, value: int) -> None:
        """
        Push an 8-bit unsigned integer.
        """
        if self._pos >= self._capacity:
            raise BufferWriteError("Write out of bounds")
        self._data[self._pos] = value
        self._pos += 1

    def _push(self, fmt: struct.Struct, value: int) -> None:
        if self._pos + fmt.size > self._capacity:
            raise BufferWriteError("Write out of bounds")
        fmt.pack_into(self._data, self._pos, value)
        self._pos += fmt.size

    def push_uint16(self, value: int) -> None:
        """
        Push a 16-bit unsigned integer.
        """
        self._push(_uint16, value)

    def push_uint32(self, value: int) -> None:
        """
        Push a 32-bit unsigned integer.
        """
        self._push(_uint32, value)

    def push_uint64(self, value: int) -> None:
        """
        Push a 64-bit unsigned integer.
        """
        self._push(_uint64, value)

    def push_uint_var(self, value: int) -> None:
        """
        Push a QUIC variable-length unsigned integer.
        """
        if value <= 0x3F:
            self.push_uint8(value)
        elif value <= 0x3FFF:
            self._push(_uint16, value | 0x4000)
        elif value <= 0x3FFFFFFF:
            self._push(_uint32, value | 0x80000000)
        elif value <= 0x3FFFFFFFFFFFFFFF:
            self._push(_uint64, value | 0xC000000000000000)
        else:
            raise ValueError("Integer is too big for a variable-length integer")


UINT_VAR_MAX = 0x3FFFFFFFFFFFFFFF
UINT_VAR_MAX_SIZE = 8


def encode_uint_var(value: int) -> bytes:
    """
    Encode a variable-length unsigned integer.
    """
    buf = Buffer(capacity=UINT_VAR_MAX_SIZE)
    buf.push_uint_var(value)
    return buf.data


def size_uint_var(value: int) -> int:
    """
    Return the number of bytes required to encode the given value
    as a QUIC variable-length unsigned integer.
    """
    if value <= 0x3F:
        return 1
    elif value <= 0x3FFF:
        return 2
    elif value <= 0x3FFFFFFF:
        return 4
    elif value <= 0x3FFFFFFFFFFFFFFF:
        return 8
    else:
        raise ValueError("Integer is too big for a variable-length integer")
