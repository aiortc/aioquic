from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Iterator, Sequence
from operator import attrgetter
from typing import Any


class RangeSet(Sequence):
    def __init__(self, ranges: Iterable[range] = []):
        self.__ranges: list[range] = []
        for r in ranges:
            assert r.step == 1
            self.add(r.start, r.stop)

    def add(self, start: int, stop: int | None = None) -> None:
        if stop is None:
            stop = start + 1
        assert stop > start

        # Find the first item which the added range is not entirely after.
        i = bisect_left(self.__ranges, start, key=_stop)

        # The added range is entirely after all existing items, append it.
        if i == len(self.__ranges):
            self.__ranges.append(range(start, stop))
            return

        # The added range is entirely before the item, insert it.
        r = self.__ranges[i]
        if stop < r.start:
            self.__ranges.insert(i, range(start, stop))
            return

        # The added range touches the item, merge it.
        start = min(start, r.start)
        j = i + 1
        if j == len(self.__ranges) or stop < self.__ranges[j].start:
            self.__ranges[i] = range(start, max(stop, r.stop))
            return

        # The added range also touches the following items, merge them all.
        j = bisect_right(self.__ranges, stop, lo=j + 1, key=_start)
        self.__ranges[i:j] = [range(start, max(stop, self.__ranges[j - 1].stop))]

    def bounds(self) -> range:
        return range(self.__ranges[0].start, self.__ranges[-1].stop)

    def shift(self) -> range:
        return self.__ranges.pop(0)

    def subtract(self, start: int, stop: int) -> None:
        assert stop > start

        i = 0
        while i < len(self.__ranges):
            r = self.__ranges[i]

            # the removed range is entirely before current item, stop here
            if stop <= r.start:
                return

            # the removed range is entirely after current item, keep looking
            if start >= r.stop:
                i += 1
                continue

            # the removed range completely covers the current item, remove it
            if start <= r.start and stop >= r.stop:
                self.__ranges.pop(i)
                continue

            # the removed range touches the current item
            if start > r.start:
                self.__ranges[i] = range(r.start, start)
                if stop < r.stop:
                    self.__ranges.insert(i + 1, range(stop, r.stop))
            else:
                self.__ranges[i] = range(stop, r.stop)

            i += 1

    def __bool__(self) -> bool:
        raise NotImplementedError

    def __contains__(self, val: Any) -> bool:
        for r in self.__ranges:
            if val in r:
                return True
        return False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RangeSet):
            return NotImplemented

        return self.__ranges == other.__ranges

    def __getitem__(self, key: Any) -> range:
        return self.__ranges[key]

    def __iter__(self) -> Iterator[range]:
        return iter(self.__ranges)

    def __len__(self) -> int:
        return len(self.__ranges)

    def __repr__(self) -> str:
        return f"RangeSet({self.__ranges!r})"


# Created once, as creating them in each call to `add()` doubles the cost of the
# search for small sets.
_start = attrgetter("start")
_stop = attrgetter("stop")
