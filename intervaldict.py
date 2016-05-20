# encoding: utf-8

from intervals import Interval


class IntervalDict(dict):
    """Dictionary whose keys are intervals, and d[x] looks for an interval
    containing x.

    Use at your own risk: behaviour is unspecified if some intervals
    overlap, or when mixing several types of interval (IntInterval,
    DateTimeInterval, etc).

    """

    def get(self, x):
        """TODO: Better data structure to avoid linear search."""
        for interval, value in self.items():
            if x in interval:
                return value

    def __getitem__(self, x):
        result = self.get(x)
        if result is None:
            raise KeyError(x)
        return result

    def __contains__(self, x):
        return any(x in interval for interval in self.keys())

    def fromdict(self, d):
        """Given a dictionary whose keys are "points" (int, datetime object,
        etc), build consecutive intervals by sorting the keys.  If
        k1 → v1 and k2 → v2 are consecutive entries in the original
        dictionary (after sorting on keys), then we add an entry
        [k1, k2) → v1.  The last entry kn → vn is transformed into
        [kn, inf) → vn.
        """
        data = sorted(d.items())
        if len(data) == 0:
            return
        for ((key1, value1), (key2, value2)) in zip(data, data[1:]):
            interval = Interval((key1, key2), lower_inc=True, upper_inc=False)
            self[interval] = value1
        # Last item is special
        (last_key, last_value) = data[-1]
        interval = Interval((last_key, None), lower_inc=True, upper_inc=False)
        self[interval] = last_value
