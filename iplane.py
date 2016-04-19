# encoding: utf-8
"""
iPlane parsing library, adapted from https://github.com/syakesaba/iplane
(MIT license)
"""

import ctypes
import struct
import itertools
from collections import namedtuple
from socket import inet_ntop, AF_INET


class Truncated_Error(Exception):
    def __init__(self, f):
        self.f = f
    def __str__(self):
        print "File %s seems to be truncated after %d Bytes"\
                     % (self.f.name, self.f.tell())

SIZEOF_INT = 4 # 4bytes = 32bit # ctypes.sizeof(ctypes.c_int)
SIZEOF_FLOAT = 4 # 4 Bytes = 32bit # ctypes.sizeof(ctypes.c_float)
RECORD_HEADER = "<iiii" # client_id, unique_id, record_size, len
TRACEROUTE_HEADER = "<4si" # dstip, hops
TRACEROUTE_HOP = "<4sfi" # hop_ip, lat, ttl


#Record = namedtuple('Record', ['client_id', 'unique_id', 'traceroutes'])
Traceroute = namedtuple('Traceroute', ['dest', 'nb_hops', 'hops'])
Hop = namedtuple('Hop', ['ip', 'rtt', 'ttl'])
    

class IPlaneTraceFile(file):
    """
    このクラスは http://iplane.cs.washington.edu/data/data.html
    にある、traceroute経路情報をピュアPythonでパースし、
    2重にイテレートできるようにするものです。
    Usage
    ===========
    f = IPlaneTraceFile("trace.out.planetlab1.dojima.wide.ad.jp", src="planetlab1.dojima.wide.ad.jp")
    for record in f:
        for dstip, hops, traceIter in record:
            path_to_dstip = dstip
            for hopped_ip, lat, ttl in traceIter:
                path_to_dstip = path_to_dstip + "=>" + hopped_ip
            print path_to_dstip
    ===========
    """

    def __init__(self, fname, src=None):
        file.__init__(self, fname)
        self.block = 0
        self.count = 0
        if src is None: #srcを省略した場合はファイル名をsrcにする。
            self.src = fname
        else:
            self.src = src
        self.record_size = 0

    def __iter__(self):
        return self

    def _readRecordHeader(self):
        try:
            return struct.unpack(RECORD_HEADER, self.read(4*SIZEOF_INT) )
            #return cId, uId, record_size, length
        except Exception as e:
            print e
            raise Truncated_Error(self)

    def _readTracerouteHeader(self):
        try:
            return struct.unpack(TRACEROUTE_HEADER, self.read(2*SIZEOF_INT))
            #return dstip, hops
        except Exception as e:
            print e
            raise Truncated_Error(self)

    def _readTracerouteHop(self):
        try:
            return struct.unpack(
                TRACEROUTE_HOP, self.read(
                    SIZEOF_INT + SIZEOF_FLOAT + SIZEOF_INT
                )
            )
            #return hopped_ip, lat, ttl
        except Exception as e:
            print e
            raise Truncated_Error(self)

    def next(self):
        # Move to the next record
        if self.count >= self.record_size:
            if self.read(1) != "":
                self.seek(self.tell()-1)
                self.cId, self.uId, self.record_size, self.length = self._readRecordHeader()
                self.count = 0
            else:
                raise StopIteration
            self.block = self.block + 1
        # Fetch next traceroute
        self.count = self.count + 1
        dstip, nb_hops = self._readTracerouteHeader()
        hops = []
        for i in range(nb_hops):
            hop_ip, lat, ttl = self._readTracerouteHop()
            if ttl > 512:
                raise Truncated_Error(self)
            # TODO: Python3 compatibility (inet_ntop already returns
            # an unicode string in Python3)
            hops.append(Hop(inet_ntop(AF_INET, hop_ip).decode(), lat, ttl))
        return Traceroute(inet_ntop(AF_INET, dstip).decode(), nb_hops, hops)

    def __del__(self):
        if not self.closed:
            try:
                self.close()
            except:
                pass
