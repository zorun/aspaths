from __future__ import print_function, unicode_literals

import sys
import os
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address, IPv4Network
from collections import namedtuple
import cPickle as pickle
import logging

from _pybgpstream import BGPStream, BGPRecord, BGPElem
from pytricia import PyTricia

from iplane import IPlaneTraceFile, Hop
import peeringdb
import utils


class M(object):
    """Simple message class to allow to use {}-style formatting with the
    logging module.  For details, see:

    https://docs.python.org/3/howto/logging-cookbook.html#using-custom-message-objects

    """
    def __init__(self, fmt, *args, **kwargs):
        self.fmt = fmt
        self.args = args
        self.kwargs = kwargs

    def __str__(self):
        return self.fmt.format(*self.args, **self.kwargs)


class ASPathsAnalyser(object):
    IPV4_NULLADDRESS = IPv4Address("0.0.0.0")
    CACHE_BASEDIR = "cache"

    def __init__(self, source_asn):
        self.source_asn = source_asn

    def ris_cache_filename(self, ris_filename):
        """Use the input filename and source ASN to determine a cache filename"""
        ris_filename = os.path.basename(ris_filename)
        return os.path.join(self.CACHE_BASEDIR,
                            ris_filename + "_" + str(self.source_asn) + ".pickle")

    def save_ris_cache(self, ris_filename):
        """Dump bgp_origin and bgp_aspath to a file for later reuse.

        Experiments on a full RIB from RIS collector rrc12 show a
        14-times improvement in loading time (16 seconds vs. 232
        seconds), but also an increase in RAM usage while
        pickling/unpickling (1042 MB peak usage when saving, 777 MB
        peak usage when loading, 554 MB peak usage without cache).
        """
        try:
            os.mkdir(self.CACHE_BASEDIR)
        except OSError:
            pass
        cachename = self.ris_cache_filename(ris_filename)
        # PyTricia objects cannot be pickled, we need to transform
        # them first.
        serialise = lambda tree: tuple((prefix, tree[prefix]) for prefix in tree)
        obj = (serialise(self.bgp_origin), serialise(self.bgp_aspath))
        with open(cachename, "w") as f:
            pickle.dump(obj, f)

    def load_ris_cache(self, ris_filename):
        """Try to load bgp_origin and bgp_aspath from cache, returns True if
        successful"""
        cachename = self.ris_cache_filename(ris_filename)
        if not os.path.isfile(cachename):
            return False
        with open(cachename, "r") as f:
            # TODO: handle more pickle exceptions
            try:
                (bgp_origin, bgp_aspath) = pickle.load(f)
            except EOFError:
                return False
        def deserialise(obj):
            p = PyTricia()
            for (prefix, value) in obj:
                p[prefix] = value
            return p
        self.bgp_origin = deserialise(bgp_origin)
        self.bgp_aspath = deserialise(bgp_aspath)
        return True

    def load_ris(self, filename):
        """Loads a full RIS BGP table and store it in prefix trees for later use.
        A pickled cache is kept to avoid recomputing prefix trees."""
        # This maps each IP prefix to a set of origin AS (singleton except for MOAS)
        self.bgp_origin = PyTricia()
        # This maps each IP prefix to its AS path as seen by self.source_asn
        self.bgp_aspath = PyTricia()
        # Try to load from cache
        if self.load_ris_cache(filename):
            logging.info(M("[RIS] Loaded {} BGP prefixes from cache", len(self.bgp_origin)))
            logging.info(M("[RIS] Loaded {} BGP prefixes from AS {} from cache",
                           len(self.bgp_aspath), self.source_asn))
            return
        # No cache, use BGPstream to parse the RIS dump.
        record = BGPRecord()
        stream = BGPStream()
        stream.set_data_interface("singlefile")
        stream.set_data_interface_option("singlefile", "rib-file", filename)
        # Add additional filters here
        stream.start()
        while(stream.get_next_record(record)):
            if record.status == "valid":
                elem = record.get_next_elem()
                while(elem):
                    prefix = elem.fields['prefix']
                    # Discard IPv6 prefixes (crude but fast)
                    if ':' in prefix:
                        elem = record.get_next_elem()
                        continue
                    if len(elem.fields['as-path']) == 0:
                        logging.warning(M("Prefix {} with empty AS-path", prefix))
                        elem = record.get_next_elem()
                        continue
                    # First get the origin AS
                    origin = elem.fields['as-path'].split(b' ')[-1]
                    # In rare cases, we have an as-set (BGP aggregation).
                    if '{' in origin:
                        origin = {int(asn) for asn in origin.strip(b'{}').split(b',')}
                    else:
                        origin = {int(origin)}
                    if self.bgp_origin.has_key(prefix):
                        self.bgp_origin[prefix].update(origin)
                    else:
                        self.bgp_origin[prefix] = origin
                    # If received from self.source_asn, record the whole AS-path
                    if elem.peer_asn == self.source_asn:
                        # In rare cases, we have an as-set (BGP aggregation).
                        # We simply take the first ASN for now.
                        # TODO: possible MOAS
                        as_path = [int(asn.strip(b'{}').split(b',')[0])
                                   for asn in elem.fields['as-path'].split(b' ')]
                        self.bgp_aspath[prefix] = as_path
                    elem = record.get_next_elem()
        logging.info(M("[RIS] Loaded {} BGP prefixes in total", len(self.bgp_origin)))
        logging.info(M("[RIS] Loaded {} BGP prefixes from AS {}",
                       len(self.bgp_aspath), self.source_asn))
        logging.info("[RIS] Saving data to pickle cache")
        self.save_ris_cache(filename)

    def ris_origin_asn(self, ip):
        """Returns a set of origin ASN for the given IP address, by looking at
        the most specific prefix covering the IP.  If no such prefix
        exists, an empty set is returned.
        """
        try:
            return self.bgp_origin[ip]
        except KeyError:
            return set()

    def ris_aspath_from_source(self, ip):
        """Returns the AS-path for the most specific prefix seen by
        self.source_asn, with AS-path prepending removed.  If no
        prefix is found, None is returned.
        """
        try:
            raw_path = self.bgp_aspath[ip]
            return list(utils.uniq(raw_path))
        except KeyError:
            return None

    def load_peeringdb(self):
        p = peeringdb.PeeringDB('.')
        self.ix_prefixes = [ip_network(prefix) for prefix in p.prefixes_ipv4()]
        logging.info(M("[peeringdb] Loaded {} prefixes", len(self.ix_prefixes)))
        # Normalise keys (mostly useful for IPv6, where a single IP
        # can have many string representations)
        self.ix_ip = {ip_address(ip_str): int(asn) for (ip_str, asn) in p.ipv4_asn()}
        logging.info(M("[peeringdb] Loaded {} exact IP-ASN matches", len(self.ix_ip)))

    def is_in_ix(self, ip):
        # Linear search is OK performance-wise, we only have a few
        # hundreds prefixes.
        assert(isinstance(ip, (IPv4Address, IPv6Address)))
        return any((ip in prefix for prefix in self.ix_prefixes))

    def ip_to_asn(self, ip):
        """Translate an IP address to a set of ASN, using peeringdb and RIS.
        Returns empty set if the IP is part of an IX or if no ASN can be found."""
        # TODO: MOAS?
        # TODO: distinguish IXP and no match
        assert(isinstance(ip, (IPv4Address, IPv6Address)))
        # 0.0.0.0 represents an empty hop (and is an unusable IP anyway)
        if ip == self.IPV4_NULLADDRESS:
            return set()
        # Exact match in peeringdb
        if ip in self.ix_ip:
            return {self.ix_ip[ip]}
        # Prefix match in peeringdb
        if self.is_in_ix(ip):
            return set()
        # Best prefix match in RIS
        return self.ris_origin_asn(str(ip))

    def traceroute_aspath(self, traceroute):
        """Given a traceroute, compute an AS-path."""
        aspath = []
        for ip_str in [hop.ip for hop in traceroute.hops]:
            ip = ip_address(ip_str)
            asn = self.ip_to_asn(ip)
            aspath.append(asn)
        # Step 1: flatten any sequence of the form A * A where * is
        # unknown, recursively.
        while True:
            new_aspath = list(utils.uniq(aspath))
            new_aspath = list(utils.flatten_unknown(new_aspath))
            if new_aspath == aspath:
                break
            aspath = new_aspath
        return aspath

    def analyse_traceroute(self, traceroute):
        # Add the destination as final hop if it's not already the case
        if ip_address(traceroute.hops[-1].ip) != ip_address(traceroute.dest):
            final_hop = Hop(traceroute.dest, 0., 0)
            traceroute.hops.append(final_hop)
        aspath = self.traceroute_aspath(traceroute)
        bgp_aspath = self.ris_aspath_from_source(traceroute.dest.encode())
        # Debug:
        logging.debug(' '.join([hop.ip for hop in traceroute.hops]))
        logging.debug(aspath)
        logging.debug(bgp_aspath)
        logging.debug('--')

    def analyse_traceroutes(self, filename):
        with IPlaneTraceFile(filename) as f:
            for traceroute in f:
                self.analyse_traceroute(traceroute)


if __name__ == '__main__':
    # TODO: change the logging level using a command-line argument
    logging.basicConfig(format='%(message)s',
                        level=logging.DEBUG)
    source_asn = int(sys.argv[1])
    a = ASPathsAnalyser(source_asn)
    a.load_peeringdb()
    a.load_ris(sys.argv[2])
    a.analyse_traceroutes(sys.argv[3])
