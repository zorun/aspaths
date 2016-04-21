from __future__ import print_function, unicode_literals

import sys
import os
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address, IPv4Network
from collections import namedtuple, Counter
import cPickle as pickle
import logging
import socket
from enum import Enum

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


class BGPTracerouteMatch(Enum):
    """
    Compare AS paths obtained by traceroute and those obtained by BGP, by classifying them.

    Note that the classes are not mutually exclusive!
    """
    exact_match = "Exact match"
    exact_match_only_known = "Exact match after removing unknown hops in traceroute"
    missing_in_bgp = "BGP AS-path is a strict subsequence of traceroute path"
    missing_in_traceroute = "Traceroute AS-path is a strict subsequence of BGP path"
    distinct_asn = "Both BGP and traceroute AS-paths exhibit distinct ASN"
    distinct_but_same_second = "Both AS-paths exhibit distinct ASN, but the second known ASN is the same"
    no_bgp = "Empty BGP AS-path"
    traceroute_loop = "AS loop in the traceroute (same AS seen at least 2 times)"


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

    def ris_remove_default_route(self):
        if self.bgp_origin.has_key(b'0.0.0.0/0'):
            self.bgp_origin.delete(b'0.0.0.0/0')
            logging.info("[RIS] Removed default route in bgp_origin")
        if self.bgp_aspath.has_key(b'0.0.0.0/0'):
            self.bgp_aspath.delete(b'0.0.0.0/0')
            logging.info("[RIS] Removed default route in bgp_aspath")

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
            self.ris_remove_default_route()
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
        self.ris_remove_default_route()
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
        prefix is found, an empty list is returned.
        """
        try:
            raw_path = self.bgp_aspath[ip]
            return list(utils.uniq(raw_path))
        except KeyError:
            return []

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
        Returns empty set if either:
          - the IP is a private or reserved address
          - the IP is part of an IX
          - no ASN can be found."""
        # TODO: distinguish IXP and no match
        assert(isinstance(ip, (IPv4Address, IPv6Address)))
        # Discard private, link-local, loopback, reserved, etc
        if ip.is_private or \
           ip.is_link_local or \
           ip.is_reserved or \
           ip.is_multicast or \
           ip.is_unspecified or \
           ip.is_loopback:
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
        hops = [hop.ip for hop in traceroute.hops]
        for ip_str in hops:
            ip = ip_address(ip_str)
            asn = self.ip_to_asn(ip)
            aspath.append(asn)
        # Step 1: add the source ASN in front
        aspath.insert(0, {self.source_asn})
        # Step 2: flatten any sequence of the form A * A where * is
        # unknown, recursively.
        while True:
            new_aspath = list(utils.uniq(aspath))
            new_aspath = list(utils.flatten_unknown(new_aspath))
            if new_aspath == aspath:
                break
            aspath = new_aspath
        return aspath

    def debug_traceroute(self, traceroute):
        """Pretty-print a traceroute with reverse DNS and inferred ASN for
        each hop."""
        data = list()
        max_len = [1, 1, 1]
        hops = [hop.ip for hop in traceroute.hops]
        for ip in hops:
            if ip == "0.0.0.0":
                data.append(('X', 'X', 'X'))
            else:
                asn_set = self.ip_to_asn(ip_address(ip))
                if len(asn_set) == 0:
                    asn = 'X'
                else:
                    asn = ','.join(str(asn) for asn in sorted(asn_set))
                hostname = socket.getfqdn(ip)
                if hostname == ip:
                    hostname = 'X'
                data.append((ip, asn, hostname))
                max_len[0] = max(max_len[0], len(ip))
                max_len[1] = max(max_len[1], len(asn))
                max_len[2] = max(max_len[2], len(hostname))
        for (ip, asn, hostname) in data:
            line = {'ip': ip, 'ip_len': max_len[0] + 1,
                    'asn': asn, 'asn_len': max_len[1] + 1,
                    'hostname': hostname, 'hostname_len': max_len[2] + 1}
            logging.debug(M('{ip:{ip_len}} {asn:{asn_len}} {hostname:{hostname_len}}',
                            **line))

    def debug_aspaths(self, traceroute_aspath, bgp_aspath):
        def format_asnset(asnset):
            if len(asnset) == 0:
                return 'X'
            if len(asnset) == 1:
                return str(list(asnset)[0])
            # Yes, it looks complicated, but it isn't (will print "{foo,bar}")
            return '{{{}}}'.format(','.join(str(asn) for asn in sorted(asnset)))
        traceroute = '  '.join(format_asnset(asnset) for asnset in traceroute_aspath)
        bgp = '  '.join(str(asn) for asn in bgp_aspath)
        logging.debug(M("BGP AS-path:        {}", bgp))
        logging.debug(M("Traceroute AS-path: {}", traceroute))

    def classify_match(self, trace_path, bgp_path):
        """Classify the relation between a traceroute AS path and a BGP AS path.
        Returns a set of BGPTracerouteMatch enum members"""
        res = set()
        if len(trace_path) == len(bgp_path) \
           and all([asn in asnset for (asnset, asn) in zip(trace_path, bgp_path)]):
            res.add(BGPTracerouteMatch.exact_match)
        trace_path_only_known = [asnset for asnset in trace_path if len(asnset) > 0]
        if len(trace_path_only_known) == len(bgp_path) \
           and all([asn in asnset for (asnset, asn) in zip(trace_path_only_known, bgp_path)]):
            res.add(BGPTracerouteMatch.exact_match_only_known)
        else:
            # In this branch, we didn't have an exact match, so the
            # subsequence must be strict.
            if utils.is_subsequence_set2(bgp_path, trace_path_only_known):
                res.add(BGPTracerouteMatch.missing_in_bgp)
            if utils.is_subsequence_set1(trace_path_only_known, bgp_path):
                res.add(BGPTracerouteMatch.missing_in_traceroute)
        # TODO: is this correct?
        bgp_ases = set(bgp_path)
        traceroute_ases = set()
        for asnset in trace_path:
            traceroute_ases.update(asnset)
        inter = traceroute_ases.intersection(bgp_ases)
        if inter != traceroute_ases and inter != bgp_ases:
            res.add(BGPTracerouteMatch.distinct_asn)
            if len(trace_path_only_known) >= 2 and len(bgp_path) >= 2 \
               and bgp_path[1] in trace_path_only_known[1]:
                res.add(BGPTracerouteMatch.distinct_but_same_second)
        if len(bgp_path) == 0:
            res.add(BGPTracerouteMatch.no_bgp)
        occurrences = Counter([frozenset(asnset) for asnset in trace_path])
        if occurrences.most_common(1)[0][1] > 1:
            res.add(BGPTracerouteMatch.traceroute_loop)
        return res

    def analyse_traceroute(self, traceroute):
        # Add the destination as final hop if it's not already the case
        if ip_address(traceroute.hops[-1].ip) != ip_address(traceroute.dest):
            final_hop = Hop(traceroute.dest, 0., 0)
            traceroute.hops.append(final_hop)
        aspath = self.traceroute_aspath(traceroute)
        bgp_aspath = self.ris_aspath_from_source(traceroute.dest.encode())
        matches = self.classify_match(aspath, bgp_aspath)
        logging.debug(M("Matches for {}: {}", traceroute.dest, ' '.join([m.name for m in matches])))
        if not BGPTracerouteMatch.exact_match_only_known in matches:
            if logging.root.isEnabledFor(logging.DEBUG):
                self.debug_aspaths(aspath, bgp_aspath)
                self.debug_traceroute(traceroute)
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
