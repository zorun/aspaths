from __future__ import print_function, unicode_literals

import sys
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address, IPv4Network
from collections import namedtuple
import random

from _pybgpstream import BGPStream, BGPRecord, BGPElem
from pytricia import PyTricia

from iplane import IPlaneTraceFile, Hop
import peeringdb


class ASPathsAnalyser(object):
    IPV4_NULLADDRESS = IPv4Address("0.0.0.0")

    def __init__(self, source_asn):
        self.source_asn = source_asn

    def load_ris(self, filename):
        """Loads a full RIS BGP table and store it in prefix trees for later use"""
        # This maps each IP prefix to a set of origin AS (singleton except for MOAS)
        self.bgp_origin = PyTricia()
        # This maps each IP prefix to its AS path as seen by self.source_asn
        self.bgp_aspath = PyTricia()
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
                        print("Warning: prefix {} with empty AS-path".format(prefix),
                              file=sys.stderr)
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
        print("[RIS] Loaded {} BGP prefixes in total".format(len(self.bgp_origin)),
              file=sys.stderr)
        print("[RIS] Loaded {} BGP prefixes from AS {}".format(len(self.bgp_aspath),
                                                               self.source_asn),
              file=sys.stderr)

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
        self.source_asn.  If no prefix is found, None is returned.
        """
        try:
            return self.bgp_aspath[ip]
        except KeyError:
            return None

    def load_peeringdb(self):
        p = peeringdb.PeeringDB('.')
        self.ix_prefixes = [ip_network(prefix) for prefix in p.prefixes_ipv4()]
        print("[peeringdb] Loaded {} prefixes".format(len(self.ix_prefixes)),
              file=sys.stderr)
        # Normalise keys (mostly useful for IPv6, where a single IP
        # can have many string representations)
        self.ix_ip = {ip_address(ip_str): int(asn) for (ip_str, asn) in p.ipv4_asn()}
        print("[peeringdb] Loaded {} exact IP-ASN matches".format(len(self.ix_ip)),
              file=sys.stderr)

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
        # TODO: post-process the raw AS-path
        return aspath

    def analyse_traceroute(self, traceroute):
        # Add the destination as final hop if it's not already the case
        if ip_address(traceroute.hops[-1].ip) != ip_address(traceroute.dest):
            final_hop = Hop(traceroute.dest, 0., 0)
            traceroute.hops.append(final_hop)
        aspath = self.traceroute_aspath(traceroute)
        bgp_aspath = self.ris_aspath_from_source(traceroute.dest.encode())
        # Debug:
        print(' '.join([hop.ip for hop in traceroute.hops]))
        print(aspath)
        print(bgp_aspath)

    def analyse_traceroutes(self, filename):
        with IPlaneTraceFile(filename) as f:
            for traceroute in f:
                self.analyse_traceroute(traceroute)


if __name__ == '__main__':
    source_asn = int(sys.argv[1])
    a = ASPathsAnalyser(source_asn)
    a.load_peeringdb()
    a.load_ris(sys.argv[2])
    a.analyse_traceroutes(sys.argv[3])
