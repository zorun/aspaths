from __future__ import print_function, unicode_literals

import sys
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address, IPv4Network
from collections import namedtuple
import random

from _pybgpstream import BGPStream, BGPRecord, BGPElem

from iplane import IPlaneTraceFile, Hop
import peeringdb


BGPdata = namedtuple('BGPdata', ['prefix', 'as_path'])


class ASPathsAnalyser(object):
    IPV4_NULLADDRESS = IPv4Address("0.0.0.0")

    def __init__(self, source_asn):
        self.source_asn = source_asn

    def load_ris(self, filename):
        # TODO: faster datastructure
        self.bgp = list()
        record = BGPRecord()
        stream = BGPStream()
        stream.set_data_interface("singlefile")
        stream.set_data_interface_option("singlefile", "rib-file", filename)
        # Add additional filters here
        stream.start()
        count = 0
        while(stream.get_next_record(record)):
            if record.status == "valid":
                elem = record.get_next_elem()
                while(elem):
                    count += 1
                    # for testing: only pick one element in X
                    if count % 2 != 0:
                        break
                    prefix = ip_network(elem.fields['prefix'].decode())
                    if not isinstance(prefix, IPv4Network):
                        elem = record.get_next_elem()
                        continue
                    if len(elem.fields['as-path']) == 0:
                        print("Warning: prefix {} with empty AS-path".format(prefix),
                              file=sys.stderr)
                        elem = record.get_next_elem()
                        continue
                    # In rare cases, we have an as-set (BGP aggregation).
                    # We simply take the first ASN for now.
                    # TODO: possible MOAS
                    as_path = [int(asn.strip(b'{}').split(b',')[0])
                               for asn in elem.fields['as-path'].split(b' ')]
                    d = BGPdata(prefix=prefix,
                                as_path=as_path)
                    self.bgp.append(d)
                    elem = record.get_next_elem()
            # For testing
            #if count > 300000:
            #    break
        print("[RIS] Loaded {} BGP elements".format(len(self.bgp)),
              file=sys.stderr)

    def ris_best_prefix_match(self, ip, first_asn=None):
        """If [first_asn] is set, only look at BGP data with the specified ASN
        as first ASN.
        """
        assert(isinstance(ip, (IPv4Address, IPv6Address)))
        # TODO: faster algorithm
        # TODO: MOAS handling
        best_prefix = ip_network('0.0.0.0/0')
        match = None
        for elem in self.bgp:
            if ip in elem.prefix:
                #print("Found", ip, elem.prefix)
                if elem.prefix.prefixlen > best_prefix.prefixlen:
                    best_prefix = elem.prefix
                    match = elem
        return match

    def ris_best_prefix_match_constrained(self, ip, first_asn):
        """Only look at BGP data where the first ASN of the AS-path is equal
        to [first_asn].
        """
        assert(isinstance(ip, (IPv4Address, IPv6Address)))
        best_prefix = ip_network('0.0.0.0/0')
        match = None
        for elem in self.bgp:
            if ip in elem.prefix:
                if elem.as_path[0] != first_asn:
                    continue
                if elem.prefix.prefixlen > best_prefix.prefixlen:
                    best_prefix = elem.prefix
                    match = elem
        return match

    def ris_aspath(self, ip):
        match = self.ris_best_prefix_match_constrained(ip, self.source_asn)
        if match != None:
            return match.as_path

    def bgp_originator(self, bgp_elem):
        return bgp_elem.as_path[-1]

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
        """Translate an IP address to an ASN, using peeringdb and RIS.
        Returns None if the IP is part of an IX or if no ASN can be found."""
        # TODO: MOAS?
        # TODO: distinguish IXP and no match
        assert(isinstance(ip, (IPv4Address, IPv6Address)))
        # 0.0.0.0 represents an empty hop (and is an unusable IP anyway)
        if ip == self.IPV4_NULLADDRESS:
            return None
        # Exact match in peeringdb
        if ip in self.ix_ip:
            return self.ix_ip[ip]
        # Prefix match in peeringdb
        if self.is_in_ix(ip):
            return None
        # Best prefix match in RIS
        bgp_elem = self.ris_best_prefix_match(ip)
        if bgp_elem != None:
            return self.bgp_originator(bgp_elem)

    def traceroute_aspath(self, traceroute):
        """Given a traceroute, compute an AS-path."""
        aspath = []
        for ip_str in [hop.ip for hop in traceroute.hops]:
            ip = ip_address(ip_str)
            asn = self.ip_to_asn(ip)
            if asn != None:
                aspath.append(asn)
        # TODO: post-process the raw AS-path
        return aspath

    def analyse_traceroute(self, traceroute):
        # Add the destination as final hop if it's not already the case
        if ip_address(traceroute.hops[-1].ip) != ip_address(traceroute.dest):
            final_hop = Hop(traceroute.dest, 0., 0)
            traceroute.hops.append(final_hop)
        aspath = self.traceroute_aspath(traceroute)
        bgp_aspath = self.ris_aspath(ip_address(traceroute.dest))
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
