#!/usr/bin/env python

from __future__ import print_function, unicode_literals, division

import os
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address, IPv4Network
from collections import namedtuple, Counter, defaultdict
import cPickle as pickle
import logging
import socket
from enum import Enum
import argparse
import datetime
import sys
import subprocess

from pytricia import PyTricia

import warts
import peeringdb
import utils
from utils import M
from bgp import load_rib_mrtdump, BGPASPathLoader


WartsTraceroute = namedtuple('WartsTraceroute', ['flags', 'hops'])


class BGPTracerouteMatch(Enum):
    """
    Compare AS paths obtained by traceroute and those obtained by BGP, by classifying them.

    Note that the classes are not mutually exclusive!
    """
    # Define iteration order for python2 (python3 uses definition order by default)
    __order__ = "exact_match exact_match_only_known missing_in_bgp missing_in_traceroute \
    distinct_asn distinct_but_same_second no_bgp traceroute_loop destination_as_mismatch \
    cogent_ntt ntt_router_madrid rfc7789_candidate \
    warts_none warts_completed warts_unreach warts_icmp warts_loop warts_gaplimit \
    warts_error warts_hoplimit warts_gss warts_halted"

    exact_match = "Exact match"
    exact_match_only_known = "Exact match after removing unknown hops in traceroute"
    missing_in_bgp = "BGP AS-path is a strict subsequence of traceroute path"
    missing_in_traceroute = "Traceroute AS-path is a strict subsequence of BGP path"
    distinct_asn = "Both BGP and traceroute AS-paths exhibit distinct ASN"
    distinct_but_same_second = "Both AS-paths exhibit distinct ASN, but the second known ASN is the same"
    no_bgp = "Empty BGP AS-path"
    traceroute_loop = "AS loop in the traceroute (same AS seen at least 2 times)"
    destination_as_mismatch = "Origin AS for destination IP is not consistent (IP-to-AS mapping issue)"
    cogent_ntt = "Traceroute path has [Cogent, NTT], but BGP path has [Cogent, not NTT]"
    ntt_router_madrid = "A router from NTT in Madrid (130.117.14.190) is present in the traceroute"
    rfc7789_candidate = "Traceroute path ends with A Y B while BGP path ends with A B"
    warts_none = "No stopping reason"
    warts_completed = "Got an ICMP port unreachable"
    warts_unreach = "Got an other ICMP unreachable code"
    warts_icmp = "Got an ICMP message other than unreachable"
    warts_loop = "Loop detected"
    warts_gaplimit = "Gap limit reached"
    warts_error = "Error in sendto"
    warts_hoplimit = "Hop limit reached"
    warts_gss = "Found hop in global stop set (doubletree)"
    warts_halted = "Traceroute was halted"


class TagsBitMask(object):
    """
    Represent a set of tags (BGPTracerouteMatch) as a bitmask.
    """

    def __init__(self, tags_set):
        self.value = 0
        for tag in list(BGPTracerouteMatch):
            self.value <<= 1
            if tag in tags_set:
                self.value |= 1

    def __eq__(self, other):
        return self.value == other.value

    def __hash__(self):
        return self.value

    def _tags(self):
        highest_bit = (1 << (len(BGPTracerouteMatch) - 1))
        for (i, tag) in enumerate(BGPTracerouteMatch):
            if self.value & (highest_bit >> i):
                yield tag

    def tags(self):
        """Return the list of tags represented by this bitmask"""
        return list(self._tags())

    def __str__(self):
        mask = '{:0>{}}'.format(bin(self.value).lstrip('0b'),
                                len(BGPTracerouteMatch))
        # Separate components for readability
        return '{} {} {} {} {} {}'.format(mask[:2],
                                          mask[2:4],
                                          mask[4:6],
                                          mask[6:9],
                                          mask[9:12],
                                          mask[12:])


class ASPathsAnalyser(object):
    IPV4_NULLADDRESS = IPv4Address("0.0.0.0")
    CACHE_BASEDIR = "cache"

    def __init__(self, args):
        self.source_asn = args.source_asn
        self.max_traceroutes = args.max_traceroutes
        # Automatic BGP loader to get AS paths
        prepended_source_asn = args.source_asn if args.prepend_source_asn else None
        self.bgp_loader = BGPASPathLoader(args.root_dir, args.ribfile_format,
                                          prepended_source_asn)
        # Count the number of matches from each class (beware, they are
        # not mutually exclusive).
        self.tags_counter = Counter()
        # Another way to look at tags (counting identical bitmasks)
        self.bitmask_counter = Counter()
        # Number of traceroutes processed
        self.nb_traceroutes = 0
        # Display traceroutes that mismatch?
        self.debug_traceroutes = args.debug_traceroutes
        # Debug related to the Cogent/NTT case
        self.debug_cogent_ntt = args.debug_cogent_ntt
        # Count global number of BGP paths satisfying some criteria
        self.cogent_bgp_paths = 0
        self.cogent_level3_bgp_paths = 0
        self.cogent_ntt_bgp_paths = 0
        # Dictionnary mapping origin AS to statistics related to BGP
        # paths: "nb_paths" (total number of BGP paths towards the given
        # AS), "nb_paths_cogent" (number of BGP paths going through
        # Cogent), "nb_paths_bug" (number of BGP paths exhibiting the
        # Cogent/NTT bug)
        self.cogent_ntt_stats = defaultdict(Counter)
        # Dictionnary mapping origin AS to a counter of BGP next-hop
        # ASes found just after Cogent in the BGP paths (it only takes
        # into account BGP paths going through Cogent)
        self.bgp_next_hops = defaultdict(Counter)
        # Count the occurrences of the second AS hop after Cogent
        # (both for BGP and traceroute paths, as a pair).
        self.cogent_second_hops = Counter()

    def ris_cache_filename(self, ris_filename):
        """Use the input filename to determine a cache filename"""
        ris_filename = os.path.basename(ris_filename)
        return os.path.join(self.CACHE_BASEDIR, ris_filename + "_v2.pickle")

    def save_ris_cache(self, ris_filename):
        """Dump bgp_origin to a pickle file for later reuse."""
        try:
            os.mkdir(self.CACHE_BASEDIR)
        except OSError:
            pass
        cachename = self.ris_cache_filename(ris_filename)
        # PyTricia objects cannot be pickled, we need to transform
        # them first.
        serialise = lambda tree: tuple((prefix, tree[prefix]) for prefix in tree)
        obj = serialise(self.bgp_origin)
        with open(cachename, "w") as f:
            pickle.dump(obj, f)

    def load_ris_cache(self, ris_filename):
        """Try to load bgp_origin from cache, returns True if successful"""
        cachename = self.ris_cache_filename(ris_filename)
        if not os.path.isfile(cachename):
            return False
        with open(cachename, "r") as f:
            # TODO: handle more pickle exceptions
            try:
                bgp_origin = pickle.load(f)
            except EOFError:
                return False
        def deserialise(obj):
            p = PyTricia()
            for (prefix, value) in obj:
                p[prefix] = value
            return p
        self.bgp_origin = deserialise(bgp_origin)
        return True

    def ris_remove_default_route(self):
        if self.bgp_origin.has_key(b'0.0.0.0/0'):
            self.bgp_origin.delete(b'0.0.0.0/0')
            logging.info("[RIS] Removed default route in bgp_origin")

    def load_bgp_mapping(self, filename):
        """Loads a full BGP table and store (prefix, origin AS) couples in a
        prefix tree.  This allows fast queries for finding origin ASes for a given IP.

        A pickled cache is kept to avoid recomputing the prefix tree
        each time the program is run.
        """
        # This maps each IP prefix to a set of origin AS (most often a singleton)
        self.bgp_origin = PyTricia()
        logging.info("[RIS] Trying to load BGP prefixes from cache...")
        if self.load_ris_cache(filename):
            logging.info(M("[RIS] Loaded {} BGP prefixes from cache", len(self.bgp_origin)))
            self.ris_remove_default_route()
            return
        logging.info("[RIS] No cache, loading from mrtdump file...")
        # Use BGPstream to parse the RIS dump.
        for elem in load_rib_mrtdump(filename):
            prefix = elem.fields['prefix']
            # Discard IPv6 prefixes (crude but fast)
            if ':' in prefix:
                continue
            if len(elem.fields['as-path']) == 0:
                logging.warning(M("Prefix {} with empty AS-path", prefix))
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
        self.ris_remove_default_route()
        logging.info(M("[RIS] Loaded {} BGP prefixes", len(self.bgp_origin)))
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
        hops = [hop['addr'] for hop in traceroute.hops]
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
        hops = [hop['addr'] for hop in traceroute.hops]
        for ip_str in hops:
            ip = ip_address(ip_str)
            if ip == self.IPV4_NULLADDRESS:
                data.append(('X', 'X', 'X'))
            else:
                asn_set = self.ip_to_asn(ip)
                if len(asn_set) == 0:
                    asn = 'X'
                else:
                    asn = ','.join(str(asn) for asn in sorted(asn_set))
                hostname = socket.getfqdn(str(ip)) if not ip.is_private else 'X'
                if hostname == str(ip):
                    hostname = 'X'
                data.append((str(ip), asn, hostname))
                max_len[0] = max(max_len[0], len(str(ip)))
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

    def debug_bgp(self, ip, date, bgp_path):
        """Displays the prefix matched by the IP, and communities"""
        prefix = self.bgp_loader.get_prefix(ip, date)
        if prefix == None:
            logging.debug("No BGP prefix found")
            return
        logging.debug(M("Prefix:             {}", prefix))
        communities = self.bgp_loader.get_communities(ip, date)
        if len(communities) > 0:
            logging.debug(M("Communities:        {}", ' '.join(communities)))

    def classify_match(self, traceroute, trace_path, bgp_path):
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
        elif bgp_path[-1] not in trace_path[-1]:
            res.add(BGPTracerouteMatch.destination_as_mismatch)
        occurrences = Counter([frozenset(asnset) for asnset in trace_path if len(asnset) > 0])
        if occurrences.most_common(1)[0][1] > 1:
            res.add(BGPTracerouteMatch.traceroute_loop)
        # Test Cogent/NTT case
        if any(174 in a and 2914 in b for (a, b) in zip(trace_path, trace_path[1:])) and \
           174 in bgp_path and \
           not (174, 2914) in zip(bgp_path, bgp_path[1:]):
            res.add(BGPTracerouteMatch.cogent_ntt)
        if any(hop['addr'] == u"130.117.14.190" for hop in traceroute.hops):
            res.add(BGPTracerouteMatch.ntt_router_madrid)
        # Test RFC7789-like mismatch
        if len(bgp_path) >= 2 and len(trace_path_only_known) >= 3:
            (a, b) = bgp_path[-2:]
            (x, y, z) = trace_path_only_known[-3:]
            if a in x and b in z:
                res.add(BGPTracerouteMatch.rfc7789_candidate)
        return res

    def warts_stop_reason(self, traceroute):
        """Return a tag describing the reason why scamper stopped the traceroute"""
        reason = warts.TRACEROUTE_STOP[traceroute.flags['stopreas']]
        tag_name = "warts_" + reason.lower()
        return BGPTracerouteMatch[tag_name]

    def gather_cogent_ntt_stats(self, traceroute, aspath, bgp_aspath, matches):
        if len(bgp_aspath) == 0:
            return
        origin_as = bgp_aspath[-1]
        self.cogent_ntt_stats[origin_as]["nb_paths"] += 1
        if 174 in bgp_aspath:
            self.cogent_bgp_paths += 1
            self.cogent_ntt_stats[origin_as]["nb_paths_cogent"] += 1
            # Cogent can be the origin of the prefix
            if bgp_aspath[-1] != 174:
                next_hop_as = bgp_aspath[bgp_aspath.index(174) + 1]
                self.bgp_next_hops[origin_as][next_hop_as] += 1
        if (174, 3356) in zip(bgp_aspath, bgp_aspath[1:]):
            self.cogent_level3_bgp_paths += 1
        if (174, 2914) in zip(bgp_aspath, bgp_aspath[1:]):
            self.cogent_ntt_bgp_paths += 1
        cogentntt_matches = {BGPTracerouteMatch.cogent_ntt, BGPTracerouteMatch.ntt_router_madrid}
        if cogentntt_matches.issubset(matches):
            self.cogent_ntt_stats[origin_as]["nb_paths_bug"] += 1
            second_bgp_hop = None
            if len(bgp_aspath[bgp_aspath.index(174):]) >= 3:
                second_bgp_hop = bgp_aspath[bgp_aspath.index(174) + 2]
            second_trace_hop = None
            aspath_only_known = [asnset for asnset in aspath if len(asnset) > 0]
            for (as_set1, as_set2) in zip(aspath_only_known, aspath_only_known[1:]):
                if 2914 in as_set1:
                    second_trace_hop = ",".join([str(asn) for asn in as_set2])
                    break
            self.cogent_second_hops[(second_bgp_hop, second_trace_hop)] += 1

    def analyse_traceroute(self, traceroute):
        if len(traceroute.hops) == 0:
            return
        # Preprocess traceroute to make missing hops apparent
        # Python2 hacks for copy() and clear()...
        hops = traceroute.hops[:]
        del traceroute.hops[:]
        empty_hop = {u'addr': u'0.0.0.0'}
        hop_id = 1
        for hop in hops:
            while hop['probettl'] > hop_id:
                traceroute.hops.append(empty_hop)
                hop_id += 1
            traceroute.hops.append(hop)
            hop_id += 1
        # Add the destination as final hop if it's not already the case
        last_hop = traceroute.hops[-1]['addr']
        destination = traceroute.flags['dstaddr']
        if ip_address(last_hop) != ip_address(destination):
            final_hop = {u'addr': destination}
            # Make sure there is an unknown hop, because we might be
            # missing a rather large portion of the traceroute
            traceroute.hops.append(empty_hop)
            traceroute.hops.append(final_hop)
        aspath = self.traceroute_aspath(traceroute)
        date = datetime.datetime.utcfromtimestamp(traceroute.flags['timeval'])
        bgp_aspath = self.bgp_loader.get_aspath(traceroute.flags['dstaddr'].encode(),
                                                date)
        matches = self.classify_match(traceroute, aspath, bgp_aspath)
        matches.add(self.warts_stop_reason(traceroute))
        bitmask = TagsBitMask(matches)
        all_tags = [m.name for m in matches]
        logging.debug(M("Matches for {}: {} ({})", traceroute.flags['dstaddr'],
                        ' '.join(all_tags), bitmask))
        # Update statistics
        self.tags_counter.update(matches)
        self.bitmask_counter[bitmask] += 1
        self.nb_traceroutes += 1
        # Debug
        if not BGPTracerouteMatch.exact_match_only_known in matches:
            if logging.root.isEnabledFor(logging.DEBUG):
                self.debug_aspaths(aspath, bgp_aspath)
                self.debug_bgp(traceroute.flags['dstaddr'].encode(), date, bgp_aspath)
            if self.debug_traceroutes:
                self.debug_traceroute(traceroute)
            if logging.root.isEnabledFor(logging.DEBUG) or self.debug_traceroutes:
                logging.debug('--')
        if self.debug_cogent_ntt:
            self.gather_cogent_ntt_stats(traceroute, aspath, bgp_aspath, matches)

    def analyse_traceroutes(self, filename):
        w = warts.WartsReader(filename)
        for (flags, hops) in w.read_all():
            traceroute = WartsTraceroute(flags, hops)
            self.analyse_traceroute(traceroute)
            if self.max_traceroutes != None and self.nb_traceroutes >= self.max_traceroutes:
                logging.info(M("Analysed {} traceroutes, stopping as requested.",
                               self.max_traceroutes))
                break
        print("Breakdown of match classes (not mutually exclusive!):")
        # Print a breakdown by tag
        for tag in BGPTracerouteMatch:
            count = self.tags_counter[tag]
            if count == 0:
                continue
            print("{:24} {:6}  {:7.2%}  {}".format(tag.name,
                                                   count,
                                                   count / self.nb_traceroutes,
                                                   tag.value))
        # Print a breakdown by bitmask
        print("\nBreakdown by combination of tags (bitmasks):")
        for (bitmask, count) in self.bitmask_counter.most_common():
            tags = ' '.join([t.name for t in bitmask.tags()])
            print('{:24} {:6}  {:7.2%}  {}'.format(bitmask, count,
                                                   count / self.nb_traceroutes,
                                                   tags))
        print("{:24} {:6}  {:7.2%}".format("Total", self.nb_traceroutes, 1))
        # Print statistics about Cogent/NTT bug
        if self.debug_cogent_ntt:
            print("\nGlobal Cogent/NTT stats:")
            print("[*] {:45}: {}".format("Total number of paths",
                                         self.nb_traceroutes))
            print("[*] {:45}: {}".format("Number of BGP paths through Cogent",
                                         self.cogent_bgp_paths))
            print("[*] {:45}: {}".format("Number of BGP paths through Cogent, Level3",
                                         self.cogent_level3_bgp_paths))
            print("[*] {:45}: {}".format("Number of BGP paths through Cogent, NTT",
                                         self.cogent_ntt_bgp_paths))
            print("[*] {:45}: {}".format("Number of paths exhibiting Cogent/NTT bug",
                                         self.tags_counter[BGPTracerouteMatch.cogent_ntt]))
            print("\nSecond AS hop after Cogent, for paths exhibiting Cogent/NTT bug:")
            for ((bgp, traceroute), count) in self.cogent_second_hops.most_common():
                print("bgp={:<6}, traceroute={:<10} => {:5} occurrences".format(bgp,
                                                                                traceroute,
                                                                                count))
            print("\nPer-origin-ASN Cogent/NTT stats:")
            for origin_as in self.cogent_ntt_stats:
                # Only include AS with at least one buggy path
                if self.cogent_ntt_stats[origin_as]["nb_paths_bug"] == 0:
                    continue
                print("\nAS{}".format(origin_as))
                print("[*] {:45}: {}".format("Total number of paths",
                                             self.cogent_ntt_stats[origin_as]["nb_paths"]))
                print("[*] {:45}: {}".format("Number of BGP paths through Cogent",
                                             self.cogent_ntt_stats[origin_as]["nb_paths_cogent"]))
                print("[*] {:45}: {}".format("Number of paths exhibiting Cogent/NTT bug",
                                             self.cogent_ntt_stats[origin_as]["nb_paths_bug"]))
                print("[*] {:45}: {}".format("BGP next-hops after Cogent",
                                             self.bgp_next_hops[origin_as].most_common()))


def create_parser():
    parser = argparse.ArgumentParser(description='Compare AS paths and traceroute paths.')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    parser.add_argument('--source-asn', '-s', type=int, required=True,
                        help="ASN from which the experiment was run")
    parser.add_argument('--bgp-mapping', '-r', required=True,
                        help="file containing a mrtdump BGP RIB, used for IP-to-AS mapping")
    # TODO: detect automatically whether this is needed or not
    parser.add_argument('--prepend-source-asn', '-p', action='store_true',
                        help="prepend the source ASN to all AS paths found in the ground truth RIB "
                        "(useful if the BGP data was obtained through an iBGP session)")
    parser.add_argument('--traceroute', '-t', required=True,
                        help="file containing traceroutes to analyse (warts only)")
    parser.add_argument('-n', type=int, dest="max_traceroutes",
                        help="maximum number of traceroutes to analyse (default: everything)")
    parser.add_argument('--debug-traceroutes', action="store_true",
                        help="print traceroutes for which there is a path mismatch")
    parser.add_argument('--debug-cogent-ntt', action="store_true",
                        help="print some debug statistics about the Cogent/NTT bug")
    parser.add_argument('--rib-format', '-f', dest="ribfile_format",
                        default="rib.ipv4.%Y%m%d.%H%M.bz2",
                        help="format of RIB dump filenames (default: '%(default)s')")
    parser.add_argument('root_dir',
                        help="directory containing the RIB dumps as mrtdump, used to determine BGP AS paths")
    return parser

def print_metadata():
    # Date
    msg = "# Date: {}".format(datetime.datetime.utcnow().strftime("%c UTC"))
    print(msg)
    print(msg, file=sys.stderr)
    # Hostname
    msg = "# Hostname: {}".format(os.uname()[1])
    print(msg)
    print(msg, file=sys.stderr)
    # Working directory
    msg = "# Current working directory: {}".format(os.getcwd())
    print(msg)
    print(msg, file=sys.stderr)
    # Git version
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"])
        revision = revision.decode('utf-8').strip()
        msg = "# Git revision: {}".format(revision)
    except subprocess.CalledProcessError as e:
        msg = "# Error getting git version: return code {}".format(e.returncode)
    print(msg)
    print(msg, file=sys.stderr)
    # Python version
    msg = "# Python version: {}".format(sys.version.replace('\n', ' '))
    print(msg)
    print(msg, file=sys.stderr)

def print_args():
    msg = "# Command: {}".format(" ".join(sys.argv))
    print(msg)
    print(msg, file=sys.stderr)


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    if args.verbose >= len(levels):
        args.verbose = len(levels) - 1
    logging.basicConfig(format='%(message)s',
                        level=levels[args.verbose])
    print_metadata()
    print_args()
    a = ASPathsAnalyser(args)
    a.load_peeringdb()
    a.load_bgp_mapping(args.bgp_mapping)
    a.analyse_traceroutes(args.traceroute)
