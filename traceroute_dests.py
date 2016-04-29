#!/usr/bin/env python

"""
This scripts takes BGP data from RIS (mrtdump RIB dumps), and
outputs a list of IP address to be used as destination of traceroute
measurements.

Method:

- load data from all RIS collectors
- remove default routes and any prefix smaller than /126 or /30 (inclusive)
- for each origin AS x:
  - consider all prefixes originated by x
  - remove any prefix that has a least one more-specific prefix
  - pick prefixes at random (at most 10)
  - for each of these prefixes:
    - pick the first usable IP address that does not overlap with a
      more specific prefix from a different origin AS

Note: we allow overlapping prefixes when they have different origin AS.

"""

from __future__ import unicode_literals, print_function

import logging
import sys
from collections import defaultdict
import random

from _pybgpstream import BGPStream, BGPRecord, BGPElem
from pytricia import PyTricia
from netaddr import IPSet
from ipaddress import ip_network


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


def pytricia_leaves(tree):
    """
    Returns an iterator of all prefixes that are leaves of the tree
    (i.e. prefixes that have no more specific prefixes).

    This requires pytricia > 0.9.0
    """
    for prefix in tree:
        if len(tree.children(prefix)) == 0:
            yield prefix


class PyTriciav6(PyTricia):
    """PyTricia class which defaults to 128 bits of address length (for
    use with defaultdict)"""
    def __init__(self):
        PyTricia.__init__(self, 128)


class RIS(object):

    def __init__(self):
        self.all_prefixesv4 = PyTricia()
        self.all_prefixesv6 = PyTricia(128)
        # Mapping from origin AS to a prefix tree
        self.origin_prefixesv4 = defaultdict(PyTricia)
        self.origin_prefixesv6 = defaultdict(PyTriciav6)

    def load_mrtdump(self, filename):
        record = BGPRecord()
        stream = BGPStream()
        stream.set_data_interface("singlefile")
        stream.set_data_interface_option("singlefile", "rib-file", filename)
        stream.start()
        logging.info(M("Started parsing file {}", filename))
        while(stream.get_next_record(record)):
            if record.status == "valid":
                elem = record.get_next_elem()
                while(elem):
                    prefix = elem.fields['prefix']
                    if len(elem.fields['as-path']) == 0:
                        logging.warning(M("Prefix {} with empty AS-path", prefix))
                        elem = record.get_next_elem()
                        continue
                    prefix_net = ip_network(prefix.decode())
                    # Remove any prefix smaller than /126 or /30
                    if prefix_net.num_addresses <= 4:
                        logging.warning(M("Ignored too specific route {}", prefix))
                        elem = record.get_next_elem()
                        continue
                    if prefix_net.prefixlen == 0:
                        logging.warning(M("Ignored default route {}", prefix))
                        elem = record.get_next_elem()
                        continue
                    # Get the origin AS
                    origin = elem.fields['as-path'].split(b' ')[-1]
                    # In rare cases, we have an as-set (BGP aggregation).
                    # We just take any AS.
                    if '{' in origin:
                        origin = int(origin.strip(b'{}').split(b',')[0])
                    else:
                        origin = int(origin)
                    if ':' in prefix:
                        self.all_prefixesv6[prefix] = None
                        self.origin_prefixesv6[origin][prefix] = None
                    else:
                        self.all_prefixesv4[prefix] = None
                        self.origin_prefixesv4[origin][prefix] = None
                    elem = record.get_next_elem()
        logging.info(M("Done parsing file {}", filename))
        logging.info(M("Now having {} IPv4 prefixes, {} IPv6 prefixes, {} IPv4 origin AS, {} IPv6 origin AS",
                       len(self.all_prefixesv4), len(self.all_prefixesv6),
                       len(self.origin_prefixesv4), len(self.origin_prefixesv6)))

    def generate_dest(self, max_prefixes_per_as, ip_version=6):
        """Generate a list of IP addresses to be used as destination for
        traceroute measurements."""
        self.dest = list()
        if ip_version == 4:
            all_prefixes = self.all_prefixesv4
            origin_prefixes = self.origin_prefixesv4
        else:
            all_prefixes = self.all_prefixesv6
            origin_prefixes = self.origin_prefixesv6
        for origin, tree in origin_prefixes.items():
            # Only consider the most specific prefixes
            prefixes = list(pytricia_leaves(tree))
            # Sample a small number of prefixes if necessary
            if len(prefixes) > max_prefixes_per_as:
                prefixes = random.sample(prefixes, max_prefixes_per_as)
            for prefix in prefixes:
                prefix_net = ip_network(prefix.decode())
                if prefix_net.num_addresses == 1:
                    continue
                # Check if there is some overlap (more specifics) from another origin AS
                more_specifics = all_prefixes.children(prefix)
                if len(more_specifics) == 0:
                    dest_ip = str(next(prefix_net.hosts()))
                else:
                    # This is the hard case: we want the first IP that
                    # does not belong to any more specific prefix from
                    # another origin AS.
                    # TODO: if one day ipaddress becomes as useful as netaddr, stop using netaddr...
                    subprefixes = (IPSet([prefix]) - IPSet(more_specifics)).iter_cidrs()
                    if len(subprefixes) == 0:
                        dest_ip = str(next(prefix_net.hosts()))
                    else:
                        dest_ip = str(next(subprefixes[0].iter_hosts()))
                self.dest.append(dest_ip)

    def print_dest(self, file=sys.stdout):
        for dest in self.dest:
            print("{}".format(dest), file=file)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Need args")
        exit(1)
    MAX_PREFIXES_PER_AS = 10
    r = RIS()
    for filename in sys.argv[1:]:
        r.load_mrtdump(filename)
    r.generate_dest(MAX_PREFIXES_PER_AS, ip_version=4)
    with open('destinations-ipv4', 'w') as f:
        logging.info(M("Printing {} IPv4 destinations to file {}...",
                       len(r.dest),
                       'destinations-ipv4'))
        r.print_dest(f)
    r.generate_dest(MAX_PREFIXES_PER_AS, ip_version=6)
    with open('destinations-ipv6', 'w') as f:
        logging.info(M("Printing {} IPv6 destinations to file {}...",
                       len(r.dest),
                       'destinations-ipv6'))
        r.print_dest(f)
    logging.info("Done! Don't forget to randomize the list of destination.")
