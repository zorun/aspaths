from __future__ import print_function, unicode_literals, division

import os
import datetime
from collections import defaultdict
import logging

from pytricia import PyTricia
from _pybgpstream import BGPStream, BGPRecord, BGPElem

import utils
from utils import M
from intervaldict import IntervalDict


def load_mrtdump(filename, type):
    """Load BGP data from a mrtdump file, and returns a generator on
    the BGP elements present in the file."""
    record = BGPRecord()
    stream = BGPStream()
    stream.set_data_interface("singlefile")
    stream.set_data_interface_option("singlefile", type, filename)
    # TODO: Allow additional filters to be passed
    stream.start()
    while(stream.get_next_record(record)):
        if record.status == "valid":
            elem = record.get_next_elem()
            while(elem):
                yield elem
                elem = record.get_next_elem()

def load_rib_mrtdump(filename):
    return load_mrtdump(filename, "rib-file")

def load_update_mrtdump(filename):
    return load_mrtdump(filename, "upd-file")


class BGPASPathLoader(object):
    """Loads RIB data in mrtdump format and allow to query AS paths at
    specific moments in time."""

    def __init__(self, root_dir, ribfile_format, prepended_source_asn=None):
        """[root_dir] is the directory where RIB dumps are located, and
        [ribfile_format] is a strftime-like format used to parse the
        filename of RIB dumps (and get the time at which it was generated).

        [prepended_source_asn] is an optional AS number to prepend to
        every AS-path (useful if the BGP data was obtained through an
        iBGP session)

        Note: we assume all times are expressed in UTC.
        """
        self.root_dir = root_dir
        self.ribfile_format = ribfile_format
        self.prepended_source_asn = prepended_source_asn
        # For each RIB file, map IP prefixes to their AS path
        self.bgp_aspath = defaultdict(PyTricia)
        self.load_rib_filenames()

    def load_rib_filenames(self):
        """Analyse all filenames corresponding to RIB dumps, and build a
        database mapping each file to its time of generation."""
        logging.info(M("[BGP] Loading filenames of BGP RIB dumps in {}...",
                       self.root_dir))
        ribs = dict()
        for (dir, _, files) in os.walk(self.root_dir):
            for f in files:
                try:
                    date = datetime.datetime.strptime(f, self.ribfile_format)
                except ValueError:
                    continue
                ribs[date] = os.path.join(dir, f)
        logging.info(M("[BGP] {} RIB dumps found",
                       len(ribs)))
        self.rib_filenames = IntervalDict()
        self.rib_filenames.fromdict(ribs)

    def load_rib_from_cache(self, filename):
        # TODO
        return False

    def save_rib_to_cache(self, filename):
        # TODO
        pass

    def load_rib_file(self, filename):
        """Loads the BGP table from the given RIB file, and store it in a
        prefix tree.  We first check whether the file is already
        loaded in RAM, then check whether there is a pickled cache,
        then resort to parsing the original file.

        TODO: garbage-collect RIB data from RAM when they are no longer useful.
        """
        # Already loaded
        if filename in self.bgp_aspath:
            return
        if self.load_rib_from_cache(filename):
            logging.info(M("[BGP] Loaded BGP data for {} from cache.",
                           filename))
            return
        # Parse file from scratch
        logging.info(M("[BGP] Loading BGP data from {}...",
                       filename))
        for elem in load_rib_mrtdump(filename):
            prefix = elem.fields['prefix']
            # Discard IPv6 prefixes (crude but fast)
            if ':' in prefix:
                continue
            if len(elem.fields['as-path']) == 0:
                logging.warning(M("Prefix {} with empty AS-path", prefix))
                continue
            # In rare cases, we have an as-set (BGP aggregation).
            # We simply take the first ASN for now.
            # TODO: possible MOAS
            as_path = [int(asn.strip(b'{}').split(b',')[0])
                       for asn in elem.fields['as-path'].split(b' ')]
            if self.prepended_source_asn != None:
                as_path.insert(0, self.prepended_source_asn)
            self.bgp_aspath[filename][prefix] = as_path
        logging.info(M("[BGP] Loaded {} BGP prefixes from source AS",
                       len(self.bgp_aspath[filename])))
        self.save_rib_to_cache(filename)

    def get_aspath(self, ip, date):
        """Given an IP address and a datetime object, return the AS path as
        seen from the last BGP RIB dump before this instant.  We use
        the most specific prefix for this IP, and we remove duplicate
        ASN (path-prepending).  If no prefix is found, an empty list
        is returned.
        """
        if not isinstance(date, datetime.datetime):
            raise TypeError("datetime object expected")
        rib_filename = self.rib_filenames.get(date)
        if rib_filename == None:
            raise ValueError("no BGP data for this date")
        # Make sure we have loaded the RIB file
        self.load_rib_file(rib_filename)
        try:
            raw_path = self.bgp_aspath[rib_filename][ip]
            return list(utils.uniq(raw_path))
        except KeyError:
            return []
