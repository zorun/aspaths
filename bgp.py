from __future__ import print_function, unicode_literals, division

from _pybgpstream import BGPStream, BGPRecord, BGPElem


def load_rib_mrtdump(filename):
    """Load BGP RIB data from a mrtdump file, and returns a generator on
    the BGP elements present in the file."""
    record = BGPRecord()
    stream = BGPStream()
    stream.set_data_interface("singlefile")
    stream.set_data_interface_option("singlefile", "rib-file", filename)
    # TODO: Allow additional filters to be passed
    stream.start()
    while(stream.get_next_record(record)):
        if record.status == "valid":
            elem = record.get_next_elem()
            while(elem):
                yield elem
                elem = record.get_next_elem()
