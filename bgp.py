from __future__ import print_function, unicode_literals, division

from _pybgpstream import BGPStream, BGPRecord, BGPElem


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
