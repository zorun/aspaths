from __future__ import print_function, unicode_literals

import gzip, bz2


def uniq(l):
    """Given a sequence of objects, suppress consecutive duplicate elements
    (similar to the Unix command 'uniq')"""
    last = None
    for e in l:
        if e != last:
            yield e
        last = e

def is_subsequence(l1, l2):
    """Checks whether list l1 is a subsequence of list l2.  That is,
    there exists a non-decreasing mapping from indexes in l1 to indexes
    in l2.  Alternatively, it is possible to remove elements in l2 to
    get a list equal to l1.

    >>> is_subsequence([42, 45, 42], [10000, 42, 20000, 45, 42, 30000])
    True

    """
    # From http://stackoverflow.com/a/24017747
    it = iter(l2)
    return all(any(x == y for x in it) for y in l1)

def is_subsequence_set1(l1, l2):
    """Similar, but l1 is a list of sets now.

    >>> is_set_subsequence([{42,43}, {45}, {42,44}], [10000, 42, 20000, 45, 42, 20000])
    True
    >>> is_set_subsequence([{42,43}, {45}, {42,44}], [10000, 43, 20000, 45, 44, 20000])
    True
    """
    it = iter(l2)
    return all(any(x in y for x in it) for y in l1)

def is_subsequence_set2(l1, l2):
    """Similar, but l2 is a list of sets now.

    >>> is_set_subsequence([42, 45, 42], [{10000}, {42,43}, {}, {45}, {42}, {20000,30000}])
    True
    >>> is_set_subsequence([43, 45, 42], [{10000}, {42,43}, {}, {45}, {42}, {20000,30000}])
    True
    """
    it = iter(l2)
    return all(any(y in x for x in it) for y in l1)

def flatten_unknown(l):
    """Given a list of objects, replace triplets of the form A B A
    (where bool(A) is true and bool(B) is false) to A A.
    """
    pos = 0
    while pos + 2 < len(l):
        a = l[pos]
        b = l[pos+1]
        c = l[pos+2]
        yield a
        if bool(a) and a == c and not bool(b):
            pos += 2
        else:
            pos += 1
    # The end of the list is just returned unchanged
    while pos < len(l):
        yield l[pos]
        pos += 1

def open_compressed(infile):
    """Open a file, transparently decompressing it if needed

    Borrowed from https://github.com/cmand/scamper
    """
    fd = None
    # try reading as a bz2 file
    try:
        fd = bz2.BZ2File(infile, 'rb')
        fd.read(1)
        fd = bz2.BZ2File(infile, 'rb')
        return fd
    except IOError as e:
        pass
    # try reading as a gzip file
    try:
        fd = gzip.open(infile, 'rb')
        fd.read(1)
        fd = gzip.open(infile, 'rb')
        return fd
    except IOError as e:
        pass
    return open(infile, 'rb')
