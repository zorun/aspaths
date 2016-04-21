from __future__ import print_function, unicode_literals


def uniq(l):
    """Given a sequence of objects, suppress consecutive duplicate elements
    (similar to the Unix command 'uniq')"""
    last = None
    for e in l:
        if e != last:
            yield e
        last = e

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
