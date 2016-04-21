from __future__ import print_function, unicode_literals


def uniq(l):
    """Given a sequence of objects, suppress consecutive duplicate elements
    (similar to the Unix command 'uniq')"""
    last = None
    for e in l:
        if e != last:
            yield e
        last = e
