# Scripts for working with AS paths and traceroutes

This repository contains python code dealing with BGP data and
traceroute data.

Three scripts are currently provided:

- `display_scamper_traceroutes.py`, which takes a WARTS file from Scamper
  and prints the traceroutes it contains in a readable way

- `traceroute_dests.py`, which takes a bunch of mrtdump files and produces
  a list of IP addresses that can be used as destination for traceroutes

- `compare_aspaths.py`, the most complex script, takes both traceroutes
  (warts file) and BGP data (mrtdump files).  For each traceroute destination,
  it compares the AS-path obtained by BGP with the AS-path obtained by inferring
  an AS-path from the traceroute.  Obviously, the "ground truth" BGP data needs
  to come from the same vantage point as the traceroute source.


Some libraries are included in this repository:

- peeringdb.py: parse json files taken from the PeeringDB API
- bgp.py: parse mrtdump files (needs pybgpstream)
- iplane.py: parse the file format for iPlane traceroutes
- warts.py: parse the file format used by Scamper

They are all work-in-progress, so don't expect nice APIs.

## Installing

You need to install a couple of dependencies.  First, install BGPstream,
as described here: <https://bgpstream.caida.org/docs/install/bgpstream>.

Then, you can install the python dependencies, including pybgpstream:

    pip install -r requirements_python2.txt

Currently, python3 is not supported because of pybgpstream (but as of May 2016,
the developpement version has support for python3).

## Using the scripts

The two small scripts are fairly straightforward to use.

`compare_aspaths.py` is more complex, see the help message when running the script.
Basically, it needs:

1. the source AS (which is where you launched your traceroutes from, and where you collected your BGP RIB)
2. a BGP RIB used for IP-to-AS mapping (can come from RIS, routeviews, or your own dump)
3. a BGP RIS used as "ground truth" to compare the AS paths obtained from the traceroutes
4. a warts file with traceroutes

If the source AS is not present in the AS-path of your BGP RIB (if e.g. you got
your BGP data through an iBGP session), simply use the `--prepend` option.

Without any verbosity setting, the script will be completely silent during its runtime (~1 hour),
and when it has finished crunching data, it will spit out statistics about AS-paths found.

Use one `-v` flag to get a few indications about what it is doing.  When using two `-v`,
the script will show information on every traceroute whose AS-path does not match the
BGP data, on standard error.  Lastly, you can use the `--debug-traceroute` flag to
display the traceroutes themselves (only those for which there is a mismatch).
Note that this last mode is much slower, because a lot of DNS queries are made to display
the reverse name of traceroute hops.

