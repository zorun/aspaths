#!/usr/bin/python

from __future__ import print_function, division, unicode_literals

import os
import sys
import time
from subprocess import signal

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.cli import CLI
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel


class IPv6Router(Node):
    """A Node which acts as a IPv6 router, using the standard Linux routing table
     and forwarding behaviour."""

    def config(self, **_params):
        # We don't want any automatically-assigned (IPv4) addresses
        _params.pop("ip", None)
        r = super(IPv6Router, self).config(**_params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv6.conf.all.forwarding=1')
        return r


class iBGPTopo(Topo):
    """Simulation of a simple iBGP topology"""
    def build(self):
        r1 = self.addHost('r1', cls=IPv6Router)
        r2 = self.addHost('r2', cls=IPv6Router)
        r3 = self.addHost('r3', cls=IPv6Router)
        r4 = self.addHost('r4', cls=IPv6Router)
        # Internal interconnections
        self.addLink(r1, r3)
        self.addLink(r2, r3)
        self.addLink(r3, r4)
        # External interconnections
        peer1 = self.addHost('peer1', cls=IPv6Router)
        self.addLink(r1, peer1)
        peer2 = self.addHost('peer2', cls=IPv6Router)
        self.addLink(r2, peer2)


class OSPFBGPExperiment(object):

    def __init__(self):
        topo = iBGPTopo()
        # No controller
        self.net = Mininet(topo, controller=None)
        # Store pipes to communicate with Bird instances via
        # stdin/stdout (keys are mininet host names)
        self.bird_pipes = dict()
        # Location of bird config files
        self.bird_configdir = "bird"
        self.bird_socketdir = "sockets"

    def start(self):
        self.net.start()
        self.set_addresses()
        self.launch_bird()
        CLI(self.net)
        self.terminate_bird()
        self.net.stop()

    def set_addresses(self):
        # Add loopback IP
        self.net['r1'].popen('ip addr add 2001:db8:0:1::/128 dev lo')
        self.net['r2'].popen('ip addr add 2001:db8:0:2::/128 dev lo')
        self.net['r3'].popen('ip addr add 2001:db8:0:3::/128 dev lo')
        self.net['r4'].popen('ip addr add 2001:db8:0:4::/128 dev lo')
        # Add interconnection IP for external peers
        self.net['r1'].popen('ip addr add 2001:db8:1:1::42/64 dev r1-eth1')
        self.net['peer1'].popen('ip addr add 2001:db8:1:1::ff/64 dev peer1-eth0')
        self.net['r2'].popen('ip addr add 2001:db8:1:2::42/64 dev r2-eth1')
        self.net['peer2'].popen('ip addr add 2001:db8:1:2::ff/64 dev peer2-eth0')

    def launch_bird(self):
        try:
            os.mkdir(self.bird_socketdir)
        except OSError:
            pass
        for host in self.net:
            config_file = os.path.join(self.bird_configdir, "{}.conf".format(host))
            control_socket = os.path.join(self.bird_socketdir, "bird-{}.ctl".format(host))
            cmd = ["bird6", "-d", "-c", config_file, "-s", control_socket]
            self.bird_pipes[host] = self.net[host].popen(*cmd)
        time.sleep(1)
        # Check that all instances are running
        for host in self.net:
            if self.bird_pipes[host].poll() != None:
                (out, err) = self.bird_pipes[host].communicate()
                msg = "[**] Bird exited on host {} with code {}.  Stderr was:"
                print(msg.format(host, self.bird_pipes[host].returncode),
                      file=sys.stderr)
                print(err, file=sys.stderr)
                print()

    def terminate_bird(self):
        print("Killing Bird instances...", file=sys.stderr)
        for host in self.net:
            if self.bird_pipes[host].poll() == None:
                self.bird_pipes[host].send_signal(signal.SIGTERM)
                (out, err) = self.bird_pipes[host].communicate()
                msg = "[**] Bird exited on host {} with code {}.  Stderr was:"
                print(msg.format(host, self.bird_pipes[host].returncode),
                      file=sys.stderr)
                print(err, file=sys.stderr)
                print()


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    exp = OSPFBGPExperiment()
    exp.start()
