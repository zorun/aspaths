import os
import json


class PeeringDB(object):

    def __init__(self, dir):
        """[dir]: directory containing the JSON data from peeringdb"""
        self.dir = dir
        self.ixpfx = os.path.join(dir, 'peeringdb_ixpfx.json')
        self.netixlan = os.path.join(dir, 'peeringdb_netixlan.json')

    def prefixes_ipv4(self):
        """Returns the list of IXP IPv4 prefixes from peeringdb"""
        with open(self.ixpfx) as f:
            ixpfx = json.load(f)
        return [item['prefix'] for item in ixpfx['data'] if item['protocol'] == 'IPv4']

    def ipv4_asn(self):
        """Returns mappings from IPv4 to ASN"""
        with open(self.netixlan) as f:
            netixlan = json.load(f)
        for item in netixlan['data']:
            if 'ipaddr4' in item and item['ipaddr4'] != None:
                yield (item['ipaddr4'], item['asn'])
