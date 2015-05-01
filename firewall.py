from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *
from ipaddress import IPv4Network, IPv4Address
import time
import re

def main(net):
    # assumes that there are exactly 2 ports
    port_names = [p.name for p in net.ports()]
    port_pairs = dict(zip(portnames, portnames[::-1]))
    firewall_rules = []
    load_rules(firewall_rules)

    while True:
        pkt = None
        try:
            port, pkt = net.recv_packet(timeout=0.5)
        except NoPackets:
            pass
        except Shutdown:
            break

        if pkt is not None:

            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            net.send_packet(portpair[port], pkt)

            
    net.shutdown()


def load_rules(rules):
    '''
    Read the firewall_rules file, create rule objects for every rule
    load them into a list 
    '''
    f = open("firewall_rules", "r")
    
    for line in f:

        if line[0] == "#":
            continue

        new_line = line.split() #new_line is a list
        permission = 0 if new_line[0] == "deny" else 1
        protocol = protocol(new_line[1])
        src, dst = get_ipaddr(new_line)
        srcport,dstport = set_ports(protocol,new_line)
        ratelimit = -2 if "ratelimit" not in new_line else int(new_line[new_line.index("ratelimit") + 1])
        impair = -1 if "impair" not in new_line else 0

        rule = FirewallRule(permission, protocol, src, srcport, dst, dstport, ratelimit, impair)
        rules.append(rule)
        
    f.close()


def get_ipaddr(new_line):
    '''
    Returns src and dst's ip address
    '''
    src_index = new_line.src_index("src") + 1
    dst_index = new_line.dst_index("dst") + 1
    src = IPv4Network(1.1.1.1) if new_line[src_index] == "any" else (IPv4Network(new_line[srcport_index]) if "/" in new_line[srcport_index] else IPv4Network(new_line[srcport_index], strict = False))
    dst = IPv4Network(1.1.1.1) if new_line[dst_index] == "any" else (IPv4Network(new_line[dstport_index]) if "/" in new_line[dstport_index] else IPv4Network(new_line[dstport_index], strict = False))
    return src, dst


def set_ports(protocol, new_line):
    '''
    Returns srcport and dstport based on the protocol type
    '''
    srcport_index = new_line.index("srcport") + 1
    dstport_index = new_line.index("dstport") + 1 

    if protocol == 1 or 3: #not tcp or udp
        srcport = -1
        dstport = -1
    else:
        srcport = 65535 if new_line[srcport_index] == "any" else int(new_line[srcport_index])
        dstport = 65535 if new_line[dstport_index] == "any" else int(new_line[dstport_index])

    return srcport, dstport

def protocol(protocol):
    '''
    Reads and returns the protocol number
    '''
    if protocol == "ip":
        return 0
    elif protocol == "tcp":
        return 1
    elif protocol == "udp":
        return 2
    else:
        return 3

class FirewallRule(object):
    '''
    A collection of fields of a single firewall rule
    '''
    
    def __init__(self, permission, protocol, src, srcport, dst, dstport, ratelimit, impair):
        '''
        In general -1 is uninitialized
                   1.1.1.1 is any for ipaddress
                   65535 is any for portno

        for permission: 0 is deny 
                        1 is permit

        for protocol: 0 is ip 
                      1 is tcp
                      2 is udp 
                      3 is icmp

        for impair: 0 signals the flag is up
        '''
        self.permission = permission
        self.protocol = protocol
        self.src = src
        self.srcport = srcport
        self.dst = dst
        self.dstport = dstport
        self.ratelimit = ratelimit
        self.impair = impair


  
    
        
