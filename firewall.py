from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *
from ipaddress import IPv4Network, IPv4Address
import time

def get_ipaddr(new_line):
	'''
	Returns src and dst's ip address
	'''
	src_index = new_line.index('src') + 1
	dst_index = new_line.index('dst') + 1
	src = IPv4Network('255.255.255.255/32') if new_line[src_index] == 'any' else (IPv4Network(new_line[src_index], strict=False))
	dst = IPv4Network('255.255.255.255/32') if new_line[dst_index] == 'any' else (IPv4Network(new_line[dst_index], strict=False))

	return src, dst

def get_ports(protocol, new_line):
	'''
	Returns srcport and dstport based on the protocol type
	'''
	
	if protocol == 0 or protocol == 3: # not tcp or udp
		srcport = -1
		dstport = -1
	else:
		srcport_index = new_line.index('srcport') + 1
		dstport_index = new_line.index('dstport') + 1 
		srcport = 65535 if new_line[srcport_index] == "any" else int(new_line[srcport_index])
		dstport = 65535 if new_line[dstport_index] == "any" else int(new_line[dstport_index])

	return srcport, dstport

def get_protocol(protocol):
	'''
	Reads and returns the protocol number
	'''
	if protocol == 'ip':
		return 0
	elif protocol == 'tcp':
		return 1
	elif protocol == 'udp':
		return 2
	else:
		return 3

def load_rules(rules):
	'''
	Read the firewall_rules file, create rule objects for every rule
	load them into a list 
	'''
	f = open('firewall_rules.txt', 'r')
	
	for line in f:

		if line == '\n' or line[0] == '#':
			continue

		new_line = line.split() # new_line is a list
		permission = 0 if new_line[0] == 'deny' else 1
		protocol = get_protocol(new_line[1])
		src, dst = get_ipaddr(new_line)
		srcport, dstport = get_ports(protocol, new_line)
		ratelimit = 0 if 'ratelimit' not in new_line else int(new_line[new_line.index('ratelimit') + 1])
		impair = 0 if 'impair' not in new_line else 1

		rule = FirewallRule(permission, protocol, src, srcport, dst, dstport, ratelimit, impair)
		rules.append(rule)
		
	f.close()

def ip_match(pkt, rule):
	ip = pkt.get_header(IPv4)
	ip_src = IPv4Network(ip.srcip, strict=False)
	ip_dst = IPv4Network(ip.dstip, strict=False)
	rule_src = int(rule.src.network_address)
	rule_dst = int(rule.dst.network_address)

	return ((int(ip_src.network_address) & rule_src == rule_src or rule_src ^ 2**32-1 == 0) and
			(int(ip_dst.network_address) & rule_dst == rule_dst or rule_dst ^ 2**32-1 == 0))

def icmp_match(pkt, rule):
	# since ICMP does not specify ports,
	# it is the same as comparing IP
	return ip_match(pkt, rule) and pkt.has_header(ICMP)

def tcp_match(pkt, rule):
	if not pkt.has_header(TCP):
		return False

	tcp = pkt.get_header(TCP)

	return (ip_match(pkt, rule) and
			(tcp.srcport & rule.srcport == tcp.srcport) and
			(tcp.dstport & rule.dstport == tcp.dstport))


def udp_match(pkt, rule):
	if not pkt.has_header(UDP):
		return False

	udp = pkt.get_header(UDP)

	return (ip_match(pkt, rule) and
			(udp.srcport & rule.srcport == udp.srcport) and
			(udp.dstport & rule.dstport == udp.dstport))

def match(pkt, rule):
	'''
	Checks if a packet matches a rule
	'''
	if not pkt.has_header(IPv4):
		# must be IPv6 or ARP, allow
		return False

	if rule.protocol == 0:		# IP
		return ip_match(pkt, rule)
	elif rule.protocol == 1:	# TCP
		return tcp_match(pkt, rule)
	elif rule.protocol == 2:	# UDP
		return udp_match(pkt, rule)
	else:	# rule.protocol == 3, ICMP
		return icmp_match(pkt, rule)

def rate_limit(pkt, rule):
	'''
	Returns true if the packet can be sent
	(rate is under the limit)
	'''
	size = len(pkt) - len(pkt.get_header(Ethernet))
	if size <= rule.tokenbkt:
		rule.tokenbkt -= size
		return True
	else:
		return False

def add_tokens(rules):
	'''
	Add tokens to token buckets when called.
	Add tokens proportional to time elapsed.
	'''
	for rule in rules:
		if rule.ratelimit:
			if rule.tokenbkt < 2*rule.ratelimit:
				time_elapsed = time.time() - rule.last_t
				amount_to_add = int(rule.ratelimit * time_elapsed)	# round down
				rule.tokenbkt += amount_to_add if amount_to_add <= 2*rule.ratelimit else 2*rule.ratelimit
				rule.last_t = time.time()

def main(net):
	'''
	Main body of the firewall.
	'''
	# assumes that there are exactly 2 ports
	port_names = [p.name for p in net.ports()]
	port_pairs = dict(zip(port_names, port_names[::-1]))

	firewall_rules = []
	load_rules(firewall_rules)

	while True:
		pkt = None
		try:
			port, pkt = net.recv_packet(timeout=0.45)
		except NoPackets:
			pass
		except Shutdown:
			break

		add_tokens(firewall_rules)

		if pkt is not None:
			matched = False
			# check rules
			for rule in firewall_rules:

				matched = match(pkt, rule)
				if matched:
					if rule.permit: # matches, and permitted
						# send packet if not ratelimited or impaired
						if not rule.ratelimit and not rule.impair:
							net.send_packet(port_pairs[port], pkt)
						elif rule.ratelimit:
							can_send = rate_limit(pkt, rule)
							if can_send:
								net.send_packet(port_pairs[port], pkt)
						else:	# impair
							## implement

							net.send_packet(port_pairs[port], pkt)

					# check no more rules once one matches
					break
					
			# default behavior: forward packet
			if not matched:
				net.send_packet(port_pairs[port], pkt)

	net.shutdown()


class FirewallRule(object):
	'''
	A collection of fields of a single firewall rule
	'''
	
	def __init__(self, permission, protocol, src, srcport, dst, dstport, ratelimit, impair):
		'''
		In general -1 is uninitialized/do not use
				   255.255.255.255 is for allowing any/all ipaddress
				   65535 is for allowing any/all portno

		for permission: 0 is deny 
						1 is permit

		for protocol: 0 is ip 
					  1 is tcp
					  2 is udp 
					  3 is icmp

		for ratelimit: 0 is unlimited, anything else is the limit

		for impair: 1 signals the flag is up
		'''
		self.permit = permission
		self.protocol = protocol
		self.src = src
		self.srcport = srcport
		self.dst = dst
		self.dstport = dstport
		self.ratelimit = ratelimit
		self.tokenbkt = 0
		self.last_t = time.time()
		self.impair = impair

