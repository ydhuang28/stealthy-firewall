from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *
import time

def main(net):
	# assumes that there are exactly 2 ports
	port_names = [p.name for p in net.ports()]
	port_pairs = dict(zip(portnames, portnames[::-1]))


	while True:
		pkt = None
		try:
			port, pkt = net.recv_packet(timeout=0.5)
		except NoPackets:
			pass
		except Shutdown:
			break

		if pkt is not None:
			# check against rules
			# get a matching rule back, or not
			# if not, permit the packet
			# if yes, do accordingly

			# if permit and rate limit:


			net.send_packet(portpair[port], pkt)

			
	net.shutdown()

