from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

VIRTUAL_IP = IPAddr("10.0.0.10")
Servers = [(IPAddr("10.0.0.5"), EthAddr("00:00:00:00:00:05")),
	(IPAddr("10.0.0.6"), EthAddr("00:00:00:00:00:06"))]
server_index = 0 # round-robin index

class LoadBalancer(object):
	def __init__(self, connection):
		self.connection = connection
		connection.addListeners(self)
	def _handle_PacketIn(self, event):
		global server_index
		packet = event.parsed
		# Handle ARP Requests for Virtual IP
