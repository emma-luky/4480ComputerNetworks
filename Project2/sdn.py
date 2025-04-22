from pox.core import core
from pox.lib.packet import ethernet, ipv4, arp
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

class Mapping:
    """
    Represents port and MAC address mapping for a host in the network.
    Used to store information about server hosts (h5 and h6).
    """
    def __init__(self, port: int, mac: EthAddr = None):
        self.port = port  # The port number on the switch where this host is connected
        self.mac = mac    # The MAC address of the host

class LoadBalancer(object):
    def __init__(self):
        log.info("LoadBalancer constructor entered")
        self.virtual_ip = IPAddr("10.0.0.100")

        self.connections = set()
        core.openflow.addListeners(self)
        log.info("OpenFlow listener added")

        # flag to toggle between h5 and h6 in round-robin fashion
        self.to_h5 = True  
        
        # maps server IP addresses to their port and MAC information
        self.mac_mapping = {
            "10.0.0.5": Mapping(5, EthAddr("00:00:00:00:00:05")),  # Server h5
            "10.0.0.6": Mapping(6, EthAddr("00:00:00:00:00:06")),  # Server h6
        }
        log.info("mac_mapping initialized")

        # store mappings from virtual IPs to real server IPs
        self.ip_mapping = {}
        log.info("LoadBalancer initialized completely")
        
    def __init__(self):
        self.vip = IPAddr('192.168.0.100')  # Example VIP
        self.servers = [IPAddr('192.168.0.5'), IPAddr('192.168.0.6')]  # Server IPs (h5, h6)
        self.client_to_server = {}  # Map from client to server
        self.server_idx = 0  # Round-robin index for servers
        self.listenTo(core.openflow)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port
        if isinstance(packet.next, ipv4):
            ip_packet = packet.next
            if ip_packet.dstip == self.vip:
                # Redirect traffic to the next server in round-robin fashion
                client_ip = ip_packet.srcip
                server_ip = self.servers[self.server_idx]
                self.server_idx = (self.server_idx + 1) % len(self.servers)
                self.client_to_server[client_ip] = server_ip

                log.debug(f"Redirecting traffic from {client_ip} to server {server_ip}")
                
                # Create a new IPv4 packet with the correct destination IP
                new_packet = packet.clone()
                new_packet.next.dstip = server_ip

                # Send the packet to the server
                self._send_packet(event.connection, new_packet, in_port)

            elif ip_packet.srcip in self.client_to_server:
                # Reverse mapping for return traffic
                server_ip = ip_packet.srcip
                client_ip = ip_packet.dstip
                log.debug(f"Returning traffic from server {server_ip} to client {client_ip}")

                # Create a new packet with the correct destination IP (client)
                new_packet = packet.clone()
                new_packet.next.dstip = client_ip

                # Send the packet back to the client
                self._send_packet(event.connection, new_packet, in_port)

    def _send_packet(self, connection, packet, in_port):
        # Send the modified packet out to the correct port
        eth_packet = ethernet.ethernet(packet)
        connection.send(in_port, eth_packet)

def launch():
    """
    Entry point for the POX component.
    Registers the LoadBalancer with the core.
    """
    log.info("Launching LoadBalancer...")
    try:
        core.registerNew(LoadBalancer)  # Register the load balancer with POX core
    except Exception as e:
        log.error(f"Failed to launch LoadBalancer: {e}")