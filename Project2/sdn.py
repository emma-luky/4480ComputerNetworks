from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.util import dpid_to_str
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()
IPV4 = 0x0800  # Ethernet type for IPv4
ARP_TYPE = 0x0806  # Ethernet type for ARP

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
        self.virtual_ip = IPAddr("10.0.0.10")

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
        """
        Called when a packet is sent to the controller from the switch.
        Main entry point for packet processing logic.
        """
        packet = event.parsed
        inport = event.port
        if not packet:
            log.warning("Received empty packet")
            return
        
        if packet.type == packet.ARP_TYPE:
            log.debug(f"ARP {packet.opcode} from {packet.src} to {packet.dst} on port {inport}")
            self.handle_arp(inport, event, packet)
            return

        if packet.type == packet.IPV4_TYPE:
            self.handle_ipv4_packet(inport, event, packet)
            return
        
    def construct_arp_reply(self, arp_packet, hw_src, hw_dst, protodst, protosrc):
        """
        Creates an ARP reply packet based on the provided parameters.
        Used to respond to ARP requests for the virtual IP.
        """
        arp_reply = arp()
        arp_reply.hwtype = arp_packet.hwtype
        arp_reply.prototype = arp_packet.prototype
        arp_reply.hwlen = arp_packet.hwlen
        arp_reply.protolen = arp_packet.protolen
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = hw_dst
        arp_reply.hwdst = hw_src
        arp_reply.protosrc = protodst
        arp_reply.protodst = protosrc
        return arp_reply

    def handle_arp(self, inport, event, arp_packet):
        """
        Handles ARP packets, particularly ARP requests for the virtual IP.
        Creates ARP replies and installs flow rules for the connection.
        """
        # arp_type = arp_opcode_to_text.get(, str(arp_packet.opcode))
        from_valid_host = 1 <= inport <= 4  # Verify this is from a client (h1-h4)

        # if arp_packet.prototype == arp.PROTO_TYPE_IP and arp_packet.hwtype == arp.HW_TYPE_ETHERNET:

        ## client to VIP
        if arp_packet.opcode == arp.REQUEST and from_valid_host:
            hw_dst = self.map_ip_to_mac(str(arp_packet.protodst)).mac

            arp_reply = self.construct_arp_reply(
                arp_packet,
                hw_src=arp_packet.hwsrc,
                hw_dst=hw_dst,
                protodst=arp_packet.protodst,
                protosrc=arp_packet.protosrc
            )

            ether = ethernet(type=ARP_TYPE, src=event.connection.eth_addr, dst=arp_packet.hwsrc)
            ether.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
            msg.in_port = inport
            event.connection.send(msg)

            server_real_ip = self.ip_mapping.get(str(arp_packet.protodst))
            if not server_real_ip:
                log.warning(f"IP {arp_packet.protodst} not found in ip_mapping")
                return
            else:
                outport = self.mac_mapping.get(server_real_ip, Mapping(None)).port
            if outport is None:
                log.warning(f"No port mapping found for {server_real_ip}")
                return

            # install flow rules for client -> server traffic
            event.connection.send(
                self.client_to_server_flow_entry(inport, IPAddr(arp_packet.protodst), IPAddr(server_real_ip), outport)
            )

            # install flow rules for server -> client traffic
            event.connection.send(
                self.server_to_client_flow_entry(outport, IPAddr(server_real_ip), IPAddr(arp_packet.protosrc), inport)
            )
            log.info(f"Flow installed for ARP from {arp_packet.protosrc} to {arp_packet.protodst}")

        ## server to client
        elif arp_packet.opcode == arp.REQUEST:
            # If the ARP request comes from a server (not from a client)
            log.debug(f"ARP request from server, sending to OFPP_TABLE")

            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.in_port = inport
            msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
            event.connection.send(msg)


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