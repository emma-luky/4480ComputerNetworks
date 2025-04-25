from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.util import dpid_to_str
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()
IPV4 = 0x0800  # Ethernet type for IPv4
ARP_TYPE = 0x0806  # Ethernet type for ARP

# handle arp requests coming from servers
# instead of handling ip forward packet to flow tables
# send to normal message port to of.OFPP_TABLE

class Mapping:
    """
    Represents port and MAC address mapping for a host in the network.
    Used to store information about server hosts (h5 and h6).
    """
    def __init__(self, port: int, mac: EthAddr = None):
        self.port = port
        self.mac = mac

class LoadBalancer(object):
    """
    Handles traffic distribution between two servers.
    Implements round-robin algorithm to alternate between servers h5 and h6.
    """
    def __init__(self):
        log.info("LoadBalancer constructor entered")
        self.virtual_ip = IPAddr("10.0.0.10")
        self.connections = set()
        log.info("OpenFlow listener added")

        # flag to toggle between h5 and h6 in round-robin fashion
        self.to_h5 = True  

        # maps server IP addresses to their port and MAC information
        self.mac_mapping = {
            IPAddr("10.0.0.5"): Mapping(5, EthAddr("00:00:00:00:00:05")),  # Server h5
            IPAddr("10.0.0.6"): Mapping(6, EthAddr("00:00:00:00:00:06")),  # Server h6
        }
        log.info("mac_mapping initialized")

        # store mappings from virtual IPs to real server IPs
        self.ip_mapping = {}
        core.openflow.addListeners(self)
        log.info("LoadBalancer initialized completely")

    def _handle_ConnectionUp(self, event):
        """
        Called when a switch connects to the controller.
        Sets up default flow rules.
        """
        log.info(f"Switch {dpid_to_str(event.dpid)} has connected.")
        # self.connections.add(event.connection)

        # install a flow that drops all packets by default
        # msg = of.ofp_flow_mod(priority=0)
        # event.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Called when a packet is sent to the controller from the switch.
        Main entry point for packet processing logic.
        """
        packet = event.parsed
        inport = event.port

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if packet.type == ethernet.IPV6_TYPE:
            # Drop IPv6 packets silently
            return

        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp_packet(inport, event, packet.payload)
        elif packet.type == ethernet.IP_TYPE:
            self.handle_ipv4_packet(inport, event, packet.payload)
        else:
            log.warning(f"Unknown Ethernet type: {packet.type}")


    def handle_arp_packet(self, inport, event, arp_packet):
        """
        Handles ARP packets, particularly ARP requests for the virtual IP.
        Creates ARP replies and installs flow rules for the connection.
        """
        # arp_type = arp_opcode_to_text.get(, str(arp_packet.opcode))
        from_valid_host = 1 <= inport <= 4  # Verify this is from a client (h1-h4)

        # if arp_packet.prototype == arp.PROTO_TYPE_IP and arp_packet.hwtype == arp.HW_TYPE_ETHERNET:

        ## client to VIP
        if arp_packet.opcode == arp.REQUEST and from_valid_host:
            mapped_result = self.map_ip_to_mac(str(arp_packet.protodst))
            if mapped_result is None:
                log.warning(f"No MAC mapping found for IP {arp_packet.protodst}")
                return
            hw_dst = mapped_result.mac

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
                # self.server_to_client_flow_entry(outport, IPAddr(server_real_ip), IPAddr(arp_packet.protosrc), inport)
                self.server_to_client_flow_entry(outport, IPAddr(server_real_ip), self.virtual_ip, IPAddr(arp_packet.protosrc), inport)
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

    def handle_ipv4_packet(self, inport, event, ip_packet):
        """
        Handles IPv4 packets, particularly for packets destined to the virtual IP.
        Forwards packets to the appropriate server based on the mapping.
        """
        dst_ip = str(ip_packet.dstip)
        self.map_ip_to_mac(dst_ip)
        
        msg = of.ofp_packet_out()
        msg.data = event.ofp

        real_host_ip = self.ip_mapping.get(dst_ip) if dst_ip not in self.mac_mapping else dst_ip
        if real_host_ip not in self.mac_mapping:
            log.warning(f"Unknown destination IP {dst_ip}")
            return

        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.mac_mapping[real_host_ip].mac))
        msg.actions.append(of.ofp_action_output(port=self.mac_mapping[real_host_ip].port))
        msg.in_port = inport
        event.connection.send(msg)

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

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = arp_packet.src
        ether.src = hw_dst
        ether.payload = arp_reply
        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        return arp_reply

    def client_to_server_flow_entry(self, inport, nw_dst, nw_dst_addr, outport):
        """
        Creates a flow rule that handles traffic from client to server.
        Rewrites the destination IP address to the real server IP.
        """
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 0
        fm.hard_timeout = 0
        fm.priority = 32768
        fm.match = of.ofp_match()
        fm.match.in_port = inport
        fm.match.dl_type = IPV4
        fm.match.nw_dst = self.virtual_ip
        fm.actions.append(of.ofp_action_nw_addr.set_dst(nw_dst_addr))
        fm.actions.append(of.ofp_action_output(port=outport))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(self.mac_mapping[nw_dst_addr].mac))

    #     fm.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
    # fm.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
    # fm.actions.append(of.ofp_action_output(port=server_port))
        return fm

    def server_to_client_flow_entry(self, inport, nw_src, nw_src_addr, clientIP, outport):
        """
        Creates a flow rule that handles traffic from server back to client.
        Rewrites the source IP address back to the virtual IP.
        """
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 0
        fm.hard_timeout = 0
        fm.priority = 32768
        fm.match = of.ofp_match()
        fm.match.in_port = inport
        fm.match.dl_type = IPV4
        fm.match.nw_src = nw_src
        fm.match.nw_dst = clientIP
        fm.actions.append(of.ofp_action_nw_addr.set_src(nw_src_addr))
        fm.actions.append(of.ofp_action_output(port=outport))
        return fm

    def map_ip_to_mac(self, ip: str) -> Mapping:
        """
        Maps IP addresses to the corresponding server's MAC address.
        Implements round-robin load balancing between h5 and h6.
        """
        if ip in self.mac_mapping:
            return self.mac_mapping[ip]

        if ip == str(self.virtual_ip):
            if self.to_h5:
                self.ip_mapping[ip] = "10.0.0.5"
                self.to_h5 = False
            else:
                self.ip_mapping[ip] = "10.0.0.6"
                self.to_h5 = True
            return self.mac_mapping[self.ip_mapping[ip]]

        log.warning(f"Attempted to map unknown IP: {ip}")
        return None

def launch():
    """
    Entry point for the POX component.
    Registers the LoadBalancer with the core.
    """
    log.info("Launching LoadBalancer...")
    try:
        core.registerNew(LoadBalancer)
    except Exception as e:
        log.error(f"Failed to launch LoadBalancer: {e}")
