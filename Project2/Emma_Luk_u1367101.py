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
    """
    Handles traffic distribution between two servers.
    Implements round-robin algorithm to alternate between servers h5 and h6.
    """
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

    def _handle_ConnectionUp(self, event):
        """
        Called when a switch connects to the controller.
        Sets up default flow rules.
        """
        log.info(f"Switch {dpid_to_str(event.dpid)} has connected.")
        self.connections.add(event.connection)
        
        # install a flow that drops all packets by default
        msg = of.ofp_flow_mod()
        msg.priority = 0
        event.connection.send(msg)

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

        arp_packet = packet.find('arp')
        if arp_packet:
            log.debug(f"ARP {arp_packet.opcode} from {packet.src} to {packet.dst} on port {inport}")
            self.handle_arp(inport, event, arp_packet)
            return

        ip_packet = packet.find('ipv4')
        if ip_packet:
            self.handle_ipv4_packet(inport, event, ip_packet)
            return

    def handle_arp(self, inport, event, arp_packet):
        """
        Handles ARP packets, particularly ARP requests for the virtual IP.
        Creates ARP replies and installs flow rules for the connection.
        """
        arp_opcode_to_text = {
            arp.REQUEST: "REQUEST",
            arp.REPLY: "REPLY"
        }
        arp_type = arp_opcode_to_text.get(arp_packet.opcode, str(arp_packet.opcode))
        from_valid_host = 1 <= inport <= 4  # Verify this is from a client (h1-h4)

        if arp_packet.prototype == arp.PROTO_TYPE_IP and arp_packet.hwtype == arp.HW_TYPE_ETHERNET:
            if arp_type == "REQUEST" and from_valid_host:
                # get MAC address for the requested IP (maps virtual IP to real server)
                hw_dst = self.map_ip_to_mac(str(arp_packet.protodst)).mac
                
                arp_reply = self.construct_arp_reply(
                    arp_packet,
                    hw_src=arp_packet.hwsrc,
                    hw_dst=hw_dst,
                    protodst=arp_packet.protodst,
                    protosrc=arp_packet.protosrc
                )

                # create Ethernet frame to carry the ARP reply
                ether = ethernet(type=ARP_TYPE, src=event.connection.eth_addr, dst=arp_packet.hwsrc)
                ether.payload = arp_reply

                # send the ARP reply back to the requesting host
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
                msg.in_port = inport
                event.connection.send(msg)

                # get the real server IP that was mapped to the requested destination
                server_real_ip = self.ip_mapping.get(str(arp_packet.protodst))
                if not server_real_ip:
                    log.warning(f"IP {arp_packet.protodst} not found in ip_mapping")
                    return
                outport = self.mac_mapping.get(server_real_ip, Mapping(None)).port
                if outport is None:
                    log.warning(f"No port mapping found for {server_real_ip}")
                    return

                # handle arp requests coming from servers
                # instead of handling ip forward packet to flow tables
                # send to noremal message port to of.OFPP_TABLE

                # install flow rules for client -> server traffic
                event.connection.send(
                    self.client_to_server_flow_entry(inport, arp_packet.protodst, IPAddr(server_real_ip), outport)
                )
                
                # install flow rules for server -> client traffic
                event.connection.send(
                    self.server_to_client_flow_entry(outport, IPAddr(server_real_ip), arp_packet.protosrc, inport)
                )
                log.info(f"Flow installed for ARP from {arp_packet.protosrc} to {arp_packet.protodst}")
            elif arp_type == "REQUEST":
                # If the ARP request comes from a server (not from a client)
                log.debug(f"ARP request from server or unknown port {inport}, sending to OFPP_TABLE")
                
                # Re-inject packet back into the flow table (normal pipeline handling)
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = inport
                msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))  # Let switch handle it
                event.connection.send(msg)

    def handle_ipv4_packet(self, inport, event, ip_packet):
        """
        Handles IPv4 packets, particularly for packets destined to the virtual IP.
        Forwards packets to the appropriate server based on the mapping.
        """
        dst_ip = str(ip_packet.dstip)
        msg = of.ofp_packet_out()
        msg.data = event.ofp

        # get the real server IP that this virtual IP maps to
        real_host_ip = self.ip_mapping.get(dst_ip) if dst_ip not in self.mac_mapping else dst_ip
        if real_host_ip not in self.mac_mapping:
            log.warning(f"Unknown destination IP {dst_ip}")
            return

        # rewrite the destination MAC address to the real server's MAC
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.mac_mapping[real_host_ip].mac))
        
        # forward the packet to the real server's port
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
        fm.match = of.ofp_match(in_port=inport, dl_type=IPV4, nw_dst=nw_dst)
        fm.actions.append(of.ofp_action_nw_addr.set_dst(nw_dst_addr))       
        fm.actions.append(of.ofp_action_output(port=outport))               
        return fm

    def server_to_client_flow_entry(self, inport, nw_src, nw_src_addr, outport):
        """
        Creates a flow rule that handles traffic from server back to client.
        Rewrites the source IP address back to the virtual IP.
        """
        fm = of.ofp_flow_mod()                        
        fm.idle_timeout = 0                           
        fm.hard_timeout = 0                           
        fm.priority = 32768                           
        fm.match = of.ofp_match(in_port=inport, dl_type=IPV4, nw_src=nw_src)  
        fm.actions.append(of.ofp_action_nw_addr.set_src(nw_src_addr))         
        fm.actions.append(of.ofp_action_output(port=outport))                 
        return fm

    def map_ip_to_mac(self, ip: str) -> Mapping:
        """
        Maps IP addresses to the corresponding server's MAC address.
        Implements round-robin load balancing between h5 and h6.
        """
        # if the IP corresponds to a real server, return its mapping directly
        if ip in self.mac_mapping:
            return self.mac_mapping[ip]
            
        # if the IP is the virtual IP, map it to either h5 or h6 in round-robin fashion
        if ip == str(self.virtual_ip):
            if self.to_h5:
                self.ip_mapping[ip] = "10.0.0.5"  # Map to h5
                self.to_h5 = False                # Toggle to h6 for next request
            else:
                self.ip_mapping[ip] = "10.0.0.6"  # Map to h6
                self.to_h5 = True                 # Toggle to h5 for next request
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
        core.registerNew(LoadBalancer)  # Register the load balancer with POX core
    except Exception as e:
        log.error(f"Failed to launch LoadBalancer: {e}")