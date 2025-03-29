from pox.lib.util import dpid_to_str
from pox.lib.packet.arp import arp
from pox.lib.packet.vlan import vlan
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()
IPV4 = dl_type = 0x0800  # Ethernet type for IPv4

class Mapping:
    def __init__(self, port: str, mac: EthAddr = None):
        self.port = port
        self.mac = mac

class LoadBalancer(object):
    def __init__(self):
        self.connections = set()
        core.openflow.addListeners(self)
        log.info("Switch initialized, waiting for connections...")

        self.to_h5 = True
        self.mac_mapping = {
            "10.0.0.5": Mapping(5, EthAddr("00:00:00:00:00:05")),
            "10.0.0.6": Mapping(6, EthAddr("00:00:00:00:00:06")),
        }

        self.ip_mapping = {}

    def construct_arp_packet(self, arp: arp, hw_src, hw_dst, protodst, protosrc) -> arp:
        """Construct an ARP packet with the given parameters"""
        msg = arp()
        msg.hwtype = arp.hwtype
        msg.prototype = arp.prototype
        msg.hwlen = arp.hwlen
        msg.protolen = arp.protolen
        msg.opcode = arp.REPLY
        msg.hwsrc = hw_dst
        msg.hwdst = hw_src
        msg.protosrc = protodst
        msg.protodst = protosrc
        return msg
    
    def handle_arp(self, inport, event, arp_packet):
        """Handle incoming ARP packets"""
        ARP_TYPE = 0x0806  # Ethernet type for ARP
        arp_opcode_to_text = {
            arp.REQUEST: "REQUEST",
            arp.REPLY: "REPLY"
        }

        arp_packet_type = arp_opcode_to_text.get(arp_packet.opcode, f"{arp_packet.opcode}")

        if arp_packet.prototype == arp.PROTO_TYPE_IP:
            if arp_packet.hwtype == arp.HW_TYPE_ETHERNET:
                from_acceptable_hosts = (1 <= inport <= 4)
                log.debug(f"packet inport {inport}")
                
                if arp_packet_type == "REQUEST" and from_acceptable_hosts:
                    hw_dst = self.map_ip_to_mac(str(arp_packet.protodst)).mac

                    client_to_server_arp = self.construct_arp_packet(
                        arp_packet, 
                        hw_src= arp_packet.hwsrc,
                        hw_dst= hw_dst, 
                        protodst= arp_packet.protodst,
                        protosrc= arp_packet.protosrc
                    )

                    ether_frame_header = ethernet(
                        type= ARP_TYPE,
                        src= event.connection.eth_addr,
                        dst= arp_packet.hwsrc
                    )

                    ether_frame_header.payload = client_to_server_arp

                    msg = of.ofp_packet_out()
                    msg.data = ether_frame_header.pack()
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                    msg.in_port = inport
                    event.connection.send(msg)

                    server_real_ip = self.ip_mapping.get(str(arp_packet.protodst))
                    if not server_real_ip:
                        log.warning(f"IP {arp_packet.protodst} not found in ip_mapping")
                        return
                    outport = self.mac_mapping.get(server_real_ip, Mapping(None)).port
                    if outport is None:
                        log.warning(f"No port mapping found for {server_real_ip}")
                        return


                    if server_real_ip:
                        flow_table_entry = self.client_to_server_flow_table_entry(
                            inport, arp_packet.protodst, IPAddr(server_real_ip), outport
                        )
                        event.connection.send(flow_table_entry)

                    if server_real_ip:
                        flow_table_entry = self.server_to_client_flow_table_entry(
                            outport, IPAddr(server_real_ip), arp_packet.protosrc, inport
                        )
                        event.connection.send(flow_table_entry)
                        log.info(f"Installed flow for ARP request from {arp_packet.protosrc} to {arp_packet.protodst}")

                elif arp_packet_type == "REQUEST":
                    log.debug(f"ARP request from non acceptyable host")
                    log.debug(f"ARP request from {arp_packet.protosrc} to {arp_packet.protodst} on port {inport} ignored")

                    msg = of.ofp_packet_out()
                    msg.data = arp_packet.pack() 
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                    msg.in_port = inport
                    event.connection.send(msg) 
                else:
                    log.debug("ARP reply detected")
                
    def handle_ipv4_packet(self, inport, event, ip_packet):
        """Handle incoming IPv4 packets"""
        dst_ip = str(ip_packet.dstip)
        msg = of.ofp_packet_out()
        msg.data = event.ofp

        real_host_ip = None
        if dst_ip not in self.mac_mapping:
            real_host_ip = self.ip_mapping.get(dst_ip)
        else:
            real_host_ip = dst_ip

        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.mac_mapping[real_host_ip].mac))

        outport = self.mac_mapping[real_host_ip].port 
        msg.actions.append(of.ofp_action_output(port = outport))

        msg.in_port = inport
        event.connection.send(msg) 

    def handle_PacketIn(self, event):
        """Handle incoming packets"""
        packet = event.parsed
        inport = event.port
        if not packet:
            log.warning("Received empty packet")
            return
        
        arp_packet = packet.find('arp')
        if arp_packet:
            log.debug(f"Received ARP packet: {arp_packet.opcode} from {packet.src} to {packet.dst} on port {inport}")
            self.handle_arp(inport, event, arp_packet)
            return

        ip_packet = packet.find('ipv4')
        if ip_packet:
            self.handle_ipv4_packet(inport, event, packet)
            return
        
    def client_to_server_flow_table_entry(self, inport: int, nw_dst: str, nw_dst_addr: str, outport: int):
        """Create a flow table entry for client to server traffic"""
        flow_table_entry = of.ofp_flow_mod()
        flow_table_entry.idle_timeout = 0
        flow_table_entry.hard_timeout = 0
        flow_table_entry.priority = 32768  # Default priority for flow entries
        entry_match = of.ofp_match(
            in_port=inport,
            dl_type=IPV4,
            nw_dst=nw_dst,
        )
        
        flow_table_entry.match = entry_match
        action_set_output_port = of.ofp_action_output(port=outport)
        action_set_nw_dst = of.ofp_action_nw_addr.set_dst(nw_dst_addr)

        flow_table_entry.actions.append(action_set_output_port)
        flow_table_entry.actions.append(action_set_nw_dst)

        return flow_table_entry
    
    def server_to_client_flow_table_entry(self, inport: int, nw_src: str, nw_src_addr: str, outport: int):
        """Create a flow table entry for server to client traffic"""
        flow_table_entry = of.ofp_flow_mod()
        flow_table_entry.idle_timeout = 0
        flow_table_entry.hard_timeout = 0
        flow_table_entry.priority = 32768  # Default priority for flow entries
        entry_match = of.ofp_match(
            in_port=inport,
            dl_type=IPV4,
            nw_src=nw_src,
        )
        
        flow_table_entry.match = entry_match
        action_set_output_port = of.ofp_action_output(port=outport)

        action_set_nw_src = of.ofp_action_nw_addr.set_src(nw_src_addr)

        flow_table_entry.actions.append(action_set_output_port) 
        flow_table_entry.actions.append(action_set_nw_src)

        return flow_table_entry
    
    def map_ip_to_mac(self, ip: str) -> Mapping:
        """Map an IP address to its corresponding MAC address using the mac_mapping dictionary"""
        if ip in self.mac_mapping:
            return self.mac_mapping[ip]
        else:
            log.warning(f"IP address {ip} not found in mac_mapping")

            if self.to_h5:
                self.ip_mapping[ip] = "10.0.0.5"
                self.to_h5 = False
            else:
                self.ip_mapping[ip] = "10.0.0.6"
                self.to_h5 = True
            return self.mac_mapping[self.ip_mapping[ip]]

def launch():
    """Launch the LoadBalancer component"""
    log.info("Launching LoadBalancer...")
    core.registerNew(LoadBalancer)

