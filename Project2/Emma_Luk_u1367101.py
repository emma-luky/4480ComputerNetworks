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
    def __init__(self, port: int, mac: EthAddr = None):
        self.port = port
        self.mac = mac

class LoadBalancer(object):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("LoadBalancer initialized, waiting for connections...")

        self.to_h5 = True
        self.mac_mapping = {
            "10.0.0.5": Mapping(5, EthAddr("00:00:00:00:00:05")),
            "10.0.0.6": Mapping(6, EthAddr("00:00:00:00:00:06")),
        }

        self.ip_mapping = {}

    def _handle_PacketIn(self, event):
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
        arp_opcode_to_text = {
            arp.REQUEST: "REQUEST",
            arp.REPLY: "REPLY"
        }
        arp_type = arp_opcode_to_text.get(arp_packet.opcode, str(arp_packet.opcode))
        from_valid_host = 1 <= inport <= 4

        if arp_packet.prototype == arp.PROTO_TYPE_IP and arp_packet.hwtype == arp.HW_TYPE_ETHERNET:
            if arp_type == "REQUEST" and from_valid_host:
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
                msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
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

                event.connection.send(
                    self.client_to_server_flow_entry(inport, arp_packet.protodst, IPAddr(server_real_ip), outport)
                )
                event.connection.send(
                    self.server_to_client_flow_entry(outport, IPAddr(server_real_ip), arp_packet.protosrc, inport)
                )
                log.info(f"Flow installed for ARP from {arp_packet.protosrc} to {arp_packet.protodst}")

            elif arp_type == "REQUEST":
                log.debug(f"ARP request from non-acceptable host on port {inport}, ignored")

    def handle_ipv4_packet(self, inport, event, ip_packet):
        dst_ip = str(ip_packet.dstip)
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
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 0
        fm.hard_timeout = 0
        fm.priority = 32768
        fm.match = of.ofp_match(in_port=inport, dl_type=IPV4, nw_dst=nw_dst)
        fm.actions.append(of.ofp_action_nw_addr.set_dst(nw_dst_addr))
        fm.actions.append(of.ofp_action_output(port=outport))
        return fm

    def server_to_client_flow_entry(self, inport, nw_src, nw_src_addr, outport):
        fm = of.ofp_flow_mod()
        fm.idle_timeout = 0
        fm.hard_timeout = 0
        fm.priority = 32768
        fm.match = of.ofp_match(in_port=inport, dl_type=IPV4, nw_src=nw_src)
        fm.actions.append(of.ofp_action_nw_addr.set_src(nw_src_addr))
        fm.actions.append(of.ofp_action_output(port=outport))
        return fm

    def map_ip_to_mac(self, ip: str) -> Mapping:
        if ip in self.mac_mapping:
            return self.mac_mapping[ip]

        if self.to_h5:
            self.ip_mapping[ip] = "10.0.0.5"
            self.to_h5 = False
        else:
            self.ip_mapping[ip] = "10.0.0.6"
            self.to_h5 = True

        return self.mac_mapping[self.ip_mapping[ip]]

def launch():
    log.info("Launching LoadBalancer...")
    core.registerNew(LoadBalancer)
