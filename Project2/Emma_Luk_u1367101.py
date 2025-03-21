from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# Virtual IP and server mappings
VIRTUAL_IP = IPAddr("10.0.0.10")
SERVERS = [(IPAddr("10.0.0.5"), EthAddr("00:00:00:00:00:05")),
           (IPAddr("10.0.0.6"), EthAddr("00:00:00:00:00:06"))]
server_index = 0  # Round-robin index

class LoadBalancer (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        global server_index
        packet = event.parsed

        # Handle ARP Requests for Virtual IP
        if packet.type == packet.ARP_TYPE and packet.payload.opcode == packet.payload.REQUEST:
            arp = packet.payload
            if arp.protodst == VIRTUAL_IP:
                server_ip, server_mac = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)  # Round-robin switch

                # Create ARP reply
                arp_reply = packet.copy()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = server_mac
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.hwdst = arp.hwsrc
                arp_reply.protodst = arp.protosrc

                # Create Ethernet frame
                eth = packet.copy()
                eth.type = eth.ARP_TYPE
                eth.src = server_mac
                eth.dst = arp.hwsrc
                eth.payload = arp_reply

                # Send ARP reply
                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)
                log.info(f"Responded to ARP request from {arp.protosrc} with {server_ip}")

                # Install flow rules for the client-server communication
                self.install_flow(event.port, server_ip, server_mac, arp.protosrc, arp.hwsrc)

    def install_flow(self, client_port, server_ip, server_mac, client_ip, client_mac):
        """ Install forwarding rules for client-server communication """

        # Client to server flow rule
        msg = of.ofp_flow_mod()
        msg.match.in_port = client_port
        msg.match.dl_type = 0x0800  # IP
        msg.match.nw_dst = VIRTUAL_IP
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_output(port=client_port + 4))  # Assuming client and server ports
        self.connection.send(msg)

        # Server to client flow rule
        msg = of.ofp_flow_mod()
        msg.match.in_port = client_port + 4
        msg.match.dl_type = 0x0800  # IP
        msg.match.nw_src = server_ip
        msg.match.nw_dst = client_ip
        msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:FF")))  # Fake MAC for Virtual IP
        msg.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(msg)

        log.info(f"Installed flow: {client_ip} -> {server_ip}, {server_ip} -> {client_ip}")

def launch():
    def start_switch(event):
        log.info("Starting Load Balancer...")
        LoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
