from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)

        self.mac_to_port = {
            '0000000000000001': {'00:00:00:00:00:01': 2},
            '0000000000000003': {'00:00:00:00:00:02': 1},
            '0000000000000004': {'00:00:00:00:00:03': 1},
            '0000000000000005': {'00:00:00:00:00:04': 1}
        }

        self.ip_to_mac = {
            '172.16.0.254': '00:00:00:00:00:01',
            '10.0.1.254': '00:00:00:00:00:02',
            '10.0.2.254': '00:00:00:00:00:03',
            '10.0.3.254': '00:00:00:00:00:04',
            '10.0.4.254': '00:00:00:00:00:05'
        }

        self.subnet_to_port = {
            '172.16.0.0/24': 1,
            '10.0.1.0/24': 3,
            '10.0.2.0/24': 4,
            '10.0.3.0/24': 5,
            '10.0.4.0/24': 2
        }

        self.arp_table = {

        }

        self.datapaths = {

        }

        self.router_dpid = "0000000000000002"

        self.packet_buffer = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        #Default rule to communicate with the controller
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst="10.100.100.100"
        )
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 100, match, actions)

        # Add initial flow entries from mac_to_port table
        dpid = format(datapath.id, "d").zfill(16)
        if dpid in self.mac_to_port:
            for mac, port in self.mac_to_port[dpid].items():
                match = parser.OFPMatch(eth_dst=mac)
                actions = [parser.OFPActionOutput(port)]
                self.add_flow(datapath, 1, match, actions)
                print(f"Configured switch {dpid}")


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def handle_arp_packet(self, pkt, eth, datapath, ofproto, parser, in_port):
        arp_pkt = pkt.get_protocol(arp.arp)
        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip = arp_pkt.dst_ip
        dst_mac = arp_pkt.dst_mac
        opcode = arp_pkt.opcode
        if src_ip not in self.arp_table and src_ip not in self.ip_to_mac: #Save IP to ARP Table
            print(f"{src_ip} not saved, saving in ARP table")
            self.arp_table[src_ip] = src_mac
            print(self.arp_table)
            return
        if dst_ip in self.ip_to_mac and opcode == 1:
            reply_mac = self.ip_to_mac[dst_ip]
            arp_reply = packet.Packet()
            arp_reply.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype,
                dst=eth.src,
                src=reply_mac))
            arp_reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=reply_mac,
                    src_ip=dst_ip,
                    dst_mac=src_mac,
                    dst_ip=src_ip))            
            arp_reply.serialize()
            actions = [parser.OFPActionOutput(in_port)]
                
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                        data=arp_reply.data)
            datapath.send_msg(out)
            print(f"{src_ip} requested the MAC of the switch")
            return
        if (opcode == 2 and src_ip not in self.ip_to_mac):
            if src_ip in self.packet_buffer:
                print("This IP has packets buffered")
                (buf_datapath, buf_in_port, buf_eth, buf_data) = self.packet_buffer[src_ip]
                parsed_ip = src_ip.split(".")
                subnet = f'{parsed_ip[0]}.{parsed_ip[1]}.{parsed_ip[2]}.0/24'
                router_ip = f'{parsed_ip[0]}.{parsed_ip[1]}.{parsed_ip[2]}.254'
                src_mac = self.ip_to_mac[router_ip]
                buf_out_port = self.subnet_to_port[subnet]
                buf_actions = [
                        parser.OFPActionSetField(eth_dst=src_mac),
                        parser.OFPActionSetField(eth_src=src_mac),
                        parser.OFPActionOutput(buf_out_port)
                ]
                out = parser.OFPPacketOut(datapath=buf_datapath, buffer_id=buf_datapath.ofproto.OFP_NO_BUFFER,
                                              in_port=buf_in_port, actions=buf_actions, data=buf_data)
                print("sending buffered packet")
                buf_datapath.send_msg(out)
                print("buffered packet sent")
                return

    def send_arp_request(self, datapath, parser, in_port, dst_ip):
        parsed_ip = dst_ip.split(".")
        router_ip = f'{parsed_ip[0]}.{parsed_ip[1]}.{parsed_ip[2]}.254'
        subnet = f'{parsed_ip[0]}.{parsed_ip[1]}.{parsed_ip[2]}.0/24'
        src_ip = router_ip
        out_port = self.subnet_to_port[subnet]
        pkt = packet.Packet()
        ether_frame = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                                        src=self.ip_to_mac[src_ip],
                                        ethertype=ether_types.ETH_TYPE_ARP)
        arp_req = arp.arp(opcode=arp.ARP_REQUEST,
                        src_mac=self.ip_to_mac[src_ip],
                        src_ip=router_ip,
                        dst_mac='00:00:00:00:00:00',
                        dst_ip=dst_ip)
        pkt.add_protocol(ether_frame)
        pkt.add_protocol(arp_req)
        pkt.serialize()
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                        in_port=in_port,
                                        actions=actions,
                                        data=pkt.data)
        datapath.send_msg(out)
        return
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp_packet(pkt, eth, datapath, ofproto, parser, in_port)
            
        
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        if dpid == self.router_dpid and eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt.dst == '10.100.100.100':
                print("Controller action received")
                udp_pkt = pkt.get_protocols(udp.udp)[0]
                udp_payload = pkt.protocols[-1]  # Extract the payload (text string)
                if isinstance(udp_payload, bytes):
                    text_string = udp_payload.decode('utf-8')
                    orders = text_string.split(";")
                    if orders[0] == "ban":
                        print(f"Banning IP: {orders[1]}")
                        attacker_mac = self.arp_table[orders[1]]
                        match = parser.OFPMatch(eth_src= attacker_mac)
                        for datapath in self.datapaths.values():
                            self.add_flow(datapath, 100, match, [])
                        print(f"User banned, MAC:{attacker_mac}")
                return
            if (ip_pkt.dst in self.arp_table):
                print("This packet has a ARP entry")
                dst_mac = self.arp_table[ip_pkt.dst]
                parsed_ip = ip_pkt.dst.split(".")
                subnet = f'{parsed_ip[0]}.{parsed_ip[1]}.{parsed_ip[2]}.0/24'
                router_ip = f'{parsed_ip[0]}.{parsed_ip[1]}.{parsed_ip[2]}.254'
                src_mac = self.ip_to_mac[router_ip]
                out_port = self.subnet_to_port[subnet]
                actions = [
                    parser.OFPActionSetField(eth_dst=dst_mac),
                    parser.OFPActionSetField(eth_src=src_mac),
                    parser.OFPActionOutput(out_port)
                ]
                data = msg.data
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_pkt.dst)
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                self.add_flow(datapath, 2, match, actions, msg.buffer_id)
                print("installed IP Rule for host")
                return
            else:
                print("not in the arp table :(")
                self.packet_buffer[ip_pkt.dst] = (datapath, in_port, eth, msg.data)
                print(f"Saved packet in buffer for {ip_pkt.dst}")
                self.send_arp_request(datapath, parser, in_port, ip_pkt.dst)
                return

        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch( eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)