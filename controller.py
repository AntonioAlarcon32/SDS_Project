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
from ryu.lib.packet import tcp
from ryu.app.wsgi import ControllerBase, route
from webob import Response
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

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

        self.public_ip = "80.80.80.80"
        self.monitoring_ip = "10.0.2.1"

        self.router_dpid = "0000000000000002"
        self.firewall_dpid = "0000000000000001"

        self.packet_buffer = {}

        self.snort_port = 3

        self.wsgi = kwargs['wsgi']
        self.data = {}
        self.data['custom_app'] = self
        self.datapaths = {}
        mapper = self.wsgi.mapper
        wsgi_app = self.wsgi
        mapper.connect('activate-honeypot', '/activate-honeypot',
                       controller=CustomController, action='activate_honeypot',
                       conditions=dict(method=['POST']))
        mapper.connect('deactivate-honeypot', '/deactivate-honeypot',
                       controller=CustomController, action='deactivate_honeypot',
                       conditions=dict(method=['POST']))

        mapper.connect('test', '/test',
                       controller=CustomController, action='test_function',
                       conditions=dict(method=['GET']))
        
        mapper.connect('add_firewall', '/firewall',
                       controller=CustomController, action='add_firewall',
                       conditions=dict(method=['POST']))
        
        mapper.connect('remove_firewall', '/firewall',
                       controller=CustomController, action='remove_firewall',
                       conditions=dict(method=['DELETE']))
        
        wsgi_app.registory['CustomController'] = self.data


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        # install table-miss flow entry
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
        self.restrictAccessToDatabase(parser=parser, datapath=datapath, ofproto=ofproto)

        if (dpid == self.firewall_dpid):
            self.configure_firewall(parser=parser, datapath=datapath, ofproto=ofproto)


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
            print(self.arp_table)
            self.arp_table[src_ip] = src_mac
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
                print(f"{src_ip} has packets buffered")
                (buf_datapath, buf_in_port, buf_eth, buf_data) = self.packet_buffer[src_ip]
                parsed_ip = src_ip.split(".")
                subnet = f'{parsed_ip[0]}.{parsed_ip[1]}.{parsed_ip[2]}.0/24'
                router_ip = f'{parsed_ip[0]}.{parsed_ip[1]}.{parsed_ip[2]}.254'
                src_mac = self.ip_to_mac[router_ip]
                dst_mac = self.arp_table[src_ip]
                buf_out_port = self.subnet_to_port[subnet]
                buf_actions = [
                        parser.OFPActionSetField(eth_dst=dst_mac),
                        parser.OFPActionSetField(eth_src=src_mac),
                        parser.OFPActionOutput(buf_out_port)
                ]
                out = parser.OFPPacketOut(datapath=buf_datapath, buffer_id=buf_datapath.ofproto.OFP_NO_BUFFER,
                                              in_port=buf_in_port, actions=buf_actions, data=buf_data)
                buf_datapath.send_msg(out)
                print(f"{src_ip} buffered packets sent")
                del self.packet_buffer[src_ip]
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
    
    def send_udp_packet(self, dst_ip, payload, parser, datapath, ofproto):

        ip = ipv4.ipv4(dst=dst_ip, src="10.100.100.100", proto=17)
        udp_pkt = udp.udp(dst_port=5000, src_port=5000, total_length=8+len(payload))
        pkt = packet.Packet()


        eth = ethernet.ethernet(self.arp_table[dst_ip], "00:00:00:00:00:03", ether_types.ETH_TYPE_IP)
        pkt.add_protocol(eth)
        pkt.add_protocol(ip)
        pkt.add_protocol(udp_pkt)
        pkt.add_protocol(payload)

        pkt.serialize()

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

            # Define the OpenFlow packet out message
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )

            # Send the packet out message
        datapath.send_msg(out)


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
                if ip_pkt.proto == 17:
                    print(f"Controller action received from {ip_pkt.src}")
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
                            self.send_udp_packet(self.monitoring_ip,b"FTP Bruteforce attempted, a MAC was banned" ,parser,datapath,ofproto)            
                return

            if (ip_pkt.dst in self.arp_table):
                print(f"IP {ip_pkt.dst} has a ARP table entry")
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
                print(f"Installed IP Rule for host {ip_pkt.dst}")
                return
            else:
                print(f"{ip_pkt.dst} not in the arp table ")
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


    def restrictAccessToDatabase(self, parser, datapath, ofproto):
        # Allow only packets from MAC webserver to MAC B
        webserver_ip = '10.0.3.1'
        database_ip = '10.0.3.2'
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=webserver_ip, ipv4_dst=database_ip)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 10, match, actions)

        # Drop packets from any other MAC addresses to MAC B
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=database_ip)
        actions = []
        self.add_flow(datapath, 9, match, actions)
    
    def configure_firewall(self, parser, datapath, ofproto):
        webserver_ip = '10.0.3.1'
        dns_ip = '10.0.3.3'
        out_port = 2
        in_port = 1

        # Drop packets that are not HTTP or DNS
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                in_port= 1)
        actions = [parser.OFPActionOutput(self.snort_port)]
        self.add_flow(datapath, 400, match, actions)
        #Accept packets that are DNS
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=17,
                                udp_dst=53,
                                in_port=in_port,
                                ipv4_dst=self.public_ip)

        actions = [parser.OFPActionSetField(ipv4_dst=dns_ip),
                   parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]
        self.add_flow(datapath, 500, match, actions)
        #Accept Packets that are HTTP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=6,
                                tcp_dst=80,
                                in_port=in_port,
                                ipv4_dst=self.public_ip)

        actions = [parser.OFPActionSetField(ipv4_dst=webserver_ip),
                   parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]
        self.add_flow(datapath, 500, match, actions)
        #Replace outgoing IP for DNS
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=17,
                                udp_src=53,
                                in_port=2,
                                ipv4_src = dns_ip)
        

        actions = [parser.OFPActionSetField(ipv4_src=self.public_ip),
                   parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, 500, match, actions)
        #Replace outgoing IP for HTTP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=6,
                                tcp_src=80,
                                in_port=2,
                                ipv4_src = webserver_ip)
        
        actions = [parser.OFPActionSetField(ipv4_src=self.public_ip),
                   parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, 500, match, actions)
        print("Firewall configured")




class CustomController(ControllerBase):

    webserver_ip = '10.0.3.1'
    dns_ip = '10.0.3.3'
    honeypot_ip = '10.0.4.1'
    router_out_port_to_honeypot = 2
    public_ip = "80.80.80.80"

    def __init__(self, req, link, data, **config):
        super(CustomController, self).__init__(req, link, data, **config)
        self.custom_app = data['custom_app']

    @route('activate-honeypot', '/activate-honeypot', methods=['POST'])
    def activate_honeypot(self, req, **kwargs):
        custom_app = self.custom_app
        datapath_id = int(req.json["datapath_id"])
        print(datapath_id)
        datapath = custom_app.datapaths.get(datapath_id)
        if datapath is None:
            return Response(content_type='application/json',
                            body=b'{"error": "Datapath not found"}',
                            status=404)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(self.router_out_port_to_honeypot), parser.OFPActionSetField(ipv4_dst=self.honeypot_ip)]
        # Redirect packets headed to the webserver
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst = self.webserver_ip)
        self.add_flow(datapath=datapath, priority=1000, match=match, buffer_id=[], actions=actions)
        # Redirect packets headed to the dns
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=self.public_ip, ipv4_dst = self.dns_ip)
        self.add_flow(datapath=datapath, priority=1000, match=match, buffer_id=[], actions=actions)
        return Response(content_type='application/json',
                        body=b'{"message": "Packets from the webserver and the DNS have been redirected to the honeypot"}')
            
    @route('add_firewall', '/firewall', methods=['POST'])
    def add_firewall(self, req, **kwargs):
        custom_app = self.custom_app
        datapath_id = int(req.json["datapath_id"])
        print(datapath_id)
        datapath = custom_app.datapaths.get(datapath_id)
        if datapath is None:
            return Response(content_type='application/json',
                            body=b'{"error": "Datapath not found"}',
                            status=404)

        blocked_ip_src = req.json["ip_src"]
        blocked_ip_dst = req.json["ip_dst"]
        priority = int(req.json["priority"])
        parser = datapath.ofproto_parser
        print(f"Received REST call for creating firewall from {blocked_ip_src} to {blocked_ip_dst}")
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst = blocked_ip_dst, ipv4_src= blocked_ip_src)
        ofproto = datapath.ofproto
        actions = []
        self.add_flow(datapath=datapath, priority=priority, match=match, buffer_id=[],actions=actions)
        return Response(content_type='application/json',
                        body=b'{"message": "Firewall rule created"}')
    
    @route('remove_firewall', '/firewall', methods=['DELETE'])
    def remove_firewall(self, req, **kwargs):
        custom_app = self.custom_app
        datapath_id = int(req.json["datapath_id"])
        print(datapath_id)
        datapath = custom_app.datapaths.get(datapath_id)
        if datapath is None:
            return Response(content_type='application/json',
                            body=b'{"error": "Datapath not found"}',
                            status=404)

        blocked_ip_src = req.json["ip_src"]
        blocked_ip_dst = req.json["ip_dst"]
        parser = datapath.ofproto_parser
        print(f"Received REST call for deleting firewall from {blocked_ip_src} to {blocked_ip_dst}")
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst = blocked_ip_dst, ipv4_src= blocked_ip_src)
        self.delete_flow(datapath=datapath, match=match)
        return Response(content_type='application/json',
                        body=b'{"message": "Firewall rule deleted"}')

    @route('deactivate-honeypot', '/deactivate-honeypot', methods=['POST'])
    def deactivate_honeypot(self, req, **kwargs):
        custom_app = self.custom_app
        datapath_id = int(req.json['datapath_id'])
        datapath = custom_app.datapaths.get(datapath_id)
        if datapath is None:
            return Response(content_type='application/json',
                            body=b'{"error": "Datapath not found"}',
                            status=404)
        parser = datapath.ofproto_parser
        # No longer redirect packets headed to the webserver to the honeypot
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst = self.webserver_ip)
        self.delete_flow(datapath, match)
        # No longer edirect packets headed to the dns to the honeypot
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=self.public_ip, ipv4_dst = self.dns_ip)
        self.delete_flow(datapath, match)
        return Response(content_type='application/json',
                        body=b'{"message": "Packets from the webserver and the DNS are no longer redirected to the honeypot"}')

    @route('test', '/test', methods=['GET'])
    def test_function(self, req, **kwargs):
        custom_app = self.custom_app
        body = b'{"message": "This ryu controller is reachable"}'
        return Response(content_type='application/json', body=body)
    

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def delete_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)
        