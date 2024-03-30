#!/usr/bin/python3
from graph import *
import pox.openflow.libopenflow_01 as of
import copy
from pox.lib.packet import ethernet, ipv4, udp, dns
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import heapq
    

class Graph():
    def __init__(self):
        self.hosts = []
        self.switches = []
        self.links = []
        self.switch_num = 0 
        self.host_num = 0 
        
    def add_host(self, h):
        self.hosts.append(h)
        self.host_num +=1
        
    def add_switch(self, s):
        self.switches.append(s)
        self.switch_num +=1
        
    def add_link(self, l):
        self.links.append(l)
        
    def get_min_unvisited_link (self, lst, unvisited,  v = False):
        neighbors =  list(filter(lambda l : (l[1] in unvisited), lst))
        
        if(v!=False):
            neighbors =  list(filter(lambda l : l[0]==v , neighbors))
        
        if not neighbors:
            return None 
        
        shortest_link = min(neighbors, key= lambda l: l[2])
       
        return shortest_link
    
    def get_nodes(self):
        return list(self.hosts + self.switches)
    
    def get_links_start_with_v (self, v):
        return list(filter(lambda l: l[0] == v, self.links))
    
    def get_neighbors_v(self, v):
        return list(filter(lambda l: l[1], self.get_links_start_with_v(v)))


    def get_port_of_switch(self, s, dst):
        link = list(filter(lambda l :l[0]==s and l[1]==dst, self.links))

        return link[0][3], link[0][4]
    


# KAIST CS341 SDN Lab Task 2, 3, 4
#
# All functions in this file runs on the controller:
#   - init(net):
#       - runs only once for network, when initialized
#       - the controller should process the given network structure for future behavior
#   - addrule(switchname, connection):
#       - runs when a switch connects to the controller
#       - the controller should insert routing rules to the switch
#   - handlePacket(packet, connection):
#       - runs when a switch sends unhandled packet to the controller
#       - the controller should decide whether to handle the packet:
#           - let the switch route the packet
#           - drop the packet
#
# Task 2: Getting familiarized with POX 
#   - Let switches "flood" packets
#   - This is not graded
# 
# Task 3: Implementing a Simple Routing Protocol
#   - Let switches route via Dijkstra
#   - Match ARP and ICMP over IPv4 packets
#
# Task 4: Implementing simple DNS censorship 
#   - Let switches send DNS packets to Controller
#       - By default, switches will send unhandled packets to controller
#   - Drop DNS requests for asking cs341dangerous.com, relay all other packets correctly
#
# Task 5: Implementing simple HTTP censorship 
#   - Let switches send HTTP packets to Controller
#       - By default, switches will send unhandled packets to controller
#   - Additionally, drop HTTP requests for heading cs341dangerous.com, relay all other packets correctlys


###
# If you want, you can define global variables, import libraries, or do others
###


def init(net) -> None:
    #
    # net argument has following structure:
    # 
    # net = {
    #    'hosts': {
    #         'h1': {
    #             'name': 'h1',
    #             'n'IP': '10.0.0.1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('h1', 1, 's1', 2, 3)
    #             ],
    #         },
    #         ...
    #     },
    #     'switches': {
    #         's1': {
    #             'name': 's1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('s1', 2, 'h1', 1, 3)
    #             ]
    #         },
    #         ...
    #     }
    # }
    #
    ###
    #  CODE HERE
    ###
    
    global _host_ips, _ip_to_host
    _host_ips = {}
    _ip_to_host = {}
    
    global graph
    graph = Graph()  
    
    # {'s4':[(2,0, src_ip, dst_ip), ], ...}
    global openflow_table
    openflow_table = {}
   
    
    ####  1.parse json file  ####
    # link dictionary looks like (src, dst, cost, [in_port, out_port])
    for switch_name, switch_info in net['switches'].items():
        graph.add_switch(switch_name)
        openflow_table[switch_name] = []
        for link in switch_info['links']:
            link = (link[0], link[2], link[4], link[1], link[3])
            graph.add_link(link)
           
    for host_name, host_info in net['hosts'].items():
        # add ip addr of host in dictionary
        _host_ips[host_name] = host_info['IP']
        _ip_to_host[IPAddr(host_info['IP'])] = host_name

        # add host and links into graph
        graph.add_host(host_name)
        for link in host_info['links']:
            link = (link[0], link[2], link[4], link[1], link[3])
            graph.add_link(link)
    
    global switches 
    switches = graph.switches
        
    # Create a graph from the links
    _graph = {}
    for link in graph.links:
        src, dst, weight, out_port, in_port = link
        if src not in _graph:
            _graph[src] = {}
        if dst not in _graph:
            _graph[dst] = {}
        _graph[src][dst] = weight
        _graph[dst][src] = weight  # This line makes the graph undirected
    
    # 모든 경로에 대해 다익스트라 수행. 
    for h  in graph.hosts:
        paths = dijkstra(h, _graph)
        for node, details in paths.items():
            src_ip = _host_ips[h]
            dst_ip = _host_ips[node]
            path = details[1]
            for i  in range(1, len(path)-1):
                switch = path[i]                  # _node  = ('s2', in_port_num, out_port_num, dst_ip_Addr )
                out_port, in_port = graph.get_port_of_switch(switch,  path[i+1])
                openflow_table[switch].append((switch, in_port, out_port, dst_ip))   # { 's2': (2, 0, ip_addr), ..}
    

def dijkstra( start, graph):
    queue = [(0, start, [])]  
    visited = set()
    paths = {} 

    while queue:
        (cost, vertex, path) = heapq.heappop(queue)
        if vertex not in visited:
            visited.add(vertex)
            path = path + [vertex]

            paths[vertex] = (cost, path)

            for next_node, weight in graph[vertex].items():
                if next_node not in visited:
                    heapq.heappush(queue, (cost + weight, next_node, path))
    remove_key = []
    for key, path in paths.items():
        if(key in switches):
            remove_key.append(key)
            continue
     
     
    for key in remove_key:
       paths.pop(key)
    return paths  



    
def addrule(switchname: str, connection) -> None:
    
    # This function is invoked when a new switch is connected to controller
    # Install table entry to the switch's routing table
    #
    # For more information about POX openflow API,
    # Refer to [POX official document](https://noxrepo.github.io/pox-doc/html/),
    # Especially [ofp_flow_mod - Flow table modification](https://noxrepo.github.io/pox-doc/html/#ofp-flow-mod-flow-table-modification)
    # and [Match Structure](https://noxrepo.github.io/pox-doc/html/#match-structure)
    #
    # your code will be look like:
    # msg = ....
    # connection.send(msg)
    ###
    # YOUR CODE HERE
    ###
   
    rules = openflow_table[switchname]
    global _port_dict
    for rule in rules:
        in_port = rule[1]
        out_port = rule[2]
        #src_ip = rule[2]
        dst_ip = rule[3]
        dst_ip = IPAddr(dst_ip)
        
     
        icmp = of.ofp_flow_mod()
        icmp.match.dl_type = 0x0800 #IP_V4
        icmp.match.nw_proto = 1 # ICMP protocol
        icmp.match.nw_dst = IPAddr(dst_ip)
        icmp.actions.append(of.ofp_action_output(port = out_port))
        connection.send(icmp)
        
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x0806      #arp 
        fm.match.nw_dst = IPAddr(dst_ip)
        fm.actions.append(of.ofp_action_output( port = out_port ) )
        connection.send( fm )     
    
from scapy.all import * # you can use scapy in this task

CENSORED_DOMAINS = ['cs341dangerous.com']
pending_dns_requests = []

def handlePacket(switchname, event, connection):
    packet = event.parsed
    if not packet.parsed:
        print('Ignoring incomplete packet')
        return
    # Retrieve how packet is parsed
    # Packet consists of:
    #  - various protocol headers
    #  - one content
    # For example, a DNS over UDP packet consists of following:
    # [Ethernet Header][           Ethernet Body            ]
    #                  [IPv4 Header][       IPv4 Body       ]
    #                               [UDP Header][ UDP Body  ]
    #                                           [DNS Content]
    # POX will parse the packet as following:
    #   ethernet --> ipv4 --> udp --> dns
    # If POX does not know how to parse content, the content will remain as `bytes`
    #     Currently, HTTP messages are not parsed, remaining `bytes`. you should parse it manually.
    # You can find all available packet header and content types from pox/pox/lib/packet/
    packetfrags = {}
    p = packet
    while p is not None:
        packetfrags[p.__class__.__name__] = p
        if isinstance(p, bytes):
            break
        p = p.next
    print(packet.dump()) # print out unhandled packets
    # How to know protocol header types? see name of class
    
    # If you want to send packet back to switch, you can use of.ofp_packet_out() message.
    # Refer to [ofp_packet_out - Sending packets from the switch](https://noxrepo.github.io/pox-doc/html/#ofp-packet-out-sending-packets-from-the-switch)
    # You may learn from [l2_learning.py](pox/pox/forwarding/l2_learning.py), which implements learning switches
    
    # THIS MATCHES TO QUERY
    if packet.find('udp') and packet.find('udp').dstport == 53:
        dns_packet = packet.next.next.next
        domain_query = dns_packet.questions[0].name
        # Store the DNS request state
        
        ip = packet.find('ipv4')
        udp_pkt = packet.find('udp')
        if domain_query in CENSORED_DOMAINS:
            query_tuple = (ip.srcip, udp_pkt.srcport)
            pending_dns_requests.append(query_tuple)
            
            client_ip = str(ip.srcip)
            clinet_port = udp_pkt.srcport
            dns_ip = str(ip.dstip)
            dns_port = 53
            print('eth',str(packet.dst), str(packet.src))
            print('udp',dns_ip, client_ip)
            
            eth_layer = Ether(src=str(packet.dst), dst=str(packet.src))
        
            ip_layer = IP(src=dns_ip, dst=client_ip)

            # UDP layer: swap source and destination ports
            udp_layer = UDP(sport=dns_port, dport=clinet_port)
            
            # DNS layer: set the response flags, copy the ID and set rcode to 3 (NXDOMAIN)
            dns_layer = DNS(
                id=dns_packet.id,     # Copy the ID from the request
                qr=1,                       # Set the message as a response
                aa=0,                       # Not an authoritative answer
                tc=0,                       # Not truncated
                rd=0,
                qd=DNSQR(qname=domain_query),     # Original question section
                an=None,                    # No answer section
                ns=None,                    # No authority section
                ar=None                     # No additional section
            )
            
            # Construct the full response packet
            response_packet = eth_layer / ip_layer / udp_layer / dns_layer
        
            raw_packet_data = bytes(response_packet)

            # Send the fake DNS response back to the source
            msg = of.ofp_packet_out()
            msg.data = raw_packet_data
            msg.actions.append(of.ofp_action_output(port = event.port))
            event.connection.send(msg)

            # Also send the packet out the switch port
            packet_out = of.ofp_packet_out()
            packet_out.data = event.ofp # Forward the original packet
            packet_out.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
            connection.send(packet_out)
            return
        else:
            msg = of.ofp_packet_out()
            msg.data = event.ofp # Forward the original packet
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
            connection.send(msg)
            return
    ## THIS MATCHES TO RESPONSE 
    elif packet.find('udp') and packet.find('udp').srcport == 53:
        dns_payload = packet.next.next.next
        answer =  dns_payload.answers[0]
        # Store the DNS request state
        ip = packet.find('ipv4')
        udp_pkt = packet.find('udp')
        query_tuple = (ip.dstip, udp_pkt.dstport)
        
        if query_tuple in pending_dns_requests:
                
            dns_res = of.ofp_flow_mod()
            dns_res.match.dl_type=0x800
            dns_res.match.nw_src = IPAddr(answer.rddata)
            connection.send(dns_res)
            
            dns_res = of.ofp_flow_mod()
            dns_res.match.dl_type=0x800
            dns_res.match.nw_dst = IPAddr(answer.rddata)
            connection.send(dns_res)
            return
        else: 
            # Also send the packet out the switch port
            packet_out = of.ofp_packet_out()
            packet_out.data = event.ofp # Forward the original packet
            packet_out.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
            connection.send(packet_out)
            return
                     
    else: 
        packet_out = of.ofp_packet_out()
        packet_out.data = event.ofp # Forward the original packet
        packet_out.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
        connection.send(packet_out)
        return
    