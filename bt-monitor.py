#!/usr/bin/python3

import sys
from scapy.all import *
import bencodepy
import binascii

class AliasDict(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.aliases = {}

    def __getitem__(self, key):
        return dict.__getitem__(self, self.aliases.get(key, key))

    def __setitem__(self, key, value):
        return dict.__setitem__(self, self.aliases.get(key, key), value)

    def add_alias(self, key, alias):
        self.aliases[alias] = key

    def get_aliases(self, key):
        res = []
        keys = list(self.keys())
        if key in self.aliases:
            final_key = self.aliases[key]
        elif key in keys:
            final_key = key
        else:
            return []
        
        res.append(final_key)
        for alias in self.aliases:
            if self.aliases[alias] == final_key:
                res.append(alias)

        return res
    
def get_file_size(packets):
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            raw = packet.getlayer('Raw').load
            
            if b'announce' in raw:
                raw = raw.decode('utf-8')
                args = raw.split()[1].split('?')[1]
                arg_list=args.split('&')
                arg_dict = {}
                for arg in arg_list:
                    key, val = arg.split('=')
                    arg_dict[key] = val

                if arg_dict['event'] == 'started':
                    file_size = arg_dict['left']
                    return file_size
    return None
    
def hop_bittorrent_headers(payload, requested_chunks, received_chunks):    
    chunks = []
    pos = payload.find(b'\x13BitTorrent protocol')

    if pos > -1:
        payload = payload[pos+68:]
    else:
        return False, [], requested_chunks, received_chunks
    
    while len(payload) > 0:
        if len(payload) < 5:
            break

        msg_len = int.from_bytes(bytes(reversed(payload[0:4])), sys.byteorder)

        if msg_len == 0:
            break
        
        msg_len = msg_len + 4        
        msg_type = payload[4]

        if msg_type == 7:
            chunk_id = payload[5:9]
            if chunk_id in requested_chunks:
                chunks.append(chunk_id)
            else:
                received_chunks.append(chunk_id)
        
        if msg_type == 6 or msg_type == 17:
            chunk_id = payload[5:9]
            if chunk_id in received_chunks:
                chunks.append(chunk_id)
            else:
                requested_chunks.append(chunk_id)

        if msg_len == len(payload):
            break
        if msg_len < len(payload):
            payload = payload[msg_len:]
        else:
            break

    return True, chunks, requested_chunks, received_chunks

def reassemble(packets):
    pdus = {}
    payloads = []
    all_chunks = set()
    ips_set = {}
    info_hash = None

    for packet in packets:
        if packet.haslayer(TCP):
            key = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
            if key not in pdus:
                pdus[key] = {}
            seq = packet[TCP].seq
            if seq not in pdus[key]:
                pdus[key][seq] = b''
            if int.from_bytes(bytes(packet[TCP].payload), sys.byteorder) != 0:
                pdus[key][seq] += bytes(packet[TCP].payload)
            
            if not info_hash:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if b'BitTorrent' in payload:
                        info_hash = binascii.b2a_hex(payload[28:48]).decode('utf-8')

    requested_chunks = []
    received_chunks = []

    for key, pdu in pdus.items():
        src, sport, dst, dport = key
        message = b''.join(pdu.values())

        is_bittorrent, chunks, requested_chunks, received_chunks = hop_bittorrent_headers(message, requested_chunks, received_chunks)
        if is_bittorrent:
            payloads.append(message)
            if src not in ips_set:
                ips_set[src] = [sport]
            else:
                ips_set[src].append(sport)
            if dst not in ips_set:
                ips_set[dst] = [dport]
            else:
                ips_set[dst].append(dport)
            for chunk in chunks:
                all_chunks.add(chunk)
    
    return ips_set, info_hash, all_chunks

def download(packets):
    i = 0
    
    info_hash = None
    
    known_peers, info_hash, chunks = reassemble(packets)
    file_size = get_file_size(packets)

    if len(known_peers) < 1:
        print("No file download found")
    else:
        print(f"Participating peers:")
        for ip in known_peers:
            ports = known_peers[ip]
            print(f"    IP: {ip}, PORTs: {ports}")
        print(f"Info hash: {info_hash}")
        print(f"File size: ", end="")
        if file_size:
            print(file_size)
        else:
            print("[Could not be determined]")
        print(f"Chunks:")
        for chunks in chunks:
            print(f"    {binascii.b2a_hex(chunks).decode('utf-8')}")
    


def get_local_ip(packets):
    potential_ips = {}

    for packet in packets:
        if packet.haslayer(UDP):
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    output_message = bencodepy.decode(payload)
                    message_type = output_message[b'y'].decode()
                    if message_type=='q':
                        ip = packet[IP].src
                        if ip in potential_ips:
                            potential_ips[ip] = potential_ips[ip]+1
                        else:
                            potential_ips[ip] = 1
                except:
                    pass
    
    max_ip = ('',0)
    for ip in potential_ips:
        l, r = max_ip
        if potential_ips[ip] > r:
            max_ip = (ip, potential_ips[ip])

    ip, _ = max_ip
    return ip

def print_peers(packets, active_peers):
    local_ip = ''
    local_ip = get_local_ip(packets)

    print("       IP       | PORT  |                   ID                     | # of conn")
    print("----------------+-------+------------------------------------------+-----------")
    for peer in active_peers:
        ip, port = peer
        id, num_of_conns = active_peers[peer]
        if ip != local_ip:
            print(f"{ip.ljust(15)} | {str(port).ljust(5)} | {id.decode('utf-8')} | {str(num_of_conns).ljust(11)}")
        else:
            local_peer = peer
    print("----------------+-------+------------------------------------------+-----------")
    print("    LOCAL IP    | PORT  |                   ID                     | # of conn")
    print("----------------+-------+------------------------------------------+-----------")
    ip, port = local_peer
    id, num_of_conns = active_peers[local_peer]
    print(f"{ip.ljust(15)} | {str(port).ljust(5)} | {id.decode('utf-8')} | {str(num_of_conns).ljust(11)}")
    print("----------------+-------+------------------------------------------+-----------")
    print(f"Number of peers: {len(active_peers)}")

def get_num_of_nodes(r_dict):
    return int(len(r_dict[b'nodes'])/26)

def handle_question(packet, tried_peers):
    if IP not in packet or UDP not in packet:
        return tried_peers

    dst = packet[IP].dst
    dport = packet[UDP].dport
    q = (dst, dport)
        
    tried_peers.add(q)
    return tried_peers

def handle_response(packet, tried_peers, active_peers):
    if IP not in packet or UDP not in packet:
        return (tried_peers, active_peers)
    
    src = packet[IP].src
    sport = packet[UDP].sport
    r = (src, sport)

    if r in tried_peers:
        if r in active_peers:
            id, num_of_conns = active_peers[r]
            active_peers[r] = (id, num_of_conns+1)
        else:
            output_message = bencodepy.decode(packet[Raw].load)
            r_dict = output_message[b'r']
            peer_id =  binascii.b2a_hex(r_dict[b'id'])
            peer_num_of_conns = 1 #get_num_of_nodes(r_dict)
            peer_info = (peer_id, peer_num_of_conns)
            active_peers[r] = peer_info

    return (tried_peers, active_peers)

def peers(packets):
    tried_peers = set()
    active_peers = {}

    for packet in packets:
        if packet.haslayer(UDP):
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    output_message = bencodepy.decode(payload)
                    message_type = output_message[b'y'].decode()
                    if message_type=='q':
                        tried_peers = handle_question(packet, tried_peers)
                    elif message_type=='r':
                        tried_peers, active_peers = handle_response(packet, tried_peers, active_peers)
                except bencodepy.exceptions.DecodingError as e:
                    pass
    
    print_peers(packets, active_peers)

def read_bootstraps_from_file():
    file_path = "./bootstraps.txt"
    with open(file_path, 'r') as f:
        strings = [line.strip() for line in f.readlines()]
    return strings

def get_bootstraps_dns(packets):
    bootstraps = read_bootstraps_from_file()
    bootstraps_dict = AliasDict()

    for bootstrap_str in bootstraps:
        bootstraps_dict[bootstrap_str] = ([],[])

    for packet in packets:
        if packet.haslayer(DNS):
            dns = packet[DNS]

            if packet.haslayer(DNSRR):
                qname = dns.qd.qname.decode()
                for i in range(packet.ancount):
                    answer = packet[DNSRR][i]
                    if answer.type == 1 or answer.type == 28:
                        if qname not in bootstraps_dict and ('torrent' in qname or 'dht' in qname):
                            bootstraps_dict[qname] = ([],[])
                        if qname in bootstraps_dict:
                            ip_address = answer.rdata
                            l, r = bootstraps_dict[qname]
                            bootstraps_dict.add_alias(qname, ip_address)
                            if answer.type == 1:
                                l.append(ip_address)
                                bootstraps_dict[qname] = (l, r)
                            else:
                                r.append(ip_address)
                                bootstraps_dict[qname] = (l, r) 
                            
                    elif answer.type == 5:
                        if qname in bootstraps_dict:
                            bootstraps_dict.add_alias(qname, answer.rdata.decode())
    return bootstraps_dict

def init(packets):
    bootstraps_dict = get_bootstraps_dns(packets)

    tried_bootstraps = []
    active_bootstraps = []
    for packet in packets:
        if IP in packet:
            dst = packet[IP].dst
            src = packet[IP].src

            if dst in bootstraps_dict.get_aliases(dst):
                if UDP in packet:
                        port = packet[UDP].dport
                        tried_bootstraps.append((dst, port))

            elif src in bootstraps_dict.get_aliases(src):
                if UDP in packet:
                    port = packet[UDP].sport
                    if (src, port) in tried_bootstraps:
                        active_bootstraps.append((src, port))

    
    if len(tried_bootstraps) < 1:
        print("No bootstrap DNS communication found")
    else:
        print("Bootstraps:")
        for bootstrap in tried_bootstraps:
            ip, port = bootstrap
            if bootstrap in active_bootstraps:
                print(f"    {bootstraps_dict.aliases[ip]}: [\033[92mACTIVE\033[0m]\n        IP: {ip}\n        PORT: {port}")
            else:
                print(f"    {bootstraps_dict.aliases[ip]}: [\033[91mINACTIVE (no response)\033[0m]\n        IP: {ip}\n        PORT: {port}")

def print_usage():
    print("Usage:")
    print("    bt-monitor -pcap <file.pcap>|-csv <file.csv> -init | -peers | -download")
    print("    <file.pcap>: input PCAP file or <file.csv> input CSV file")
    print("    -init: returns a list of detected bootstrap nodes (IP, port)")
    print("    -peers: returns a list of detected neighbors (IP, port, node ID, # of conn)")
    print("    - download: returns file info_hash, size, chunks, contributes (IP+port)")
    print("    - rtable: returns the routing table of the client (node IDs, IP, ports)")
    sys.exit(0)

def main():
    if len(sys.argv) != 4:
        print_usage()
        return
    
    mode_arg_idx = 3

    if sys.argv[1] == '-pcap':
        file = sys.argv[2] 
    elif sys.argv[1] == '-csv':
        print("CSV file not supported")
        print_usage()
    elif sys.argv[2] == '-pcap':
        file = sys.argv[3]
        mode_arg_idx = 1
    elif sys.argv[2] == '-csv':
        print("CSV file not supported")
        print_usage()
    else:
        print_usage()

    try:
        packets = rdpcap(file)
    except:
        print("Unable to read file")
        print_usage()

    if sys.argv[mode_arg_idx] == '-init':
        init(packets)
    elif sys.argv[mode_arg_idx] == '-peers':
        peers(packets)
    elif sys.argv[mode_arg_idx] == '-download':
        download(packets)
    else:
        print_usage()

if __name__ == "__main__":
    main()