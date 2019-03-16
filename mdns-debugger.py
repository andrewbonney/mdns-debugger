#!/usr/bin/python

import pcapy
import socket
import struct
import dpkt
import sys
import operator
import time
import argparse

from colorama import Fore, Style

#TODO: Ideally avoid flagging items as bad if they consitute a device restarting or similar and re-querying as a result
#TODO: When flagging high traffic rates, don't average over the whole run time, but over successive periods of 60s or so
#TODO: Don't flag timing issues if the backoff interval has just been reset, potentially due to an expired TTL

query_tracking = {}
response_tracking = {}
active_queries = {}
active_responses = {}
invalid_packets = {}
ip4_maps = {}
ip6_maps = {}

IP4_MULTICAST_GROUP = '224.0.0.251'
IP6_MULTICAST_GROUP = 'ff02::fb'

DNS_TYPES = {dpkt.dns.DNS_A: "A",
             dpkt.dns.DNS_NS: "NS",
             dpkt.dns.DNS_CNAME: "CNAME",
             dpkt.dns.DNS_SOA: "SOA",
             dpkt.dns.DNS_NULL: "NULL",
             dpkt.dns.DNS_PTR: "PTR",
             dpkt.dns.DNS_HINFO: "HINFO",
             dpkt.dns.DNS_MX: "MX",
             dpkt.dns.DNS_TXT: "TXT",
             dpkt.dns.DNS_AAAA: "AAAA",
             dpkt.dns.DNS_SRV: "SRV",
             dpkt.dns.DNS_OPT: "OPT"}

# Time to wait before issuing warnings
INIT_TIME = time.time() + 2

# How long after a query must all responses have been sent by
QUERY_RESPONSE_LIMIT = 2

# How long after sending a response may a server send additional related response packets for
GRATUITOUS_RESPONSE_LIMIT = 2

GENERAL_TTL = 75*60
HOSTNAME_TTL = 120

def dns_str(dns_type):
    try:
        return DNS_TYPES[dns_type]
    except KeyError:
        return str(dns_type)

def eth_addr(address):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", address)

def time_diff(time_old, time_new):
    return time_new[0] - time_old[0]

def track_query_interval(query_tracker, packet_time):
    query_tracker.append(packet_time)
    while len(query_tracker) > 3:
        query_tracker.pop(0)

def test_query_interval(query_tracker):
    if len(query_tracker) < 2:
        return False
    if len(query_tracker) == 2:
        if time_diff(query_tracker[0], query_tracker[1]) < 1:
            return time_diff(query_tracker[0], query_tracker[1])
    else:
        interval_old = time_diff(query_tracker[0], query_tracker[1])
        interval_new = time_diff(query_tracker[1], query_tracker[2])
        if interval_old < 1 or interval_new < 1:
            return min(interval_old, interval_new)
        # Re-query intervals are permitted to top out at one hour https://tools.ietf.org/html/rfc6762#section-5.2 para 3
        if interval_new < interval_old * 2 and interval_new < 3600:
            return interval_new
    return False

def test_ttl(record_name, record_type, ttl):
    if record_name.endswith(".arpa") and record_type == dpkt.dns.PTR:
        if ttl not in [0, HOSTNAME_TTL]:
            return HOSTNAME_TTL
    elif record_type in [dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA, dpkt.dns.DNS_HINFO, dpkt.dns.DNS_SRV]:
        if ttl not in [0, HOSTNAME_TTL]:
            return HOSTNAME_TTL
    elif ttl not in [0, GENERAL_TTL]:
        return GENERAL_TTL
    return False

def bytes_to_int(bytes):
    return int(struct.unpack('>H', bytes)[0])

def record_invalid_packet(eth_addr, ip_addr=None):
    if eth_addr not in invalid_packets:
        invalid_packets[eth_addr] = 1
    else:
        invalid_packets[eth_addr] += 1

def parse_ip(header, eth, ip):
    ip_data = ip.data

    ip_addr = None
    if isinstance(eth.data, dpkt.ip.IP):
        ip_addr = socket.inet_ntop(socket.AF_INET, ip.src)
    elif isinstance(eth.data, dpkt.ip6.IP6):
        ip_addr = socket.inet_ntop(socket.AF_INET6, ip.src)

    if isinstance(ip_data, dpkt.udp.UDP):
        udp = ip_data
        if udp.dport == 5353:
            mdns = dpkt.dns.DNS(udp.data)
            mdns_query = False
            mdns_response = False
            if bytes_to_int(udp.data[0:2]) & 0xFFFF == 0x0000:
                pass # Nothing gets this right, so no point flooding the reporting!
            if bytes_to_int(udp.data[2:4]) & 0x8000 == 0x0000:
                mdns_query = True
            elif bytes_to_int(udp.data[2:4]) & 0x8000 == 0x8000:
                mdns_response = True

            if udp.sport != 5353:
                # See https://tools.ietf.org/html/rfc6762#section-5.1. The UDP source port of 5353
                if mdns_query:
                    print("WARNING: Querying host is using one-shot queries with a source port of 5353 and is not fully compliant with mDNS '{}' '{}'".format(eth_addr(eth.src), ip_addr))
                elif mdns_response:
                    print("INVALID: Responding host is using one-shot responses with a source port of 5353 and is not compliant with mDNS '{}' '{}'".format(eth_addr(eth.src), ip_addr))
                    record_invalid_packet(eth_addr(eth.src))

            if len(mdns.qd) == 0 and mdns_query:
                print("INVALID: mDNS query sent without any questions '{}' '{}'".format(eth_addr(eth.src), ip_addr))
                record_invalid_packet(eth_addr(eth.src))
            if len(mdns.an) == 0 and mdns_response:
                print("INVALID: mDNS response sent without any responses '{}' '{}'".format(eth_addr(eth.src), ip_addr))
                record_invalid_packet(eth_addr(eth.src))

            if mdns_response and len(mdns.qd) > 0:
                # See https://tools.ietf.org/html/rfc6762#section-6 and https://tools.ietf.org/html/rfc6762#section-7.1
                print("INVALID: mDNS responses must not contain queries '{}' '{}'".format(eth_addr(eth.src), ip_addr))
                record_invalid_packet(eth_addr(eth.src))

            if mdns_query:
                if ip_addr not in query_tracking:
                    query_tracking[ip_addr] = {"pkt_count": 1}
                else:
                    query_tracking[ip_addr]["pkt_count"] += 1
                for question in mdns.qd:
                    if question.name not in query_tracking[ip_addr]:
                        query_tracking[ip_addr][question.name] = {}
                    if question.type not in query_tracking[ip_addr][question.name]:
                        query_tracking[ip_addr][question.name][question.type] = []
                    query_tracker = query_tracking[ip_addr][question.name][question.type]
                    track_query_interval(query_tracker, header.getts())
                    result = test_query_interval(query_tracker)
                    if result:
                        # Successive queries must be at least a second apart, then increase by a factor of two as-per para 3 of https://tools.ietf.org/html/rfc6762#section-5.2
                        print("TIMING: Repeated query issued too quickly (interval {} seconds) by host '{}' '{}' - Name: {}, Type: {}".format(result, eth_addr(eth.src), ip_addr, question.name, dns_str(question.type)))

                    if not question.name.endswith(".local") and not question.name.endswith(".arpa"):
                        # Permitted but unusual: https://tools.ietf.org/html/rfc6762#section-3 and https://tools.ietf.org/html/rfc6762#section-4
                        print("WARNING: Multicast DNS query for a unicast-only record by host '{}' '{}' - Name: {}, Type: {}".format(eth_addr(eth.src), ip_addr, question.name, dns_str(question.type)))

                    if question.name not in active_queries:
                        active_queries[question.name] = {}
                    active_queries[question.name][question.type] = header.getts()
                for known_answer in mdns.an:
                    result = test_ttl(known_answer.name, known_answer.type, known_answer.ttl)
                    if result:
                        print("WARNING: Non-standard TTL used for {} record. Expected {}s, found {}s.".format(DNS_TYPES[known_answer.type], result, known_answer.ttl))

            if mdns_response:
                if ip_addr not in response_tracking:
                    response_tracking[ip_addr] = {"pkt_count": 1}
                else:
                    response_tracking[ip_addr]["pkt_count"] += 1
                for response in mdns.an:
                    if response.name not in active_queries:
                        active_queries[response.name] = {}
                    if response.type not in active_queries[response.name]:
                        active_queries[response.name][response.type] = (0, 0)
                    if ip_addr not in active_responses:
                        active_responses[ip_addr] = (0, 0)

                    current_ts = header.getts()

                    if time.time() > INIT_TIME:
                        if time_diff(active_queries[response.name][response.type], current_ts) > QUERY_RESPONSE_LIMIT and time_diff(active_responses[ip_addr], current_ts) > GRATUITOUS_RESPONSE_LIMIT:
                            print("TIMING: Response sent when no recent query was issued '{}' '{}' - Name: {}, Type: {}".format(eth_addr(eth.src), ip_addr, response.name, dns_str(response.type)))

                    if time_diff(active_queries[response.name][response.type], current_ts) < QUERY_RESPONSE_LIMIT:
                        # A valid query has been responded to, but there may be more gratuitous records to send (for example SRV/TXT/A following a PTR)
                        active_responses[ip_addr] = current_ts

                    if response.name not in response_tracking[ip_addr]:
                        response_tracking[ip_addr][response.name] = {}
                    if response.type not in response_tracking[ip_addr][response.name]:
                        response_tracking[ip_addr][response.name][response.type] = None
                    response_tracking[ip_addr][response.name][response.type] = header.getts()

                    if not response.name.endswith(".local") and not response.name.endswith(".arpa"):
                        # Permitted but unusual: https://tools.ietf.org/html/rfc6762#section-3 and https://tools.ietf.org/html/rfc6762#section-4
                        print("WARNING: Multicast DNS response for a unicast-only record by host '{}' '{}' - Name: {}, Type: {}".format(eth_addr(eth.src), ip_addr, response.name, dns_str(response.type)))

                    result = test_ttl(response.name, response.type, response.ttl)
                    if result:
                        print("WARNING: Non-standard TTL used for {} record. Expected {}s, found {}s.".format(DNS_TYPES[response.type], result, response.ttl))

        else:
            print("INVALID: UDP destination port for mDNS set to '{}' by host '{}' '{}'".format(udp.dport, eth_addr(eth.src), ip_addr))
            record_invalid_packet(eth_addr(eth.src))
    else:
        print("INVALID: IP protocol for mDNS set to '{}' by host '{}' '{}'".format(ip.p, eth_addr(eth.src), ip_addr))
        record_invalid_packet(eth_addr(eth.src))

def parse_packet(header, packet):
    eth = dpkt.ethernet.Ethernet(packet)

    if isinstance(eth.data, dpkt.ip.IP):
        if eth_addr(eth.dst) != "01:00:5e:00:00:fb":
            print("INVALID: Destination MAC for IPv4 mDNS set to '{}' by '{}'".format(eth_addr(eth.dst), eth_addr(eth.src)))
            record_invalid_packet(eth_addr(eth.src))

        ip = eth.data
        dst_addr = socket.inet_ntop(socket.AF_INET, ip.dst)
        src_addr = socket.inet_ntop(socket.AF_INET, ip.src)
        if eth_addr(eth.src) not in ip4_maps:
            ip4_maps[eth_addr(eth.src)] = src_addr

        if dst_addr != "224.0.0.251":
            print("INVALID: Destination IP address for IPv4 mDNS set to '{}' by '{}' '{}'".format(dst_addr, eth_addr(eth.src), src_addr))
            record_invalid_packet(eth_addr(eth.src))

        try:
            parse_ip(header, eth, ip)
        except dpkt.UnpackError:
            pass

    elif isinstance(eth.data, dpkt.ip6.IP6):
        if eth_addr(eth.dst) != "33:33:00:00:00:fb":
            print("INVALID: Destination MAC for IPv6 mDNS set to '{}' by '{}'".format(eth_addr(eth.dst), eth_addr(eth.src)))
            record_invalid_packet(eth_addr(eth.src))

        ip = eth.data
        dst_addr = socket.inet_ntop(socket.AF_INET6, ip.dst)
        src_addr = socket.inet_ntop(socket.AF_INET6, ip.src)
        if eth_addr(eth.src) not in ip6_maps:
            ip6_maps[eth_addr(eth.src)] = src_addr

        if dst_addr != "ff02::fb":
            print("INVALID: Destination IP address for IPv6 mDNS set to '{}' by '{}' '{}'".format(dst_addr, eth_addr(eth.src), src_addr))
            record_invalid_packet(eth_addr(eth.src))

        try:
            parse_ip(header, eth, ip)
        except dpkt.UnpackError:
            pass

    else:
        print("INVALID: Ethernet protocol for mDNS set to '{}' by '{}'".format(eth.type, eth_addr(eth.src)))
        record_invalid_packet(eth_addr(eth.src))

def print_report(packet_count, duration):
    print("\n---- SUMMARY ----")
    print("Analysed {} packets over {} seconds".format(packet_count, duration))

    print("\n---- Queries ----")
    sort_dict = {}
    for ip_src in query_tracking:
        sort_dict[ip_src] = query_tracking[ip_src]["pkt_count"]
    for ip_src in sorted(sort_dict, key=sort_dict.get, reverse=True):
        rate = round(sort_dict[ip_src]/float(duration), 2)
        if rate > 0.4:
            print(Fore.RED + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))
        elif rate > 0.2:
            print(Fore.YELLOW + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))
        else:
            print(Style.RESET_ALL + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))

    print(Style.RESET_ALL + "\n---- Responses ----")
    sort_dict = {}
    for ip_src in response_tracking:
        sort_dict[ip_src] = response_tracking[ip_src]["pkt_count"]
    for ip_src in sorted(sort_dict, key=sort_dict.get, reverse=True):
        rate = round(sort_dict[ip_src]/float(duration), 2)
        if rate > 0.4:
            print(Fore.RED + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))
        elif rate > 0.2:
            print(Fore.YELLOW + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))
        else:
            print(Style.RESET_ALL + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))

    print(Style.RESET_ALL + "\n---- Invalid mDNS Packets ----")
    for eth_addr, count in sorted(invalid_packets.items(), key=operator.itemgetter(1)):
        if eth_addr in ip4_maps:
            print("{} ({} packets total)".format(ip4_maps[eth_addr], count))
        elif eth_addr in ip6_maps:
            print("{} ({} packets total)".format(ip6_maps[eth_addr], count))
        else:
            print("{} ({} packets total)".format(eth_addr, count))

    print("")

def create_mreqs():
    v4_group = socket.inet_pton(socket.AF_INET, IP4_MULTICAST_GROUP)
    v4_if = socket.INADDR_ANY
    v4_mreq = struct.pack('4sL', v4_group, v4_if)

    v6_group = socket.inet_pton(socket.AF_INET6, IP6_MULTICAST_GROUP)
    v6_if = chr(0)*16
    try:
        v6_mreq = struct.pack("16s16s", v6_group, v6_if)
    except struct.error:
        v6_mreq = struct.pack("16s16s", v6_group, bytearray(v6_if, "utf-8"))

    return v4_mreq, v6_mreq

def join_groups(v4_sock, v6_sock):
    v4_mreq, v6_mreq = create_mreqs()
    v4_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, v4_mreq)
    v6_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, v6_mreq)

def leave_groups(v4_sock, v6_sock):
    v4_mreq, v6_mreq = create_mreqs()
    v4_sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, v4_mreq)
    v6_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, v6_mreq)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='mDNS debugger')
    parser.add_argument('--interface', default=None, help='name of a network interface to perform a live capture from')
    parser.add_argument('--file', default=None, help='path to a pcap format file containing packets to analyse')
    args = parser.parse_args()

    if not args.interface and not args.file:
        parser.print_usage()
    elif args.interface and args.file:
        print("Only one of 'interface' or 'file' should be specified")
    else:
        ip4_server_address = ('', 9898) # Random port
        ip6_server_address = ('', 9899) # Random port

        # Create the socket
        v4_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        v6_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

        # Bind to the server address
        v4_sock.bind(ip4_server_address)
        v6_sock.bind(ip6_server_address)

        join_groups(v4_sock, v6_sock)

        pkt_filter = "dst host " + IP4_MULTICAST_GROUP + " or dst host " + IP6_MULTICAST_GROUP

        if args.interface:
            cap = pcapy.open_live(args.interface, 65536, 1, 1000)
        elif args.file:
            cap = pcapy.open_offline(args.file)
        cap.setfilter(pkt_filter)

        packet_count = 0
        start_ts_live = time.time()
        start_ts_file = None
        stop_ts_file = None

        try:
            while True:
                try:
                    (header, packet) = cap.next()
                    if packet:
                        packet_count += 1
                        parse_packet(header, packet)
                        if not start_ts_file:
                            start_ts_file = header.getts()[0]
                        stop_ts_file = header.getts()[0]
                    elif args.file:
                        break
                except socket.timeout:
                    pass
        except KeyboardInterrupt:
            pass

        stop_ts_live = time.time()

        try:
            cap.close()
        except:
            pass

        leave_groups(v4_sock, v6_sock)

        duration = 1
        if args.file and stop_ts_file is not None and start_ts_file is not None:
            duration = max(duration, int(stop_ts_file - start_ts_file))
        else:
            duration = max(duration, int(stop_ts_live - start_ts_live))

        print_report(packet_count, duration)
