#!/usr/bin/python

import pcapy
import socket
import struct
import dpkt
import sys
import operator
import time

from colorama import Fore, Style

#TODO: Ideally avoid flagging items as bad if they consitute a device restarting or similar and re-querying as a result
#TODO: When flagging high traffic rates, don't average over the whole run time, but over successive periods of 60s or so

query_tracking = {}
response_tracking = {}
active_queries = {}
invalid_packets = {}
ip4_maps = {}
ip6_maps = {}

DNS_TYPES = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV"}

# Time to wait before issuing warnings
INIT_TIME = time.time() + 2

def dns_str(dns_type):
    try:
        return DNS_TYPES[dns_type]
    except KeyError:
        return str(dns_type)

def eth_addr(address):
    return ':'.join('%02x' % ord(b) for b in address)

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
        if interval_new < interval_old * 2:
            return interval_new

def bytes_to_int(bytes):
    return int(bytes.encode("hex"), 16)

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

            if len(mdns.qd) > 0:
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

            if len(mdns.an) > 0:
                if ip_addr not in response_tracking:
                    response_tracking[ip_addr] = {"pkt_count": 1}
                else:
                    response_tracking[ip_addr]["pkt_count"] += 1
                for response in mdns.an:
                    current_ts = header.getts()
                    if response.name not in active_queries or response.type not in active_queries[response.name] \
                        or time_diff(active_queries[response.name][response.type], current_ts) > 2 and time.time() > INIT_TIME:
                        print("TIMING: Response sent when no recent query was issued '{}' '{}' - Name: {}, Type: {}".format(eth_addr(eth.src), ip_addr, response.name, dns_str(response.type)))

                    if response.name not in response_tracking[ip_addr]:
                        response_tracking[ip_addr][response.name] = {}
                    if response.type not in response_tracking[ip_addr][response.name]:
                        response_tracking[ip_addr][response.name][response.type] = None
                    response_tracking[ip_addr][response.name][response.type] = header.getts()

                    if not response.name.endswith(".local") and not response.name.endswith(".arpa"):
                        # Permitted but unusual: https://tools.ietf.org/html/rfc6762#section-3 and https://tools.ietf.org/html/rfc6762#section-4
                        print("WARNING: Multicast DNS response for a unicast-only record by host '{}' '{}' - Name: {}, Type: {}".format(eth_addr(eth.src), ip_addr, response.name, dns_str(response.type)))

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


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("python mdns-debugger.py <interface-name>")
    else:
        ip4_multicast_group = '224.0.0.251'
        ip6_multicast_group = 'ff02::fb'
        ip4_server_address = ('', 9898) # Random port
        ip6_server_address = ('', 9899) # Random port

        # Create the socket
        v4_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        v6_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

        # Bind to the server address
        v4_sock.bind(ip4_server_address)
        v6_sock.bind(ip6_server_address)

        v4_group = socket.inet_pton(socket.AF_INET, ip4_multicast_group)
        v4_mreq = struct.pack('4sL', v4_group, socket.INADDR_ANY)

        v6_group = socket.inet_pton(socket.AF_INET6, ip6_multicast_group)
        v6_mreq = struct.pack("16s16s", v6_group, chr(0)*16)

        v4_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, v4_mreq)
        v6_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, v6_mreq)

        pkt_filter = "dst host " + ip4_multicast_group + " or dst host " + ip6_multicast_group

        start_ts = None
        stop_ts = None
        packet_count = 0

        cap = pcapy.open_live(sys.argv[1], 65536, 1, 1000) # Don't use 'any', it doesn't work!
        cap.setfilter(pkt_filter)

        try:
            while True:
                try:
                    (header, packet) = cap.next()
                    if packet:
                        packet_count += 1
                        parse_packet(header, packet)
                        if not start_ts:
                            start_ts = header.getts()[0]
                        stop_ts = header.getts()[0]
                except socket.timeout:
                    pass
        except KeyboardInterrupt:
            pass

        try:
            cap.close()
        except:
            pass

        v4_sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, v4_mreq)
        v6_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, v6_mreq)

        duration = 1
        if stop_ts is not None and start_ts is not None:
            duration = max(stop_ts - start_ts, 1)

        print("\n---- SUMMARY ----")
        print("Analysed {} packets over {} seconds".format(packet_count, duration))

        print("\n---- Queries ----")
        sort_dict = {}
        for ip_src in query_tracking:
            sort_dict[ip_src] = query_tracking[ip_src]["pkt_count"]
        for ip_src in sorted(sort_dict, key=sort_dict.get, reverse=True):
            rate = round(sort_dict[ip_src]/float(duration), 2)
            if rate > 1:
                print(Fore.RED + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))
            else:
                print(Style.RESET_ALL + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))

        print(Style.RESET_ALL + "\n---- Responses ----")
        sort_dict = {}
        for ip_src in response_tracking:
            sort_dict[ip_src] = response_tracking[ip_src]["pkt_count"]
        for ip_src in sorted(sort_dict, key=sort_dict.get, reverse=True):
            rate = round(sort_dict[ip_src]/float(duration), 2)
            if rate > 1:
                print(Fore.RED + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))
            else:
                print(Style.RESET_ALL + "{} ({} packets total, {} per second)".format(ip_src, sort_dict[ip_src], rate))

        print(Style.RESET_ALL + "\n---- Invalid mDNS Packets ----")
        for eth_addr, count in sorted(invalid_packets.items(), key=operator.itemgetter(1)):
            print("{} ({} packets total)".format(eth_addr, count))

        print("")
