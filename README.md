# Multicast DNS (mDNS) Debugger

Multicast DNS provides an convenient way to discover services within Layer 2 network segments. This tool is intended to identify malformed packets, and 'chatty' implementations which do not abide by the rules of the [mDNS RFC](https://tools.ietf.org/html/rfc6762).

This application captures all traffic sent to the relevant IPv4 and IPv6 multicast groups, and joins the matching multicast groups via IGMP. Any packets which are either invalid or not inkeeping with the requirements of the mDNS RFC are highlighted. Upon exiting the program, a summary of the traffic and packet rates is displayed.
