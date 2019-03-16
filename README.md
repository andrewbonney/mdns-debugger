# Multicast DNS (mDNS) Debugger

Multicast DNS provides a convenient way to discover services within Layer 2 network segments. This tool is intended to identify malformed packets, and 'chatty' implementations which do not abide by the rules of the [mDNS RFC](https://tools.ietf.org/html/rfc6762).

This application captures all traffic sent to the relevant IPv4 and IPv6 multicast groups, and joins the matching multicast groups via IGMP and MLD. Any packets which are either invalid or not in-keeping with the requirements of the mDNS RFC are highlighted. Upon exiting the program, a summary of the traffic and packet rates is displayed.

## Requirements

* Linux (untested on Windows and Mac)
* Python 2 or 3
* Pip

## Installation

```shell
$ pip3 install -r requirements.txt
```

## Usage

Live capture and analysis from a selected network interface:

```shell
$ python3 mdns-debugger.py --interface <ifname>
```

Offline pcap file analysis:

```shell
$ python3 mdns-debugger.py --file <filename.pcap>
```

In both modes of operation packet errors and timing issues are flagged. Once analysis is complete a summary of packet rates and error counts is displayed (after a CTRL+C when in live mode).
