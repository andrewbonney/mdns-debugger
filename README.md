# Multicast DNS (mDNS) Debugger

Multicast DNS provides a convenient way to discover services within Layer 2 network segments. This tool is intended to identify malformed packets, and 'chatty' implementations which do not abide by the rules of the [mDNS RFC](https://tools.ietf.org/html/rfc6762).

This application captures all traffic sent to the relevant IPv4 and IPv6 multicast groups, and joins the matching multicast groups via IGMP and MLD. Any packets which are either invalid or not in-keeping with the requirements of the mDNS RFC are highlighted. Upon exiting the program, a summary of the traffic and packet rates is displayed.

## Requirements

*   Linux (untested on Windows and Mac)
*   Python 2 or 3
*   Pip

## Installation

```shell
$ pip3 install -r requirements.txt
```

Note that 'pcapy' requires that 'libpcap-dev' is available on the system. This can be installed via 'apt-get' on Ubuntu.

## Usage

Live capture and analysis from a selected network interface:

```shell
$ python3 mdns-debugger.py --interface <ifname> [--suppress-warnings --suppress-timing]
```

Offline pcap file analysis:

```shell
$ python3 mdns-debugger.py --file <filename.pcap> [--suppress-warnings --suppress-timing]
```

In both modes of operation packet errors and timing issues are flagged. Once analysis is complete a summary of packet rates and error counts is displayed (after a CTRL+C when in live mode).

### Avoiding False Positives

The mDNS specification permits implementations to (amongst other things) send gratuitous responses upon initial advertisement. This may be incorrectly flagged as an error by this tool. As such it is recommended that this tool is only used to analyse implementations in their 'steady state' when no reboots or user input are occurring.

Query timing checks assume that the TTLs required by the mDNS RFC are being followed. If they are not, implementations may quite correctly send queries more frequently than expected. This tool will indicate when unexpected TTLs are encountered in responses, provided warnings are not being suppressed. The response TTL errors should be resolved before pursuing the potential querier issues.
