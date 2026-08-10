# UDP-ICMP Host Discovery Scanner

A lightweight Python-based network host discovery tool that identifies active hosts within an IPv4 subnet using UDP probes, raw sockets, and ICMP response analysis.

## Overview

This project demonstrates an alternative approach to network host discovery without relying on traditional ICMP Echo Requests (`ping`).

The scanner sends UDP datagrams containing a custom payload to hosts within a specified subnet. When an active host receives a packet destined for a closed UDP port, it may respond with an ICMP **Destination Unreachable – Port Unreachable** message.

The scanner captures these ICMP responses using a raw socket, parses the IP and ICMP headers, validates the response, and identifies the originating host as active.

## Features

* UDP-based host discovery
* Raw socket packet capture
* IP and ICMP header parsing
* ICMP Type 3 / Code 3 detection
* Custom payload verification
* IPv4 subnet enumeration
* Multi-threaded UDP packet transmission
* Windows and Linux support
* Live host detection and scan summary

## Requirements

* Python 3.x
* Administrator/root privileges
* A network interface capable of packet capture

## Usage

Configure the target subnet in the script:

```python
SUBNET = '192.168.1.0/24'
```

Run the scanner:

```bash
python scanner.py
```

You can also specify the local host IP as a command-line argument:

```bash
python scanner.py 192.168.1.203
```

Press `Ctrl+C` to stop the scan and display the discovered hosts.

## Example Output

```text
Host Up: 192.168.1.1
Host Up: 192.168.1.5
Host Up: 192.168.1.10

Summary: Hosts up on 192.168.1.0/24
192.168.1.1
192.168.1.5
192.168.1.10
```

## Technologies

* Python
* Socket Programming
* Raw Sockets
* UDP
* ICMP
* IPv4 Networking
* Multithreading

## Learning Objectives

This project provides practical experience with:

* Raw socket programming
* Network packet structure and parsing
* IP and ICMP protocols
* UDP-based host discovery
* IPv4 subnet enumeration
* Concurrent network operations
* Low-level network traffic analysis

## Disclaimer

This project is intended for educational purposes and authorized security testing. Only scan networks that you own or have explicit permission to assess.
