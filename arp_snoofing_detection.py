
"""
Advanced Packet Sniffer + ARP Spoofing Detector
Beginner-friendly educational project.

Use live capture only on networks you own or have
explicit permission to monitor.
"""

import argparse
import csv
import os
from datetime import datetime

from scapy.all import ARP, IP, TCP, UDP, ICMP, sniff


# These files store our results.
PACKET_FILE = "packet_log.csv"
ALERT_FILE = "arp_alerts.csv"


class ARPDetector:
    """Remember IP-to-MAC mappings and detect changes."""

    def __init__(self):
        # Example: {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}
        self.known_mappings = {}

    def check_mapping(self, ip_address, mac_address):
        """Check whether an IP address changed its MAC address."""

        # Ignore empty or placeholder sender addresses.
        if not ip_address or ip_address == "0.0.0.0":
            return

        if not mac_address or mac_address == "00:00:00:00:00:00":
            return

        old_mac = self.known_mappings.get(ip_address)

        if old_mac is None:
            # First time we have seen this IP address.
            self.known_mappings[ip_address] = mac_address
            print(f"[INFO] Learned {ip_address} -> {mac_address}")

        elif old_mac.lower() != mac_address.lower():
            # The same IP address now has a different MAC address.
            message = (
                f"IP {ip_address} changed MAC from "
                f"{old_mac} to {mac_address}"
            )

            print(f"[WARNING] POSSIBLE ARP SPOOFING: {message}")

            save_row(
                ALERT_FILE,
                ["time", "ip_address", "old_mac", "new_mac", "message"],
                {
                    "time": timestamp(),
                    "ip_address": ip_address,
                    "old_mac": old_mac,
                    "new_mac": mac_address,
                    "message": message,
                },
            )

            # Remember the latest value for future comparisons.
            self.known_mappings[ip_address] = mac_address


def timestamp():
    """Return the current time as readable text."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def save_row(filename, columns, row):
    """Save one row of information to a CSV file."""

    file_exists = os.path.exists(filename)
    needs_header = not file_exists or os.path.getsize(filename) == 0

    with open(filename, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)

        if needs_header:
            writer.writeheader()

        writer.writerow(row)


def handle_packet(packet, detector):
    """Read one captured packet and record a short summary."""

    source = "Unknown"
    destination = "Unknown"
    protocol = "Other"
    details = ""

    # Is this an IPv4 packet?
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "IPv4"

    # Is this an ARP packet?
    if ARP in packet:
        protocol = "ARP"

        arp = packet[ARP]
        source = arp.psrc
        destination = arp.pdst

        details = (
            f"operation={arp.op}, "
            f"sender_mac={arp.hwsrc}, "
            f"sender_ip={arp.psrc}"
        )

        # ARP operation 2 means an ARP reply.
        # Check replies rather than treating every request as a claim.
        if arp.op == 2:
            detector.check_mapping(arp.psrc, arp.hwsrc)

    print(
        f"[{timestamp()}] {protocol}: "
        f"{source} -> {destination} {details}"
    )

    save_row(
        PACKET_FILE,
        ["time", "protocol", "source", "destination", "details"],
        {
            "time": timestamp(),
            "protocol": protocol,
            "source": source,
            "destination": destination,
            "details": details,
        },
    )


def run_demo():
    """Test the detector with made-up addresses; send no packets."""

    print("\n=== SAFE OFFLINE DEMO ===")

    detector = ARPDetector()

    # Pretend the router first has one MAC address.
    detector.check_mapping(
        "192.168.1.1", "aa:bb:cc:dd:ee:01"
    )

    # Pretend the same IP suddenly has another MAC address.
    detector.check_mapping(
        "192.168.1.1", "aa:bb:cc:dd:ee:99"
    )

    print("\nDemo finished. No network packets were sent.")


def main():
    """Choose demo mode or live packet capture."""

    parser = argparse.ArgumentParser(
        description="Packet sniffer and ARP mapping-change detector"
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a safe offline demonstration",
    )

    parser.add_argument(
        "--interface",
        help="Network interface to monitor, e.g. eth0 or wlan0",
    )

    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    detector = ARPDetector()

    print("Starting packet capture.")
    print("Press Ctrl+C to stop.")
    print("Only monitor networks you are authorized to inspect.")

    try:
        sniff(
            iface=args.interface,
            filter="ip or arp",
            prn=lambda packet: handle_packet(packet, detector),
            store=False,
        )
    except PermissionError:
        print("Permission denied. Check your packet-capture permissions.")
    except OSError as error:
        print(f"Network capture error: {error}")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
