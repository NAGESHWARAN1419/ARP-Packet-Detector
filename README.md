Advanced Packet Sniffer & ARP Spoofing Detector

A Python-based network monitoring tool built using Scapy to capture IPv4 and ARP packets, identify common network protocols, monitor IP-to-MAC address mappings, and detect suspicious ARP mapping changes.

This project was developed for educational purposes to understand packet analysis, network monitoring, and basic ARP spoofing detection.

<img width="930" height="304" alt="image" src="https://github.com/user-attachments/assets/2f6ca54a-b373-4a3d-8626-af050a5f62a5" />


Project Overview

The project has two main components:

Packet Sniffer: Captures IPv4 and ARP packets from a selected network interface and identifies protocols such as TCP, UDP, ICMP, and ARP.

ARP Spoofing Detector: Maintains observed IP-to-MAC address mappings and generates an alert when an IP address is associated with a different MAC address.

Captured packet information and possible ARP spoofing alerts are saved in CSV files for later analysis.



Features

Live packet capture using Scapy.

IPv4 and ARP packet identification.

TCP, UDP, and ICMP protocol identification.

IP-to-MAC address mapping.

Detection of suspicious MAC address changes.

Automatic ARP alert generation.

Packet logging using CSV files.

Timestamped packet and alert records.

Offline demonstration mode for safe testing.

Command-line interface selection.



Technologies Used

Python 3

Scapy

CSV Module

Argparse

OS Module

Datetime Module



Project Structure

arp-detection/

│

├── arp_snooping_detection.py

├── README.md

├── requirements.txt

├── .gitignore

│

└── Generated Files:
       
         packet_log.csv
   
         arp_alerts.csv


<img width="607" height="186" alt="image" src="https://github.com/user-attachments/assets/2f0e60a4-1ebd-4c53-a0a5-d8ba5a21735b" />



Requirements

Python 3

Scapy

Kali Linux or another Linux environment

Appropriate packet-capture permissions for live monitoring


Installation

1. Clone the repository

          git clone https://github.com/NAGESHWARAN1419/ARP-Spoofing-Detection.git

2. Navigate to the project directory

           cd ARP-Spoofing-Detection

3. Install dependencies

           pip install -r requirements.txt



How to Run

1. Safe Offline Demonstration

Run the following command:

         python3 arp_snoofing_detection.py --demo

This demonstrates the ARP detection logic using simulated IP and MAC addresses. No network packets are sent.

<img width="874" height="142" alt="image" src="https://github.com/user-attachments/assets/720bb8fa-9a80-43cd-a4d8-fac024bb9ac4" />


2. Live Packet Monitoring

First, identify your available network interfaces:

ip link show

Start monitoring an authorized network interface:

     sudo python3 arp_snoofing_detection.py --interface wlan0

Replace wlan0 with your actual network interface.

Press **Ctrl + C **to stop packet capture.

<img width="944" height="299" alt="image" src="https://github.com/user-attachments/assets/0ab0b00a-7643-4131-9288-24ee2c42dce8" />

Demo Output

=== SAFE OFFLINE DEMO ===

[INFO] Learned 192.168.1.1 -> aa:bb:cc:dd:ee:01

[WARNING] POSSIBLE ARP SPOOFING:
IP 192.168.1.1 changed MAC from
aa:bb:cc:dd:ee:01 to aa:bb:cc:dd:ee:99

Demo finished. No network packets were sent.

Generated Output Files

File

Purpose

packet_log.csv

Stores captured packet summaries

arp_alerts.csv

Stores possible ARP spoofing alerts

Packet Log Information

Timestamp

Protocol

Source IP

Destination IP

Packet details

ARP Alert Information

Timestamp

IP address

Previously observed MAC address

Newly observed MAC address

Alert message



How ARP Detection Works

The detector maintains a dictionary containing observed IP-to-MAC address mappings.

Example:

192.168.1.1 -> aa:bb:cc:dd:ee:01

If the same IP address is later observed with another MAC address:

192.168.1.1 -> aa:bb:cc:dd:ee:99

The program identifies the mapping change and generates a possible ARP spoofing alert.

Note: A MAC address change does not automatically confirm an attack. Legitimate network changes can also produce different mappings.


Learning Outcomes

Through this project, I gained practical experience with:

Network packet analysis.

Address Resolution Protocol (ARP).

IP and MAC address relationships.

TCP, UDP, and ICMP protocols.

Python classes and functions.

Dictionaries and conditional statements.

CSV file handling.

Command-line arguments.

Basic network security monitoring.

Using Scapy for packet capture.



Limitations

1.The detector identifies observed IP-to-MAC mapping changes; it does not confirm an attack.

2.Mapping information is stored in memory and is lost when the program restarts.

3.The current implementation checks ARP replies rather than every ARP claim.

4.The program does not automatically block suspicious devices.

5.The packet filter captures IPv4 and ARP traffic, not all network protocols.


Disclaimer

This project is developed strictly for educational and authorized network monitoring purposes.
Only perform live packet capture on networks and devices you own or have explicit permission to monitor.

Author

Nageshwaran N
