from scapy.all import *
from mac_vendor_lookup import MacLookup
import socket

def main():
    vendor_lookup = MacLookup()
    eth = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst="192.168.1.0/24")
    packet = eth / arp
    answered, unanswered = srp(packet, timeout=2, verbose=True)
    
    for sent, received in answered:
        ip=received.psrc
        mac = received.hwsrc

        if is_private(mac):
            print("Private")
        else:
            device = vendor_lookup.lookup(mac)
            print(f"{ip} {mac} {device}")
            
def is_private(mac):
    first_byte_str = mac.split(":")[0]
    first_byte = int(first_byte_str, 16)
    is_local = (first_byte & 2) != 0
    return is_local

if __name__ == "__main__":
    main()

