from scapy.all import *
from mac_vendor_lookup import MacLookup
from tqdm import tqdm

def main():
    vendor_lookup = MacLookup()
    eth = Ether(dst="ff:ff:ff:ff:ff:ff",)
    arp = ARP(pdst="192.168.1.0/24")
    packet = eth / arp
    devices = {}
    
    for x in tqdm(range(10)):
        answered, unanswered = srp(packet, timeout=2, verbose=False)
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            devices[mac] = ip
    print()
    print("Found devices: ")
    for mac, ip in devices.items():
        if is_private(mac):
            print(f"{ip} Private")
        else:
            print(f"{ip} {vendor_lookup.lookup(mac)}")
        
def is_private(mac):
    first_byte_str = mac.split(":")[0]
    first_byte = int(first_byte_str, 16)
    is_local = (first_byte & 2) != 0
    return is_local

if __name__ == "__main__":
    main()

