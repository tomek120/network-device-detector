import sys
from scapy.all import *
from mac_vendor_lookup import MacLookup
from tqdm import tqdm
import csv
from datetime import datetime
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def main():
    trusted_devices = load_trusted_devices("trusted-devices.json")
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

    if "--trust" in sys.argv:
        trusted = {}
        for mac in devices:
            if not is_private(mac):
                trusted[mac] = devices[mac]

        file = open("trusted-devices.json", "w")
        json.dump(trusted, file)
        file.close()

    save_scan_history(devices, trusted_devices, vendor_lookup)

    print()
    print("Found devices: ")

    for mac, ip in devices.items():
        if is_private(mac):                
            print(f"{ip} Private {RED}{is_trusted(mac, trusted_devices)}{RESET}")
        else:
            if is_trusted(mac, trusted_devices) == "Trusted":
                print(f"{ip} {vendor_lookup.lookup(mac)} {GREEN}{is_trusted(mac, trusted_devices)}{RESET}")
            else:
                print(f"{ip} {vendor_lookup.lookup(mac)} {RED}{is_trusted(mac, trusted_devices)}{RESET}")
            
def is_private(mac):
    first_byte_str = mac.split(":")[0]
    first_byte = int(first_byte_str, 16)
    is_local = (first_byte & 2) != 0
    return is_local

def load_trusted_devices(filename):
    try:
        file = open(filename, "r")
        load = json.load(file)
        file.close()
        return load
    except FileNotFoundError:
        return {}
        
def is_trusted(mac, trusted_device_list):
        if mac in trusted_device_list:
            return "Trusted"
        return "New"

def save_scan_history(devices, trusted_devices, vendor_lookup, filename="scan_history.csv"):
    now = datetime.now()
    file = open(filename, "a")
    writer = csv.writer(file)

    for mac, ip in devices.items():
        if is_private(mac):
            vendor = "Private"
        else:
            vendor = vendor_lookup.lookup(mac)
        status = is_trusted(mac, trusted_devices)
        writer.writerow([now, ip, mac, vendor, status])

    file.close()


if __name__ == "__main__":
    main()

