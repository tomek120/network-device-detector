from scapy.all import *

def main():
	eth = Ether(dst="ff:ff:ff:ff:ff:ff")
	arp = ARP(pdst="192.168.1.0/24")
	packet = eth / arp
	answered, unanswered = srp(packet, timeout=1, verbose=True)
	answered.show()


if __name__ == "__main__":
	main()

