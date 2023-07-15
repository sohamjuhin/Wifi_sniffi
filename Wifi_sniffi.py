from scapy.all import *

def process_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            # Extract the SSID (Wi-Fi network name) from the beacon frame
            ssid = packet.info.decode()

            # Print the SSID
            print("SSID: ", ssid)

def start_wifi_sniffing():
    # Set up the Wi-Fi interface in monitor mode
    os.system("ifconfig wlan0 down")
    os.system("iwconfig wlan0 mode monitor")
    os.system("ifconfig wlan0 up")

    # Start sniffing Wi-Fi packets
    sniff(iface="wlan0", prn=process_packet)

if __name__ == "__main__":
    start_wifi_sniffing()
