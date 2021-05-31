#Ahmed Al-Hanshali & Abdullah Al-Ramadhan
#A Basic Firewall:

#Libraries needed for the firewall
from netfilterqueue import NetfilterQueue
from scapy.all import *
import json

try:
    f = open("Barricade.json","r")
    y = json.load(f)
    f.close()

#Check if there are specified Ips to block
    if("BlockedIps" in y):
        if(type(y["BlockedIps"])==list):
            BlockedIps = y["BlockedIps"]
        else:
            print("Invalid listing of Blocked IPs. Defaulting to none")
            BlockedIps = []
    else:
        print("No Blocked IPs found. Defaulting to none")
        BlockedIps = []
    
#Check if there are specified ports to block
    if("BlockedPorts" in y):
        if(type(y["BlockedPorts"])==list):
            BlockedPorts = y["BlockedPorts"]
        else:
            print("Invalid Listing Of Blokced Ports . Defaulting to none")
            BlockedPorts = []
    else:
        print("List of Blocked Ports missing. Defaulting to none")
        BlockedPorts = []

#Check if there are specified networks to block	
    if("BlockedNetworks" in y):
        if(type(y["BlockedNetworks"])==list):
            BlockedNetworks = y["BlockedNetworks"]
        else:
            print("Invalid Listing Of Blocked Networks. Defaulting to none")
            BlockedNetworks= []
    else:
        print("Listing Of Blocked Networks missing. Defaulting to none")
        BlockedNetworks = []


except FileNotFoundError:
    print("Rule file (Barricade.json) not found, setting default values")
    BlockedIps = [] 
    BlockedPorts = []
    BlockedNetworks = []
   
def Barricade(pkt):
	sca = IP(pkt.get_payload())

#Filter packets
	if(sca.src in BlockedIps):
		print(sca.src, "is a incoming IP address that is blocked by the barricade.")
		pkt.drop()
		return 

	if(sca.haslayer(TCP)):
		t = sca.getlayer(TCP)
		if(t.dport in BlockedPorts):
			print(t.dport, "is a destination port that is blocked by the barricade.")
			pkt.drop()
			return 

	if(sca.haslayer(UDP)):
		t = sca.getlayer(UDP)
		if(t.dport in BlockedPorts):
			print(t.dport, "is a destination port that is blocked by the barricade.")
			pkt.drop()
			return 

	if(True in [sca.src.find(suff)==0 for suff in BlockedNetworks]):
		print("Prefix of " + sca.src + " is blocked by the barricade.")
		pkt.drop()
		return


	pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1,Barricade)

try:
    nfqueue.run()
except KeyboardInterrupt:
	pass

nfqueue.unbind()
