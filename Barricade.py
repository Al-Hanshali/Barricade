#Ahmed Al-Hanshali & Abdullah Al-Ramadhan
#A Basic Firewall:

from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import json

try:
    f = open("Barricade.json","r")
    y = json.load(f)
    f.close()

    if("BlockedIps" in y):
        if(type(y["BlockedIps"])==list):
            BlockedIps = y["BlockedIps"]
        else:
            print("Invalid listing of Blocked IPs. Defaulting to none")
            BlockedIps = []
    else:
        print("NO Blocked IPs found. Defaulting to none")
        BlockedIps = []
            
    if("BlockedPorts" in y):
        if(type(y["BlockedPorts"])==list):
            BlockedPorts = y["BlockedPorts"]
        else:
            print("Invalid Listing Of Blokced Ports . Defaulting to none")
            BlockedPorts = []
    else:
        print("List of Blocked Ports missing. Defaulting to none")
        BlockedPorts = []
            
    if("BlockedNetworks" in y):
        if(type(y["BlockedNetworks"])==list):
            BlockedNetworks = y["BlockedNetworks"]
        else:
            print("Invalid Listing Of Blocked Networks. Defaulting to none")
            BlockedNetworks= []
    else:
        print("Listing Of Blocked Networks missing. Defaulting to none")
        BlockedNetworks = []

    if("TimeThreshold" in y):
        if(type(y["TimeThreshold"])==int):
            TimeThreshold = y["TimeThreshold"]
        else:
            print("Invalid TimeThreshold in rule file. Defaulting to 10")
            TimeThreshold = 10
    else:
        print("TimeThreshold missing in rule file. Defaulting to 10")
        TimeThreshold = 10

    if("PacketThreshold" in y):
        if(type(y["PacketThreshold"])==int):
            PacketThreshold = y["PacketThreshold"]
        else:
            print("Invalid PacketThreshold in rule file. Defaulting to 100")
            PacketThreshold = 100
    else:
        print("PacketThreshold missing in rule file. Defaulting to 100")
        PacketThreshold = 100

    if("BlockPingAttacks" in y):
        if(y["BlockPingAttacks"]=="True" or y["BlockPingAttacks"]=="False"):
            BlockPingAttacks = eval(y["BlockPingAttacks"])
        else:
            print("Invalid BlockPingAttacks in rule file. Defaulting to True")
            BlockPingAttacks = True
    else:
        print("BlockPingAttacks missing in rule file. Defaulting to True")
        BlockPingAttacks = True

except FileNotFoundError:
    print("Rule file (Barricade.json) not found, setting default values")
    BlockedIps = [] 
    BlockedPorts = []
    BlockedNetworks = []
    TimeThreshold = 10 #sec
    PacketThreshold = 100    
    BlockPingAttacks = True

def Barricade(pkt):
	sca = IP(pkt.get_payload())

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

# For Ping Attacks
#	if(BlockPingAttacks and sca.haslayer(ICMP)): #attempt at preventing hping3
#		t = sca.getlayer(ICMP)
#		if(t.code==0):
#			if(sca.src in DictOfPackets):
#				temptime = list(DictOfPackets[sca.src])
#				if(len(DictOfPackets[sca.src]) >= PacketThreshold):
#					if(time.time()-DictOfPackets[sca.src][0] <= TimeThreshold):
#						print("Ping by %s blocked by the barricade (too many requests in short span of time)." %(sca.src))
#						pkt.drop()
#						return
#					else:
#						DictOfPackets[sca.src].pop(0)
#						DictOfPackets[sca.src].append(time.time())
#				else:
#					DictOfPackets[sca.src].append(time.time())
#			else:
#				DictOfPackets[sca.src] = [time.time()]

		#print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src))		
#		pkt.accept()
#		return 
	
	#print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src)) 
	pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1,Barricade)

try:
    nfqueue.run()
except KeyboardInterrupt:
	pass

nfqueue.unbind()
