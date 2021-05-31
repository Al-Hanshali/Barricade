# Barricade
Barricade is a packet filtering firewall that acts as a network security system.
The motivation behind this project comes from our passion towards how hacking works and how to find ways to prevent it.
Barricade uses Python to blocks certain networks, ports, IP addresses, and ping attacks that are specified in a json file

# Want to use this repository?

* git clone https://github.com/Al-Hanshali/Barricade

* cd Barricade

* // Check to see what rules you already have: sudo iptables -L

* // For incoming packet filtering: sudo iptables -I INPUT -j NFQUEUE --queue-num 1

* // For outgoing packet filtering: sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1

* python3 Barricade.py

* //Once finished, make sure you flush the rules: sudo iptables -F

# Future developments
* Proxy Firewall
* Statefull Firewall


# Credits
Dr. Lin Chase

https://github.com/Naklecha/firewall

https://pypi.org/project/NetfilterQueue/

https://scapy.net/

