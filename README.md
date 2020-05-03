# Packet Sniffer
Program sniffs packet from the given interface. Interface was given by the user as an argument of the program "-i", if an interface wasn't given then the program prints available interfaces, their name, ip adress and broadcast adress.

## Extensions
Program processes also ICMP packets and accepts two additional arguments -c and -icmp, which are used to display just ICMP packets.

## Akceptované argumenty
- -i \<interface>  = specifies interface for sniffing
- -n \<number of packets> = specifies number of packets to print 
- -p \<port number> = specifies port of wanted packets
- -t/--tcp = filters tcp packet
- -u/--udp = filters udp packet
- -c/--icmp = filters udp packet
- -h = zobrazí nápovedu

## Examples of usage
-- prints 200 packets with supported protocols  <br>
sudo ./sniffer -i enx00e04c68021d -n 200
-- prints one TCP packet  <br>
sudo ./sniffer -i enx00e04c68021d -t
-- prints one UDP packet  <br>
sudo ./sniffer -i enx00e04c68021d -u

## List of files
- sniffer.cpp = source code of packet sniffer
- Makefile 
- READNE.md = README in slovak
- READMEeng.md = README in english
- manual.pdf
