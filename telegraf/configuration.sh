#!/bin/bash

cp ./telegraf.conf /etc/telegraf/telegraf.conf
ip link add name s1-telegraf type dummy
ip link set s1-telegraf up
ovs-vsctl add-port s1 s1-telegraf 
ovs-ofctl show s1
sudo service telegraf restart
#sudo tcpdump -i s1-telegraf -n -U -w - | socat - udp-sendto:localhost:8094
sudo tcpdump -i s1-telegraf -w /home/capture.pcap
