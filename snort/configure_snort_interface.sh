#!/bin/bash

cp ./snort.conf /etc/snort/snort.conf
cp ./project.rules /etc/snort/rules/project.rules
ip link add name s1-snort type dummy
ip link set s1-snort up
ovs-vsctl add-port s1 s1-snort
ovs-ofctl show s1
snort -i s1-snort -A Unsock -l /tmp -c /etc/snort/snort.conf > /dev/null 2>&1 &
