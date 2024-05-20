ip link add name s1-snort type dummy
ip link set s1-snort up
ovs-vsctl add-port s1 s1-snort
ovs-ofctl show s1