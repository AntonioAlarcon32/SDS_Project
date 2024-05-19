from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import RemoteController, OVSSwitch


class MyTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)
        
        # Add hosts and switches with IP addresses
        h1 = self.addHost('h1', ip='172.16.0.1/24') # Internet host
        h2 = self.addHost('h2', ip='10.0.1.2/24') # Attacker WS
        h3 = self.addHost('h3', ip='10.0.1.1/24') # FTP SERVER
        h4 = self.addHost('h4', ip='10.0.2.1/24') # Monitoring WS
        h5 = self.addHost('h5', ip='10.0.3.1/24') # Web server
        h6 = self.addHost('h6', ip='10.0.3.2/24') # Database
        h7 = self.addHost('h7', ip='10.0.3.3/24') # DNS
        h8 = self.addHost('h8', ip='10.0.4.1/24') # Honeypot
        h9 = self.addHost('h9', ip='10.0.1.3/24') # Normal WS
        
        s1 = self.addSwitch('s1', cls=OVSSwitch)     # Firewall
        s2 = self.addSwitch('s2', cls=OVSSwitch)     # Main router
        s3 = self.addSwitch('s3', cls=OVSSwitch)     # Employee switch
        s4 = self.addSwitch('s4', cls=OVSSwitch)     # Monitoring switch
        s5 = self.addSwitch('s5', cls=OVSSwitch)     # DMZ switch
        
        # Add (bidirectional) links
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h8)
        self.addLink(s2, s3)
        self.addLink(s2, s4)
        self.addLink(s2, s5)
        self.addLink(s3, h2)
        self.addLink(s3, h3)
        self.addLink(s3, h9)
        self.addLink(s4, h4)
        self.addLink(s5, h5)
        self.addLink(s5, h6)
        self.addLink(s5, h7)

def configure_routes(net):
    # Assign default routes for each host
    net.get('h1').cmd('ip route add default via 172.16.0.254')
    net.get('h2').cmd('ip route add default via 10.0.1.254')
    net.get('h3').cmd('ip route add default via 10.0.1.254')
    net.get('h4').cmd('ip route add default via 10.0.2.254')
    net.get('h5').cmd('ip route add default via 10.0.3.254')
    net.get('h6').cmd('ip route add default via 10.0.3.254')
    net.get('h7').cmd('ip route add default via 10.0.3.254')
    net.get('h8').cmd('ip route add default via 10.0.4.254')
    net.get('h9').cmd('ip route add default via 10.0.1.254')

def configure_switches(net):
    s1 = net.get('s1')
    s2 = net.get('s2')
    s3 = net.get('s3')
    s4 = net.get('s4')
    s5 = net.get('s5')
    

def run():
    topo = MyTopo()
    net = Mininet(topo=topo, controller=None)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    configure_routes(net)
    configure_switches(net)
    h3 = net.get('h3')
    h3.cmd("python3 ftp.py &> /dev/null &")
    h5 = net.get('h5')
    h5.cmd("python3 webserver.py &> /dev/null &")
    h6 = net.get('h6')
    h6.cmd("python3 dbapi.py &> /dev/null &")
    h7 = net.get('h7')
    h7.cmd("python3 dnsserver.py &> /dev/null &")

    net.start()

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

