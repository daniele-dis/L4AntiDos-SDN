from mininet.topo import Topo
from mininet.link import TCLink
import json
 
class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')  # nuovo switch
 
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')
        h4 = self.addHost('h4', ip='10.0.0.4')  # nuovo host
 
        self.addLink(h1, s1, cls=TCLink, bw=1)
        self.addLink(h2, s1, cls=TCLink, bw=100)
        self.addLink(s1, s2, cls=TCLink, bw=1000)
        self.addLink(h3, s2, cls=TCLink, bw=1000)
        self.addLink(s2, s3, cls=TCLink, bw=1000)  # nuovo link
        self.addLink(h4, s3, cls=TCLink, bw=5)     # nuovo host, link da 5 Mbps
 
        port_bw = {
            "1,1": 1,
            "1,2": 100,
            "1,3": 1000,
            "2,1": 1000,
            "2,2": 1000,
            "2,3": 1000,
            "3,1": 1000,
            "3,2": 5,    # h4 su link da 5 Mbps → soglia bassa → bannato
        }
        with open('/tmp/port_bw.json', 'w') as f:
            json.dump(port_bw, f)
 
 
topos = { 'mytopo': ( lambda: MyTopo() ) }