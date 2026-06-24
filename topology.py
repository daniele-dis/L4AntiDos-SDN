from mininet.topo import Topo
from mininet.link import TCLink
import json

class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')

        self.addLink(h1, s1, cls=TCLink, bw=100)
        self.addLink(h2, s1, cls=TCLink, bw=100)
        self.addLink(s1, s2, cls=TCLink, bw=10000)
        self.addLink(h3, s2, cls=TCLink, bw=1000)

        # Scrivi la mappa (switch i-esimo, porta i-esima) → bandwith per il controller al fine di popolare il file JSON
        # Se cambia la topologia, si aggiorna solo qui + sopra con link e host
        port_bw = {
            "1,1": 100, # s1 -> h1
            "1,2": 100, # s1 -> h2
            "1,3": 10000, # s1 -> s2
            "2,1": 1000, # s2 -> s1
            "2,2": 1000, # s2 -> h3
        }
        with open('/tmp/port_bw.json', 'w') as f:
            json.dump(port_bw, f)

# topos = dizionario per mininet che richiama la classe in cui definiamo la topologia
# al fine di crearla (MyTopo) ed è invocata da terminale con la sua chiave: mytopo

topos = { 'mytopo': ( lambda: MyTopo() ) }