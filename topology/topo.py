from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI


class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")
        alice    = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        attacker = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        server   = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
        for h in (alice, attacker, server):
            self.addLink(h, s1)


if __name__ == "__main__":
    net = Mininet(
        topo=FirewallTopo(),
        switch=lambda n, **kw: OVSSwitch(n, protocols="OpenFlow10", **kw),
        controller=lambda n: RemoteController(n, ip="127.0.0.1", port=6633),
    )
    net.start()
    net.get("h3").cmd("python3 -m http.server 9000 &")   # start the app server
    CLI(net)
    net.stop()
