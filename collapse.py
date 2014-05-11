from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.util import dumpNodeConnections

class CollapseTopo(Topo):
    def __init__(self, n=2):
        super(CollapseTopo, self).__init__()

        attacker = self.addHost('h1')
        victim = self.addHost('h2')

        router = self.addSwitch('s0')

        for host in (attacker, victim):
            self.addLink(host, router,
                         delay='10ms',
                         bandwidth=1000)



def collapse():
    topo = CollapseTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()

    dumpNodeConnections(net.hosts)
    net.pingAll()


if __name__ == '__main__':
    collapse()
