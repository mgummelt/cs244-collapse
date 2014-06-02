import os

from time import sleep
from subprocess import Popen
from signal import SIGINT

from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI



TIME = 5
CONG='reno'

class CollapseTopo(Topo):
    def __init__(self, n=2):
        super(CollapseTopo, self).__init__()

        attacker = self.addHost('h1')
        victim = self.addHost('h2')

        router = self.addSwitch('s0')

        self.addLink(attacker, router,
                     delay='10ms',
                     bw=2,
                     max_queue_size=20)

        self.addLink(victim, router,
                     delay='10ms',
                     bw=1000)

def start_iperf(net):
    h2 = net.get('h2')
    h1 = net.get('h1')
    print "Starting iperf server..."
    # For those who are curious about the -w 16m parameter, it ensures
    # that the TCP flow is not receiver window limited.  If it is,
    # there is a chance that the router buffer may not get filled up.
    server = h2.popen("iperf -s -w 16m")
    # TODO: Start the iperf client on h1.  Ensure that you create a
    # long lived TCP flow.
    h1.popen('iperf -c %s -t %s' % (h2.IP(), TIME))


def start_webserver(net):
    h2 = net.get('h2')
    webserver = h2.popen("python -m SimpleHTTPServer", shell=True)
    sleep(1)
    return webserver

def block_reset(attacker):
    attacker.cmd("iptables -I OUTPUT -p tcp --dport 8000 --tcp-flags RST RST -j DROP")

def wget(net):
    h1 = net.get('h1')
    h2 = net.get('h2')
    h1.cmd("wget http://%s:8000/big -O /dev/null" % (h2.IP(),))

def attack(net):
    h1 = net.get('h1')
    h2 = net.get('h2')
    h1.cmd("./schnell/schnell -v -7 http://%s:8000" % (h2.IP(),))


def start_tcpprobe(outfile):
    os.system("rmmod tcp_probe; modprobe tcp_probe full=1;")
    Popen("cat /proc/net/tcpprobe > %s" % outfile,
          shell=True)

def stop_tcpprobe():
    Popen("killall -9 cat", shell=True).wait()

def collapse():
    os.system("sysctl -w net.ipv4.tcp_congestion_control=%s" % CONG)

    topo = CollapseTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()

    dumpNodeConnections(net.hosts)
    net.pingAll()

    #CLI(net)

    print 'starting tcpprobe...'
    start_tcpprobe("out/cwnd.txt")

    print 'starting web server...'
    webserver = start_webserver(net)

    print 'starting wget...'
    wget(net)

    print 'stopping tcpprobe...'
    stop_tcpprobe()

    # print 'stopping web server...'
    # webserver.terminate()

    # print 'starting web server...'
    # webserver = start_webserver(net)

    print 'starting tcpprobe...'
    start_tcpprobe("out/cwnd_lazy.txt")

    print 'starting attack...'
    block_reset(net.get('h1'))
    attack(net)

    # print 'stopping web server...'
    # webserver.send_signal(SIGINT)

    print 'stopping tcpprobe...'
    stop_tcpprobe()

    net.stop()


if __name__ == '__main__':
    try:
        collapse()
    except:
        print "-"*80
        print "Caught exception.  Cleaning up..."
        print "-"*80
        import traceback
        traceback.print_exc()
        os.system("killall -9 top bwm-ng tcpdump cat mnexec iperf ping; mn -c")
