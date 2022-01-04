#!/usr/bin/env python3

from sys import argv
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time

host_names = [ 'h1', 'h2', 'h3' ]
atk_file_path = '/dos_exp/data/dos.pcap'

class Network(Topo):
    def build(self):
        switch = self.addSwitch('s1')
        for h in host_names:
            host = self.addHost(h)
            self.addLink(host, switch, bw=1, loss=0)


def generate_attack_traffic(net):
    h3 = net.get('h3')
    if_h3 = h3.intfNames()[0]

    h3.cmd( 'tcpdump -i %s "icmp[0] == 8" -w %s &' % (if_h3, atk_file_path))

    h1 = net.get('h1')
    ping_dest_ip = str(h1.IP())

    h3.cmd('ping %s &' % ping_dest_ip)

    print('Capturing traffic')
    time.sleep(10)

    print('Attack traffic captured')
    h3.cmd('killall ping')
    h3.cmd('killall tcpdump')


def start_dos(net):
    h1 = net.get('h1')
    h3 = net.get('h3')
    if_h3 = h3.intfNames()[0]

    print('Starting DoS')
    h3.cmd('tcpreplay -i %s -t -l 10000 %s &' % (if_h3, atk_file_path))

    time.sleep(20)

    print('Stopping DoS')
    h3.cmd('killall tcpreplay')


def start_experiment():
    topo = Network()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, autoStaticArp=True)
    net.start()

    # Generate attack traffic
    generate_attack_traffic(net)

    time.sleep(2)

    # Start traffic monitoring
    for h in [ 'h1', 'h2', 'h3' ]:
        hx = net.get(h)
        hx_name = hx.intfNames()[0]
        hx.cmd('tcpdump -i' + hx_name + ' -w /home/knox/iass/dos_exp/data/' + hx_name + '.pcap &')

    # # Usual traffic
    net.get('h1').cmd('iperf -s &')
    net.get('h2').cmd('iperf -c 10.0.0.1 -t 100 &')

    time.sleep(10)

    # Start DoS attack
    start_dos(net)

    time.sleep(20)

    for i, h in enumerate([ 'h1', 'h2', 'h3' ]):
        hx = net.get(h)
        hx.cmd('killall tcpdump')
        if i < 2:
            hx.cmd('killall iperf')
    
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    start_experiment()
