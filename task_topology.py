from typing import List, Tuple

from mininet.topo import Topo       
        
class Topology(Topo):
   
    def build(self, switches: List[str], hosts: List[str], links: List[Tuple[str, str, int]]) -> None:
        # KAIST CS341 SDN Lab Task 1: Building Your Own Network
        #
        # input:
        # - switches: List[str]
        #     -> List of switch names
        # - hosts: List[str]
        #     -> List of host names
        # - links: List[Tuple[str,str,int]]
        #     -> List of links, which is represented by a tuple
        #        The first and the second components represents name of the components
        #        The third component represents cost of the link; not used in this task
                
        ###
        # YOUR CODE HERE
        ###
        for s in switches:
            self.addSwitch(s)
        
        for h in hosts: 
            self.addHost(h)
        
        for l in links:
            self.addLink(l[0], l[1])
        
        # # ex) switches = ['s1'], hosts = ['h1'], links = [('s1','h1',100),]
        # self.addSwitch('s1')
        # self.addHost('h1')
        # self.addLink('s1', 'h1')
        
        