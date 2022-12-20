from scapy.all import *
from threading import Thread
from select import select
import socket
import sys
import time
load_contrib("ospf") 

class FibbingController():
    def __init__ (self, number_fake_node):
        self.number_fake_node = int(number_fake_node)
        self.iface_R1 = "virt_r_1"
        self.iface_R99 = "virt_r_2"
        self.reads = []
        self.iface_sock_mapping = {}
        for iface in [self.iface_R1, self.iface_R99]:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((iface, 0))
            sock.setblocking(0)
            self.reads.append(sock)
            self.iface_sock_mapping.setdefault(iface, sock)
        
        # OSPF information
        self.seq = 0x80002000
        self.hidden_ip_address = {}
        self.pre_check_time = time.time()
        return
    
    def pack_OSPF_message(self, parsed, lsa_message):
        del (parsed[OSPF_LSUpd].lsalist)
        parsed[OSPF_LSUpd].lsalist=[lsa_message]
        parsed[OSPF_LSUpd].lsacount=1
        msg = Ether(src=parsed[Ether].src, dst=parsed[Ether].dst)/IP(src=parsed[IP].src,dst=parsed[IP].dst, ttl=1, tos=0xc0)/parsed[OSPF_Hdr]
        del(msg[IP].chksum)
        del(msg[OSPF_Hdr].chksum)
        del(msg[IP].len)
        del(msg[OSPF_Hdr].len)
        msg = (msg.__class__(bytes(msg)))
        self.seq += 1
        return msg

    def Type_5_LSA_Message(self, age, state_id, adrouter, forward_ip):
        lsa_header = []
        temp_link_info = OSPF_External_LSA(age=age, options=0x02, id=state_id, adrouter=adrouter, seq = self.seq, mask="255.255.255.255", metric=1, fwdaddr=forward_ip)
        del(temp_link_info.chksum)
        temp_link_Fake_Acknowledge_Messageinfo = (temp_link_info.__class__(bytes(temp_link_info)))
        lsa_header.append(temp_link_info)
        OSPF_LS_Update = OSPF_LSUpd(lsacount=1, lsalist=lsa_header)
        OSPF_Header = OSPF_Hdr(version=2,type=4,src="99.99.99.99")
        msg = Ether(src="aa:bb:cc:dd:ee:01", dst="01:00:5e:00:00:05")/IP(src="192.0.0.1",dst="224.0.0.5", ttl=1, tos=0xc0)/OSPF_Header/OSPF_LS_Update
        del(msg[IP].chksum)
        del(msg[OSPF_Hdr].chksum)
        msg = bytes(msg.__class__(bytes(msg)))
        self.iface_sock_mapping[self.iface_R1].send(msg)
        self.seq+=1
        return
    
    # Inserting fake nodes to the system
    def Fake_Node_Initial_Message(self, msg_type, parsed):
        if msg_type == 1: # Router LSA messages: Act like R99 to communicate with R1
            OSPF_Link_Message = []
            temp_link_info = OSPF_Link(id="99.99.99.99", data="255.255.255.255", type=3, toscount=0, metric=10)
            OSPF_Link_Message.append(temp_link_info)
            temp_link_info = OSPF_Link(id="192.0.0.1", data="192.0.0.2", type=2, toscount=0, metric=10)
            OSPF_Link_Message.append(temp_link_info)
            for i in range(self.number_fake_node):
                temp_link_info = OSPF_Link(id="192.0.%d.2"%(i+1), data="192.0.%d.1"%(i+1), type=2, toscount=0, metric=10)
                OSPF_Link_Message.append(temp_link_info)
            Router_LSA = OSPF_Router_LSA(age=0, options=2, type=1, id="99.99.99.99", adrouter="99.99.99.99", seq=self.seq, flags=0x2, linkcount=len(OSPF_Link_Message), linklist=OSPF_Link_Message)
            del(Router_LSA.chksum)
            Router_LSA = (Router_LSA.__class__(bytes(Router_LSA)))
            self.iface_sock_mapping[self.iface_R1].send(bytes(self.pack_OSPF_message(parsed, Router_LSA)))
            self.seq+=1
        elif msg_type == 2: # Router LSA messages: describing how many fake nodes to R1
            for i in range(self.number_fake_node):
                router_id = i+101
                router_id_address = "%d.%d.%d.%d"%(router_id,router_id,router_id,router_id)
                OSPF_Link_Message = []
                temp_link_info = OSPF_Link(id=router_id_address, data="255.255.255.255", type=3, toscount=0, metric=10)
                OSPF_Link_Message.append(temp_link_info)
                temp_link_info = OSPF_Link(id="192.0.%d.2"%(i+1), data="192.0.%d.1"%(i+1), type=2, toscount=0, metric=10)
                OSPF_Link_Message.append(temp_link_info)
                Router_LSA = OSPF_Router_LSA(age=0, options=2, type=1, id=router_id_address, adrouter=router_id_address, seq=self.seq, flags=0x2, linkcount=len(OSPF_Link_Message), linklist=OSPF_Link_Message)
                del(Router_LSA.chksum)
                Router_LSA = (Router_LSA.__class__(bytes(Router_LSA)))
                self.iface_sock_mapping[self.iface_R1].send(bytes(self.pack_OSPF_message(parsed, Router_LSA)))
                self.seq+=1
        elif msg_type == 3: # Network LSA messages: describing the links between fake nodes and R99
            Network_LSA = OSPF_Network_LSA(age=0, options=2, type=2, id="192.0.0.1", adrouter="99.99.99.99", seq=self.seq, mask="255.255.255.0", routerlist=["99.99.99.99", "1.1.1.1"])
            del(Network_LSA.chksum)
            Network_LSA = (Network_LSA.__class__(bytes(Network_LSA)))
            self.iface_sock_mapping[self.iface_R1].send(bytes(self.pack_OSPF_message(parsed, Network_LSA)))
            self.seq += 1
            for i in range(self.number_fake_node):
                router_id = i+101
                router_id_address = "%d.%d.%d.%d"%(router_id,router_id,router_id,router_id)
                Network_LSA = OSPF_Network_LSA(age=0, options=2, type=2, id="192.0.%d.2"%(i+1), adrouter=router_id_address, seq=self.seq, mask="255.255.255.0", routerlist=["99.99.99.99", router_id_address])
                del(Network_LSA.chksum)
                Network_LSA = (Network_LSA.__class__(bytes(Network_LSA)))
                self.iface_sock_mapping[self.iface_R1].send(bytes(self.pack_OSPF_message(parsed, Network_LSA)))
                self.seq+=1
        return
    
    # Reply Fake LSA Ack messages to R99
    def Fake_Acknowledge_Message(self, parsed):
        OSPF_Header = OSPF_Hdr(version=2,type=5,src="1.1.1.1")
        lsa_header = []
        for i in range(parsed[OSPF_LSUpd].lsacount):
            temp_message = OSPF_LSA_Hdr(age=parsed[OSPF_LSUpd].lsalist[i].age, options=parsed[OSPF_LSUpd].lsalist[i].options, type=parsed[OSPF_LSUpd].lsalist[i].type, id=parsed[OSPF_LSUpd].lsalist[i].id, adrouter=parsed[OSPF_LSUpd].lsalist[i].adrouter, seq=parsed[OSPF_LSUpd].lsalist[i].seq, chksum=parsed[OSPF_LSUpd].lsalist[i].chksum)
            lsa_header.append(temp_message)
        OSPF_LS_Ack = OSPF_LSAck(lsaheaders = lsa_header) 
        msg = Ether(src="aa:bb:cc:dd:ee:02", dst="01:00:5e:00:00:05")/IP(src="192.0.0.2",dst="224.0.0.5",ttl=1,tos=0xc0)/OSPF_Header/OSPF_LS_Ack
        del(msg[IP].chksum)
        del(msg[OSPF_Hdr].chksum)
        msg = (msg.__class__(bytes(msg)))
        self.iface_sock_mapping[self.iface_R99].send(bytes(msg))
        return 

    def message_transfer(self):
        while (True):
            readable, _, _ = select(self.reads, [], [])
            for r in readable:
                msg = r.recv(1514)
                message = Ether(msg)
                # print (message.show2())
                if self.iface_sock_mapping[self.iface_R1] == r:
                    if message.haslayer(OSPF_Hdr) and message[OSPF_Hdr].type == 5:
                        continue
                    self.iface_sock_mapping[self.iface_R99].send(msg)
                elif self.iface_sock_mapping[self.iface_R99] == r:
                    if message.haslayer(OSPF_Hdr) and message[OSPF_Hdr].type == 4:
                        self.Fake_Acknowledge_Message(parsed = message)
                        for i in range(1,4):
                            self.Fake_Node_Initial_Message(msg_type=i, parsed = message)
                    else:
                        self.iface_sock_mapping[self.iface_R1].send(msg)
    
    # Function for inject Type 5 LSA message
    def inject_lsa(self, age, target_ip_address, fake_link_ip_address, fake_router_id):
        age = age # 0 for insert, 3600 for remove (in second, reinstall every 3600 s)
        state_id = target_ip_address # 142.x.0.2 
        forward_ip = fake_link_ip_address # Fake link (next hop ip address)
        adrouter = fake_router_id # Fake router ID
        self.Type_5_LSA_Message(age=age,state_id=state_id, adrouter=adrouter, forward_ip=forward_ip)
        return 
        
    def main(self):
        print ("Start Fibbing controller")
        print (" - Initializate proxy")
        t = Thread(target = self.message_transfer)
        t.setDaemon(True)
        t.start()
        print (" - ..... wait 5 s")
        time.sleep(5)
        print (" - Injecting fake Type 5 LSA messages")
        # input codes here

        # Waiting...
        while (True):
            try:
                pass
            except(KeyboardInterrupt):
                print (" - Keyboard Interrupted, exit...")
                break


if ("__main__" == __name__):
    fc = FibbingController(sys.argv[1])
    fc.main()