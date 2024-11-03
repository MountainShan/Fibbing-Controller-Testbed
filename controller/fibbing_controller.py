#!/usr/bin/python3

from scapy.all import *
from threading import Thread, Event
from subprocess import check_output, PIPE
import socket
import select
import sys
import time
import yaml
import os
import subprocess
load_contrib("ospf") 

MULTICAST_MAC_ADDRESS = "01:00:5e:00:00:05"
MULTICAST_IP_ADDRESS = "224.0.0.5"
MASK_32 = "255.255.255.255"
MASK_24 = "255.255.255.0"
TIEMOUT = 1

class Fibbing_Message_Handler(): 
    def pack_OSPF_message(self, seq, message, lsa_message):
        del (message[OSPF_LSUpd].lsalist)
        message[OSPF_LSUpd].lsalist=[lsa_message]
        message[OSPF_LSUpd].lsacount=1
        msg = Ether(src=message[Ether].src, dst=message[Ether].dst)/IP(src=message[IP].src,dst=message[IP].dst, ttl=1, tos=0xc0)/message[OSPF_Hdr]
        del(msg[IP].chksum)
        del(msg[OSPF_Hdr].chksum)
        del(msg[IP].len)
        del(msg[OSPF_Hdr].len)
        seq += 1
        return bytes(msg.__class__(bytes(msg)))
        
    # Inserting fake nodes to the system
    
    # Reply Fake LSA Ack messages to R99
    def Fake_Acknowledge_Message(self, info, message):
        OSPF_Header = OSPF_Hdr(version=2,type=5,src=info["router_id"])
        lsa_header = []
        for i in range(message[OSPF_LSUpd].lsacount):
            temp_message = OSPF_LSA_Hdr(age=message[OSPF_LSUpd].lsalist[i].age, options=message[OSPF_LSUpd].lsalist[i].options, type=message[OSPF_LSUpd].lsalist[i].type, id=message[OSPF_LSUpd].lsalist[i].id, adrouter=message[OSPF_LSUpd].lsalist[i].adrouter, seq=message[OSPF_LSUpd].lsalist[i].seq, chksum=message[OSPF_LSUpd].lsalist[i].chksum)
            lsa_header.append(temp_message)
        OSPF_LS_Ack = OSPF_LSAck(lsaheaders = lsa_header) 
        msg = Ether(src=info["mac"], dst=MULTICAST_MAC_ADDRESS)/IP(src=info["ip"],dst=MULTICAST_IP_ADDRESS,ttl=1,tos=0xc0)/OSPF_Header/OSPF_LS_Ack
        del(msg[IP].chksum)
        del(msg[OSPF_Hdr].chksum)
        return bytes(msg.__class__(bytes(msg)))
    
    # Router LSA messages: Act like R99 to communicate with R1 ()
    def Gen_Fake_Node_Link_Message (self, seq, number_fake_node, fake, real):
        OSPF_Link_Message = []
        temp_link_info = OSPF_Link(id=fake["router_id"], data=MASK_32, type=3, toscount=0, metric=10)
        OSPF_Link_Message.append(temp_link_info)
        temp_link_info = OSPF_Link(id=fake["ip"], data=real["ip"], type=2, toscount=0, metric=10)
        OSPF_Link_Message.append(temp_link_info)
        for i in range(number_fake_node):
            temp_link_info = OSPF_Link(id="192.0.%d.2"%(i+1), data="192.0.%d.1"%(i+1), type=2, toscount=0, metric=10)
            OSPF_Link_Message.append(temp_link_info)
        Router_LSA = OSPF_Router_LSA(age=0, options=2, type=1, id=fake["router_id"], adrouter=fake["router_id"], seq=seq, flags=0x2, linkcount=len(OSPF_Link_Message), linklist=OSPF_Link_Message)
        del(Router_LSA.chksum)
        seq+=1
        return [Router_LSA.__class__(bytes(Router_LSA))]
    
    def Gen_Fake_Node_Router_Message (self, seq, number_fake_node):
        message_list = []
        for i in range(number_fake_node):
            fake_router_id = i+101
            fake_router_id_address = "%d.%d.%d.%d"%(fake_router_id,fake_router_id,fake_router_id,fake_router_id)
            OSPF_Link_Message = []
            temp_link_info = OSPF_Link(id=fake_router_id_address, data=MASK_32, type=3, toscount=0, metric=10)
            OSPF_Link_Message.append(temp_link_info)
            temp_link_info = OSPF_Link(id="192.0.%d.2"%(i+1), data="192.0.%d.1"%(i+1), type=2, toscount=0, metric=10)
            OSPF_Link_Message.append(temp_link_info)
            Router_LSA = OSPF_Router_LSA(age=0, options=2, type=1, id=fake_router_id_address, adrouter=fake_router_id_address, seq=seq, flags=0x2, linkcount=len(OSPF_Link_Message), linklist=OSPF_Link_Message)
            del(Router_LSA.chksum)
            seq+=1
            message_list.append(Router_LSA.__class__(bytes(Router_LSA)))
        return message_list

    def Gen_Fake_Node_Network_Message (self, seq, number_fake_node, fake, real):
        message_list = []
        Network_LSA = OSPF_Network_LSA(age=0, options=2, type=2, id=fake["ip"], adrouter=fake["router_id"], seq=seq, mask=MASK_24, routerlist=[fake["router_id"], real["router_id"]])
        del(Network_LSA.chksum)
        message_list.append(Network_LSA.__class__(bytes(Network_LSA)))
        seq += 1
        for i in range(number_fake_node):
            fake_router_id = i+101
            fake_router_id_address = "%d.%d.%d.%d"%(fake_router_id,fake_router_id,fake_router_id,fake_router_id)
            Network_LSA = OSPF_Network_LSA(age=0, options=2, type=2, id="192.0.%d.2"%(i+1), adrouter=fake_router_id_address, seq=seq, mask=MASK_24, routerlist=[fake["router_id"], fake_router_id_address])
            del(Network_LSA.chksum)
            seq+=1
            message_list.append(Network_LSA.__class__(bytes(Network_LSA)))
        return message_list

    def Type_5_LSA_Message(self, info, seq, age, state_id, adrouter, forward_ip, metric):
        temp_link_info = OSPF_External_LSA(age=age, options=0x02, id=state_id, adrouter=adrouter, seq = self.seq, mask=MASK_32, metric=metric, fwdaddr=forward_ip)
        del(temp_link_info.chksum)
        lsa_header = [(temp_link_info.__class__(bytes(temp_link_info)))]
        OSPF_LS_Update = OSPF_LSUpd(lsacount=1, lsalist=lsa_header)
        OSPF_Header = OSPF_Hdr(version=2,type=4,src=info["route_id"])
        msg = Ether(src=info["mac"], dst=MULTICAST_MAC_ADDRESS)/IP(src=info["ip"],dst=MULTICAST_IP_ADDRESS, ttl=1, tos=0xc0)/OSPF_Header/OSPF_LS_Update
        del(msg[IP].chksum)
        del(msg[OSPF_Hdr].chksum)
        seq+=1
        return bytes(msg.__class__(bytes(msg)))
    
    
class Controller():
    def __init__ (self):

        def raw_sock_creator(intf):
            subprocess.run(["ip", "link", "set", intf, "promisc", "on"])
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            return sock

        def tunnel_sock_creator(intf, ip, port):
            subprocess.run(["ip", "addr", "add",  "{}/24".format(ip), "dev", intf])
            subprocess.run(["ip", "link", "set", intf, "promisc", "on"])
            subprocess.run(["ip", "link", "set", "dev", intf, "mtu", "9000"])
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind((ip, port))
            return sock

        self.fb_msg_handler = Fibbing_Message_Handler()
        self.seq = 0x80002000
        self.threads = {}
        self._threads_loop_control = Event()
        self.controller_id = os.environ['CONTROLLER_ID']
        self.number_fake_node = int(os.environ['NUM_FAKE_NODE'])
        
        with open('/yaml/tunnel.yaml', 'r') as f:
            self.tunnel = yaml.safe_load(f)
        t = self.controller_id
        self.tunnel[t]['sockfd'] = tunnel_sock_creator(self.tunnel[t]['interface'], self.tunnel[t]['ip_addr'], self.tunnel[t]['port'])
        self.threads.setdefault("tunnel", Thread(target = self.tunnel_communication, daemon=True))        

        with open('/yaml/{}.yaml'.format(self.controller_id), 'r') as f:
            data = yaml.safe_load(f)
        self.real = data['real']
        self.real['sockfd'] = raw_sock_creator(self.real["interface"])
        self.real["router_id"] = "{}.{}.{}.{}".format(self.real['router_id'], self.real['router_id'], self.real['router_id'], self.real['router_id'])
        self.threads.setdefault("real", Thread(target = self.real_network_message_handler, daemon=True))
        self.fake = data['fake']
        self.fake['sockfd'] = raw_sock_creator(self.fake['interface'])
        self.fake["router_id"] = "{}.{}.{}.{}".format(self.fake['router_id'], self.fake['router_id'], self.fake['router_id'], self.fake['router_id'])
        self.threads.setdefault("fake", Thread(target = self.fake_netwokr_message_handler, daemon=True))
        
    def tunnel_communication(self):
        fd = self.tunnel[self.controller_id]
        inputs = [fd]
        others = { v['ip_addr']:{'id':k, 'exist':False} for k, v in self.tunnel.items() if k != self.controller_id }
        count = 0
        while not self._threads_loop_control.is_set():
            read, _, _ = select([fd], [], [], TIMEOUT)
            if read:
                addr, msg = read.recvfrom(65535)
                if msg.decode() == "HelloWorld":
                    print ("Received message from Controller-{}".format(others[addr]['id']))
                    others[addr]['exists'] = True
                
            if count % 5 == 0:
                for o in others.keys():
                    others[o]['exists'] = False
                    fd.sendto(o, "HelloWorld".encode())
            count += 1

        
    def real_network_message_handler(self):
        while (self._threads_loop_control):
            msg = self.real["sockfd"].recv(1514)
            message = Ether(msg)
            if message.haslayer(OSPF_Hdr) and message[OSPF_Hdr].type == 5:
                continue
            self.fake["sockfd"].send(msg)
        return
    
    def fake_netwokr_message_handler(self):
        while (self._threads_loop_control):
            msg = self.fake["sockfd"].recv(1514)
            message = Ether(msg)
            if message.haslayer(OSPF_Hdr) and message[OSPF_Hdr].type == 4:
                self.fake["sockfd"].send(self.fb_msg_handler.Fake_Acknowledge_Message(self.real, message))
                payload_list = self.fb_msg_handler.Gen_Fake_Node_Link_Message(self.seq, self.number_fake_node, self.fake, self.real)
                payload_list += self.fb_msg_handler.Gen_Fake_Node_Router_Message(self.seq, self.number_fake_node)
                payload_list += self.fb_msg_handler.Gen_Fake_Node_Network_Message(self.seq, self.number_fake_node, self.fake, self.real)
                for payload in payload_list:
                    msg = self.fb_msg_handler.pack_OSPF_message(self.seq, message, payload)
                    self.real["sockfd"].send(msg)
            else:
                self.real["sockfd"].send(msg)
        return
    
    # Function for inject Type 5 LSA message
    def inject_lsa(self, age, target_ip_address, fake_link_ip_address, fake_router_id, metric):
        age = age # 0 for insert, 3600 for remove (in second, reinstall every 3600 s)
        state_id = target_ip_address # 142.x.0.2 
        forward_ip = fake_link_ip_address # Fake link (next hop ip address)
        adrouter = fake_router_id # Fake router ID
        self.real.send(
            self.fb_msg_handler.Type_5_LSA_Message(
                self.real, self.seq, age=age,state_id=state_id, adrouter=adrouter, forward_ip=forward_ip, metric=metric))
    
    def main(self):
        print ("Start Fibbing controller")
        print (" - Initializate proxy")
        for t in self.threads: self.threads[t].start()
        print (" - ..... wait 5 s")
        time.sleep(5)
        print (" - Injecting fake Type 5 LSA messages")
        # input codes here

        # Waiting...
        try:
            while (True):
                pass
        except(KeyboardInterrupt):
            print (" - Keyboard Interrupted, exit...")
            self._threads_loop_control.set()
            return

    
if "__main__" == __name__:
    fc = Controller()    
    fc.main()