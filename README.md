# Fibbing Controller testcode
A Repo for implementing fibbing controller in gNS3 emulator
![Topology](https://github.com/MountainShan/Fibbing-Controller-Testbed/blob/main/topology.png)
## gNS3 remote server install (from gNS3 website)
```shell
cd /tmp
curl https://raw.githubusercontent.com/GNS3/gns3-server/master/scripts/remote-install.sh > gns3-remote-install.sh
sudo bash gns3-remote-install.sh --with-iou --with-i386-repository
```

## Setup gNS3 testbed
- Import project gNS3-cisco-fibbing-testbed.gns3project to gNS3 remote server.

## How to run
1. Run the `iface_setup.sh` to create virtual interfaces
```shell
sudo ./iface_setup.sh
```
2. Start fibbing_controller.py through venv
```shell
sudo fibbing_venv/bin/python3 ./fibbing_controller.py <number of fake nodes>
<number of fake nodes> = Number of fake node for injection.
```
3. Start gNS3 client, and start all devices

## Useful Commands: 
 - Shows the neighbor routers
 ```show ip ospf neighbor```
 - Shows the database of the router (only correct data)
 ```show ip ospf database```
 - Routing table of a router
 ```show ip route```
 - configure a router, ex. R1
 ```shell
 enable 
 configure terminal
 ```
*copy the information to the console, the configure files: ./Configure/R1.cfg*
 
 - configure a host
*copy the information to the console, the configure files: ./Configure/hosts.cfg*
