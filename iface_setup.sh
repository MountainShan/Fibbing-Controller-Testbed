#!/bin/bash 
num_veth_pairs=2
TOE_OPTIONS="rx tx sg tso ufo gso gro lro rxvlan txvlan rxhash"

echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
sudo sysctl -w net.ipv4.conf.all.arp_announce=1
sudo sysctl -w net.ipv4.conf.all.arp_ignore=2
sudo sysctl net.ipv6.conf.all.disable_ipv6=1

for i in $(seq 1 $num_veth_pairs); do
    sudo ip link add phy_r_$i type veth peer name virt_r_$i
    sudo ip link set phy_r_$i up
    sudo ip link set virt_r_$i up
    sudo ifconfig phy_r_$i promisc
    sudo ifconfig virt_r_$i promisc
    for TOE_OPTION in $TOE_OPTIONS; do
        sudo /sbin/ethtool --offload phy_r_$i "$TOE_OPTION" off >/dev/null 2>&1
        sudo /sbin/ethtool --offload virt_r_$i "$TOE_OPTION" off >/dev/null 2>&1   
    done
done