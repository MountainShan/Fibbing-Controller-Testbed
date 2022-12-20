#!/bin/bash

num_veth_pairs=2

for i in $(seq 1 $num_veth_pairs); do
    sudo ip link del virt_r_$i
done

