#!/bin/bash

nsname=testns
va=vt1
vb=vt2

vaaddr=10.11.0.1/24
vbaddr=10.11.0.2/24

ip="sudo ip"
ipns="$ip netns exec $nsname ip"

# create netns and set veth-b to the ns
$ip netns add $nsname
$ip link add $va type veth peer name $vb
$ip link set dev $vb netns $nsname

# vetha up
$ip link set dev $va up
$ip addr add dev $va $vaaddr

#vethb up
$ipns link set dev lo up
$ipns link set dev $vb up
$ipns addr add dev $vb $vbaddr
