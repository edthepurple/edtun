#!/bin/bash

# Flush all chains in all tables (IPv4 + IPv6) and zero counters
for table in filter nat mangle raw security; do
    iptables -t $table -F
    iptables -t $table -X
    iptables -t $table -Z
    ip6tables -t $table -F
    ip6tables -t $table -X
    ip6tables -t $table -Z
done

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT

# Enable IP forwarding (safe to run again)
echo 1 > /proc/sys/net/ipv4/ip_forward

#################################
# NAT PREROUTING (TCP + UDP)
#################################

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 8443 \
    -j DNAT --to-destination 192.168.100.2:8443

iptables -t nat -A PREROUTING -i eth0 -p udp --dport 8443 \
    -j DNAT --to-destination 192.168.100.2:8443

#################################
# FORWARD chain (TCP)
#################################

iptables -A FORWARD -p tcp -d 192.168.100.2 --dport 8443 \
    -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

iptables -A FORWARD -p tcp -s 192.168.100.2 --sport 8443 \
    -m state --state ESTABLISHED,RELATED -j ACCEPT

#################################
# FORWARD chain (UDP)
#################################

iptables -A FORWARD -p udp -d 192.168.100.2 --dport 8443 \
    -j ACCEPT

iptables -A FORWARD -p udp -s 192.168.100.2 --sport 8443 \
    -j ACCEPT

#################################
# POSTROUTING (Masquerade TCP + UDP)
#################################

iptables -t nat -A POSTROUTING -o edtun0 -p tcp -d 192.168.100.2 --dport 8443 \
    -j MASQUERADE

iptables -t nat -A POSTROUTING -o edtun0 -p udp -d 192.168.100.2 --dport 8443 \
    -j MASQUERADE
