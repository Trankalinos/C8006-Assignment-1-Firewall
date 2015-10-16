##################################
##### USER-DEFINED VARIABLES #####
##################################
NET_INTERFACE="em1"
SERV_IP="192.168.0.2"
DHCP_SPORT="68" 	#singleton
DHCP_DPORT="67"		#singleton
DNS_PORT="53"		#singleton
WWW_PORT="80,443"	#multiport
SSH_PORT="22"		#singleton

##################################
##### DFT!! - IMPLEMENTATION #####
##################################
# Flush the tables
iptables -F
iptables -X

# Set the defaults
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# User-Defined Chains
# iptables -N tcp_in_chain
# iptables -N tcp_out_chain
# iptables -N udp_in_chain
# iptables -N udp_out_chain
# iptables -A tcp_in_chain -j ACCEPT
# iptables -A tcp_out_chain -j ACCEPT
# iptables -A udp_in_chain -j ACCEPT
# iptables -A udp_out_chain -j ACCEPT
# iptables -A INPUT -i $NET_INTERFACE -p tcp -j tcp_in_chain
# iptables -A OUTPUT -o $NET_INTERFACE -p tcp -j tcp_out_chain
# iptables -A INPUT -i $NET_INTERFACE -p udp -j udp_in_chain
# iptables -A OUTPUT -o $NET_INTERFACE -p udp -j udp_out_chain

# Traffic Forwarding Rules
iptables -N ssh-traffic 		# ssh traffic (22)
iptables -N www-traffic			# www traffic (80,443)
iptables -N noness-traffic		# non-essential traffic
iptables -A ssh-traffic
iptables -A www-traffic
iptables -A noness-traffic
iptables -A INPUT -p tcp -m tcp --sport $SSH_PORT -j ssh-traffic
iptables -A INPUT -p tcp -m multiport --sport $WWW_PORT -j www-traffic
iptables -A INPUT -j noness-traffic

# Allow DNS traffic
iptables -A noness-traffic -p udp -m udp --dport $DNS_PORT -j ACCEPT
iptables -A noness-traffic -p udp -m udp --sport $DNS_PORT -j ACCEPT
iptables -A noness-traffic -p tcp -m tcp --dport $DNS_PORT -j ACCEPT
iptables -A noness-traffic -p tcp -m tcp --sport $DNS_PORT -j ACCEPT

# Allow DHCP traffic
iptables -A noness-traffic -p udp -o $NET_INTERFACE --dport $DHCP_SPORT:$DHCP_DPORT -j ACCEPT
iptables -A noness-traffic -p udp -i $NET_INTERFACE --sport $DHCP_DPORT:$DHCP_SPORT -j ACCEPT

# Drop inbound traffic to port 80,443(http,https) from source ports less than 1024
iptables -A www-traffic -i $NET_INTERFACE -p tcp -s 0/0 --sport 0:1023 -d $SERV_IP --dport 80 -j DROP
iptables -A www-traffic -i $NET_INTERFACE -p tcp -s 0/0 --sport 0:1023 -d $SERV_IP --dport 443 -j DROP

# Permit inbound www(80,443) packets.
iptables -A www-traffic -p tcp -s 0/0 -d $SERV_IP -m multiport --dport $WWW_PORT -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A www-traffic -p tcp -s $SERV_IP -m multiport --sport $WWW_PORT -d 0/0 -m state --state ESTABLISHED -j ACCEPT

# Permit outbound www(80,443) packets.
iptables -A www-traffic -p tcp -s $SERV_IP -d 0/0 -m multiport --dport $WWW_PORT -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A www-traffic -p tcp -s 0/0 -m multiport --sport $WWW_PORT -d $SERV_IP -m state --state ESTABLISHED -j ACCEPT

# Permit inbound ssh(22) packets.
iptables -A ssh-traffic -p tcp -s 0/0 -d $SERV_IP --dport $SSH_PORT -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A ssh-traffic -p tcp -s $SERV_IP --sport $SSH_PORT -d 0/0 -m state --state ESTABLISHED -j ACCEPT

# Permit outbound ssh(22) packets.
iptables -A ssh-traffic -p tcp -s $SERV_IP -d 0/0 --dport $SSH_PORT -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A ssh-traffic -p tcp -s 0/0 --sport $SSH_PORT -d $SERV_IP -m state --state ESTABLISHED -j ACCEPT

# Drop all incoming and outgoing packets to and from port 0
iptables -A OUTPUT -p tcp -o $NET_INTERFACE -s $SERV_IP -m tcp --sport 0 -j DROP
iptables -A INPUT -p tcp -i $NET_INTERFACE -d $SERV_IP -m tcp --dport 0 -j DROP
iptables -A OUTPUT -p udp -o $NET_INTERFACE -s $SERV_IP -m udp --sport 0 -j DROP
iptables -A INPUT -p udp -i $NET_INTERFACE -d $SERV_IP -m udp --dport 0 -j DROP

# Drop all inbound SYN packets
iptables -A INPUT -i $NET_INTERFACE -p tcp ! --syn -m state --state NEW -j DROP

# Traffic Accounting Rules
iptables -A INPUT -i $NET_INTERFACE -p tcp -m multiport --dport $WWW_PORT -j www-traffic
iptables -A OUTPUT -o $NET_INTERFACE -p tcp -m multiport --sport $WWW_PORT -j www-traffic
iptables -A INPUT -i $NET_INTERFACE -p tcp -m multiport --sport $WWW_PORT -j www-traffic
iptables -A OUTPUT -o $NET_INTERFACE -p tcp -m multiport --dport $WWW_PORT -j www-traffic

iptables -A INPUT -i $NET_INTERFACE -p tcp -m tcp --dport $SSH_PORT -j ssh-traffic
iptables -A OUTPUT -o $NET_INTERFACE -p tcp -m tcp --sport $SSH_PORT -j ssh-traffic
iptables -A INPUT -i $NET_INTERFACE -p tcp -m tcp --sport $SSH_PORT -j ssh-traffic
iptables -A OUTPUT -o $NET_INTERFACE -p tcp -m tcp --dport $SSH_PORT -j ssh-traffic

iptables -A INPUT -i $NET_INTERFACE -s $SERV_IP -p tcp -m multiport ! --dport $WWW_PORT,$SSH_PORT -j noness-traffic
iptables -A OUTPUT -o $NET_INTERFACE -s $SERV_IP -p tcp -m multiport ! --sport $WWW_PORT,$SSH_PORT -j noness-traffic
iptables -A INPUT -i $NET_INTERFACE -d $SERV_IP -p tcp -m multiport ! --sport $WWW_PORT,$SSH_PORT -j noness-traffic
iptables -A OUTPUT -o $NET_INTERFACE -d $SERV_IP -p tcp -m multiport ! --dport $WWW_PORT,$SSH_PORT -j noness-traffic

iptables -A INPUT -i $NET_INTERFACE -s $SERV_IP -p udp -m multiport ! --dport $WWW_PORT,$SSH_PORT -j noness-traffic
iptables -A OUTPUT -o $NET_INTERFACE -s $SERV_IP -p udp -m multiport ! --sport $WWW_PORT,$SSH_PORT -j noness-traffic
iptables -A INPUT -i $NET_INTERFACE -d $SERV_IP -p udp -m multiport ! --sport $WWW_PORT,$SSH_PORT -j noness-traffic
iptables -A OUTPUT -o $NET_INTERFACE -d $SERV_IP -p udp -m multiport ! --dport $WWW_PORT,$SSH_PORT -j noness-traffic

# save, restart, and check the iptables
service iptables save
service iptables restart
iptables -L -n -v -x 
