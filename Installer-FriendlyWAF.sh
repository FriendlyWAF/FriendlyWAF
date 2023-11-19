#!/bin/bash
# this command give the script sudo perms
if [ `id -u` -ne 0 ]; then
	echo Need sudo
	exit 1
fi

set -v
sleep 5
clear

######################################################################################
######################################################################################
#                             FriendlyWAF Cloud Install                              #
#        ----------------------------------------------------------------------      #
#                                 by FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 3
cd /root/
sleep 2
apt update && apt upgrade -y
sleep 2
apt install software-properties-common -y
sleep 2
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
sleep 2
sudo sudo apt-get install speedtest
sleep 2
wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh && sh /tmp/netdata-kickstart.sh
sleep 3
# logging the connections
iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -D INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -D INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -D INPUT -p tcp --dport 81 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -D INPUT -p tcp --dport 81 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -D INPUT -p tcp --dport 53 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -D INPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j DROP
sleep 2
# Icmp blocking 
iptables -D INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
sleep 2
iptables -D INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
sleep 2
iptables -D INPUT -p icmp -m icmp --icmp-type 1 -m limit --limit 10/min -j ACCEPT 
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -D INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -D INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -D INPUT -p tcp --dport 10000 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -D INPUT -p tcp --dport 10000 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -D INPUT -p tcp --dport 19999 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -D INPUT -p tcp --dport 19999 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -D INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -D INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -D INPUT -p tcp --dport 25565 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -D INPUT -p tcp --dport 25565 -m conntrack --ctstate NEW -j DROP
sleep 2
# Reconfigure your Iptables
sleep 4
# logging the connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -A INPUT -p tcp --dport 81 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -A INPUT -p tcp --dport 81 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -A INPUT -p tcp --dport 53 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -A INPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j DROP
sleep 2
# Icmp blocking 
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
sleep 2
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
sleep 2
iptables -A INPUT -p icmp -m icmp --icmp-type 2 -m limit --limit 2/hour -j ACCEPT 
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -A INPUT -p tcp --dport 10000 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -A INPUT -p tcp --dport 10000 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -A INPUT -p tcp --dport 19999 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -A INPUT -p tcp --dport 19999 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j DROP
sleep 2
# These rules continue to accept new connections as long as they don’t exceed the limit of 3 connections per hour from each IP address.
iptables -A INPUT -p tcp --dport 25565 -m conntrack --ctstate NEW -m limit --limit 3/hour --limit-burst 3 -j ACCEPT
sleep 2
iptables -A INPUT -p tcp --dport 25565 -m conntrack --ctstate NEW -j DROP
sleep 2
# Save Iptables Commands
sudo /sbin/iptables-save > /etc/iptables/rules.v4
sleep 2
# installing Web Panel
cd /var/www/html/
sleep 2
wget https://mirror.friendlywaf.com/Scripts-CE/WebPanel.zip
sleep 2
sudo unzip WebPanel.zip
sleep 2
cd /root/
# Installing Snort ++ for IPS/IDS
sleep 2
wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.13.zip
sleep 2
unzip v3.0.13.zip
sleep 2
chmod 755 -R *
sleep 2
cd libdaq-3.0.13
sleep 2
./bootstrap
sleep 2
./configure
sleep 2
make
sleep 2
make install
sleep 2
cd /root/
sleep 2
wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.13/gperftools-2.13.tar.gz
sleep 2
tar xzf gperftools-2.13.tar.gz
sleep 2
chmod 755 -R *
sleep 2
cd gperftools-2.13
sleep 2
./configure
sleep 2
make
sleep 2
make install
sleep 2
cd /root/
# Custom Config made by Us of Snort ++
wget https://mirror.friendlywaf.com/Scripts-CE/snort3-3.1.74.0.zip
sleep 2
unzip snort3-3.1.74.0.zip
sleep 2
cd snort3-3.1.74.0
sleep 2
sudo chmod 755 -R *
sleep 2
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
sleep 2
cd build
sleep 2
chmod 755 -R *
sleep 2
make
sleep 2
make install
sleep 1
ldconfig
sleep 1
snort -V
sleep 5

# Get a list of active network interfaces
active_interfaces=$(ip link | grep 'state UP' | cut -d ':' -f 2)

# Loop through each interface and select the first active one
uplink=""
for interface in $active_interfaces; do
    uplink=$interface
    break
done

if [ -z "$uplink" ]; then
    echo "No active network interface found."
else
sleep 2
ip link set dev $uplink promisc on
ethtool -k $uplink | grep receive-offload
ethtool -K $uplink gro off lro off
sleep 2
fi
cd /etc/systemd/system/
sleep 2

# Get a list of active network interfaces
active_interfaces=$(ip link | grep 'state UP' | cut -d ':' -f 2)

# Loop through each interface and select the first active one
uplink=""
for interface in $active_interfaces; do
    uplink=$interface
    break
done

if [ -z "$uplink" ]; then
    echo "No active network interface found."
else
echo "[Unit]
Description=Set Snort 3 NIC in promiscuous mode and Disable GRO, LRO on boot
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev $uplink promisc on
ExecStart=/usr/sbin/ethtool -K $uplink gro off lro off
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=default.target" > snort3-nic.service
sleep 2
fi
systemctl daemon-reload
sleep 2
systemctl start snort3-nic.service
systemctl enable snort3-nic.service
sleep 2
mkdir -p /usr/local/etc/rules
sleep 2
cd /usr/local/etc/rules/
# Snort Rules Default ones
wget https://mirror.friendlywaf.com/Scripts-CE/snort3-community-rules.zip
sleep 2
unzip snort3-community-rules.zip
sleep 2
cd /root/
sleep 2
wget https://www.snort.org/downloads/openappid/33380 -O snort-openappid.tar.gz
sleep 2
tar -xzvf snort-openappid.tar.gz
sleep 2
cp -R odp /usr/local/lib/
sleep 2
mkdir -p /var/log/snort
sleep 12
snort -c /usr/local/etc/snort/snort.lua
sleep 5
cd /etc/systemd/system/
sleep 2

# Get a list of active network interfaces
active_interfaces=$(ip link | grep 'state UP' | cut -d ':' -f 2)

# Loop through each interface and select the first active one
uplink=""
for interface in $active_interfaces; do
    uplink=$interface
    break
done

if [ -z "$uplink" ]; then
    echo "No active network interface found."
else
echo "[Unit]
Description=Snort Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -s 65535 -k none -l /var/log/snort -D -i $uplink -m 0x1b -u root -g root
ExecStop=/bin/kill -9 $MAINPID

[Install]
WantedBy=multi-user.target" > snort3.service
sleep 2
fi
cd /root/
sleep 2
rm -R *
sleep 2
systemctl daemon-reload
sleep 12
systemctl enable --now snort3
sleep 2
cd /etc/
sleep 2
# Auto-Upgrades form Us like bugs fixses and more
echo "#!/bin/bash
if [ `id -u` -ne 0 ]; then
	echo Need sudo
	exit 1
fi

set -v

sleep 2
clear

######################################################################################
######################################################################################
#                          Updating & Upgrading the System                           #
#           ---------------------------------------------------------------          #
#                                 By FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
apt update && apt upgrade -y
sleep 3
systemctl start snort3
sleep 2592000
apt update && apt upgrade -y
clear

######################################################################################
######################################################################################
#                               Reboot the System                                    #
#           -------------------------------------------------------------------      #
#                                 By FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 1
reboot" > auto-update.sh
sleep 2
chmod 755 auto-update.sh
sleep 2
cd /etc/systemd/system/
sleep 2

echo "[Unit]
Description=FriendlyWAF-Upgrading-System

[Service]
#ExecStartPre=
ExecStart=/etc/auto-update.sh
SyslogIdentifier=Diskutilization
#ExecStop=

[Install]
WantedBy=multi-user.target " > auto-update.service
sleep 2
systemctl enable --now auto-update.service
sleep 2
# Comment for knowlegd your system version and IPv4 address to managed
sleep 2
echo "################################################################################
                                FriendlyWAF 23.12
        Welcome to our software FriendlyWAF this is a Free version

                Web-Panel: http://\4/
                SSH: \4

################################################################################
" > /etc/issue
sleep 2
shutdown -r +2
clear

######################################################################################
######################################################################################
#                             System Installer is Done                               #
#          ---------------------------------------------------------------           #
#                                 By FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 1
