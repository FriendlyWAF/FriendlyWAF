#!/bin/bash
# this command give the script sudo perms
if [ `id -u` -ne 0 ]; then
        echo Need sudo
        exit 1
fi

set -v
sleep 25
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
ufw allow 443/tcp
sleep 1
ufw allow 25565/tcp
sleep 1
ufw allow 81/tcp
sleep 1
ufw allow 19999/tcp
sleep 1
ufw allow 80/tcp
sleep 2
ufw reload
sleep 2
cd /etc/ufw/
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
echo "
#
# rules.before
#
# Rules that should be run before the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw-before-input
#   ufw-before-output
#   ufw-before-forward
#

# Don't delete these required lines, otherwise there will be errors
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]
# End required lines

# Rate limit ICMP echo requests to 20 per hour
-A ufw-before-input -p icmp --icmp-type echo-request -m limit --limit 20/hour -j ACCEPT

# ----- 3 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 22 -m connlimit --connlimit-above 3 -j DROP
# UDP
-A ufw-before-input -p udp --dport 22 -m connlimit --connlimit-above 3 -j DROP

# ----- 7 connections per 1 hour per ip -----
# TCP
-A ufw-before-input -p tcp --dport 22 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 22 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP
# UDP
-A ufw-before-input -p udp --dport 22 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 22 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP

# ----- 3 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 443 -m connlimit --connlimit-above 3 -j DROP
# UDP
-A ufw-before-input -p udp --dport 443 -m connlimit --connlimit-above 3 -j DROP

# ----- 7 connections per 1 hour per ip -----
# TCP
-A ufw-before-input -p tcp --dport 443 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 443 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP
# UDP
-A ufw-before-input -p udp --dport 443 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 443 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP

# ----- 2 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 80 -m connlimit --connlimit-above 2 -j DROP
# UDP
-A ufw-before-input -p udp --dport 80 -m connlimit --connlimit-above 2 -j DROP

# ----- 4 connections per 1 hour per ip -----
# TCP
-A ufw-before-input -p tcp --dport 80 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 80 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 80 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 80 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 4 -j DROP

# ----- 3 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 81 -m connlimit --connlimit-above 3 -j DROP
# UDP
-A ufw-before-input -p udp --dport 81 -m connlimit --connlimit-above 3 -j DROP

# ----- 7 connections per 1 hour per ip -----
# TCP
-A ufw-before-input -p tcp --dport 81 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 81 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP
# UDP
-A ufw-before-input -p udp --dport 81 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 81 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP

# ----- 3 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 19999 -m connlimit --connlimit-above 3 -j DROP
# UDP
-A ufw-before-input -p udp --dport 19999 -m connlimit --connlimit-above 3 -j DROP

# ----- 5 connections per 1 hour per ip -----
# TCP
-A ufw-before-input -p tcp --dport 19999 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 19999 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP
# UDP
-A ufw-before-input -p udp --dport 19999 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 19999 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP

# ----- 2 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 53 -m connlimit --connlimit-above 2 -j DROP
# UDP
-A ufw-before-input -p udp --dport 53 -m connlimit --connlimit-above 2 -j DROP

# ----- 3 connections per 1 hour per ip -----
# TCP
-A ufw-before-input -p tcp --dport 53 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 53 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 3 -j DROP
# UDP
-A ufw-before-input -p udp --dport 53 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 53 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 3 -j DROP

# ----- 3 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 25565 -m connlimit --connlimit-above 3 -j DROP
# UDP
-A ufw-before-input -p udp --dport 25565 -m connlimit --connlimit-above 3 -j DROP

# ----- 7 connections per 1 hour per ip -----
# TCP
-A ufw-before-input -p tcp --dport 25565 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 25565 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP
# UDP
-A ufw-before-input -p udp --dport 25565 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 25565 -i $uplink -m state --state NEW -m recent --update --seconds 3600 --hitcount 7 -j DROP

# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop INVALID packets (logs these in loglevel medium and higher)
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# allow dhcp client to work
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

#
# ufw-not-local
#
-A ufw-before-input -j ufw-not-local

# if LOCAL, RETURN
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN

# if MULTICAST, RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN

# if BROADCAST, RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN

# all other non-local packets are dropped
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT

# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
" > before.rules
sleep 2
fi
sleep 2
ufw reload
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
wget https://ams1.vultrobjects.com/script/snort3-3.1.77.0.zip
sleep 2
unzip snort3-3.1.77.0.zip
sleep 2
cd snort3-3.1.77.0
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
wget https://ams1.vultrobjects.com/script/snort3-community-rules.zip
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
sleep 2
systemctl daemon-reload
sleep 12
systemctl enable --now snort3
sleep 2
mkdir /etc/waf/
sleep 2
cd /etc/waf/
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
ExecStart=/etc/waf/auto-update.sh
SyslogIdentifier=Diskutilization
#ExecStop=

[Install]
WantedBy=multi-user.target " > auto-update.service
sleep 2
systemctl enable --now auto-update.service
sleep 2
cd /etc/waf/
sleep 2
# Auto-Upgrades form Us like bugs fixses and more
echo "#!/bin/bash
if [ `id -u` -ne 0 ]; then
        echo Need sudo
        exit 1
fi

set -v

sleep 12
clear

######################################################################################
######################################################################################
#                FriendlyWAF is blocking the datacenters and others                  #
#           ---------------------------------------------------------------          #
#                                 By FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 2
cd /etc/waf/
sleep 2
wget https://raw.githubusercontent.com/brahma-dev/ufw-bots/master/files/ufw.sh
sleep 2
chmod +x ufw.sh
sleep 2
./ufw.sh
sleep 2
rm ufw.sh
sleep 3

######################################################################################
######################################################################################
#                            Firewall has been updated                               #
#           -------------------------------------------------------------------      #
#                                 By FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 3" > block-bots.sh
sleep 2
chmod 755 block-bots.sh
sleep 2
cd /etc/systemd/system/
sleep 2

echo "[Unit]
Description=FriendlyWAF-Upgrading-System

[Service]
#ExecStartPre=
ExecStart=/etc/waf/block-bots.sh
SyslogIdentifier=Diskutilization
#ExecStop=

[Install]
WantedBy=multi-user.target " > auto-block-bots.service
sleep 2
systemctl enable --now auto-block-bots.service
sleep 2
cd /etc/waf/
sleep 2
# Auto-Upgrades form Us like bugs fixses and more
echo "echo "Clearing old ipv4 rules"
sudo sed -z -i.bak.old -u "s/### tuple.* comment=7566772d626f7473\n.*DROP//gm" /etc/ufw/user.rules
sudo sed -i 'N;/^\n$/d;P;D' /etc/ufw/user.rules

echo "Clearing old ipv6 rules"
sudo sed -z -i.bak.old -u "s/### tuple.* comment=7566772d626f7473\n.*DROP//gm" /etc/ufw/user6.rules
sudo sed -i 'N;/^\n$/d;P;D' /etc/ufw/user6.rules" > unblock-bots.sh
sleep 2
cd /root/
sleep 2
# Comment for knowlegd your system version and IPv4 address to managed
sleep 2
echo "################################################################################
                                FriendlyWAF 24.1
    Welcome to our software FriendlyWAF, this is a Enterprise Version for FREE.

                Proxy: http://\4:81
                Monitoring: http://\4:19999
                SSH: \4

################################################################################
" > /etc/issue
sleep 2
clear

######################################################################################
######################################################################################
#                             System Installer is Done                               #
#          ---------------------------------------------------------------           #
#                                 By FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 5
reboot
