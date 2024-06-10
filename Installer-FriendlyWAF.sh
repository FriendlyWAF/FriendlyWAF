#!/bin/bash
sleep 5

######################################################################################
#                             FriendlyWAF Cloud Install                              #
#        ----------------------------------------------------------------------      #
#                                 by FriendlyWAF                                     #
######################################################################################
cd /root/

# Update and upgrade the system
apt update && apt upgrade -y

# Install requerd tools
apt-get install apt-transport-https ca-certificates curl software-properties-common -y

# Install required packages
apt install -y sudo nano ethtool curl cmake wget unzip ufw nload git build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev libunwind-dev libfl-dev software-properties-common

# Install NGINX Proxy Manager
sh -c "$(wget --no-cache -qO- https://raw.githubusercontent.com/ej52/proxmox/main/install.sh)" -s --app nginx-proxy-manager

# Install Speedtest CLI
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
sudo apt-get install speedtest

# Install Netdata
wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh && sh /tmp/netdata-kickstart.sh

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure UFW rules
ufw allow 443/tcp
ufw allow 25565/tcp
ufw allow 3389/tcp
ufw allow 8080/tcp
ufw allow 22/tcp
ufw allow 80/tcp
ufw reload
cd /etc/ufw/

# Configure custom UFW rules
active_interfaces=$(ip link | grep 'state UP' | cut -d ':' -f 2)

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

# Rate limit ICMP echo requests to 10 per hour per source IP
-A ufw-before-input -p icmp --icmp-type echo-request -m hashlimit --hashlimit-upto 10/hour --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name icmp-limit -j ACCEPT

# ----- 4 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 22 -m connlimit --connlimit-above 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 22 -m connlimit --connlimit-above 4 -j DROP

# ----- 8 connections per 5 min per ip -----
# TCP
-A ufw-before-input -p tcp --dport 22 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 22 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP
# UDP
-A ufw-before-input -p udp --dport 22 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 22 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP

# ----- 4 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 443 -m connlimit --connlimit-above 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 443 -m connlimit --connlimit-above 4 -j DROP

# ----- 8 connections per 5 min per ip -----
# TCP
-A ufw-before-input -p tcp --dport 443 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 443 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP
# UDP
-A ufw-before-input -p udp --dport 443 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 443 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP

# ----- 4 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 80 -m connlimit --connlimit-above 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 80 -m connlimit --connlimit-above 4 -j DROP

# ----- 8 connections per 5 min per ip -----
# TCP
-A ufw-before-input -p tcp --dport 80 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 80 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP
# UDP
-A ufw-before-input -p udp --dport 80 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 80 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP

# ----- 4 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 53 -m connlimit --connlimit-above 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 53 -m connlimit --connlimit-above 4 -j DROP

# ----- 8 connections per 5 min per ip -----
# TCP
-A ufw-before-input -p tcp --dport 53 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 53 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP
# UDP
-A ufw-before-input -p udp --dport 53 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 53 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP

# ----- 4 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 25565 -m connlimit --connlimit-above 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 25565 -m connlimit --connlimit-above 4 -j DROP

# ----- 8 connections per 5 min per ip -----
# TCP
-A ufw-before-input -p tcp --dport 25565 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 25565 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP
# UDP
-A ufw-before-input -p udp --dport 25565 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 25565 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP

# ----- 4 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 3389 -m connlimit --connlimit-above 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 3389 -m connlimit --connlimit-above 4 -j DROP

# ----- 8 connections per 5 min per ip -----
# TCP
-A ufw-before-input -p tcp --dport 3389 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 3389 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP
# UDP
-A ufw-before-input -p udp --dport 3389 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 3389 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP

# ----- 4 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 8080 -m connlimit --connlimit-above 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 8080 -m connlimit --connlimit-above 4 -j DROP

# ----- 8 connections per 5 min per ip -----
# TCP
-A ufw-before-input -p tcp --dport 8080 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 8080 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP
# UDP
-A ufw-before-input -p udp --dport 8080 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 8080 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP

# ----- 4 concurrent connections per ip -----
# TCP
-A ufw-before-input -p tcp --syn --dport 22 -m connlimit --connlimit-above 4 -j DROP
# UDP
-A ufw-before-input -p udp --dport 22 -m connlimit --connlimit-above 4 -j DROP

# ----- 8 connections per 5 min per ip -----
# TCP
-A ufw-before-input -p tcp --dport 19999 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p tcp --dport 19999 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP
# UDP
-A ufw-before-input -p udp --dport 19999 -i $uplink -m state --state NEW -m recent --set
-A ufw-before-input -p udp --dport 19999 -i $uplink -m state --state NEW -m recent --update --seconds 300 --hitcount 8 -j DROP

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

# Install Snort ++
cd /root/
wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.15.zip
unzip v3.0.15.zip
cd libdaq-3.0.15
./bootstrap
./configure
make
make install
# pause 2 sec
sleep 2

# Install gperftools
cd /root/
wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.15/gperftools-2.15.tar.gz
tar xzf gperftools-2.15.tar.gz
cd gperftools-2.15
./configure
make
make install
# pause 2 sec
sleep 2

# Install Snort ++
cd /root/
wget https://github.com/FriendlyWAF/FriendlyWAF/raw/main/snort3-3.2.2.0.zip
unzip snort3-3.2.2.0.zip
cd snort3-3.2.2.0
chmod 755 -R *
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
chmod 755 -R *
make
make install
ldconfig
snort -V

# Configure network interfaces for Snort ++
active_interfaces=$(ip link | grep 'state UP' | cut -d ':' -f 2)
uplink=""
for interface in $active_interfaces; do
    uplink=$interface
    break
done

if [ -z "$uplink" ]; then
    echo "No active network interface found."
else
    ip link set dev $uplink promisc on
    ethtool -k $uplink | grep receive-offload
    ethtool -K $uplink gro off lro off

# Configure Snort 3 NIC in promiscuous mode and Disable GRO, LRO on boot
cat > /etc/systemd/system/snort3-nic.service <<EOL
[Unit]
Description=Set Snort 3 NIC in promiscuous mode and Disable GRO, LRO on boot
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev $uplink promisc on
ExecStart=/usr/sbin/ethtool -K $uplink gro off lro off
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=default.target
EOL

fi
systemctl daemon-reload
systemctl start snort3-nic.service
systemctl enable snort3-nic.service

# Download Snort rules
mkdir -p /usr/local/etc/rules
cd /usr/local/etc/rules/
wget https://github.com/FriendlyWAF/FriendlyWAF/raw/main/snort3-community-rules.zip
unzip snort3-community-rules.zip

# Download Snort OpenAppID
cd /root/
wget https://www.snort.org/downloads/openappid/33380 -O snort-openappid.tar.gz
tar -xzvf snort-openappid.tar.gz
cp -R odp /usr/local/lib/

# Configure Snort Daemon
active_interfaces=$(ip link | grep 'state UP' | cut -d ':' -f 2)
uplink=""
for interface in $active_interfaces; do
    uplink=$interface
    break
done

if [ -z "$uplink" ]; then
    echo "No active network interface found."
else
cat > /etc/systemd/system/snort3.service <<EOL
[Unit]
Description=Snort Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -s 65535 -k none -l /var/log/snort -D -i $uplink -m 0x1b -u root -g root
ExecStop=/bin/kill -9 $MAINPID

[Install]
WantedBy=multi-user.target
EOL

fi
systemctl daemon-reload
systemctl enable --now snort3

# Configure auto-update service
mkdir -p /etc/waf/
cat > /etc/waf/auto-update.sh <<EOL
#!/bin/bash
if [ \$(id -u) -ne 0 ]; then
    echo "Need sudo"
    exit 1
fi

set -v

apt update && apt upgrade -y
sleep 2592000  # 1 month
apt update && apt upgrade -y
sleep 2 # wait 2 sec to reboot
reboot
EOL

chmod 755 /etc/waf/auto-update.sh

cat > /etc/systemd/system/auto-update.service <<EOL
[Unit]
Description=FriendlyWAF-Upgrading-System

[Service]
ExecStart=/etc/waf/auto-update.sh
SyslogIdentifier=Diskutilization

[Install]
WantedBy=multi-user.target
EOL

systemctl enable --now auto-update.service

# Configure system version and IPv4 address to manage
echo "################################################################################
                                FriendlyWAF 24.6
    Welcome to our software FriendlyWAF, this is a Enterprise Version for FREE.

                Proxy: http://\4:81
                Monitoring: http://\4:19999
                SSH: \4
                Proxy-Email:    admin@example.com
                Proxy-Password: changeme

################################################################################
" > /etc/issue

# Rebooting System
reboot
