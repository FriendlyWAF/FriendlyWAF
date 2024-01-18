#!/bin/bash
# this command give the script sudo perms
if [ `id -u` -ne 0 ]; then
        echo Need sudo
        exit 1
fi

set -v
sleep 10
clear

######################################################################################
######################################################################################
#                         FriendlyWAF upgrade 24.1 => 24.2                           #
#        ----------------------------------------------------------------------      #
#                                 by FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 3
systemctl stop snort3
sleep 2
systemctl stop snort3-nic.service
sleep 3
cd /root/
# Snort Upgrade snort3-3.1.76 => snort3-3.1.77.0
wget http://mirror.friendlywaf.com/Scripts-CE/snort3-3.1.77.0.zip
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
sleep 2
# Comment for knowlegd your system version and IPv4 address to managed
sleep 2
echo "################################################################################
                                FriendlyWAF 24.2
    Welcome to our software FriendlyWAF, this is a Enterprise Version for FREE.

                Proxy: http://\4:81
                Monitoring: http://\4:19999
                SSH: \4

################################################################################
" > /etc/issue
sleep 5
clear

######################################################################################
######################################################################################
#                  FriendlyWAF upgrade 24.1 => 24.2 has been done                   #
#        ----------------------------------------------------------------------      #
#                                 by FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 5
reboot
