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
#                           FriendlyWAF upgrade 24.1 -> 24.2                         #
#        ----------------------------------------------------------------------      #
#                                 by FriendlyWAF                                     #
#                                                                                    #
######################################################################################
######################################################################################
sleep 2
cd /root/
# Custom Config made by Us of Snort ++
wget http://mirror.friendlywaf.com/Scripts-CE/snort3-3.1.78.0.zip
sleep 2
unzip snort3-3.1.78.0.zip
sleep 2
cd snort3-3.1.78.0
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
sleep 10
