#!/bin/bash
if [ `id -u` -ne 0 ]; then
        echo Need sudo
        exit 1
fi
set -v
sleep 2
echo "No Upgrades"
sleep 1
