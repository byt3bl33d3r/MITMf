#!/usr/bin/env bash
if [[ $EUID -ne 0 ]]; then
  echo "You must be root" 2>&1
  exit 1
fi

apt-get install python-scapy python-dns python-pip msgpack-python python-imaging -y
apt-get install python-twisted-web python-dnspython python-requests python-configobj python-pefile -y
git submodule init
git submodule update
cd bdfactory/ && ./install.sh
