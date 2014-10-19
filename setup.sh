#!/usr/bin/env bash
if [[ $EUID -ne 0 ]]; then
  echo "You must be root" 2>&1
  exit 1
fi

apt-get install python-pip msgpack-python python-nfqueue python-imaging -y
apt-get install python-requests python-configobj python-pefile -y
git submodule init
git submodule update
cd bdfactory/ && ./install.sh
