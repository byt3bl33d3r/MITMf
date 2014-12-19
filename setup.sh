#!/usr/bin/env bash
if [[ $EUID -ne 0 ]]; then
  echo "You must be root" 2>&1
  exit 1
fi

apt-get install python-scapy python-dns python-pip msgpack-python python-nfqueue python-imaging -y
apt-get install python-twisted-web python-dnspython python-requests python-configobj python-pefile -y
pip install pyyaml ua-parser user-agents
git submodule init
git submodule update
cd libs/bdfactory/ && ./install.sh
