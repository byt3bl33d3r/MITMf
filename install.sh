#!/bin/bash
sudo apt-get install python-pip msgpack-python python-nfqueue python-imaging capstone -y
sudo apt-get install python-requests python-configobj python-pefile -y
pip install capstone
./update.sh
./install-bdfactory.sh
./bdfactory/update.sh
