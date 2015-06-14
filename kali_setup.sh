#!/usr/bin/env bash

git submodule init && git submodule update --recursive
apt-get install -y python-capstone python-twisted python-requests python-scapy python-dnspython python-cryptography python-crypto
apt-get install -y python-msgpack python-configobj python-pefile python-ipy python-openssl python-pypcap
pip install Pillow mitmflib
