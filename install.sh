#!/bin/bash
apt-get install -y libsasl2-dev libldap2-dev python-dev python3-pip
git clone https://github.com/SecureAuthCorp/impacket.git 
cd impacket
python3 setup.py install
pip3 install -r ../requirements.txt
