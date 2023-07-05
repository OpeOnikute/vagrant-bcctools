#!/bin/bash
set -eux

sudo apt-get install git build-essential systemtap-sdt-dev python make -y

sudo mkdir -p /var/src 
cd /var/src
if [ ! -d "/var/src/node/.git" ]
then
    git clone https://github.com/nodejs/node.git
fi
echo `pwd`
cd node
git checkout v12.x
./configure --with-dtrace
# The -j2 option will cause make to run 4 simultaneous compilation 
# jobs which may reduce build time.
make -j2

sudo ln -s /var/src/node/out/Release/node /usr/bin/node
echo "Finished building. Node binary location: /var/src/node/out/Release/node"