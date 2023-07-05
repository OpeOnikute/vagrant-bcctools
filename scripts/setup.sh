#!/bin/bash

set -eux

sudo apt-get upgrade

# sudo apt-get install  -y

# Install the correct/latest version of BCC things
# sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
# echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
echo deb http://cloudfront.debian.net/debian sid main | sudo tee -a /etc/apt/sources.list

sudo apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev linux-headers-$(uname -r) bpftrace curl linux-perf