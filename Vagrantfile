# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bullseye64"
  config.vm.provision :shell, :privileged => false, :path => "scripts/setup.sh"

  config.vm.provider "virtualbox" do |v|
    v.memory = 6144
    v.cpus = 4
  end
end