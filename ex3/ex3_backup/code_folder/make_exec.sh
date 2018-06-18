#!/bin/bash

cd /mnt/qemu*

# make clean

cp -a /root/ex3/virtio-crypto/qemu/. /mnt/qemu-2.0.0

./configure --prefix=/mnt/utopia/qemu/ --enable-kvm --target-list=x86_64-softmmu

make > make.txt 2>&1

make install > make-install.txt 2>&1