#!/bin/bash

set -e  # Exit on error

# Install dependencies
echo "Installing required packages..."
sudo apt update
sudo apt-get install libncurses-dev flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
sudo apt-get install libpfm4-dev elfutils libdw-dev systemtap-sdt-dev libunwind-dev libslang2-dev libcap-dev libcapstone-dev libbabeltrace-ctf-dev libtraceevent-dev libbfd-dev libperl-dev
sudo apt-get install libbabeltrace-ctf-dev libbabeltrace-ctf1 libbabeltrace1 libbabeltrace-dev python3-babeltrace

# Get the current kernel version
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1,2)

# Clone only the perf tool directory

if [ -d "linux-src" ]; then
    echo "Using existing linux-src directory. If running kernel version is changed then remove this directory for updated code"
else
    echo "Cloning perf tool sources for v$KERNEL_MAJOR ..."
    git clone --depth=1 --branch v$KERNEL_MAJOR https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-src
fi
cd linux-src/tools/perf

# Build perf with CTF support
echo "Building perf with CTF support..."
make clean
make -j$(nproc) LDFLAGS=-lbabeltrace2

# Check if the build was successful
if [ -f "./perf" ]; then
    echo "perf built successfully!"
    cp ./perf ../../..
    echo "You can now use ./perf or move it to /usr/bin (preferred)."
    echo "    sudo cp ./perf /usr/bin/"
    echo "linux-src directory can be deleted to save space"

else
    echo "Build failed. Check for missing dependencies."
    exit 1
fi

