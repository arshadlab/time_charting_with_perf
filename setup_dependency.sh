#!/bin/bash

# Tested with python 3.10 & 3.12

# Get the absolute path of the directory where the script resides
root_dir=$(dirname "$(realpath "$0")")

# Install babel trace
sudo apt-get install libbabeltrace-dev
mkdir -p $root_dir/3rdparty

cd $root_dir/3rdparty
# Clone, patch and build ctf2ctf
git clone --depth 1  https://github.com/KDAB/ctf2ctf.git
cd ctf2ctf
git fetch --depth 1 origin 489cc5e8dd5ecf51ed3e37a012a287a16c16b51c
git checkout 489cc5e8dd5ecf51ed3e37a012a287a16c16b51c
git apply $root_dir/extra/perf_support.patch
git submodule update --init --recursive
mkdir -p ./build
cmake -B ./build -S ./
make -j$(nproc) -C ./build

cd $root_dir/3rdparty

# Clone trace2html tool
git clone --depth 1 https://chromium.googlesource.com/catapult

# Delete these two packages and install them via requirements.txt.  This due to incompatibility with python 3.12
rm -rf ./catapult/third_party/six
rm -rf ./catapult/third_party/beautifulsoup4

# Clone flamegraph implementation
git clone --depth 1 https://github.com/brendangregg/FlameGraph.git

cd $root_dir
pip install -r requirements.txt
