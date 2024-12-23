# Tested with python 3.10 & 3.12
# Install babel trace
sudo apt-get install libbabeltrace-dev

# Clone, patch and build ctf2ctf
git clone --depth 1  https://github.com/KDAB/ctf2ctf.git
cd ctf2ctf
git checkout 489cc5e8dd5ecf51ed3e37a012a287a16c16b51c
git apply ../perf_support.patch
git submodule update --init --recursive
mkdir -p ./build
cmake -B ./build -S ./
make -j$(nproc) -C ./build
cd ..

# Clone trace2html tool
git clone --depth 1 https://chromium.googlesource.com/catapult

# Delete these two packages and install them via requirements.txt.  This due to incompatibility with python 3.12
rm -rf ./catapult/third_party/six
rm -rf ./catapult/third_party/beautifulsoup4

pip install -r requirements.txt

# Clone flamegraph implementation
git clone --depth 1 https://github.com/brendangregg/FlameGraph.git
