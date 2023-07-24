# Install babel trace
sudo apt-get install libbabeltrace-dev

# Clone, patch and build ctf2ctf
git clone  https://github.com/KDAB/ctf2ctf.git
cd ctf2ctf
git checkout 489cc5e8dd5ecf51ed3e37a012a287a16c16b51c
git apply ../perf_support.patch
git submodule update --init --recursive
mkdir -p ./build
cmake -B ./build -S ./
make -j$(nproc) -C ./build
cd ..

# Clone trace2html tool
git clone https://chromium.googlesource.com/catapult

# Clone flamegraph implementation
git clone https://github.com/brendangregg/FlameGraph.git
