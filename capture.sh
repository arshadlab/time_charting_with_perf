# Copyright 2023
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Arshad Mehmood

# This bash script captures perf events from already added probes
# A process name or pid can be given to capture events for that process only. Otherwise system wide events are captured
#    ./capture.sh [processname|pid]
#


# Get duration value from command line. Else set default to 8
capture_duration=${1:-8}
p_cmd=""
ctf_cmd=""

if [ ! -f "./ctf2ctf/build/ctf2ctf" ]; then
     echo "ctf2ctf binary not found.  Building for the first run"
     mkdir -p ./ctf2ctf/build
     cmake -B ./ctf2ctf/build -S ./ctf2ctf/
     make -j$(nproc) -C ./ctf2ctf/build
fi

if [ ! -d "./FlameGraph" ]; then
     echo "Flame Graph not found.  Cloning"
     git clone https://github.com/brendangregg/FlameGraph
fi

# Single process capture logic disabled for now
#if ! [ -z "$1" ]; then
#     target_pid=$1

#     # Either pid or process name given at command prompt
#     if  [ -z "${target_pid##*[!0-9]*}" ]; then
#         target_pid=$(pgrep $1)
#     fi

#     p_cmd="-p $target_pid"
#     ctf_cmd="--pid-whitelist=$target_pid"
#fi

echo "Capturing for $capture_duration seconds"

# Save running process list to a variable.  Use pid,comm,cmd for full command line
processes=$(ps -ao pid,comm --sort=start_time)


OUTPUT_DIR=./output
mkdir -p $OUTPUT_DIR
rm -rf $OUTPUT_DIR/*


# Redirect output and errors to /dev/null, but keep standard output
sudo bash -c "perf record $p_cmd  -B --namespaces -m 2048 -r50  -e probe_*:* -o $OUTPUT_DIR/instrace.data -aR sleep $capture_duration > /dev/null 2>&1" &
sudo bash -c "perf record $p_cmd  -B --namespaces -m 2048 -F 1000  -r50 -o $OUTPUT_DIR/systrace.data -g -aR sleep $capture_duration > /dev/null 2>&1"

# Gnome Terminal gets messed up after record triggered in background mode using &
stty sane
# Loop while the perf process is running
while pgrep -x "perf" >/dev/null; do
    # Print a message to indicate the process is still running
    echo "Waiting for perf record to complete..."
    # Wait for 1 second before the next check (you can adjust the duration as needed)
    sleep 1
done
stty sane
sync && sleep 2
echo "Recording completed"



USER=$(whoami)
sudo chown $USER:$USER $OUTPUT_DIR/systrace.data
sudo chown $USER:$USER $OUTPUT_DIR/instrace.data

perf data -i $OUTPUT_DIR/systrace.data convert --to-ctf $OUTPUT_DIR/systrace_data
perf data -i $OUTPUT_DIR/instrace.data convert --to-ctf $OUTPUT_DIR/instrace_data


echo "CTF conversion completed"
sh -c "./ctf2ctf/build/ctf2ctf $OUTPUT_DIR/systrace_data/ $ctf_cmd > $OUTPUT_DIR/systrace.json"
sh -c "./ctf2ctf/build/ctf2ctf $OUTPUT_DIR/instrace_data/ $ctf_cmd > $OUTPUT_DIR/instrace.json"

echo "JSON conversion completed"
./catapult/tracing/bin/trace2html $OUTPUT_DIR/systrace.json $OUTPUT_DIR//instrace.json --output $OUTPUT_DIR/trace.html --config full
echo "HTML conversion completed"

# Generate flamegraph if tools are present in current directory
# git clone https://github.com/brendangregg/FlameGraph"

if test -f ./FlameGraph/stackcollapse-perf.pl ; then
        echo "Generating FlameGraph"
        perf script -i $OUTPUT_DIR/systrace.data  | ./FlameGraph/stackcollapse-perf.pl > $OUTPUT_DIR/flamegraph.perf-folded
        ./FlameGraph/flamegraph.pl $OUTPUT_DIR/flamegraph.perf-folded > $OUTPUT_DIR/flamegraph.svg
fi

echo "Capture completed.  Use web browser to open $OUTPUT_DIR/trace.html and $OUTPUT_DIR/flamegraph.svg files"
echo "Running Processes:"
echo "$processes"
