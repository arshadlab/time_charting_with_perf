# This bash script captures perf events from already added probes
# A process name or pid can be given to capture events for that process only. Otherwise system wide events are captured
#    ./capture.sh [processname|pid]
#

rm -rf ./systrace_data/
rm -rf ./instrace_data/

capture_duration=8
p_cmd=""
ctf_cmd=""

if ! [ -z "$1" ]; then
     target_pid=$1

     # Either pid or process name given at command prompt
     if  [ -z "${target_pid##*[!0-9]*}" ]; then
         target_pid=$(pgrep $1)
     fi

     p_cmd="-p $target_pid"
     ctf_cmd="--pid-whitelist=$target_pid"
fi

echo "Capturing for $capture_duration seconds"

sudo perf record $p_cmd -B --namespaces -m 2048 -r50  -e probe_*:* -o instrace.data -aR sleep $capture_duration &
sudo perf record $p_cmd -B --namespaces -m 2048 -F 1000  -r50 -o systrace.data -g -aR sleep $capture_duration

sleep 2

echo "Recording completed"

sudo chown $USER:$USER systrace.data
sudo chown $USER:$USER instrace.data

perf data -i systrace.data convert -v --to-ctf systrace_data
perf data -i instrace.data convert -v --to-ctf instrace_data
echo "CTF conversion completed"
./ctf2ctf/build/ctf2ctf ./systrace_data/ $ctf_cmd > systrace.json
./ctf2ctf/build/ctf2ctf ./instrace_data/ $ctf_cmd > instrace.json
echo "JSON conversion completed"
./catapult/tracing/bin/trace2html ./systrace.json ./instrace.json --output trace.html --config full
echo "HTML conversion completed"

# Generate flamegraph if tools are present in current directory
# git clone https://github.com/brendangregg/FlameGraph"

if test -f ./FlameGraph/stackcollapse-perf.pl ; then
        echo "Generating FlameGraph"
        perf script -i ./systrace.data  | ./FlameGraph/stackcollapse-perf.pl > flamegraph.perf-folded
        ./FlameGraph/flamegraph.pl flamegraph.perf-folded > flamegraph.svg
fi
