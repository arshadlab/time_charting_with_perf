rm -rf ./systrace_data/
rm -rf ./instrace_data/

p_cmd=""
ctf_cmd=""
if ! [ -z "$1" ]; then target_pid=$(pgrep $1); p_cmd="-p $target_pid"; ctf_cmd="--pid-whitelist=$target_pid"; fi

sudo perf record $p_cmd -B -m 2048 -r50 -e probe_*:* -o instrace.data -aR sleep 2 &
sudo perf record $p_cmd -B -m 2048 -r50 -o systrace.data -aR sleep 3


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
