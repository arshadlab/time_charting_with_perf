#!/bin/bash
# Copyright 2025
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

# Set TRACE_ROOT to repo root folder.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TRACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"


#**************************************
# Shows loaded dynamic libraries with their paths by a process.
# Syntax:
#   probe_show_loaded  <process_name>> [namefilter]
#   probe_show_loaded  gzserver rcl
#**************************************
probe_show_loaded() {
	local param1=$1
	local filter=$2
	local pid="$param1"

	# If param1 is not all digits, assume it's a process name and get the PID
	if [[ -z "${param1##*[!0-9]*}" ]]; then
		pid=$(pgrep -o "$param1")
		if [[ -z "$pid" ]]; then
			echo "Error: No process found with name '$param1'"
			return 1
		fi
	fi

	if [[ ! -r /proc/$pid/maps ]]; then
		echo "Error: Cannot access /proc/$pid/maps"
		return 1
	fi

	cat /proc/$pid/maps | grep '\.so' | grep "$filter" | tr -s ' ' | cut -d ' ' -f 6 | sort | uniq
}

#**************************************
# Shows symbols exported by .so file. Includes debug symbols if present.
# Returns Demangled name followed by mangled name per line
# Syntax:
#   probe_show_symbols  <lib_absolute_path> [namefilter]
#   probe_show_symbols  /opt/ros/foxy/lib/librcl.so publish
#**************************************
probe_show_symbols() {
	local lib_path="$1"
	local filter="$2"
	local probe_filter="(!__k???tab_* & !__crc_* & !__* & !*@plt)"

	if [[ "$filter" == *"::"* ]]; then
		# Filter contains ::, so search demangled names efficiently
		perf probe -x "$lib_path" -F --no-demangle --filter "$probe_filter" | sort | uniq |
		while IFS= read -r mangled_name; do
			printf "%s\n" "$mangled_name"
		done |
		c++filt |
		paste -d '\t' - <(perf probe -x "$lib_path" -F --no-demangle --filter "$probe_filter") |
		while IFS=$'\t' read -r demangled_name mangled_name_2; do
			if [[ "$demangled_name" == *"$filter"* ]]; then
				printf "%-60s -> %s\n" "$mangled_name_2" "$demangled_name"
			fi
		done
	else
		# Filter is a plain name, so search mangled names directly
		perf probe -x "$lib_path" -F --no-demangle --filter "$probe_filter" | sort | uniq | grep -E "$filter" |
			while IFS= read -r mangled_name; do
				demangled_name=$(echo "$mangled_name" | c++filt)
				printf "%-60s -> %s\n" "$mangled_name" "$demangled_name"
			done
	fi
}

#**************************************
# Set probes on exported functions by a dynamic library/kernel module/executable.  probe_name could be an exported function but in case of just a string, address in hex must be provided.
# Syntax:
#   probe_set_from_binary  <lib_absolute_path> [symbol_filter] [probe_name]
#
#   probe_set_from_binary  /opt/ros/foxy/lib/librcl.so
#   probe_set_from_binary  /opt/ros/foxy/lib/librcl.so  pub
#
#   Using grep -E capability e.g \b for word boundary
#   probe_set_from_binary  /opt/ros/foxy/lib/librcl.so  '\bTracking\b|\bFrame\b'
#
#   Tips:
#   ## Get unique names of triggered functions
# 		$ perf script -i ./output/instrace.data |  sed 's/^[ \t]*//;s/[ \t]*$//' | tr -s ' '  | awk -F'[ ]' '{print $5}' | awk -F'[:]' '{print$2}' | sort | uniq > function.txt
#		May use "sed 's/_entry$//'"
#	# Get count of each function
# 		$ sudo perf script |  sed 's/^[ \t]*//;s/[ \t]*$//' | tr -s ' '  | awk -F'[ ]' '{print $5}' | awk -F'[:]' '{print$2}' | sort | uniq -c | sort -nr

#	## Or from successful probe insertion points
# 		$ sudo perf probe -l | cut -d':' -f2  | cut -d ' ' -f1 > function.txt
#**************************************
probe_set_from_binary() {
	local lib_path="$1"
	local filter="$2"
	# Get address and demangled symbol names, and filter only valid symbol lines
	local symbols
	symbols=$(probe_show_symbols "$lib_path" "$filter")

	local symbol_count=$(echo "$symbols" | wc -l)

	local current_count=1
	# Loop through each symbol line
	echo "$symbols" | while read -r line; do
		local mangled_name demangled_name
		mangled_name=$(echo "$line" | tr -s ' ' | cut -d ' ' -f 1)
		demangled_name=$(echo "$line" |  tr -s ' ' | cut -d ' ' -f 3-)
		function_name=$(echo "$demangled_name" | sed 's/::/_/g' | sed 's/(.*//')  # Replace :: with _ and function params

		echo "($current_count/$symbol_count) Setting probe for: $function_name $mangled_name"
		probe_set_with_duration $lib_path $function_name $mangled_name
		current_count=$((current_count + 1))
	done
}

#**************************************
# Adds an entry and exit probes for a symbol
# Syntax:
#   probe_set_with_duration <.so path> function_name [mangled name/address]
#**************************************
probe_set_with_duration() {
	local address=$3
	local function_with_signature="$2"
	local function_name="${function_with_signature%%(*}"

	# Remove trailing underscores
	function_name="${function_name%_}"

	# Remove ALL leading underscores using a loop
	while [[ "${function_name:0:1}" == "_" ]]; do
		function_name="${function_name:1}"
	done

	if [[ -z "$3" ]]; then address=$2; fi

	local probe_target=""
	if [[ "$1" == *.ko ]]; then
		probe_target="-m $1"
	else
		probe_target="-x $1"
	fi

	sudo perf probe -q -d ${function_name}_entry
	local perf_cmd="sudo perf probe $probe_target --no-demangle -a ${function_name}_entry='$address'"
	echo -e "perf command:\n\t $perf_cmd"
	echo $perf_cmd >> perf_cmd.sh
	eval "$perf_cmd"

	sudo perf probe -q -d ${function_name}__return
	local perf_cmd="sudo perf probe $probe_target --no-demangle -a ${function_name}='$address%return'"
	echo -e "perf command:\n\t $perf_cmd"
	echo $perf_cmd >> perf_cmd.sh
	eval "$perf_cmd"
}

#**************************************
# Sets a single probe
# Syntax:
#   probe_set_single
#**************************************
probe_set_single() {
	sudo perf probe -q -d $2

	local address=$3

	if [ -z "$3"]; then address=$2; fi

	local probe_target=""
	if [[ "$1" == *.ko ]]; then
		probe_target="-m $1"
	else
		probe_target="-x $1"
	fi

	local perf_cmd="sudo perf probe $probe_target --no-demangle -a $2=$address"
	echo -e "perf command:\n\t $perf_cmd"
	eval "$perf_cmd"
}

#**************************************
# Delete all probes
# Syntax:
#   probe_remove_all
#**************************************
probe_remove_all() {
	sudo perf probe -d '*'
}

#**************************************
# Delete a single probe entry and exit
# Syntax:
#   probe_remove  <probe_name>
#**************************************
probe_remove() {
	sudo perf probe -d $1_entry
	sudo perf probe -d $1__return
}

#**************************************
# This bash functions reads probe requests from probe.csv and sets up entry and exit probe for request function
#
# probe.csv fields: '.so name','process name','symbol filter'   (without quotes)
# No space before and after commas. Process name from previous rows will be used if none given for non absolute lib names.
# Sample csv format:
#   libgazebo_ros_init.so,benchmark_app,GazeboRosInitPrivate::Publish
#   <path>/libopenvino_intel_gpu_plugin.so,,ov::intel_gpu::SyncInferRequest::infer\(\)\s*$
#   <path>/libopenvino_intel_gpu_plugin.so,,\bcldnn::network::execute_impl\(.*\)\s$
#   <path>/i915.ko,,\bi915_gem_do_execbuffer$
#
# Grep regex format for symbol filter:
#   e.g \bcldnn::network::execute_impl\(.*\)$
#       This regular expression matches lines that begin with the word boundary of the function
#        cldnn::network::execute_impl() called with any arguments, ensuring it's a separate word,
#        followed by optional whitespace and ending precisely at the line's end.
#
# TIPS:
#	Extract names from .C file using ctags and add absolute path to .so for first row only.
#		$ ctags --c-kinds=f -x --fields=+n mos_bufmgr_xe.c  | awk '{print ",," $1}' > function.csv
# $ probe_set_csv probes.csv
#
# If the .so names are not absolute paths, the process name must include the process that utilizes
# these .so files, and /proc/pid/maps is used to determine their absolute paths. Therefore, the
# process must be active during the execution of the probe_set_csv script. This requirement
# is unnecessary when all .so names are provided as absolute paths.
#**************************************
probe_set_from_csv() {
	probe_file=$1
	# Initialize previous_process_name outside the loop
	previous_process_name=""
	previous_library_name=""

	# Add info to perf command log file.
	echo -e "\n# Adding probes from $probe_file\n" >> perf_cmd.sh

	local line_count=$(wc -l < "$probe_file")
	local current_line=0
	while IFS=, read -r library_name process_name symbol_filter
	do
		current_line=$((current_line + 1))

		# Skip completely empty lines
		if [[ ( -z "$library_name" && -z "$process_name" && -z "$symbol_filter" ) || \
			  ( "$library_name" == \#* ) ]]; then
			echo "Skipping empty line $current_line"
			continue
		fi

		# Use previous process_name if the current one is empty
		if [ -z "$library_name" ] && [ -n "$previous_library_name" ]; then
			library_name=$previous_library_name
		elif [ -n "$library_name" ]; then
			previous_library_name=$library_name  # Update previous_library_name
		fi

		# Skip empty and commented rows
		if [ -z "$previous_library_name" ] || [[ "$previous_library_name" =~ ^# ]]; then
			echo "Skipping empty or commented line $current_line"
			continue
		fi

		library_path=$library_name

		# Direct probe call for kernel modules.  no symbol search supported
		if [[ "$library_name" == *.ko ]]; then

			# Use modinfo to get the full path of the kernel module
			library_path=$(modinfo -n -m "$library_name")
			if [ -z "$library_path" ]; then
				echo "Error: Could not find full path for kernel module $library_name"
				continue
			fi

		elif ! [[ "$library_name" =~ ^/ ]]; then
			# Use previous process_name if the current one is empty
			if [ -z "$process_name" ] && [ -n "$previous_process_name" ]; then
				process_name=$previous_process_name
			elif [ -n "$process_name" ]; then
				previous_process_name=$process_name  # Update previous_process_name
			fi

			# Retrieve the PID of the process
			pid=$(pgrep -o "$process_name")
			if [ -z "$pid" ]; then
				echo "Process $process_name not running"
				continue
			fi

			echo "PID $pid ($process_name) will be used to locate library path for $library_name"

			# Find out library path from loaded list
			library_path=$(cat /proc/$pid/maps | grep  "$library_name" | tr -s ' ' | cut -d ' ' -f 6 | sort | uniq)

			if [ -z "$library_path" ]; then
				echo "Library $library_name not found"
				continue
			fi
		fi

		printf "(%d/%d) Processing Line: %s,%s,%s\n" "$current_line" "$line_count" "$library_name" "$process_name" "$symbol_filter"
		probe_set_from_binary $library_path $symbol_filter

	done < "$probe_file"
}

#**************************************
# This bash functions removes probe listed in csv file
#**************************************
probe_remove_from_csv() {
	probe_file=$1

	local line_count=$(wc -l < "$probe_file")
	local current_line=0
	while IFS=, read -r library_name process_name symbol_filter
	do
		current_line=$((current_line + 1))
		printf "(%d/%d) Processing Line: %s\n" "$current_line" "$line_count" "$symbol_filter"
		probe_remove $symbol_filter

	done < "$probe_file"
}

#**************************************
# This bash funtion captures perf events from already added probes
# A process name or pid can be given to capture events for that process only. Otherwise system wide events are captured
#    trace_capture_and_convert [duration] [processname|pid]
#    trace_capture_and_convert 8 gzserver
#    trace_capture_and_convert 4
#**************************************
trace_capture_and_convert() {
	local root_dir
	#root_dir=$(dirname "$(dirname "$(realpath "$0")")")

	local capture_duration=${1:-8}
	local p_cmd=""
	local ctf_cmd=""

	# Determine project root from environment variable or fallback
	if [[ -n "$TRACE_ROOT" ]]; then
		root_dir="$TRACE_ROOT"
	elif [[ -d "./3rdparty" ]]; then
		root_dir="$(pwd)"
	else
		echo "Error: TRACE_ROOT environment variable not set and 3rdparty directory not found in current path."
		return 1
	fi

	local thirdparty="$root_dir/3rdparty"

	if [ ! -f "$thirdparty/ctf2ctf/build/ctf2ctf" ]; then
		echo "ctf2ctf binary not found. Building for the first run"
		mkdir -p "$thirdparty/ctf2ctf/build"
		cmake -B "$thirdparty/ctf2ctf/build" -S "$root_dir/ctf2ctf/"
		make -j$(nproc) -C "$thirdparty/ctf2ctf/build"
	fi

	if [ ! -d "$thirdparty/FlameGraph" ]; then
		echo "Flame Graph not found. Cloning"
		git -C "$thirdparty" clone https://github.com/brendangregg/FlameGraph
	fi

	if [ ! -z "$2" ]; then
		local target_pid="$2"
		if [[ -z "${target_pid##*[!0-9]*}" ]]; then
			target_pid=$(pgrep -o "$2")
			echo "Target process $2 with pid $target_pid"
		fi
		p_cmd="-p $target_pid"
		ctf_cmd="--pid-whitelist=$target_pid"
	fi

	echo "Capturing for $capture_duration seconds"

	local processes
	processes=$(ps -ao pid,comm --sort=start_time)

	local OUTPUT_DIR="$PWD/output"
	mkdir -p "$OUTPUT_DIR"
	rm -rf "$OUTPUT_DIR"/*

	sudo bash -c "set -x; perf record $p_cmd --running-time --timestamp-boundary -B --namespaces -m 2048 -r50 -e probe*:* -o $OUTPUT_DIR/instrace.data -aR sleep $capture_duration > /dev/null 2>&1" &
	sudo bash -c "set -x; perf record $p_cmd -B --namespaces -m 2048 -F 1000 -r50 -o $OUTPUT_DIR/systrace.data -g -aR sleep $capture_duration > /dev/null 2>&1"

	stty sane
	while pgrep -x "perf" > /dev/null; do
		echo "Waiting for perf record to complete..."
		sleep 1
	done
	stty sane
	sync && sleep 2
	echo "Recording completed"

	local USER
	USER=$(whoami)
	sudo chown "$USER:$USER" "$OUTPUT_DIR"/*.data

	set -x
	perf data -i "$OUTPUT_DIR/systrace.data" convert --to-ctf "$OUTPUT_DIR/systrace_data"
	perf data -i "$OUTPUT_DIR/instrace.data" convert --to-ctf "$OUTPUT_DIR/instrace_data"
	{ set +x; } 2>/dev/null

	echo "CTF conversion completed"

	set -x
	"$thirdparty/ctf2ctf/build/ctf2ctf" "$OUTPUT_DIR/systrace_data/" $ctf_cmd > "$OUTPUT_DIR/systrace.json"
	"$thirdparty/ctf2ctf/build/ctf2ctf" "$OUTPUT_DIR/instrace_data/" $ctf_cmd > "$OUTPUT_DIR/instrace.json"
	{ set +x; } 2>/dev/null

	echo "JSON conversion completed"

	set -x
	"$thirdparty/catapult/tracing/bin/trace2html" "$OUTPUT_DIR/systrace.json" "$OUTPUT_DIR/instrace.json" --output "$OUTPUT_DIR/trace.html" --config full
	{ set +x; } 2>/dev/null

	echo "HTML conversion completed"

	if [ -f "$thirdparty/FlameGraph/stackcollapse-perf.pl" ]; then
		echo "Generating FlameGraph"
		perf script -i "$OUTPUT_DIR/systrace.data" | "$thirdparty/FlameGraph/stackcollapse-perf.pl" > "$OUTPUT_DIR/flamegraph.perf-folded"
		"$thirdparty/FlameGraph/flamegraph.pl" "$OUTPUT_DIR/flamegraph.perf-folded" > "$OUTPUT_DIR/flamegraph.svg"
	fi

	echo "Capture completed. Use a web browser to open:"
	echo "  - $OUTPUT_DIR/trace.html"
	echo "  - $OUTPUT_DIR/flamegraph.svg"
	echo
	echo "Running Processes:"
	echo "$processes"
}

