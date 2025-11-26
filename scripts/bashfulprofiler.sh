#!/bin/bash
# Copyright 2025
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

# Author: Arshad Mehmood

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TRACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

############################################################
# Show loaded libraries from a process
############################################################
probe_show_loaded() {
	local param1="$1"
	local filter="$2"
	local pid="$param1"

	# If param1 is not digits → treat as process name
	if [[ -z "${param1##*[!0-9]*}" ]]; then
		pid=$(pgrep -o "$param1")
		if [[ -z "$pid" ]]; then
			echo "Error: No process found with name '$param1'" >&2
			return 1
		fi
	fi

	if [[ ! -r "/proc/$pid/maps" ]]; then
		echo "Error: Cannot access /proc/$pid/maps" >&2
		return 1
	fi

	# Pure return value
	grep '\.so' "/proc/$pid/maps" | grep "$filter" | awk '{print $6}' | sort -u
}

############################################################
# Show exported symbols from a binary (.so or .ko)
# Returns: "<mangled> <demangled>" per line
############################################################
probe_show_symbols() {
	local lib_path="$1"
	local filter="$2"
	local probe_filter='(!__k???tab_* & !__crc_* & !__* & !*@plt)'

	if [[ -z "$lib_path" ]]; then
		echo "Usage: probe_show_symbols <lib_absolute_path> [regex_filter]" >&2
		return 1
	fi

	# Build perf command
	local perf_cmd="perf probe -x \"$lib_path\" -F --no-demangle --filter \"$probe_filter\""
	#echo "$perf_cmd" >&2

	# Get mangled symbol list
	local symbols
	symbols=$(eval "$perf_cmd" 2>/dev/null | sort -u)
	if [[ -z "$symbols" ]]; then
		echo "Error: No symbols found" >&2
		return 1
	fi

	# FAST version: paste + grep
	paste \
		<(echo "$symbols") \
		<(echo "$symbols" | c++filt) \
	| {
		if [[ -z "$filter" ]]; then
			cat
		else
			# Grep only demangled (column 2)
			# But still returns mangled (column 1)
			grep -E "$filter"
		fi
	}
}

############################################################
# Set probes from a binary based on symbol filter
############################################################
probe_set_from_binary() {
	local lib_path="$1"
	local filter="$2"

	local symbols
	symbols=$(probe_show_symbols "$lib_path" "$filter")
	if [[ $? -ne 0 ]]; then
		echo "Error: Failed to fetch symbols." >&2
		return 1
	fi

	local symbol_count
	symbol_count=$(echo "$symbols" | wc -l)

	local current=1
	echo "$symbols" | while read -r mangled demangled; do
		local function_name
		function_name=$(echo "$demangled" | sed 's/::/_/g' | sed 's/(.*//')

		echo "($current/$symbol_count) Setting probe for: $function_name ($mangled)" >&2

		probe_set_with_duration "$lib_path" "$function_name" "$mangled"
		current=$((current + 1))
	done
}

############################################################
# Add entry + exit probes for a symbol
############################################################
probe_set_with_duration() {
	local lib="$1"
	local fn_sig="$2"
	local addr="$3"

	local function_name="${fn_sig%%(*}"
	function_name="${function_name%_}"

	# Remove leading underscores
	while [[ "${function_name:0:1}" == "_" ]]; do
		function_name="${function_name:1}"
	done

	if [[ -z "$addr" ]]; then
		addr="$fn_sig"
	fi

	local target="-x $lib"
	[[ "$lib" == *.ko ]] && target="-m $lib"

	# ENTRY probe
	sudo perf probe -q -d "${function_name}_entry"
	local cmd1="sudo perf probe $target --no-demangle -a ${function_name}_entry='$addr'"
	echo "$cmd1" >&2
	eval "$cmd1"

	# RETURN probe
	sudo perf probe -q -d "${function_name}__return"
	local cmd2="sudo perf probe $target --no-demangle -a ${function_name}='$addr%return'"
	echo "$cmd2" >&2
	eval "$cmd2"
}

############################################################
# Single probe
############################################################
probe_set_single() {
	sudo perf probe -q -d "$2"

	local address="$3"
	[[ -z "$3" ]] && address="$2"

	local probe_target="-x $1"
	[[ "$1" == *.ko ]] && probe_target="-m $1"

	local cmd="sudo perf probe $probe_target --no-demangle -a $2=$address"
	echo "$cmd" >&2
	eval "$cmd"
}

############################################################
# Remove all probes
############################################################
probe_remove_all() {
	sudo perf probe -d '*'
}

############################################################
# Remove a single entry/exit pair
############################################################
probe_remove() {
	sudo perf probe -d "$1"_entry
	sudo perf probe -d "$1"__return
}

############################################################
# Set probes based on CSV file
############################################################
probe_set_from_csv() {
	local probe_file="$1"
	local previous_process_name=""
	local previous_library_name=""

	echo -e "\n# Adding probes from $probe_file\n" >> perf_cmd.sh

	local line_count
	line_count=$(wc -l < "$probe_file")
	local current_line=0

	while IFS=, read -r library_name process_name symbol_filter; do
		current_line=$((current_line + 1))

		# Skip empty or commented
		if [[ ( -z "$library_name" && -z "$process_name" && -z "$symbol_filter" ) || "$library_name" =~ ^# ]]; then
			continue
		fi

		# Carry forward library name
		if [[ -z "$library_name" && -n "$previous_library_name" ]]; then
			library_name="$previous_library_name"
		else
			previous_library_name="$library_name"
		fi

		# Kernel module case
		local library_path="$library_name"
		if [[ "$library_name" == *.ko ]]; then
			library_path=$(modinfo -n -m "$library_name")
		elif [[ ! "$library_name" =~ ^/ ]]; then
			# Carry forward process name
			if [[ -z "$process_name" && -n "$previous_process_name" ]]; then
				process_name="$previous_process_name"
			else
				previous_process_name="$process_name"
			fi

			local pid
			pid=$(pgrep -o "$process_name")
			if [[ -z "$pid" ]]; then
				echo "Process $process_name not running" >&2
				continue
			fi

			library_path=$(grep "$library_name" /proc/$pid/maps | awk '{print $6}' | sort -u)
		fi

		printf "(%d/%d) Processing Line: %s,%s,%s\n" \
			   "$current_line" "$line_count" "$library_name" "$process_name" "$symbol_filter" >&2

		probe_set_from_binary "$library_path" "$symbol_filter"

	done < "$probe_file"
}

############################################################
# Remove probes from CSV
############################################################
probe_remove_from_csv() {
	local probe_file="$1"
	local line_count
	line_count=$(wc -l < "$probe_file")
	local current_line=0

	while IFS=, read -r library_name process_name symbol_filter; do
		current_line=$((current_line + 1))
		printf "(%d/%d) Removing: %s\n" "$current_line" "$line_count" "$symbol_filter" >&2
		probe_remove "$symbol_filter"
	done < "$probe_file"
}

############################################################
# Capture perf events and convert to FlameGraph + trace.html
############################################################
trace_capture_and_convert() {
	local capture_duration="${1:-8}"
	local p_cmd=""
	local ctf_cmd=""

	local root_dir="$TRACE_ROOT"
	if [[ ! -d "$TRACE_ROOT/3rdparty" ]]; then
		echo "Error: TRACE_ROOT not set correctly." >&2
		return 1
	fi

	local thirdparty="$root_dir/3rdparty"

	# Build tools if missing
	if [[ ! -f "$thirdparty/ctf2ctf/build/ctf2ctf" ]]; then
		echo "Building ctf2ctf..." >&2
		mkdir -p "$thirdparty/ctf2ctf/build"
		cmake -B "$thirdparty/ctf2ctf/build" -S "$root_dir/ctf2ctf/"
		make -j$(nproc) -C "$thirdparty/ctf2ctf/build"
	fi

	if [[ ! -d "$thirdparty/FlameGraph" ]]; then
		echo "Cloning FlameGraph..." >&2
		git -C "$thirdparty" clone https://github.com/brendangregg/FlameGraph
	fi

	# Process name or PID
	if [[ -n "$2" ]]; then
		local target_pid="$2"
		if [[ -z "${target_pid##*[!0-9]*}" ]]; then
			target_pid=$(pgrep -o "$2")
		fi
		p_cmd="-p $target_pid"
		ctf_cmd="--pid-whitelist=$target_pid"
	fi

	echo "Capturing for $capture_duration seconds" >&2

	local OUTPUT_DIR="$PWD/output"
	mkdir -p "$OUTPUT_DIR"
	rm -rf "$OUTPUT_DIR"/*

	sudo bash -c "perf record $p_cmd --running-time --timestamp-boundary -B --namespaces -m 2048 -r50 -e probe*:* -o $OUTPUT_DIR/instrace.data -aR sleep $capture_duration" &
	sudo bash -c "perf record $p_cmd -B --namespaces -m 2048 -F 1000 -r50 -o $OUTPUT_DIR/systrace.data -g -aR sleep $capture_duration"

	while pgrep -x "perf" >/dev/null; do
		sleep 1
	done

	sudo chown "$(whoami)" "$OUTPUT_DIR"/*.data

	# Convert to CTF
	perf data -i "$OUTPUT_DIR/systrace.data" convert --to-ctf "$OUTPUT_DIR/systrace_data"
	perf data -i "$OUTPUT_DIR/instrace.data" convert --to-ctf "$OUTPUT_DIR/instrace_data"

	# Convert to JSON
	"$thirdparty/ctf2ctf/build/ctf2ctf" "$OUTPUT_DIR/systrace_data/" $ctf_cmd > "$OUTPUT_DIR/systrace.json"
	"$thirdparty/ctf2ctf/build/ctf2ctf" "$OUTPUT_DIR/instrace_data/" $ctf_cmd > "$OUTPUT_DIR/instrace.json"

	# Generate HTML
	"$thirdparty/catapult/tracing/bin/trace2html" \
		"$OUTPUT_DIR/systrace.json" "$OUTPUT_DIR/instrace.json" \
		--output "$OUTPUT_DIR/trace.html" --config full

	# Generate FlameGraph
	if [[ -f "$thirdparty/FlameGraph/stackcollapse-perf.pl" ]]; then
		perf script -i "$OUTPUT_DIR/systrace.data" | \
			"$thirdparty/FlameGraph/stackcollapse-perf.pl" > "$OUTPUT_DIR/flamegraph.perf-folded"
		"$thirdparty/FlameGraph/flamegraph.pl" "$OUTPUT_DIR/flamegraph.perf-folded" > "$OUTPUT_DIR/flamegraph.svg"
	fi

	echo "Capture done. Open:" >&2
	echo "  $OUTPUT_DIR/trace.html" >&2
	echo "  $OUTPUT_DIR/flamegraph.svg" >&2
}

