#!/bin/bash
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

# Desc: Script to set perf probes 
# Author: Arshad Mehmood

# This bash script reads probe requests from probe.csv and sets up entry and exit probe for request function
# Caution: Script deletes all previous probes before proceeding. 
# probe.csv fields: '.so name','process name','symbol filter','probe name'   (without quotes)
# No space before and after commas. Process name from previous rows will be used if none given for non absolute lib names.
# Sample csv format:
#   libgazebo_ros_init.so,benchmark_app,GazeboRosInitPrivate::Publish,ros_init_pubtime
#   <path>/libopenvino_intel_gpu_plugin.so,,ov::intel_gpu::SyncInferRequest::infer\(\)\s*$,infer_request
#   <path>/libopenvino_intel_gpu_plugin.so,,\bcldnn::network::execute_impl\(.*\)\s$,execute_impl
#   <path>/i915.ko,,\bi915_gem_do_execbuffer,i915_gem_do_execbuffer
#
# Grep regex format for symbol filter:
#   e.g \bcldnn::network::execute_impl\(.*\)$
#       This regular expression matches lines that begin with the word boundary of the function
#        cldnn::network::execute_impl() called with any arguments, ensuring it's a separate word,
#        followed by optional whitespace and ending precisely at the line's end.
#
# $ ./set_probes_csv.sh probes.csv
#
# If the .so names are not absolute paths, the process name must include the process that utilizes
# these .so files, and /proc/pid/maps is used to determine their absolute paths. Therefore, the
# process must be active during the execution of the set_probes_csv.sh script. This requirement
# is unnecessary when all .so names are provided as absolute paths.

root_dir=$(dirname $(dirname "$(realpath "$0")"))

probe_file=$1

if [ -z $1 ]
then
    echo "Using default probe file probes.csv"
    probe_file="$root_dir/probes/probes.csv"
fi

#Delete all previous probes
#echo "Deleting existing probes"
#sudo perf probe -q -d '*'

# Initialize previous_process_name outside the loop
previous_process_name=""
previous_library_name=""

while IFS=, read -r library_name process_name symbol_filter probe_name
do
    # Use previous process_name if the current one is empty
    if [ -z "$library_name" ] && [ -n "$previous_library_name" ]; then
        library_name=$previous_library_name
    elif [ -n "$library_name" ]; then
        previous_library_name=$library_name  # Update previous_library_name
    fi
            
    # Skip empty and commented rows
    if [ -z "$previous_library_name" ] || [[ "$previous_library_name" =~ ^# ]]; then
        continue
    fi


    # Direct probe call for kernel modules.  no symbol search supported
    if [[ "$library_name" == *.ko ]]; then

        # Use modinfo to get the full path of the kernel module
        full_path=$(modinfo -n -m "$library_name")
        if [ -z "$full_path" ]; then
            echo "Error: Could not find full path for kernel module $library_name"
            continue
        fi
	
	# Delete existing probe with same name (if any)
	sudo perf probe -q -d ${probe_name}*
	
        entry_cmd="sudo perf probe -m $full_path -a ${probe_name}_entry=$probe_name"

        # Print and execute the entry command
	echo "$entry_cmd"
	eval "$entry_cmd"
	
	
        #echo "perf probe -m $full_path -a ${probe_name}_entry=$probe_name"
        #sudo perf probe -m $full_path -a ${probe_name}_entry=$probe_name


	
	exit_cmd="sudo perf probe -m $full_path -a ${probe_name}=$probe_name%return"

	# Print and execute the entry command
	echo "$exit_cmd"
	eval "$exit_cmd"
	
        # Set exit/return probe
        #sudo perf probe -m $full_path -a ${probe_name}=$probe_name%return
        continue
    fi

    library_path=$library_name

    if ! [[ "$library_name" =~ ^/ ]]; then
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

    libname=$(basename $library_path)
    libname=${libname%%.so*}
    # Truncate to the first 10 characters
    libname=${libname:0:10}
        
    # Retrieve and display objdump output with addresses and full line information
    full_lines=$(objdump -t "$library_path" | c++filt | grep -E "$symbol_filter")

    # Check if no lines found, then try with -T
    if [ -z "$full_lines" ]; then
        echo "Trying with -T for better visibility on $library_path and symbol $symbol_filter"
        full_lines=$(objdump -T "$library_path" | c++filt | grep -E "$symbol_filter")
    fi

    if [ -z "$full_lines" ]; then
        echo "Address not found for lib $library_path and symbol $symbol_filter"
        continue
    fi

    # Convert full lines into an array to count them
    readarray -t lines <<< "$full_lines"
    num_addresses=${#lines[@]}

    echo "Setting probes on [$library_path] at symbol [$symbol_filter]"
    while read -r line; do
        address=$(echo "$line" | cut -d ' ' -f 1)
        address="0x${address#0x}"

        if [ "$((address))" -eq 0 ] 2>/dev/null; then
            echo "Address is 0x0, skipping invalid address."
            continue
        fi

        echo "Full line: $line"
        echo "Using address: $address"

        # Determine unique probe names based on the address and count
        stripped_address=$(printf "%x" "$address")

	# Append the address to the probe name only if there are multiple addresses
	if [ $num_addresses -gt 1 ]; then
		entry_name="${libname}_${probe_name}_0x${stripped_address}_entry"
		exit_name="${libname}_${probe_name}_0x${stripped_address}"
	else
		entry_name="${libname}_${probe_name}_entry"
		exit_name="${libname}_${probe_name}"
	fi

	# Delete existing probe with same name (if any)
	sudo perf probe -q -d ${libname}_${exit_name}*
	
        entry_cmd="sudo perf probe -x $library_path -f -a $entry_name=$address"

        # Print and execute the entry command
	echo "$entry_cmd"
	eval "$entry_cmd"
	
	exit_cmd="sudo perf probe -x $library_path -f -a $exit_name=$address%return"

	# Print and execute the exit command
	echo "$exit_cmd"
	eval "$exit_cmd"

    done <<< "$full_lines"

done < "$probe_file"

