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
# probe.csv fields: '.so name', 'process name', 'symbol filter', 'probe name'   (without quotes)
# Sample csv format:
#   libgazebo_ros_init.so, ,GazeboRosInitPrivate::Publish, ros_init_pubtime
#   <path>/libopenvino_intel_gpu_plugin.so, ,ov::intel_gpu::SyncInferRequest::infer\(\)\s*$,infer_request
#   <path>/libopenvino_intel_gpu_plugin.so, ,\bcldnn::network::execute_impl\(.*\)\s$,execute_impl
#   <path>/i915.ko, ,\bi915_gem_do_execbuffer,i915_gem_do_execbuffer
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

probe_file=$1

if [ -z $1 ]
then
    echo "Using default probe file probes.csv"
    probe_file="probes.csv"
fi

#Delete all previous probes
echo "Deleting existing probes"
sudo perf probe -d '*' 

while IFS=, read -r library_name process_name symbol_filter probe_name
do
    # Skip empty lines
    if [ -z $library_name ]; then
        continue
    fi

    # Skip comments row
    if [[ $library_name =~ ^# ]]; then
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

        echo "perf probe -m $full_path -a ${probe_name}_entry=$probe_name"
        sudo perf probe -m $full_path -a ${probe_name}_entry=$probe_name

        # Set exit/return probe
        sudo perf probe -m $full_path -a ${probe_name}=$probe_name%return
        continue
    fi

    library_path=$library_name

    if ! [[ "$library_name" =~ ^/ ]]; then
    
            if  [ $process_name ]; then
                pid=$(pgrep -o $process_name)
                if [ -z $pid ]; then
                    echo "Process $process_name not running"
                    continue
                fi
                echo "PID $pid will be used to locate library path for $library_name"
            fi

            # Find out library path from loaded list
            library_path=$(cat /proc/$pid/maps | grep  $library_name | tr -s ' ' | cut -d ' ' -f 6 | sort | uniq)

            if [ -z $library_path ]; then
                echo "Library $library_name not found"
                continue
            fi
    fi

    # NOTE: should change -T to -t for .so compiled with debug symbols on
    addresses=$(objdump -t $library_path | c++filt | grep -E $symbol_filter | cut -d ' ' -f 1)

    # If no addresses found, try with -T
    if [ -z "$addresses" ]; then
        echo "Trying with -T for better visibility on $library_path and symbol $symbol_filter"
        addresses=$(objdump -T $library_path | c++filt | grep -E $symbol_filter | cut -d ' ' -f 1)
    fi

    if [ -z "$addresses" ]; then
        echo "Address not found for lib $library_path and symbol $symbol_filter "
        continue
    fi

    echo "Setting probes on [$library_path] at symbol [$symbol_filter]"

    addresses_array=($addresses)
    num_addresses=${#addresses_array[@]}

    for address in "${addresses_array[@]}"
    do
    	address=0x$address
        if [ $((address)) -eq 0 ] 2>/dev/null; then
            echo "Address is 0x0"
            continue
        fi

        stripped_address=$(printf "%x" "$address")
        # Determine if address should be appended due multiple entries for same symbol
        if [ $num_addresses -gt 1 ]; then
            entry_name="${probe_name}_0x${stripped_address}_entry"
            exit_name="${probe_name}_0x${stripped_address}"
        else
            entry_name="${probe_name}_entry"
            exit_name="${probe_name}"
        fi

        # Set entry probe
        sudo perf probe -x $library_path -f -a "$entry_name=$address"

        # Set exit/return probe
        sudo perf probe -x $library_path -f -a "$exit_name=$address%return"

    done
done < "$probe_file"
