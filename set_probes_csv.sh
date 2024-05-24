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
# probe.csv fields: '.so name', 'symbol filter', 'probe name'   (without quotes)
# Sample csv format:
#   libgazebo_ros_init.so, GazeboRosInitPrivate::Publish, ros_init_pubtime
#   <path>/libopenvino_intel_gpu_plugin.so, ,ov::intel_gpu::SyncInferRequest::infer\(\)\s*$,infer_request
#   <path>/libopenvino_intel_gpu_plugin.so, ,\bcldnn::network::execute_impl\(.*\)$,execute_impl
#   <path>/i915.ko, ,\bi915_gem_do_execbuffer,i915_gem_do_execbuffer
#
#    ./set_probes_csv.sh probes.csv
#

probe_file=$1

if [ -z $1 ]
then
    echo "Using default probe file probes.csv"
    probe_file="probes.csv"
fi

#Delete all previous probes
echo "Deleting existing probes"
sudo perf probe -d '*' 


probe_file=$1

while IFS=, read -r library_name process_name symbol_filter probe_name
do
    # Skip empty lines
    if [ -z $library_name ]; then
        continue
    fi
        
    # Skip comments row
    if [ "$library_name" == '#' ]; then
        continue
    fi

    # Direct probe call for kernel modules.  no symbol search supported
    if [[ "$library_name" == *.ko ]]; then
        echo "perf probe -m $library_name -a ${probe_name}_entry=$probe_name"
        sudo perf probe -m $library_name -a ${probe_name}_entry=$probe_name

        # Set exit/return probe
        sudo perf probe -m $library_name -a ${probe_name}=$probe_name%return
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

    if [ -z "$addresses" ]; then
        echo "Address not found for lib $library_path and symbol $symbol_filter "
        continue
    fi

    echo "Setting probes on [$library_path] at symbol [$symbol_filter]"

    for address in $addresses
    do
    	address=0x$address
        if [ $((address)) -eq 0 ] 2>/dev/null; then
            echo "Address is 0x0"
            continue
        fi

        # Set entry probe
        sudo perf probe -x $library_path -f -a ${probe_name}_entry=$address

        # Set exit/return probe
        sudo perf probe -x $library_path -f -a ${probe_name}=$address%return
    done
done < "$probe_file"
