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

# Author: Arshad Mehmood

# Set probes on exported functions by a dynamic library.  probe_name could be an exported function but in case of just a string, address in hex must be provided.
# Syntax: 
#   ./set_probe_lib.sh  <lib_absolute_path> [symbol_filter] [probe_name]
#
#   ./set_probe_lib.sh  /opt/ros/foxy/lib/librcl.so 
#   ./set_probe_lib.sh  /opt/ros/foxy/lib/librcl.so  pub 
#
#   Using grep -P capability e.g \b for word boundary
#   ./set_probe_lib.sh  /opt/ros/foxy/lib/librcl.so  '\bTracking\b|\bFrame\b'

symbols=$(objdump -j .text -C -T $1 | grep -E "$2" | tr -s ' ' | cut -d ' ' -f 1,6)
if [ -z $symbols ]
then
 symbols=$(objdump -j .text -C -t $1 | grep -E "$2" | tr -s ' ' | cut -d ' ' -f 1,5)
fi
echo $symbols

echo "$symbols" | while read -r address symbol
do
      
        libname=$(basename $1)
        #libname=${libname%.*}
        libname=${libname%%.so*}

        addr=0x$address
        echo $address, $symbol
        #function_name=$(echo "$symbol" | sed -E 's/.*::([^<(]*).*/\1/')
        function_name=$(echo "$symbol" | sed 's/[(<].*//')
        function_name="${function_name##*::}"
        echo "Setting Probes for $symbol.  Function name $function_name"
        echo "perf probe -x $1 -f -a  ${libname}_${function_name}_entry=$addr"
        # Set entry probe
        sudo perf probe -x $1 -f -a  ${libname}_${function_name}_entry=$addr

        # Set exit/return probe
        sudo perf probe -x $1 -f -a  ${libname}_${function_name}=$addr%return

done


## Experimental: Below commented code try to add probes on all of exported symbols.  Disabled for now.
# Delete existing probes
#sudo sh -c "objdump -j .text -C -T $1 | grep '$2' | tr -s ' ' | cut -d ' ' -f 6 | xargs -i{} perf probe -d {}_entry"
#sudo sh -c "objdump -j .text -C -T $1 | grep '$2' | tr -s ' ' | cut -d ' ' -f 6 | xargs -i{} perf probe -d {}__return"

# Add function entry probe
#sudo sh -c "objdump -j .text -C -T $1 | grep '$2' | tr -s ' ' | cut -d ' ' -f 6 | xargs -i{} perf probe -x $1 -a {}_entry={}"
# Add function exit probe
#sudo sh -c "objdump -j .text -C -T $1 | grep '$2' | tr -s ' ' | cut -d ' ' -f 6 | xargs -i{} perf probe -x $1 -a {}={}%return"

