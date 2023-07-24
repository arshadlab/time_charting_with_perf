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

# Sets a single probe in a library.  probe_name could be an exported function but in case of just a string, address in hex must be provided.
# Syntax: 
#   ./set_probe_single.sh  <lib_absolute_path> <probe_name> [address in hex>
#
#   ./set_probe_single.sh  /opt/ros/foxy/lib/librcl.so rcl_timer_fini
#   ./set_probe_single.sh  /opt/ros/foxy/lib/librcl.so timerfinal 0x25fe0

# Delete existing probe if any
sudo perf probe -d $2_entry
sudo perf probe -d $2__return

address=$3

if [ -z "$3"]; then address=$2; fi

sudo perf probe -x $1 -a $2_entry=$address
sudo perf probe -x $1 -a $2=$address%return
