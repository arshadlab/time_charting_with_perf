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

# Shows symbols exported by .so file. Includes debug symbols if present.
# Syntax: 
#   ./show_lib_symbols.sh  <lib_absolute_path> [namefilter]
#   ./show_lib_symbols.sh  /opt/ros/foxy/lib/librcl.so publish

(objdump -j .text -C -T $1 | grep "$2" | tr -s ' ' | cut -d ' ' -f 1,6- ; objdump -j .text -C -t $1 | grep "$2" | tr -s ' ' | cut -d ' ' -f 1,5-) | sort | uniq
