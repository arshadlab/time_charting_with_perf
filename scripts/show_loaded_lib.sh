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

# Shows loaded dynamic libraries with their paths by a process.
# Syntax: 
#   ./show_loaded_lib.sh  <process_name>> [namefilter]
#   ./show_loaded_lib.sh  gzserver rcl

param1=$1
pid=$1

if  [ -z "${param1##*[!0-9]*}" ]; then
        pid=$(pgrep $1)
fi

cat /proc/$pid/maps | grep '\.so' | grep "$2" | tr -s ' ' | cut -d ' ' -f 6 | sort | uniq
