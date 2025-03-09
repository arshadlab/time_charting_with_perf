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

## Get function names from source code .c file
# ctags --c-kinds=f -x --fields=+n intel_display.c  | awk '{print $1}' > function.txt

## Get unique names of triggered functions
# $ sudo perf script |  sed 's/^[ \t]*//;s/[ \t]*$//' | tr -s ' '  | awk -F'[ ]' '{print $5}' | awk -F'[:]' '{print$2}' | sort | uniq > function.txt
# Or
# $ sudo perf probe -l | cut -d':' -f2  | cut -d ' ' -f1 > function.txt

## Get count of each function 
# $ sudo perf script |  sed 's/^[ \t]*//;s/[ \t]*$//' | tr -s ' '  | awk -F'[ ]' '{print $5}' | awk -F'[:]' '{print$2}' | sort | uniq -c | sort -nr

# Check if sufficient arguments were provided
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <module_path> <function_list_file> [add_return_probe]"
    exit 1
fi

# Assign command-line arguments to variables
MODULE_PATH="$1"
FUNCTION_LIST="$2"
ADD_RETURN_PROBE="${3:-0}"  # Default to 0 if not provided

# Check if the module path is valid
if [ ! -f "$MODULE_PATH" ]; then
    echo "Error: Module path '$MODULE_PATH' does not exist."
    exit 2
fi

# Check if the function list file exists
if [ ! -f "$FUNCTION_LIST" ]; then
    echo "Error: Function list file '$FUNCTION_LIST' does not exist."
    exit 3
fi

# Calculate the total number of functions to process
total_functions=$(wc -l < "$FUNCTION_LIST")
if [ "$total_functions" -eq 0 ]; then
    echo "Error: No functions to process in '$FUNCTION_LIST'."
    exit 4
fi

# Determine the type of module based on its extension and set the appropriate flag
if [[ "$MODULE_PATH" == *.ko ]]; then
    echo "Detected a kernel module."
    probe_flag="-m"
elif [[ "$MODULE_PATH" == *.so* ]]; then
    echo "Detected a user mode shared library."
    probe_flag="-x"
else
    echo "Unsupported module type."
    exit 1  # Exit the script if the module type is not supported
fi

# Initialize a counter for the current function number
current_function=0

# Read each function name and set a probe
while IFS= read -r function_name; do
    ((current_function++))
    echo "Setting probe on function $current_function/$total_functions: $function_name"

    # Check if return probe should also be added
    if [ "$ADD_RETURN_PROBE" -eq 1 ]; then
        sudo perf probe $probe_flag "$MODULE_PATH" -a "${function_name}_entry"
        echo "Setting return probe on function $current_function/$total_functions: $function_name"
        sudo perf probe $probe_flag "$MODULE_PATH" -a "$function_name%return"
    else
        sudo perf probe $probe_flag "$MODULE_PATH" -a "$function_name"
    fi
done < "$FUNCTION_LIST"

echo "Finished setting probes on all $total_functions functions."
