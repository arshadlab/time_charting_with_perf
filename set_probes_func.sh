#!/bin/bash
# script to set probes in a lib using function list in text file.
# Generate list of functions from .c file
# ctags --c-kinds=f -x --fields=+n intel_display.c  | awk '{print $1}' > func.txt
# Syntax:
#   set_probes_func.sh <path to.ko/.so> func.txt

# Check if sufficient arguments were provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <module_path> <function_list_file>"
    exit 1
fi

# Assign command-line arguments to variables
MODULE_PATH="$1"
FUNCTION_LIST="$2"

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

# Initialize a counter for the current function number
current_function=0

# Read each function name and set a probe
while IFS= read -r function_name; do
    ((current_function++))
    echo "Setting probe on function $current_function/$total_functions: $function_name"
    sudo perf probe -m "$MODULE_PATH" -a "$function_name"
done < "$FUNCTION_LIST"

echo "Finished setting probes on all $total_functions functions."
