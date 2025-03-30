#!/usr/bin/python
# Parse a perf script call stack enabled output to generate dot file.
# Syntax/Flow:
# $ sudo perf script > perf.output
# $ python parse_perf.py perf.output perf.dot
# $ xdot perf.dot
#

import re
import sys
from collections import defaultdict

# Whether to include offset in function name.  Results in more function nodes
include_offset = False

def parse_perf_output(perf_files):
    edges = defaultdict(int)
    call_counts = defaultdict(int)
    skip = False;
    for perf_file in perf_files:
        with open(perf_file, 'r') as file:
            current_stack = {}
            record = []  # Temporary list to hold function calls for a record

            for line in file:
                line = line.strip()
                if line and skip == True:
                    continue
                if not line:
                    if skip == True:
                        skip = False;
                        continue
                    # Process the record, then reset for the next record
                    process_record(record, current_stack, edges, call_counts)
                    record = []  # Reset the record
                    skip = False
                    continue

                if ':' in line:
                    match = re.search(r'probe(?:_[^:]*)?:([^:]+):', line)
                    if not match:
                        continue
                    function_name = match.group(1).strip()
                    if function_name.endswith("_return"):
                        skip =  True;
                        continue
                    if function_name.endswith("_entry"):
                        function_name = function_name[:-6] #strip "_entry"

                else:
                    #match = re.search(r'\s+(.*?)\+0x[0-9a-fA-F]+', line) if include_offset else re.search(r'\s+(.*?)\+0x', line)
                    if include_offset:
                         match = re.search(r'\s+([a-zA-Z0-9_:]+)(?:\([^)]*\))?(?:\+0x([0-9a-fA-F]+))?', line)
                    else:
                         match = re.search(r'\s+([a-zA-Z0-9_:]+)(?:\([^)]*\))?(?:\+0x[0-9a-fA-F]+)?', line)

                    if not match:
                        continue
                    function_name = match.group(0).split()[-1] if include_offset else match.group(1).strip()
                    if function_name.endswith("_entry"):
                       function_name = function_name[:-6] #strip "_entry"
                record.append(function_name)
            
            # Process any remaining record after the last line
            if record:
                process_record(record, current_stack, edges, call_counts)

    return edges, call_counts

def process_record(record, current_stack,  edges, call_counts):
    record.reverse()  # Reverse the record so the parent call is at index 0
 
    # Find the point of divergence where the current record differs from the current stack
    min_length = 0
    if record[0] in current_stack:
        min_length = min(len(record), len(current_stack[record[0]]))

    divergence_point = min_length  # Assume divergence at the end of the shortest list
    for i in range(min_length):
        if record[i] != current_stack[record[0]][i]:
            divergence_point = i
            break

    previous_function = record[divergence_point - 1] if divergence_point > 0 else None
    for function in record[divergence_point:]:
       call_counts[function] += 1
       if previous_function:
          edges[(previous_function, function)] += 1
       previous_function = function
    
    # Update the current stack to the new stack
    current_stack[record[0]] = record

def generate_dot(edges, call_counts, output_file):
    with open(output_file, 'w') as f:
        f.write("digraph G {\n")
        for function, count in call_counts.items():
            f.write(f'    "{function}" [label="{function} (Calls: {count})"];\n')
        for (caller, callee), count in edges.items():
            f.write(f'    "{caller}" -> "{callee}" [label="{count} calls"];\n')
        f.write("}\n")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parse_perf.py <output1.txt> <output2.txt> ... <output.dot>")
        sys.exit(1)
    edges, call_counts = parse_perf_output(sys.argv[1:-1])
    generate_dot(edges, call_counts, sys.argv[-1])

