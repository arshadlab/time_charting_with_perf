#!/bin/bash
# Delete a single probe entry and exit
# Syntax: 
#   ./delete_probe_single.sh  <probe_name>
#

# Delete existing probe if any
sudo perf probe -d $1_entry
sudo perf probe -d $1__return

