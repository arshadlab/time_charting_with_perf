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
