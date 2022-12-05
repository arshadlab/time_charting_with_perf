# Shows loaded dynamic libraries with their paths by a process.
# Syntax: 
#   ./show_loaded_lib.sh  <process_name>> [namefilter]
#   ./show_loaded_lib.sh  gzserver rcl

cat /proc/$(pgrep $1)/maps | grep '\.so' | grep "$2" | tr -s ' ' | cut -d ' ' -f 6 | sort | uniq
