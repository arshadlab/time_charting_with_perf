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
