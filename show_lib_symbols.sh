# Shows symbols exported by .so file. Includes debug symbols if present.
# Syntax: 
#   ./show_lib_symbols.sh  <lib_absolute_path> [namefilter]
#   ./show_lib_symbols.sh  /opt/ros/foxy/lib/librcl.so publish

(objdump -j .text -C -T $1 | grep "$2" | tr -s ' ' | cut -d ' ' -f 1,6- ; objdump -j .text -C -t $1 | grep "$2" | tr -s ' ' | cut -d ' ' -f 1,5-) | sort | uniq

