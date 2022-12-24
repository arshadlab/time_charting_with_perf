# Set probes on exported functions by a dynamic library.  probe_name could be an exported function but in case of just a string, address in hex must be provided.
# Syntax: 
#   ./set_probe_lib.sh  <lib_absolute_path> [symbol_filter]
#
#   ./set_probe_lib.sh  /opt/ros/foxy/lib/librcl.so 
#   ./set_probe_lib.sh  /opt/ros/foxy/lib/librcl.so  pub

# Delete existing probes
#sudo sh -c "objdump -j .text -C -T $1 | grep '$2' | tr -s ' ' | cut -d ' ' -f 6 | xargs -i{} perf probe -d {}_entry"
#sudo sh -c "objdump -j .text -C -T $1 | grep '$2' | tr -s ' ' | cut -d ' ' -f 6 | xargs -i{} perf probe -d {}__return"

# Add function entry probe
#sudo sh -c "objdump -j .text -C -T $1 | grep '$2' | tr -s ' ' | cut -d ' ' -f 6 | xargs -i{} perf probe -x $1 -a {}_entry={}"
# Add function exit probe
#sudo sh -c "objdump -j .text -C -T $1 | grep '$2' | tr -s ' ' | cut -d ' ' -f 6 | xargs -i{} perf probe -x $1 -a {}={}%return"

# NOTE: should change -T to -t for .so compiled with debug symbols on
addresses=$(objdump -j .text -C -T $1 | grep $2 | cut -d ' ' -f 1)

if [ -z $addresses ]; then
  echo "Address not found"
  continue
fi

libname=$(basename $1)
libname=${libname%.*}


for address in $addresses
do
    	addr=0x$address
    	echo $address
    	# Set entry probe
    	sudo perf probe -x $1 -f -a  ${libname}_${address}_entry=$addr
    
    	# Set exit/return probe
    	sudo perf probe -x $1 -f -a  ${libname}_${address}=$addr%return
done
