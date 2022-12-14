# This bash script reads probe requests from probe.csv and sets up entry and exit probe for request function
# Caution: Script deletes all previous probes before proceeding. 
# probe.csv fields: '.so name', 'symbol filter', 'probe name'   (without quotes)
# Sample csv format:
#   libgazebo_ros_init.so, GazeboRosInitPrivate::Publish, ros_init_pubtime
#
# default process name to gzserver (Gazebo)
#    ./set_probes_csv.sh [processname|pid]
#

process_name=gzserver
if ! [ -z "$1" ]; then process_name=$1; fi

pid=$1

# Either pid or process name given at command prompt
if  [ -z "${process_name##*[!0-9]*}" ]; then
        pid=$(pgrep $process_name)
fi


#Delete all previous probes
sudo perf probe -d '*'


while IFS=, read -r library_name symbol_filter probe_name
do
    # Skip empty lines
    if [ -z $library_name ]; then
        continue
    fi
        
    # Skip comments row
    if [ "$library_name" == '#' ]; then
        continue
    fi
    library_path=$library_name

    if ! [[ "$library_name" =~ ^/ ]]; then

            # Find out library path from loaded list
            library_path=$(cat /proc/$pid/maps | grep  $library_name | tr -s ' ' | cut -d ' ' -f 6 | sort | uniq)

            if [ -z $library_path ]; then
                echo "Library not found"
                continue
            fi
    fi

    # NOTE: should change -T to -t for .so compiled with debug symbols on
    addresses=$(objdump -T $library_path | c++filt | grep $symbol_filter | cut -d ' ' -f 1)
    
    if [ -z $addresses ]; then
        echo "Address not found"
        continue
    fi
    
    for address in $addresses
    do
    	address=0x$address
    	echo $address
    	# Set entry probe
    	sudo perf probe -x $library_path -f -a ${probe_name}_entry=$address
    
    	# Set exit/return probe
    	sudo perf probe -x $library_path -f -a ${probe_name}=$address%return
    done
done < probes.csv
