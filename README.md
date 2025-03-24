# Bash Scripting Meets Performance Analysis:
## BashfulProfiler for Linux application and Kernel

Introducing BashfulProfiler: a robust, non-intrusive, and highly adaptable performance analysis tool built around Bash. Designed to offer developers flexible and detailed insights into the performance characteristics of their Linux-based applications, BashfulProfiler leverages the power of the Linux perf tool. It works best when the target binaries — executables or shared libraries — are compiled with symbols (e.g., using the -g flag). This implementation has been tested on Ubuntu 22.04 and 24.04, with Python versions 3.10 and 3.12. While the core logic is implemented in Bash, several third-party utilities integrated into the workflow are Python-based.

## Overview
The tool's design is split into two main components: the front end, built entirely using bash scripting, and the backend, which relies on the Linux Kernel Perf tool, ctf2ctf, trace2html and flamegraph. Probes or traces are defined in a configuration file (for instance, probes.csv), which are then parsed and passed to the Perf tool to set up the probes. Once set, a capturing script proceeds to record these probes over a predetermined duration (such as 8 seconds). After the recording phase, the captured data is processed and transformed into easily understandable time charts and flamegraphs, offering clear insights for performance analysis.  The probe setting is done once for that boot session however capture can be done multiple times depending on run configuratins and needs.

Flow Diagram:

![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/71ae12ec-4c0f-4655-aa5d-9f2c97ef1220)



### Features
**Dynamic Tracepoint Injection**: No need to modify  source code, simply provide the shared libraries and functions of interest, and BashfulProfiler will handle the rest.

**Robust Data Collection** The tool captures comprehensive data from the tracepoints, such as execution start and stop timestamps, to provide a detailed timeline of function execution.

**Data Processing** The raw trace data is processed through perf convert and ctf2ctf to convert it into a more readable and analyzable format.

**Interactive Performance Charts** The processed trace data is then passed to trace2html to generate interactive performance time charts. These charts provide a visual representation of how functions within the application execute and interact over time, making it easier to identify potential bottlenecks or performance inefficiencies.

**Flamegraph Generation**: In addition to time charts, BashfulProfiler also generates Flamegraph visualizations, offering a more consolidated and intuitive view of the program’s performance. This helps in quickly identifying hotspots and understanding function call hierarchies at a glance.

### Probe configuration file (probes.csv)
```
#, Header: ".so name", "process name", "symbol filter", "probe name"
#, ROS2 libraries
#, set_probes_csv.sh will look into the given process to find library path from loaded .so files
#, If absolute path is given then process name is ignored.

/opt/ros/humble/lib/librcl.so,,rcl_publish$,rclpublish
librcl.so,gzserver,rcl_take_request$,rcl_take_request
librcl.so,gzserver,rcl_take$,rcl_take_topic_subscription
...
```

The probes.csv is a comma-separated .csv file with four columns and no spaces around commas. The first column is designated for the .so/binary to be probed, and it can contain either just the name or the absolute path. If only the name is provided, the process name - which is the second entry - will be utilized to determine the absolute location of the .so. The process, presumably running with the .so file loaded, should be active prior to setting up probes. However, if an absolute path is provided, there's no requirement for the process name, and probe setup can be conducted at any time.

The third column is designated for the symbol on which the probe is to be set. This symbol can be either fully named or partially named with a wildcard, following the Linux grep regular expression pattern. If multiple entries match, probes will be set up on all of them. The final column is for the probe name, which is usually the same as the symbol.

The process name is required for the first row without path, and all subsequent rows use the same name for finding the .so path. Also if multiple symbols match the regular expression, the probe name is appended with the symbol address to ensure uniqueness and facilitate tracking. Additionally, the complete symbol line output by objdump is displayed in the script, which helps relate the captured probe to the exact symbol signature.

The sample probes.csv for Gazebo performance analysis leverages symbols exported by .so. However, if the binary is compiled with the -g option, more precise probing is possible as a larger set of symbols will be accessible for selection.

Scripts are included in the repo to view loaded libraries and symbols exported by them.

## Sample probes for OpenVino Run:
Here is a sample probe CSV file designed to set trace points at key locations, including the entry points when a model is compiled and then sent for inference. At this stage, primitives are assembled into GPU kernels, and following a flush, the call waits for the GPU to complete execution. Having all this information visually presented at the forefront provides a holistic view of how the framework internally handles requests and the time spent at each stage. The included probes offer a comprehensive picture, though users can add more probes as needed. Note: The probes below require OpenVino to be built from source with the RelWithDebugInfo option.

Sample probe file for OpenVino analysis:
```
#, Header: ".so name","process name","symbol filter","probe name"
#, No space before and after commas
#, Openvino library with debug symbol included
#, set_probes_csv.sh will look into the given process to find library path from loaded .so files
#, If absolute path is given then process name is ignored.
#, Below probes assume openvino plugins are compiled with debug symbols included (e.g -g).

# GPU
libopenvino_intel_gpu_plugin.so,benchmark_app,\bov::intel_gpu::SyncInferRequest::infer\(\)\s*$,gpu_infer_request
libopenvino_intel_gpu_plugin.so,,\bov::intel_gpu::Plugin::compile_model\(.*\),gpu_compile_model
libopenvino_intel_gpu_plugin.so,,ov::intel_gpu::SyncInferRequest::enqueue\(\)\s*$,gpu_infer_enqueue
libopenvino_intel_gpu_plugin.so,,ov::intel_gpu::SyncInferRequest::wait\(\)\s*$,gpu_infer_wait
libopenvino_intel_gpu_plugin.so,,\bcldnn::network::execute_impl\(.*\)$,cldnn_execute_impl
libopenvino_intel_gpu_plugin.so,,\bcldnn::ocl::ocl_stream::flush\(\)\sconst$,cldnn_flush
libopenvino_intel_gpu_plugin.so,,\bcldnn::ocl::typed_primitive_impl_ocl<.*>::execute_impl,cldnn_execute_impl
libopenvino_intel_gpu_plugin.so,,\bcldnn::onednn::typed_primitive_onednn_impl<.*>::build_primitive,onednn_build_primitive
libopenvino_intel_gpu_plugin.so,,\bcldnn::onednn::typed_primitive_onednn_impl<.*>::execute_impl,onednn_execute_impl
libopenvino_auto_batch_plugin.so,,\bov::autobatch_plugin::Plugin::compile_model\(.*\),auto_batch_compile_model

# CPU
libopenvino_intel_cpu_plugin.so,benchmark_app,\bov::intel_cpu::SyncInferRequest::infer\(\)\s*$, cpu_infer_request
libopenvino_intel_cpu_plugin.so,,\bov::intel_cpu::Plugin::compile_model\(.*\), cpu_compile_model

# Kernel mode driver.  i915.ko
i915.ko, ,\bi915_gem_do_execbuffer,i915_gem_do_execbuffer
i915.ko, ,\bii915_gem_wait_ioctl,i915_gem_wait_ioctl
i915.ko, ,\bi915_request_wait_timeout,i915_request_wait_timeout
i915.ko, ,\bflush_submission,flush_submission

```


To further explain regex expressions, the pattern **\bov::intel_gpu::Plugin::compile_model\(.*\)** for the compile_model probe is designed to match lines in text where the compile_model() method of the Plugin class in the ov::intel_gpu namespace is invoked. It captures any arguments it might take (e.g., .*), and ensures it starts at a word boundary (\b) to prevent partial matches. Additionally, the $ character in some probes ensures that matching occurs only for those symbols where there is no extra word or character at the end.


![image](https://github.com/user-attachments/assets/243aef33-3058-4049-9750-e23697ad6185)


## Analyzing Gazebo ROS2:

The default probes included with the tool are specifically chosen to analyze Gazebo simulations that involve ROS 2, including interactions with the Navigation2 and MoveIt2 stacks. These probes help uncover performance characteristics such as:

**Time chart of key events in Gazebo and ROS2:** Visualize the timeline of critical events, helping to understand system's operation and identify potential performance issues.

**Publish/Subscribe events by ROS2 nodes:** Analyze the Pub/Sub event dynamics between ROS2 nodes, enabling a closer look at communication efficiency and latencies within system.

**Path planning latencies by Nav2 and Moveit2 stacks:** Understand and optimize the time taken for path planning, an essential aspect of robotic navigation in ROS2 systems.

**FlameGraph of system hotspots:** Gain a clear visual representation of system's performance hotspots, helping focus optimization efforts effectively.

**Compatible with all ROS2 Distributions:** The tool should work on all ROS2 distributions as long as the exported symbols are the same.

Sample trace.html and flamegraph.svg are provide in the repo.

<img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/2d0bfe2e-1fbc-4c7b-9565-4dc296cdd1a8" width="400" height="300"> <img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/f590ca90-62e6-4cfc-8f89-0fa84d0a4447" width="400" height="300"> 

Simulation update breakup

<img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/a02adab4-17b7-49a7-af90-afa106193a08" width="800" height="300">

<img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/6f2dfc90-86be-4092-96cb-2963c9ee4bdf" width="800" height="100">


<img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/ec6fb5e5-cd6b-470a-ae75-3efaf9ad2716" width="350" height="300"> <img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/da9bdf97-1e1a-44c8-b5d3-002dbe68b6ef" width="250" height="250"> <img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/3b91487e-dd1b-4f0e-882a-bf768d7088d5" width="250" height="170"> 

<img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/2b6c62ce-8971-4426-889e-e91cd2c1e566" width="350" height="270">


BashfulProfiler acts as a seamless conduit between applications and the Linux Perf tool, offering  a user-friendly and efficient way to gain insights into system's performance and take action where necessary.


## Getting Started
### Installation
#### Setup system with linux perf tool enabled

The Linux Perf tool is a powerful utility for profiling and performance monitoring on Linux systems.  Here are brief steps to setup system with perf tool

##### Install perf tool

Due to the necessity of perf, root access (for example, using sudo) is required.

```
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install linux-tools-common linux-tools-generic linux-tools-`uname -r`
```

Verify perf installation
```
perf --version
sudo perf stat ls
```
Remember that the Perf tool requires certain permissions and capabilities, and it may not function correctly without them.  It requires kernel to be build with certain CONFIGs and requires sudo access to run commands.

if above perf command doesn't work then most likely kernel is not build with required configs.  Please refer to existing manuals on how to rebuild kernel.  Make sure below configs are enabled in the .config file.

```
CONFIG_PERF_EVENTS=y
CONFIG_FRAME_POINTER=y
CONFIG_KALLSYMS=y
CONFIG_TRACEPOINTS=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
# user-level dynamic tracing:
CONFIG_UPROBES=y
CONFIG_UPROBE_EVENTS=y
```

It is also important to ensure that perf is built with CTF support enabled. This can be verified by checking if the --to-ctf option appears in the list of supported commands:

```
$ perf data convert --help
  Usage: perf data convert [<options>]

    -f, --force           don't complain, do it
    -i, --input <file>    input file name
    -v, --verbose         be more verbose
        --all             Convert all events
        --to-ctf ...      Convert to CTF format
        --to-json ...     Convert to JSON format
        --tod             Convert time to wall clock time

```

If --to-ctf is not listed, the following packages should be installed before rebuilding the perf tool from the kernel source:

Install kernel build packages
```
sudo apt-get install libncurses-dev flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
```

Install perf specific packages
```
sudo apt-get install libpfm4-dev elfutils libdw-dev systemtap-sdt-dev libunwind-dev libslang2-dev libcap-dev libbabeltrace-ctf-dev libtraceevent-dev libbfd-dev libperl-dev
sudo apt-get install libbabeltrace-ctf-dev libbabeltrace-ctf1 libbabeltrace1 libbabeltrace-dev python3-babeltrace
```

As long as the kernel headers for the target kernel are properly installed, there's no need to rebuild the entire kernel. The perf tool can be built separately by navigating to the <kernel_source>/tools/perf directory and running make, provided that all required development packages are in place.

##### Clone this repo and install dependencies

```
git clone https://github.com/arshadlab/time_charting_with_perf
cd time_charting_with_perf
./setup_dependency.sh
```

##### Setup probes using csv

It's important to initiate Gazebo or the target process before setting up the probes. This is because the probes, as defined in the probe.csv file, rely on running target process in order to determine the absolute locations of the .so files within the system. However, if  probe.csv file contains the full paths to the .so files, running the target process prior to setting up the probes is not necessary.
```
ros2 launch <package> <launch command>
```

Setup probes using set_probes_csv.sh script

```
./scripts/set_probes_csv.sh ./probes/probes.csv
Setting probes on [/opt/ros/humble/lib/librcl.so] at symbol [ rcl_publish$]
Address is 0x0
Added new event:
  probe_librcl:rclpublish_entry (on 0x0000000000021b40 in /opt/ros/humble/lib/librcl.so)

You can now use it in all perf tools, such as:

	perf record -e probe_librcl:rclpublish_entry -aR sleep 1

Added new event:
  probe_librcl:rclpublish__return (on 0x0000000000021b40%return in /opt/ros/humble/lib/librcl.so)

You can now use it in all perf tools, such as:

	perf record -e probe_librcl:rclpublish__return -aR sleep 1

```

##### Setup probes using lib

Probes can also be set directly on .so files. Use the set_probes_lib.sh script with an optional filter to set probes. If no filter is provided, probes will be added to all exported symbols. Initially, publicly available symbols will be searched (e.g., using -T), and if no symbol is found, debug symbols will be searched (e.g., using -t).

```
$ ./scripts/set_probes_lib.sh /usr/lib/x86_64-linux-gnu/intel-opencl/libigdrcl.so
```

Setting up probes is typically a one-time task, unless the system is rebooted or the target binary is modified or updated. New probes are appended to the existing list, and if a probe with the same name is added again, it will be overwritten. Once configured, these probes remain available, allowing multiple capture sessions to be conducted without the need for reconfiguration. This persistence across sessions provides the flexibility to perform repeated analyses efficiently.

##### Start Capturing

Initiating capture using capture.sh.  Make sure target process is running (e.g gazebo).  Default capturing duration is 8 seconds
```
./scripts/capture.sh
```
trace.html and flamegraph.svg will be in output folder and ready to be viewed in browser

```
$ <browser> ./output/trace.html ./output/flamegraph.svg
```


#### Remove Probes
Once established, probes remain created (though inactive) until the system is rebooted or the associated binary is modified. It’s important to note that these probes do not consume any CPU resources unless they are actively used by a perf record session. However, if the probes are no longer needed, it’s a good practice to remove them to keep the environment clean and avoid potential conflicts. The following command can be used to remove all probes:
```
./scripts/remove_all_probes.sh
```

## Troubleshoot
If the number of trace samples becomes too large, loading the generated .html file in a browser may become difficult or unresponsive. In such cases, there are two practical options: either reduce the number of active trace probes or shorten the capture duration to limit the volume of collected data.

Additionally, probe names have a length restriction. If issues arise while setting probes, it may help to shorten the probe names defined in the .csv file to ensure compatibility.
