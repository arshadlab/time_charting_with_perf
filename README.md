# Bash Scripting Meets Performance Analysis:
## BashfulProfiler for Linux application and Kernel

Introducing BashfulProfiler: a robust, non-intrusive, and highly adaptable performance analysis tool built around Bash. Designed to offer developers flexible and detailed insights into the performance characteristics of their Linux-based applications, BashfulProfiler leverages the power of the Linux perf tool. It works best when the target binaries — executables or shared libraries — are compiled with symbols (e.g., using the -g flag). This implementation has been tested on Ubuntu 22.04 and 24.04, with Python versions 3.10 and 3.12. While the core logic is implemented in Bash, several third-party utilities integrated into the workflow are Python-based.

## Overview
The tool's design is split into two main components: the front end, built entirely using bash scripting, and the backend, which relies on the Linux Kernel Perf tool, ctf2ctf, trace2html and flamegraph. Probes or traces are defined in a configuration file (for instance, probes.csv), which are then parsed and passed to the Perf tool to set up the probes. Once set, a capturing script proceeds to record these probes over a predetermined duration (such as 8 seconds). After the recording phase, the captured data is processed and transformed into easily understandable time charts and flamegraphs, offering clear insights for performance analysis.  The probe setting is done once for that boot session however capture can be done multiple times depending on run configuratins and needs.

Flow Diagram:

![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/71ae12ec-4c0f-4655-aa5d-9f2c97ef1220)


### Usage
- Use the provided script to build the Linux perf tool with CTF support. The script downloads the Linux kernel source for the running kernel’s major version and compiles only the perf tool. The tool also requires certain kernel CONFIG options to be enabled, which are typically enabled in stock kernels.

- Identify binaries and their exported functions or symbols to set probes on. Any .so file or kernel module with publicly exported methods can be traced. However, using binaries built with debug symbols (-g option, but still optimized for release) provides richer probe points. It is recommended to generate binaries with debug symbols included and not stripped. Regular expression is supported (e.g grep) as symbol filter.

- set TRACE_ROOT to this repo local path and source bashfulprofiler.sh for bash function availability.

- Create a .csv recipe to define probes across multiple .so files and kernel modules. Alternatively, users can set ad hoc probe points by directly calling the script's functions. See probes directory for examples.
  
- Start the workload in a separate console.
  
- Run trace_capture_and_convert to capture traces while the workload is running.
  
- Open the generated trace.html and flamegraph in a browser to analyze the results.

- Once set, probes remain available throughout the boot session or until the binary is rebuilt.

### Features
**Dynamic Tracepoint Injection**: No need to modify  source code, simply provide the shared libraries and functions of interest, and BashfulProfiler will handle the rest.

**Robust Data Collection** The tool captures comprehensive data from the tracepoints, such as execution start and stop timestamps, to provide a detailed timeline of function execution.

**Data Processing** The raw trace data is processed through perf convert and ctf2ctf to convert it into a more readable and analyzable format.

**Interactive Performance Charts** The processed trace data is then passed to trace2html to generate interactive performance time charts. These charts provide a visual representation of how functions within the application execute and interact over time, making it easier to identify potential bottlenecks or performance inefficiencies.

**Flamegraph Generation**: In addition to time charts, BashfulProfiler also generates Flamegraph visualizations, offering a more consolidated and intuitive view of the program’s performance. This helps in quickly identifying hotspots and understanding function call hierarchies at a glance.

Users can set up probes either by directly calling the probe-setting Bash functions or by using a .csv file as a recipe for a quick and consistent setup across different binaries and kernel modules. This approach allows teams to share recipes, ensuring uniform output and faster results.


## Getting Started
### Installation

#### Clone this repo and install dependencies
First of all, git clone repo to local folder.

```
git clone https://github.com/arshadlab/time_charting_with_perf
cd time_charting_with_perf
./setup_dependency.sh
export TRACE_ROOT=$PWD
source ./scripts/bashfulprofiler.sh
```

#### Setup system with linux perf tool enabled

The Linux Perf tool is a powerful utility for profiling and performance monitoring on Linux systems.  Here are brief steps to setup system with perf tool

##### Install perf tool

Due to the necessity of perf, root access (for example, using sudo) is required. Perf also need to be compiled with ctf conversion support which the default build doesn't comes with. 
A helper script is provided in the scripts folder to download the kernel source for the current major version and compile only the perf tool. This script also installs all necessary dependencies.
For more control, users can choose to execute the commands manually.

```
$ ./build_perf_with_ctf.sh
```

Keep in mind that the perf tool requires root permissions (e.g sudo) and capabilities to function properly. It also depends on certain kernel CONFIG options being enabled. In most cases, the stock kernel includes the necessary configurations by default.

If perf command doesn't work as expected then most likely kernel is not build with required configs.  Please refer to existing manuals on how to rebuild kernel.  Make sure below configs are enabled in the .config file.

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

The given script builds perf with ctf support.  This can be verified by checking if the --to-ctf option appears in the list of supported commands:

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

If --to-ctf is not listed, the require packages listed in perf install script should be installed before rebuilding the perf tool from the kernel source.

As long as the kernel headers for the target kernel are properly installed, there's no need to rebuild the entire kernel. The perf tool can be built separately by navigating to the <kernel_source>/tools/perf directory and running make, provided that all required development packages are in place.

```
<kernel src>/tools/perf $ make
```

Once the perf binary is built, it can either be copied to /usr/bin/ for system-wide access, or the current directory can be added to the PATH environment variable for convenient use.

#### Setup probes using csv

It's important to initiate workload or the target process before setting up the probes. This is because the probes, as defined in the probe.csv file, rely on running target process in order to determine the absolute locations of the .so files within the system. However, if  probe.csv file contains the full paths to the .so files, running the target process prior to setting up the probes is not necessary.
```
gst-launch-1.0 filesrc location=<h265file path> ! h265parse ! vah265dec  ! queue ! gvafpscounter starting-frame=2000 ! fakesink async=false
```

The helper functions are provided in bashfulprofiler.sh, so make sure to source it before proceeding if you haven't already.

```
source ./scripts/bashfulprofiler.sh
```

Setup probes using probe_set_csv bash function

```
$ probe_set_csv ./probes/intel_media.csv
Setting probe for: vaDisplayIsValid at 0x00000000000043e0
perf command:
	 sudo perf probe -x /usr/lib/x86_64-linux-gnu/libva.so.2.2200.0 -a vaDisplayIsValid_entry=0x00000000000043e0
Added new event:
  probe_libva:vaDisplayIsValid_entry (on 0x00000000000043e0 in /usr/lib/x86_64-linux-gnu/libva.so.2.2200.0)

You can now use it in all perf tools, such as:

	perf record -e probe_libva:vaDisplayIsValid_entry -aR sleep 1

perf command:
	 sudo perf probe -x /usr/lib/x86_64-linux-gnu/libva.so.2.2200.0 -a vaDisplayIsValid=0x00000000000043e0%return
Added new event:
  probe_libva:vaDisplayIsValid__return (on 0x00000000000043e0%return in /usr/lib/x86_64-linux-gnu/libva.so.2.2200.0)


You can now use it in all perf tools, such as:

	perf record -e probe_librcl:rclpublish__return -aR sleep 1

```

#### Setup probes using lib

Probes can also be set directly on .so files. Use the probe_set_all_from_binary script function with an optional filter to set probes. If no filter is provided, probes will be added to all exported symbols. Both, publicly available symbols (e.g., using -T) as well as debug symbols will be searched (e.g., using -t).

This will place entry/exit probes on all function symbols in iHD_drv_video.so that contain 'Execute(' in their names.  Note the escape '\' for special characters.

```
$ probe_set_all_from_binary /usr/lib/x86_64-linux-gnu/dri/iHD_drv_video.so 'Execute\('
```

Setting up probes is typically a one-time task, unless the system is rebooted or the target binary is modified or updated. New probes are appended to the existing list, and if a probe with the same name is added again, it will be overwritten. Once configured, these probes remain available, allowing multiple capture sessions to be conducted without the need for reconfiguration. This persistence across sessions provides the flexibility to perform repeated analyses efficiently.

#### Start Capturing

Initiating capture using capture.sh.  Make sure target process is running (e.g gst-launch).  Default capturing duration is 8 seconds
```
$ trace_capture_and_convert [capture duration in seconds]
```
trace.html and flamegraph.svg will be in output folder and ready to be viewed in browser

```
$ <browser> ./output/trace.html ./output/flamegraph.svg
```


#### Remove Probes
Once established, probes remain created (though inactive) until the system is rebooted or the associated binary is modified. It’s important to note that these probes do not consume any CPU resources unless they are actively used by a perf record session. However, if the probes are no longer needed, it’s a good practice to remove them to keep the environment clean and avoid potential conflicts. The following command can be used to remove all probes:
```
$ probe_remove_all
```

### Sample probes for Intel Media driver (intel_media.csv)
A sample recipe file, intel_media.csv, is included in this repo as a starting point for Intel Media Driver profiling. It sets up probes on all libva functions that start with va, adds probes to the media driver for symbols containing CreateBuffer, and finally, includes probes for selected functions in the i915 module.

```
#,probe_set_csv will look into the given process to find library path from loaded .so files
#,If absolute path is given then process name is ignored.

#,Header: ".so name","process name","symbol filter"
# Add probes to libva's publically exported symbols.
/usr/lib/x86_64-linux-gnu/libva.so.2.2200.0,,va

# Add probes to media driver's symbols containing CreateBuffer keyword.  Requires media driver to be build with -g else will not hit any
/usr/lib/x86_64-linux-gnu/dri/iHD_drv_video.so,,CreateBuffer

# Add probe to i915 execbuffer call.  Xe probes can be added accordingly.
i915.ko,,\bi915_gem_do_execbuffer$
i915.ko,,\bi915_gem_wait_ioctl$
i915.ko,,\bi915_request_wait$
i915.ko,,\bi915_request_wait_timeout$
i915.ko,,\bflush_submission$
...
```

Setting probes based on recipe can be done using probe_set_csv function call.

```
$ probe_set_csv ./scripts/intel_media.csv
```

The probes.csv is a comma-separated .csv file with four columns and no spaces around commas. The first column is designated for the .so/binary to be probed, and it can contain either just the name or the absolute path. If only the name is provided, the process name - which is the second entry - will be utilized to determine the absolute location of the .so. The process, presumably running with the .so file loaded, should be active prior to setting up probes. However, if an absolute path is provided, there's no requirement for the process name, and probe setup can be conducted at any time.

The third column is designated for the symbol on which the probe is to be set. This symbol can be either fully named or partially named with a wildcard, following the Linux grep regular expression pattern. If multiple entries match, probes will be set up on all of them.

The process name is required for the first row without path, and all subsequent rows use the same name for finding the .so path. Also if multiple symbols match the regular expression, the probe name is appended with the symbol address to ensure uniqueness and facilitate tracking. Additionally, the complete symbol line output by objdump is displayed in the script, which helps relate the captured probe to the exact symbol signature.

The sample intel_media.csv for Intel media performance analysis leverages symbols exported by .so. However, if the binary is compiled with the -g option, more precise probing is possible as a larger set of symbols will be accessible for selection.

Scripts are included in the repo to view loaded libraries and symbols exported by them.

![image](https://github.com/user-attachments/assets/10cc7e95-8de7-46bb-a049-43cc7d698667)


## Sample probes for OpenVino Run:
Here is a sample probe CSV file designed to set trace points at key locations, including the entry points when a model is compiled and then sent for inference. At this stage, primitives are assembled into GPU kernels, and following a flush, the call waits for the GPU to complete execution. Having all this information visually presented at the forefront provides a holistic view of how the framework internally handles requests and the time spent at each stage. The included probes offer a comprehensive picture, though users can add more probes as needed. Note: The probes below require OpenVino to be built from source with the RelWithDebugInfo option.

Sample probe file for OpenVino analysis:
```
#, Header: ".so name","process name","symbol filter"
#, No space before and after commas
#, Openvino library with debug symbol included
#, probe_set_csv will look into the given process to find library path from loaded .so files
#, If absolute path is given then process name is ignored.
#, Below probes assume openvino plugins are compiled with debug symbols included (e.g -g).

# GPU
libopenvino_intel_gpu_plugin.so,benchmark_app,\bov::intel_gpu::SyncInferRequest::infer\(\)\s*$
libopenvino_intel_gpu_plugin.so,,\bov::intel_gpu::Plugin::compile_model\(.*\)
libopenvino_intel_gpu_plugin.so,,ov::intel_gpu::SyncInferRequest::enqueue\(\)\s*$
libopenvino_intel_gpu_plugin.so,,ov::intel_gpu::SyncInferRequest::wait\(\)\s*$
libopenvino_intel_gpu_plugin.so,,\bcldnn::network::execute_impl\(.*\)$
libopenvino_intel_gpu_plugin.so,,\bcldnn::ocl::ocl_stream::flush\(\)\sconst$
libopenvino_intel_gpu_plugin.so,,\bcldnn::ocl::typed_primitive_impl_ocl<.*>::execute_impl
libopenvino_intel_gpu_plugin.so,,\bcldnn::onednn::typed_primitive_onednn_impl<.*>::build_primitive
libopenvino_intel_gpu_plugin.so,,\bcldnn::onednn::typed_primitive_onednn_impl<.*>::execute_impl
libopenvino_auto_batch_plugin.so,,\bov::autobatch_plugin::Plugin::compile_model\(.*\)

# CPU
libopenvino_intel_cpu_plugin.so,benchmark_app,\bov::intel_cpu::SyncInferRequest::infer\(\)\s*$
libopenvino_intel_cpu_plugin.so,,\bov::intel_cpu::Plugin::compile_model\(.*\)

# Kernel mode driver.  i915.ko
i915.ko, ,\bi915_gem_do_execbuffer
i915.ko, ,\bii915_gem_wait_ioctl
i915.ko, ,\bi915_request_wait_timeout
i915.ko, ,\bflush_submission

```


Setting up probes is typically a one-time task, unless the system is rebooted or the target binary is modified or updated. New probes are appended to the existing list, and if a probe with the same name is added again, it will be overwritten. Once configured, these probes remain available, allowing multiple capture sessions to be conducted without the need for reconfiguration. This persistence across sessions provides the flexibility to perform repeated analyses efficiently.

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

## Troubleshoot
If the number of trace samples becomes too large, loading the generated .html file in a browser may become difficult or unresponsive. In such cases, there are two practical options: 
Either
- Reduce the number of trace probes by adjusting symbol filter criteria.
- Shorten the capture duration to limit the volume of collected data.
- Remove probe with highest count to reduce capture size in subsequent run.

Use below command to count by probe name in captured trace.
```
$ perf script -i ./output/instrace.data |  sed 's/^[ \t]*//;s/[ \t]*$//' | tr -s ' '  | awk -F'[ ]' '{print $5}' | awk -F'[:]' '{print$2}' | sort | uniq -c | sort -nr
  42868 vaDisplayIsValid__return
  42868 vaDisplayIsValid_entry
  10845 vaDestroyBuffer__return
  10845 vaDestroyBuffer_entry
  10845 vaCreateBuffer__return
  10845 vaCreateBuffer_entry
  10845 DdiMediaDecode_CreateBuffer__return
  10845 DdiMediaDecode_CreateBuffer_entry
  10845 DdiMedia_CreateBuffer__return
  10845 DdiMedia_CreateBuffer_entry
  10845 DdiDecode_CreateBuffer__return
  10845 DdiDecode_CreateBuffer_entry
   8223 i915_gem_wait_ioctl__return
   8223 i915_gem_wait_ioctl_entry
```
Once unncessarry probes are identified then either remove them from .csv by adjusting symbol filter criteria or use probe_remove call to remove entry and return probes.
```
$ probe_remove vaDisplayIsValid
```

Probe names have a length restriction. If issues arise while setting probes, it may help to shorten the probe names defined in the .csv file to ensure compatibility.

