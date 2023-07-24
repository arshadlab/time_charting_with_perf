# Time Chart with Linux Perf tool (BashfulProfiler)
Introducing BashfulProfiler: a powerful, non-intrusive, and highly adaptable bash-based performance analysis tool. Its core objective is to offer developers an easily customizable and comprehensive perspective on the performance traits of their Linux-based applications.

The default probes bundled with the tool are specifically curated for the analysis of Gazebo simulations that involve ROS2, including interactions with Navigation2 and Moveit2 stacks. Here is what can be gleaned from the provided set of probes:

**Time chart of key events in Gazebo and ROS2:** Visualize the timeline of critical events, helping to understand system's operation and identify potential performance issues.

**Publish/Subscribe events by ROS2 nodes:** Analyze the Pub/Sub event dynamics between ROS2 nodes, enabling a closer look at communication efficiency and latencies within system.

**Path planning latencies by Nav2 and Moveit2 stacks:** Understand and optimize the time taken for path planning, an essential aspect of robotic navigation in ROS2 systems.

**FlameGraph of system hotspots:** Gain a clear visual representation of system's performance hotspots, helping focus optimization efforts effectively.

Sample trace.html and flamegraph.svg are provide in the repo.

<img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/2d0bfe2e-1fbc-4c7b-9565-4dc296cdd1a8" width="500" height="350"> <img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/f590ca90-62e6-4cfc-8f89-0fa84d0a4447" width="500" height="350"> 


Simulation update breakup
![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/a02adab4-17b7-49a7-af90-afa106193a08)



![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/6f2dfc90-86be-4092-96cb-2963c9ee4bdf)  

<img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/ec6fb5e5-cd6b-470a-ae75-3efaf9ad2716" width="350" height="300"> <img src="https://github.com/arshadlab/time_charting_with_perf/assets/85929438/2b6c62ce-8971-4426-889e-e91cd2c1e566" width="350" height="250">




In essence, BashfulProfiler acts as a seamless conduit between applications and the Linux Perf tool, offering  a user-friendly and efficient way to gain insights into system's performance and take action where necessary.
## Project Overview
The tool's design is split into two main components: the front end, built entirely using bash scripting, and the backend, which relies on the Linux Kernel Perf tool, ctf2ctf, trace2html and flamegraph. Probes or traces are defined in a configuration file (for instance, probes.csv), which are then parsed and passed to the Perf tool to set up the probes. Once set, a capturing script proceeds to record these probes over a predetermined duration (such as 8 seconds). After the recording phase, the captured data is processed and transformed into easily understandable time charts and flamegraphs, offering clear insights for performance analysis.

BashfulProfiler leverages the power of dynamic tracepoints to dissect application performance at the function level. It reads from a configurable list of .so files, injects tracepoints, and captures runtime performance data. This captured information is then processed and visualized, providing insights into where your application spends its time, down to the level of individual function calls.

Flow Diagram:

![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/71ae12ec-4c0f-4655-aa5d-9f2c97ef1220)



## Features
**Dynamic Tracepoint Injection**: No need to modify your source code, simply provide the shared libraries and functions of interest, and BashfulProfiler will handle the rest.

**Robust Data Collection** The tool captures comprehensive data from the tracepoints, such as execution start and stop timestamps, to provide a detailed timeline of function execution.

**Data Processing** The raw trace data is processed through perf convert and ctf2ctf to convert it into a more readable and analyzable format.

**Interactive Performance Charts** The processed trace data is then fed into trace2html to create interactive performance time charts. The time chart visualizes how your application's functions interact over time, helping you spot potential bottlenecks or inefficiencies.

**Flamegraph Generation**: In addition to time charts, BashfulProfiler also provides Flamegraph visualizations for a more consolidated view of your program's performance.

## Use Case
To demonstrate the power and versatility of BashfulProfiler, I have included an example case study: a performance analysis of a Gazebo simulation run. This example captures the updates and sub-function calls within the Gazebo simulation over time, demonstrating the detailed insights BashfulProfiler can provide.

## Getting Started
Head over to our documentation section for detailed steps on how to configure and use BashfulProfiler. Don't forget to check out the example case study to get a feel for what the tool can do. If you have any questions, suggestions, or run into any issues, please don't hesitate to raise an issue or submit a pull request.

Happy performance hunting!
