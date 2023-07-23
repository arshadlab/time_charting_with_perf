# Time Chart with Linux Perf tool (BashfulProfiler)
Welcome to BashfulProfiler, a versatile bash-based performance analysis tool. It's aim is to provide developers with an easily configurable and comprehensive view of the performance characteristics of their applications, especially focusing on shared libraries (.so files).

## Project Overview
BashfulProfiler leverages the power of dynamic tracepoints to dissect application performance at the function level. It reads from a configurable list of .so files, injects tracepoints, and captures runtime performance data. This captured information is then processed and visualized, providing insights into where your application spends its time, down to the level of individual function calls.



![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/2b6c62ce-8971-4426-889e-e91cd2c1e566)

Gazebo simulation timechart

![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/2d0bfe2e-1fbc-4c7b-9565-4dc296cdd1a8)


Simulation update breakup
![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/a02adab4-17b7-49a7-af90-afa106193a08)


![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/6f2dfc90-86be-4092-96cb-2963c9ee4bdf)


Flamegraph of Gazebo simulation run
![image](https://github.com/arshadlab/time_charting_with_perf/assets/85929438/f590ca90-62e6-4cfc-8f89-0fa84d0a4447)

## Features
`Dynamic Tracepoint Injection`: No need to modify your source code, simply provide the shared libraries and functions of interest, and BashfulProfiler will handle the rest.

`Robust Data Collection`: The tool captures comprehensive data from the tracepoints, such as execution start and stop timestamps, to provide a detailed timeline of function execution.

`Data Processing`: The raw trace data is processed through perf convert and ctf2ctf to convert it into a more readable and analyzable format.

`Interactive Performance Charts`: The processed trace data is then fed into trace2html to create interactive performance time charts. The time chart visualizes how your application's functions interact over time, helping you spot potential bottlenecks or inefficiencies.

`Flamegraph Generation`: In addition to time charts, BashfulProfiler also provides Flamegraph visualizations for a more consolidated view of your program's performance.

## Use Case
To demonstrate the power and versatility of BashfulProfiler, I have included an example case study: a performance analysis of a Gazebo simulation run. This example captures the updates and sub-function calls within the Gazebo simulation over time, demonstrating the detailed insights BashfulProfiler can provide.

## Getting Started
Head over to our documentation section for detailed steps on how to configure and use BashfulProfiler. Don't forget to check out the example case study to get a feel for what the tool can do. If you have any questions, suggestions, or run into any issues, please don't hesitate to raise an issue or submit a pull request.

Happy performance hunting!
