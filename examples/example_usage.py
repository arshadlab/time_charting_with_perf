#!/usr/bin/env python3
"""
Example usage of BashfulProfiler Python API

This demonstrates how to use BashfulProfiler as a Python library
rather than from the command line.
"""

import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from bashfulprofiler import BashfulProfiler


def example_show_loaded_libraries():
    """Example: Show loaded libraries from a process"""
    print("=== Example: Show Loaded Libraries ===")
    profiler = BashfulProfiler()
    
    # Show all .so files loaded by a process
    libs = profiler.probe_show_loaded("gst-launch-1.0")
    print(f"Found {len(libs)} libraries")
    for lib in libs[:5]:  # Show first 5
        print(f"  {lib}")
    print()


def example_show_symbols():
    """Example: Show symbols from a library"""
    print("=== Example: Show Symbols ===")
    profiler = BashfulProfiler()
    
    # Show symbols matching a pattern
    symbols = profiler.probe_show_symbols("/usr/lib/x86_64-linux-gnu/libva.so.2", "^va")
    print(f"Found {len(symbols)} symbols matching '^va'")
    for mangled, demangled in symbols[:5]:  # Show first 5
        print(f"  {mangled} -> {demangled}")
    print()


def example_set_probes_from_binary():
    """Example: Set probes on a binary"""
    print("=== Example: Set Probes from Binary ===")
    profiler = BashfulProfiler()
    
    # Set probes for symbols matching pattern
    # Note: This requires sudo privileges
    # profiler.probe_set_from_binary("/usr/lib/x86_64-linux-gnu/libva.so.2", "vaDisplay")
    print("Uncomment the line above to actually set probes (requires sudo)")
    print()


def example_set_probes_from_csv():
    """Example: Set probes from CSV file"""
    print("=== Example: Set Probes from CSV ===")
    profiler = BashfulProfiler()
    
    # Set probes based on CSV recipe
    # profiler.probe_set_from_csv("./probes/intel_media.csv")
    print("Uncomment the line above to set probes from CSV (requires sudo)")
    print()


def example_capture_traces():
    """Example: Capture traces"""
    print("=== Example: Capture Traces ===")
    profiler = BashfulProfiler()
    
    # Capture traces for 5 seconds, all processes
    # profiler.trace_capture_and_convert(duration=5)
    
    # Or capture specific process
    # profiler.trace_capture_and_convert(duration=5, target_process="gst-launch-1.0")
    print("Uncomment the lines above to capture traces (requires sudo)")
    print()


def example_programmatic_workflow():
    """Example: Complete programmatic workflow"""
    print("=== Example: Complete Workflow ===")
    profiler = BashfulProfiler()
    
    # 1. Find process and show its libraries
    process_name = "my_app"
    print(f"1. Looking for libraries in process: {process_name}")
    # libs = profiler.probe_show_loaded(process_name, "libva")
    
    # 2. Show symbols from a specific library
    print("2. Showing symbols from library")
    # symbols = profiler.probe_show_symbols(libs[0], "CreateBuffer")
    
    # 3. Set probes
    print("3. Setting probes")
    # profiler.probe_set_from_binary(libs[0], "CreateBuffer")
    
    # 4. Capture traces
    print("4. Capturing traces")
    # profiler.trace_capture_and_convert(duration=10, target_process=process_name)
    
    # 5. Cleanup
    print("5. Removing probes")
    # profiler.probe_remove_all()
    
    print("Uncomment the lines above for actual execution (requires sudo)")
    print()


def example_custom_probe_management():
    """Example: Manual probe management"""
    print("=== Example: Custom Probe Management ===")
    profiler = BashfulProfiler()
    
    # Get unique probe names for duplicate symbols
    name1 = profiler.get_unique_name("CreateBuffer")
    name2 = profiler.get_unique_name("CreateBuffer")
    name3 = profiler.get_unique_name("CreateBuffer")
    print(f"Unique names: {name1}, {name2}, {name3}")
    
    # Shorten template names
    long_name = "std::vector<int, std::allocator<int>>::push_back"
    short_name = profiler.shorten_templates(long_name)
    print(f"Shortened: {long_name} -> {short_name}")
    print()


if __name__ == "__main__":
    print("BashfulProfiler Python API Examples\n")
    print("Note: Most examples are commented out to avoid requiring sudo.")
    print("Uncomment the function calls to try them.\n")
    
    # Examples that don't require sudo or running processes
    example_custom_probe_management()
    
    # Examples that require running processes (commented by default)
    # example_show_loaded_libraries()
    # example_show_symbols()
    
    # Examples that require sudo (commented by default)
    # example_set_probes_from_binary()
    # example_set_probes_from_csv()
    # example_capture_traces()
    # example_programmatic_workflow()
    
    print("See example_usage.py for more examples")
