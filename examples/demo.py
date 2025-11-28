#!/usr/bin/env python3
"""
Interactive demo of BashfulProfiler Python API

This script demonstrates the key features without requiring sudo or specific processes.
"""

import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from bashfulprofiler import BashfulProfiler


def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")


def demo_initialization():
    """Demo 1: Creating a profiler instance"""
    print_header("Demo 1: Initialize BashfulProfiler")
    
    profiler = BashfulProfiler()
    print(f"✓ Profiler initialized")
    print(f"✓ TRACE_ROOT: {profiler.trace_root}")
    print(f"✓ Log file: {profiler.log_file}")
    
    return profiler


def demo_unique_names(profiler):
    """Demo 2: Unique name generation"""
    print_header("Demo 2: Unique Name Generation")
    
    print("When multiple symbols match, unique names are generated:\n")
    
    names = []
    for i in range(5):
        name = profiler.get_unique_name("CreateBuffer")
        names.append(name)
        print(f"  Call {i+1}: {name}")
    
    print(f"\n✓ Generated {len(names)} unique names from same base")


def demo_template_shortening(profiler):
    """Demo 3: Template name shortening"""
    print_header("Demo 3: C++ Template Shortening")
    
    examples = [
        "std::vector<int, std::allocator<int>>::push_back",
        "MyClass<TypeA, TypeB, TypeC>::method",
        "simple_function",  # No template
        "ov::intel_gpu::Plugin::compile_model<Graph, Context>",
    ]
    
    print("Long C++ template names are shortened for readability:\n")
    for example in examples:
        shortened = profiler.shorten_templates(example)
        print(f"  Before: {example}")
        print(f"  After:  {shortened}")
        print()
    
    print("✓ Template names shortened successfully")


def demo_probe_name_sanitization(profiler):
    """Demo 4: Probe name sanitization"""
    print_header("Demo 4: Probe Name Sanitization")
    
    examples = [
        "vaCreateBuffer(VADisplay, VAContextID, int)",
        "std::vector<int>::push_back(int const&)",
        "MyNamespace::MyClass::myMethod(void)",
    ]
    
    print("C++ symbols are sanitized to valid probe names:\n")
    for example in examples:
        sanitized = profiler._sanitize_probe_name(example)
        print(f"  Symbol: {example}")
        print(f"  Probe:  {sanitized}")
        print()
    
    print("✓ All names sanitized successfully")


def demo_available_commands():
    """Demo 5: Show available commands"""
    print_header("Demo 5: Available Commands")
    
    print("Command-Line Interface:\n")
    commands = [
        ("show-loaded <process>", "Show libraries loaded by a process"),
        ("show-symbols <lib> [--filter]", "Show symbols from a library"),
        ("set-binary <lib> <filter>", "Set probes on matching symbols"),
        ("set-csv <file.csv>", "Set probes from CSV recipe"),
        ("capture [--duration] [--process]", "Capture and convert traces"),
        ("remove <name>", "Remove a probe"),
        ("remove-all", "Remove all probes"),
    ]
    
    for cmd, desc in commands:
        print(f"  {cmd:40} - {desc}")
    
    print("\n✓ All commands available via CLI")
    print("\nTry: ./scripts/bashfulprofiler.py --help")


def demo_programmatic_usage():
    """Demo 6: Show programmatic usage"""
    print_header("Demo 6: Programmatic Usage")
    
    print("Example Python script:\n")
    
    code = '''
from bashfulprofiler import BashfulProfiler

# Create profiler
profiler = BashfulProfiler()

# Find libraries in a process
libs = profiler.probe_show_loaded("my_app", filter_pattern="libva")

# Show symbols
for lib in libs:
    symbols = profiler.probe_show_symbols(lib, filter_pattern="Create")
    print(f"{lib}: {len(symbols)} symbols")

# Set probes from CSV
profiler.probe_set_from_csv("./probes/my_probes.csv")

# Capture traces
profiler.trace_capture_and_convert(duration=10, target_process="my_app")

# Cleanup
profiler.probe_remove_all()
'''
    
    print(code)
    print("✓ Easy to integrate into your Python workflows")


def demo_error_handling():
    """Demo 7: Error handling"""
    print_header("Demo 7: Error Handling")
    
    profiler = BashfulProfiler()
    
    print("Example: Trying to show symbols from non-existent file:\n")
    
    symbols = profiler.probe_show_symbols("/nonexistent/library.so")
    
    if not symbols:
        print("  ✓ Error handled gracefully - returned empty list")
        print("  ✓ Error message shown to user")
    
    print("\nPython version provides better error messages than Bash!")


def demo_csv_compatibility():
    """Demo 8: CSV compatibility"""
    print_header("Demo 8: CSV File Compatibility")
    
    print("CSV format (same for both Bash and Python):\n")
    
    csv_example = '''
# Library/Binary, Process Name, Symbol Filter
/usr/lib/x86_64-linux-gnu/libva.so.2,,va
/usr/lib/dri/iHD_drv_video.so,,CreateBuffer
i915.ko,,\\bi915_gem_do_execbuffer$
'''
    
    print(csv_example)
    
    print("✓ Same CSV files work with both versions")
    print("✓ No migration needed for existing probe recipes")


def main():
    """Run all demos"""
    print("\n" + "█" * 60)
    print("  BashfulProfiler Python API - Interactive Demo")
    print("█" * 60)
    
    # Run demos
    profiler = demo_initialization()
    demo_unique_names(profiler)
    demo_template_shortening(profiler)
    demo_probe_name_sanitization(profiler)
    demo_available_commands()
    demo_programmatic_usage()
    demo_error_handling()
    demo_csv_compatibility()
    
    # Final summary
    print_header("Demo Complete!")
    print("Next steps:")
    print("  1. Check out PYTHON_README.md for full documentation")
    print("  2. See examples/example_usage.py for more examples")
    print("  3. Try: ./scripts/bashfulprofiler.py --help")
    print("  4. Read QUICKSTART.md for common tasks")
    print("\nHappy profiling! 🚀\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user. Goodbye!")
        sys.exit(0)
