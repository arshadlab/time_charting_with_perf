# BashfulProfiler Python Edition

Python implementation of BashfulProfiler — a performance analysis tool for Linux applications using perf probes.

The Python version is the **recommended choice for C++ binaries**.  It uses `pyelftools` to read ELF symbol tables directly and passes numeric hex addresses to `perf probe`, completely bypassing C++ name-mangling issues that cause the Bash version to fail on complex class/template method names.

## Features

- **Probe Discovery**: Show loaded libraries and symbols (with ELF address)
- **C++-safe probing**: Registers probes by hex address — mangled names never reach perf's argument parser
- **Lambda / clone filtering**: Compiler-generated variants (`.clone`, `.cold`, `.isra`, `.part`, lambdas) are skipped automatically
- **Probe Management**: Set and remove probes on binaries and kernel modules
- **CSV Recipe Support**: Batch probe setup from configuration files
- **Trace Capture**: Record and convert perf data to HTML and FlameGraph
- **Programmatic API**: Use as a Python library in your scripts

## Installation

```bash
# Ensure you've run the main setup
./setup_dependency.sh

# Install pyelftools (required for ELF-based C++ symbol resolution)
pip install pyelftools        # or: pip install -r requirements.txt

# Make the Python script executable
chmod +x ./scripts/bashfulprofiler.py
```

> **Without pyelftools** the tool automatically falls back to `perf probe -F` for symbol discovery (same as the Bash version), which works for C binaries but may fail on complex C++ names.

## Command-Line Usage

### Show Loaded Libraries

```bash
# Show all .so files loaded by a process
./scripts/bashfulprofiler.py show-loaded <process_name_or_pid>

# Filter libraries by pattern
./scripts/bashfulprofiler.py show-loaded gst-launch-1.0 --filter libva

# Example output:
# /usr/lib/x86_64-linux-gnu/libva.so.2.2200.0
# /usr/lib/x86_64-linux-gnu/libva-drm.so.2.2200.0
```

### Show Symbols

```bash
# Show all symbols from a library
./scripts/bashfulprofiler.py show-symbols /usr/lib/x86_64-linux-gnu/libva.so.2

# Filter symbols by pattern (regex matched against the *demangled* name)
./scripts/bashfulprofiler.py show-symbols /usr/lib/x86_64-linux-gnu/libva.so.2 --filter "^va"

# Example output (tab-separated: address, mangled, demangled):
# 0x12a40  vaDisplayIsValid    vaDisplayIsValid
# 0x13c80  _ZN..._vaCreateBuffer    vaCreateBuffer(VADisplay, VAContextID, ...)
```

### Set Probes

```bash
# Set probes on all symbols matching a pattern
sudo ./scripts/bashfulprofiler.py set-binary /usr/lib/x86_64-linux-gnu/libva.so.2 "^va"

# Set probes from CSV recipe file
sudo ./scripts/bashfulprofiler.py set-csv ./probes/intel_media.csv
```

### Capture Traces

```bash
# Capture all processes for 8 seconds (default)
sudo ./scripts/bashfulprofiler.py capture

# Capture for specific duration
sudo ./scripts/bashfulprofiler.py capture --duration 10

# Capture specific process
sudo ./scripts/bashfulprofiler.py capture --duration 10 --process gst-launch-1.0

# Capture by PID
sudo ./scripts/bashfulprofiler.py capture --duration 10 --process 12345
```

### Remove Probes

```bash
# Remove specific probe (removes both entry and return)
sudo ./scripts/bashfulprofiler.py remove vaDisplayIsValid

# Remove all probes
sudo ./scripts/bashfulprofiler.py remove-all

# Remove probes defined in CSV
sudo ./scripts/bashfulprofiler.py remove-csv ./probes/intel_media.csv
```

### Help

```bash
# Show all available commands
./scripts/bashfulprofiler.py --help

# Show help for specific command
./scripts/bashfulprofiler.py capture --help
```

## Python API Usage

Use BashfulProfiler as a library in your Python scripts:

```python
#!/usr/bin/env python3
from bashfulprofiler import BashfulProfiler

# Create profiler instance
profiler = BashfulProfiler()

# Show loaded libraries
libs = profiler.probe_show_loaded("my_process", filter_pattern="libva")
for lib in libs:
    print(lib)

# Show symbols
symbols = profiler.probe_show_symbols("/usr/lib/libva.so.2", filter_pattern="^va")
for mangled, demangled, addr in symbols:
    print(f"{hex(addr)}  {mangled} -> {demangled}")

# Set probes (requires sudo)
profiler.probe_set_from_binary("/usr/lib/libva.so.2", "CreateBuffer")

# Set probes from CSV
profiler.probe_set_from_csv("./probes/intel_media.csv")

# Capture traces
profiler.trace_capture_and_convert(duration=10, target_process="my_process")

# Remove probes
profiler.probe_remove("CreateBuffer")
profiler.probe_remove_all()
```

## API Reference

### Class: BashfulProfiler

#### Methods

**probe_show_loaded(process_name_or_pid: str, filter_pattern: str = "") -> List[str]**
- Show loaded libraries from a running process
- Returns: List of library paths

**probe_show_symbols(lib_path: str, filter_pattern: str = "") -> List[Tuple[str, str, int]]**
- List functions in a binary whose demangled name matches *filter_pattern* (regex)
- Returns: List of `(mangled_name, demangled_name, address)` tuples
- `address` is the ELF `st_value` (hex offset from load base for shared libs); `0` when pyelftools is unavailable

**probe_set_from_binary(lib_path: str, symbol_filter: str)**
- Set entry/exit probes for all symbols matching filter

**probe_set_from_csv(csv_file: str)**
- Set probes based on CSV recipe file

**probe_set_with_duration(lib_path: str, probe_name: str, addr_or_sym: str)**
- Set entry and exit probes for a specific symbol
- `addr_or_sym`: hex address string (e.g. `'0x1a2b3c'`) preferred; mangled name used as fallback

**probe_set_single(lib_path: str, probe_name: str, address: str = "")**
- Set a single probe (without automatic entry/exit pair)

**probe_remove(probe_name: str)**
- Remove entry and exit probes for a function

**probe_remove_all()**
- Remove all active probes

**probe_remove_from_csv(csv_file: str)**
- Remove probes defined in a CSV file

**trace_capture_and_convert(duration: int = 8, target_process: Optional[str] = None)**
- Capture perf traces and convert to HTML and FlameGraph
- duration: Capture duration in seconds (default: 8)
- target_process: Optional process name or PID to filter

**get_unique_name(base: str) -> str**
- Generate unique probe name with index suffix if needed

> `shorten_templates` has been superseded by `_strip_templates` / `_sanitize_probe_name`, which handle arbitrarily nested C++ templates correctly.

## Examples

See `examples/example_usage.py` for comprehensive usage examples:

```bash
python3 examples/example_usage.py
```

## Comparison with Bash Version

### Advantages of Python Version

1. **C++ compatible**: probes registered by numeric ELF address — mangled names never parsed by perf
2. **Lambda/clone filtering**: compiler-generated symbol variants skipped automatically
3. **Better Error Handling**: proper exception handling and error messages
4. **Type Hints**: better IDE support and code documentation
5. **Programmatic API**: easy to integrate into Python workflows
6. **Object-Oriented**: cleaner state management
7. **Testing**: easier to write unit tests

### Compatibility

- Both versions produce identical output
- CSV files are 100% compatible
- Probe names and formats are identical
- Can be used interchangeably in workflows

### Performance

- Python version has similar performance for most operations
- Trace capture is I/O bound, so performance is equivalent
- Symbol parsing might be slightly slower but negligible

## Requirements

- Python 3.8 or higher
- `pyelftools` ≥ 0.31 (`pip install pyelftools`) — required for ELF-based C++ address resolution
- All dependencies from main setup (perf with CTF support, ctf2ctf, trace2html, etc.)
- `sudo` privileges for probe operations

## Troubleshooting

### Import Error

If you get `ImportError: No module named 'bashfulprofiler'`:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "scripts"))
from bashfulprofiler import BashfulProfiler
```

### Permission Errors

Most probe operations require sudo:

```bash
# Run with sudo
sudo python3 ./scripts/bashfulprofiler.py set-csv ./probes/intel_media.csv

# Or use sudo -E to preserve environment
sudo -E python3 ./scripts/bashfulprofiler.py capture
```

### Process Not Found

Ensure the target process is running before setting probes or capturing:

```bash
# Check if process is running
pgrep -a my_process

# Start your application first, then set probes
```

## Contributing

The Python implementation maintains feature parity with the Bash version. When adding features:

1. Update both Bash and Python versions
2. Maintain compatible CSV format
3. Keep probe naming consistent
4. Update documentation in both READMEs

## License

Apache License 2.0 - Same as the main project
