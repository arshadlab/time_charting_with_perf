# Migration Guide: Bash to Python

This guide helps you migrate from the Bash version of BashfulProfiler to the Python version.

## Quick Reference

### Command Equivalents

| Bash Function | Python CLI | Python API |
|--------------|------------|------------|
| `probe_show_loaded process` | `./scripts/bashfulprofiler.py show-loaded process` | `profiler.probe_show_loaded("process")` |
| `probe_show_symbols lib filter` | `./scripts/bashfulprofiler.py show-symbols lib --filter filter` | `profiler.probe_show_symbols("lib", "filter")` |
| `probe_set_from_binary lib filter` | `./scripts/bashfulprofiler.py set-binary lib filter` | `profiler.probe_set_from_binary("lib", "filter")` |
| `probe_set_from_csv file.csv` | `./scripts/bashfulprofiler.py set-csv file.csv` | `profiler.probe_set_from_csv("file.csv")` |
| `probe_remove name` | `./scripts/bashfulprofiler.py remove name` | `profiler.probe_remove("name")` |
| `probe_remove_all` | `./scripts/bashfulprofiler.py remove-all` | `profiler.probe_remove_all()` |
| `trace_capture_and_convert` | `./scripts/bashfulprofiler.py capture` | `profiler.trace_capture_and_convert()` |
| `trace_capture_and_convert 10` | `./scripts/bashfulprofiler.py capture --duration 10` | `profiler.trace_capture_and_convert(10)` |
| `trace_capture_and_convert 10 myapp` | `./scripts/bashfulprofiler.py capture --duration 10 --process myapp` | `profiler.trace_capture_and_convert(10, "myapp")` |

## Migration Examples

### Example 1: Basic Workflow

**Bash:**
```bash
source ./scripts/bashfulprofiler.sh
probe_set_from_csv ./probes/intel_media.csv
trace_capture_and_convert 8
probe_remove_all
```

**Python CLI:**
```bash
sudo ./scripts/bashfulprofiler.py set-csv ./probes/intel_media.csv
sudo ./scripts/bashfulprofiler.py capture --duration 8
sudo ./scripts/bashfulprofiler.py remove-all
```

**Python API:**
```python
from bashfulprofiler import BashfulProfiler

profiler = BashfulProfiler()
profiler.probe_set_from_csv("./probes/intel_media.csv")
profiler.trace_capture_and_convert(duration=8)
profiler.probe_remove_all()
```

### Example 2: Exploring Process Libraries

**Bash:**
```bash
source ./scripts/bashfulprofiler.sh
probe_show_loaded gst-launch-1.0
probe_show_symbols /usr/lib/libva.so.2 "^va"
```

**Python CLI:**
```bash
./scripts/bashfulprofiler.py show-loaded gst-launch-1.0
./scripts/bashfulprofiler.py show-symbols /usr/lib/libva.so.2 --filter "^va"
```

**Python API:**
```python
from bashfulprofiler import BashfulProfiler

profiler = BashfulProfiler()
libs = profiler.probe_show_loaded("gst-launch-1.0")
for lib in libs:
    print(lib)

symbols = profiler.probe_show_symbols("/usr/lib/libva.so.2", "^va")
for mangled, demangled in symbols:
    print(f"{mangled}\t{demangled}")
```

### Example 3: Programmatic Analysis

**Bash Script:**
```bash
#!/bin/bash
source ./scripts/bashfulprofiler.sh

PROCESS="my_app"
LIBS=$(probe_show_loaded "$PROCESS" | grep libva)

for lib in $LIBS; do
    probe_set_from_binary "$lib" "CreateBuffer"
done

trace_capture_and_convert 10 "$PROCESS"
probe_remove_all
```

**Python Script:**
```python
#!/usr/bin/env python3
from bashfulprofiler import BashfulProfiler

profiler = BashfulProfiler()
process = "my_app"

# Find libraries
libs = profiler.probe_show_loaded(process)
va_libs = [lib for lib in libs if 'libva' in lib]

# Set probes
for lib in va_libs:
    profiler.probe_set_from_binary(lib, "CreateBuffer")

# Capture
profiler.trace_capture_and_convert(duration=10, target_process=process)

# Cleanup
profiler.probe_remove_all()
```

## Key Differences

### 1. No Need to Source

**Bash:** Must source the script first
```bash
source ./scripts/bashfulprofiler.sh
probe_show_loaded my_app
```

**Python:** Direct execution
```bash
./scripts/bashfulprofiler.py show-loaded my_app
```

### 2. Error Handling

**Bash:** Returns error codes
```bash
probe_show_loaded nonexistent_process
echo $?  # Check return code
```

**Python:** Raises exceptions
```python
try:
    profiler.probe_show_loaded("nonexistent_process")
except Exception as e:
    print(f"Error: {e}")
```

### 3. Return Values

**Bash:** Prints to stdout, capture with command substitution
```bash
libs=$(probe_show_loaded my_app)
```

**Python API:** Returns Python objects
```python
libs = profiler.probe_show_loaded("my_app")  # Returns list
```

### 4. State Management

**Bash:** Uses global associative array
```bash
declare -Ag NAME_INDEX=()
```

**Python:** Instance variables
```python
profiler = BashfulProfiler()  # Each instance has its own state
profiler.name_index  # Dictionary
```

## Advantages of Python Version

1. **Better Integration**: Easy to integrate with Python data analysis tools
2. **Error Messages**: More descriptive error messages
3. **Type Safety**: Type hints help catch errors early
4. **Testing**: Easier to write unit tests
5. **IDE Support**: Better autocomplete and documentation

## When to Use Each Version

### Use Bash Version When:
- Working in shell scripts
- Quick one-off commands
- Prefer shell scripting
- Need minimal dependencies

### Use Python Version When:
- Building automation tools
- Integrating with Python workflows
- Need programmatic access
- Want better error handling
- Building CI/CD pipelines

## CSV Files

Both versions use **identical CSV format**. You can use the same CSV files with both:

```csv
# This CSV works with both Bash and Python versions
/usr/lib/x86_64-linux-gnu/libva.so.2.2200.0,,va
/usr/lib/x86_64-linux-gnu/dri/iHD_drv_video.so,,CreateBuffer
i915.ko,,\bi915_gem_do_execbuffer$
```

## Output Files

Both versions produce identical output:
- Same probe names
- Same trace.html format
- Same flamegraph.svg format
- Same perf.data files

## Converting Existing Scripts

### Bash Script Template:
```bash
#!/bin/bash
source ./scripts/bashfulprofiler.sh

# Your analysis code here
probe_set_from_csv ./probes/my_probes.csv
trace_capture_and_convert 8
```

### Python Script Template:
```python
#!/usr/bin/env python3
import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent / "scripts"))
from bashfulprofiler import BashfulProfiler

# Your analysis code here
profiler = BashfulProfiler()
profiler.probe_set_from_csv("./probes/my_probes.csv")
profiler.trace_capture_and_convert(8)
```

## Troubleshooting

### "Module not found" Error

Add scripts directory to Python path:
```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "scripts"))
```

### Permission Errors

Both versions need sudo for probe operations:
```bash
# Bash
sudo bash -c 'source ./scripts/bashfulprofiler.sh && probe_set_from_csv file.csv'

# Python
sudo ./scripts/bashfulprofiler.py set-csv file.csv
```

### Different Behavior

If you notice different behavior:
1. Check Python version (requires 3.8+)
2. Verify TRACE_ROOT is detected correctly
3. Ensure all dependencies are installed
4. Report issues with specific examples

## Getting Help

- Bash version: `./scripts/bashfulprofiler.sh` and check function definitions
- Python CLI: `./scripts/bashfulprofiler.py --help`
- Python API: See `PYTHON_README.md` and `examples/example_usage.py`

## Testing Your Migration

Use the provided test script:
```bash
python3 tests/test_bashfulprofiler.py
```

Or compare outputs:
```bash
# Bash
source ./scripts/bashfulprofiler.sh
probe_show_loaded my_app > bash_output.txt

# Python
./scripts/bashfulprofiler.py show-loaded my_app > python_output.txt

# Compare
diff bash_output.txt python_output.txt
```
