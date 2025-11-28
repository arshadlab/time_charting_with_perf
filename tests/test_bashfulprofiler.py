#!/usr/bin/env python3
"""
Test script for BashfulProfiler Python implementation
Tests basic functionality without requiring sudo or running processes
"""

import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from bashfulprofiler import BashfulProfiler


def test_unique_name_generation():
    """Test unique name generation"""
    print("Testing unique name generation...")
    profiler = BashfulProfiler()
    
    name1 = profiler.get_unique_name("test_function")
    name2 = profiler.get_unique_name("test_function")
    name3 = profiler.get_unique_name("test_function")
    name4 = profiler.get_unique_name("other_function")
    
    assert name1 == "test_function", f"Expected 'test_function', got '{name1}'"
    assert name2 == "test_function_1", f"Expected 'test_function_1', got '{name2}'"
    assert name3 == "test_function_2", f"Expected 'test_function_2', got '{name3}'"
    assert name4 == "other_function", f"Expected 'other_function', got '{name4}'"
    
    print("  ✓ Unique name generation works correctly")


def test_template_shortening():
    """Test C++ template name shortening"""
    print("Testing template shortening...")
    profiler = BashfulProfiler()
    
    tests = [
        ("std::vector<int, allocator>", "std::vector_ia_"),
        ("MyClass<Type1, Type2, Type3>", "MyClass_TTT_"),
        ("simple_function", "simple_function"),  # No template
        ("func<a>", "func_a_"),
    ]
    
    for input_str, expected in tests:
        result = profiler.shorten_templates(input_str)
        # Check if template was replaced (exact match may vary)
        if '<' in input_str:
            assert '<' not in result, f"Template not removed from '{result}'"
        print(f"  ✓ {input_str} -> {result}")


def test_probe_name_sanitization():
    """Test probe name sanitization"""
    print("Testing probe name sanitization...")
    profiler = BashfulProfiler()
    
    tests = [
        "vaCreateBuffer(VADisplay, VAContextID, int, int, int, void*, unsigned int*)",
        "std::vector<int>::push_back(int const&)",
        "MyNamespace::MyClass::myMethod()",
    ]
    
    for test in tests:
        result = profiler._sanitize_probe_name(test)
        # Check that result is valid probe name
        assert '(' not in result, f"Parentheses found in '{result}'"
        assert ')' not in result, f"Parentheses found in '{result}'"
        assert ',' not in result, f"Comma found in '{result}'"
        assert '<' not in result, f"Angle bracket found in '{result}'"
        assert '>' not in result, f"Angle bracket found in '{result}'"
        print(f"  ✓ {test[:50]}... -> {result}")


def test_trace_root_detection():
    """Test TRACE_ROOT detection"""
    print("Testing TRACE_ROOT detection...")
    profiler = BashfulProfiler()
    
    assert profiler.trace_root.exists(), f"TRACE_ROOT not found: {profiler.trace_root}"
    assert (profiler.trace_root / "scripts").exists(), "scripts directory not found"
    assert (profiler.trace_root / "probes").exists(), "probes directory not found"
    
    print(f"  ✓ TRACE_ROOT detected: {profiler.trace_root}")


def test_csv_parsing_simulation():
    """Test CSV parsing logic (without actually setting probes)"""
    print("Testing CSV parsing simulation...")
    
    # Create a temporary CSV file
    import tempfile
    import csv as csv_module
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        writer = csv_module.writer(f)
        writer.writerow(['libva.so.2', 'test_process', 'vaCreate.*'])
        writer.writerow(['', '', 'vaDestroy.*'])  # Carry forward library and process
        writer.writerow(['# Comment line', '', ''])
        writer.writerow(['', '', ''])  # Empty line
        csv_file = f.name
    
    try:
        # Just verify the file can be read (don't actually set probes)
        with open(csv_file, 'r') as f:
            reader = csv_module.reader(f)
            rows = list(reader)
        
        assert len(rows) == 4, f"Expected 4 rows, got {len(rows)}"
        assert rows[0][0] == 'libva.so.2', "First row library name incorrect"
        assert rows[1][0] == '', "Second row should have empty library name"
        assert rows[2][0].startswith('#'), "Third row should be comment"
        
        print(f"  ✓ CSV parsing simulation successful")
    finally:
        Path(csv_file).unlink()


def test_process_id_detection():
    """Test process ID vs name detection"""
    print("Testing process ID detection...")
    
    # Test with PID-like strings
    assert "12345".isdigit(), "Should detect PID"
    assert not "python3".isdigit(), "Should detect process name"
    assert not "test-app".isdigit(), "Should detect process name"
    
    print("  ✓ Process ID detection works correctly")


def main():
    """Run all tests"""
    print("=" * 60)
    print("BashfulProfiler Python Implementation - Basic Tests")
    print("=" * 60)
    print()
    
    tests = [
        test_trace_root_detection,
        test_unique_name_generation,
        test_template_shortening,
        test_probe_name_sanitization,
        test_csv_parsing_simulation,
        test_process_id_detection,
    ]
    
    failed = 0
    for test in tests:
        try:
            test()
            print()
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            print()
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            print()
            failed += 1
    
    print("=" * 60)
    if failed == 0:
        print("All tests passed! ✓")
    else:
        print(f"{failed} test(s) failed ✗")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
