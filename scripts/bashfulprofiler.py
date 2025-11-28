#!/usr/bin/env python3
"""
BashfulProfiler - Python Edition
Performance analysis tool for Linux applications using perf probes.

Uses pyelftools to extract function addresses directly from ELF binaries,
bypassing C++ name-mangling issues entirely.  Entry and return probes are
registered via their numeric ELF address (e.g. 0x1a2b3c), so perf never
needs to resolve a mangled C++ symbol name.

Fallback to 'perf probe -F' (symbol-name based) is used automatically when
pyelftools is not installed.

Copyright 2025
Licensed under the Apache License, Version 2.0

Author: Arshad Mehmood
"""

import os
import re
import csv
import shutil
import subprocess
import sys
import time
import argparse
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from collections import defaultdict

try:
	from elftools.elf.elffile import ELFFile
	from elftools.elf.sections import SymbolTableSection
	HAS_ELFTOOLS = True
except ImportError:
	HAS_ELFTOOLS = False
	print(
		"Warning: pyelftools not installed — falling back to 'perf probe -F'.\n"
		"  Install with:  pip install pyelftools",
		file=sys.stderr,
	)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _batch_demangle(names: List[str]) -> List[str]:
	"""Demangle a list of C++ mangled names in a single c++filt invocation."""
	if not names:
		return []
	try:
		result = subprocess.run(
			['c++filt'],
			input='\n'.join(names),
			capture_output=True,
			text=True,
			check=True,
		)
		# c++filt appends a trailing newline; trim to match input length
		parts = result.stdout.split('\n')
		return parts[:len(names)]
	except Exception:
		return list(names)


class BashfulProfiler:
	"""Main class for managing perf probes and trace capture."""

	def __init__(self):
		script_dir = Path(__file__).resolve().parent
		self.trace_root = script_dir.parent
		self.name_index: Dict[str, int] = defaultdict(int)
		self.log_file = Path("perf_cmd.sh")

	# -----------------------------------------------------------------------
	# Internal helpers
	# -----------------------------------------------------------------------

	def _run_command(self, cmd: List[str], capture_output=True, check=True) -> subprocess.CompletedProcess:
		"""Run a command list."""
		return subprocess.run(cmd, capture_output=capture_output, text=True, check=check)

	def _run_shell(self, cmd: str, capture_output=True, check=False) -> subprocess.CompletedProcess:
		"""Run a shell command string via bash."""
		return subprocess.run(
			cmd, shell=True, capture_output=capture_output,
			text=True, check=check, executable='/bin/bash',
		)

	# -----------------------------------------------------------------------
	# ELF symbol extraction (primary path — requires pyelftools)
	# -----------------------------------------------------------------------

	def _extract_elf_symbols(self, binary_path: str) -> List[Tuple[int, str]]:
		"""
		Extract STT_FUNC symbols from an ELF binary using pyelftools.

		Prefers .symtab (full table) over .dynsym (exported-only) so that
		non-exported C++ methods are also reachable.

		Returns a list of (address, mangled_name) sorted by address.
		For shared libraries the address is the offset from the load base
		(ELF st_value), which perf probe -x accepts directly.
		"""
		symbols: Dict[str, int] = {}  # mangled_name -> st_value

		with open(binary_path, 'rb') as fh:
			elf = ELFFile(fh)
			sec_names = {s.name for s in elf.iter_sections()}
			preferred = ['.symtab', '.dynsym'] if '.symtab' in sec_names else ['.dynsym']

			for sec_name in preferred:
				section = elf.get_section_by_name(sec_name)
				if section is None or not isinstance(section, SymbolTableSection):
					continue
				for sym in section.iter_symbols():
					if (
						sym['st_info']['type'] == 'STT_FUNC'
						and sym['st_value'] != 0
						and sym.name
						and sym.name not in symbols
						and not self._is_compiler_generated(sym.name)
					):
						symbols[sym.name] = sym['st_value']

		return sorted(((addr, name) for name, addr in symbols.items()), key=lambda x: x[0])

	# -----------------------------------------------------------------------
	# Fallback: symbol discovery via 'perf probe -F'
	# -----------------------------------------------------------------------

	def _get_symbols_via_perf(self, binary_path: str) -> List[Tuple[int, str]]:
		"""
		Fallback when pyelftools is unavailable.

		Uses 'perf probe -F' to list exported symbol names.  Address is
		returned as 0 (unknown); callers must use the mangled name instead
		of a hex address when registering probes.
		"""
		probe_filter = '(!__k???tab_* & !__crc_* & !__* & !*@plt)'
		cmd = f'perf probe -x "{binary_path}" -F --no-demangle --filter "{probe_filter}"'
		result = self._run_shell(cmd, capture_output=True, check=False)
		if result.returncode != 0 or not result.stdout.strip():
			return []
		names = sorted({n for n in result.stdout.strip().split('\n') if n})
		return [(0, name) for name in names]

	# -----------------------------------------------------------------------
	# Combined: extract + demangle + filter
	# -----------------------------------------------------------------------

	def _get_symbols_with_demangle(
		self,
		binary_path: str,
		filter_pattern: str = "",
	) -> List[Tuple[int, str, str]]:
		"""
		Return (address, mangled, demangled) triples from *binary_path*.

		*filter_pattern* is a regex applied to the **demangled** name so
		C++ class/method patterns like 'RenderNode::render_loop' work
		correctly even when the binary stores mangled names.

		When pyelftools is available the address is the ELF st_value.
		When falling back to perf probe -F the address is 0.
		"""
		if HAS_ELFTOOLS:
			raw = self._extract_elf_symbols(binary_path)
		else:
			raw = self._get_symbols_via_perf(binary_path)

		if not raw:
			return []

		mangled_list = [m for _, m in raw]
		demangled_list = _batch_demangle(mangled_list)

		result = []
		for (addr, mangled), demangled in zip(raw, demangled_list):
			if '{lambda' in demangled or '<lambda' in demangled:
				continue
			if filter_pattern and not re.search(filter_pattern, demangled):
				continue
			result.append((addr, mangled, demangled))

		return result

	# -----------------------------------------------------------------------
	# Probe-name helpers
	# -----------------------------------------------------------------------

	# GCC/Clang append these suffixes to generate specialised or split copies
	# of a function.  perf probes on them are almost never useful and they
	# clutter the output significantly.
	_COMPILER_GENERATED = re.compile(
		r'(\.clone\.|\.cold(\.\d+)?$|\.isra\.|\.part\.|\.constprop\.'
		r'|\$_\d+|__cxx_global_var_init)'
	)

	def _is_compiler_generated(self, mangled_name: str) -> bool:
		"""Return True for clone, cold, isra, part, constprop and similar variants."""
		return bool(self._COMPILER_GENERATED.search(mangled_name))

	def _strip_templates(self, name: str) -> str:
		"""Remove C++ template parameters, handling arbitrary nesting depth."""
		result = []
		depth = 0
		for ch in name:
			if ch == '<':
				depth += 1
			elif ch == '>':
				depth -= 1
			elif depth == 0:
				result.append(ch)
		return ''.join(result)
	
	# -----------------------------------------------------------------------
	# Public API – symbol inspection
	# -----------------------------------------------------------------------

	def probe_show_loaded(self, process_name_or_pid: str, filter_pattern: str = "") -> List[str]:
		"""Return sorted list of .so paths loaded by a process."""
		if process_name_or_pid.isdigit():
			pid = process_name_or_pid
		else:
			try:
				result = self._run_command(['pgrep', '-o', process_name_or_pid])
				pid = result.stdout.strip()
			except subprocess.CalledProcessError:
				pid = ""
			if not pid:
				print(f"Error: No process found with name '{process_name_or_pid}'", file=sys.stderr)
				return []

		maps_file = Path(f"/proc/{pid}/maps")
		if not maps_file.exists():
			print(f"Error: Cannot access {maps_file}", file=sys.stderr)
			return []

		libraries: set = set()
		try:
			with open(maps_file, 'r') as f:
				for line in f:
					if '.so' in line:
						parts = line.split()
						if len(parts) >= 6:
							lib_path = parts[5]
							if not filter_pattern or re.search(filter_pattern, lib_path):
								libraries.add(lib_path)
		except OSError as exc:
			print(f"Error reading maps file: {exc}", file=sys.stderr)
			return []

		return sorted(libraries)

	def probe_show_symbols(
		self,
		lib_path: str,
		filter_pattern: str = "",
	) -> List[Tuple[str, str, int]]:
		"""
		List functions in *lib_path* that match *filter_pattern*.

		Returns a list of (mangled_name, demangled_name, address) tuples.
		Address is the ELF st_value (0 when pyelftools is unavailable).
		"""
		if not lib_path:
			print("Usage: probe_show_symbols <lib_absolute_path> [regex_filter]", file=sys.stderr)
			return []

		entries = self._get_symbols_with_demangle(lib_path, filter_pattern)
		if not entries:
			print("No matching symbols found.", file=sys.stderr)
			return []

		return [(m, d, a) for a, m, d in entries]

	def get_unique_name(self, base: str) -> str:
		"""Return *base* on first call; *base_N* (N>=1) on subsequent calls."""
		if base not in self.name_index:
			self.name_index[base] = 0
			return base
		self.name_index[base] += 1
		return f"{base}_{self.name_index[base]}"

	def _sanitize_probe_name(self, demangled: str) -> str:
		"""
		Convert a demangled C++ symbol to a valid perf probe identifier.

		Strategy:
		  1. Keep only the part before the first '(' (drop argument list).
		  2. Strip template parameters (handles nesting via depth counter).
		  3. Replace '::' with '_'.
		  4. Replace any remaining non-identifier character with '_'.
		  5. Collapse consecutive underscores; strip leading/trailing ones.
		"""
		name = demangled.split('(')[0].strip()
		name = self._strip_templates(name)
		name = name.replace('::', '_')
		name = re.sub(r'[^A-Za-z0-9_]', '_', name)
		name = re.sub(r'_+', '_', name).strip('_')
		return name
	
	def probe_set_with_duration(self, lib_path: str, function_name: str, address: str):
		"""
		Set entry and exit probes for a function
		
		Args:
			lib_path: Path to library or kernel module
			function_name: Name for the probe
			address: Symbol address or name
		"""
		# Clean function name
		function_name = function_name.rstrip('_')
		function_name = function_name.lstrip('_')
		
		if not address:
			address = function_name
		
		# Determine target type
		target = f"-x {lib_path}"
		if lib_path.endswith('.ko'):
			target = f"-m {lib_path}"
		
		# Set ENTRY probe
		entry_name = f"{function_name}_entry"
		self._run_shell(f"sudo perf probe -q -d {entry_name}", check=False)
		
		cmd1 = f"sudo perf probe {target} --no-demangle -a {entry_name}='{address}'"
		print(cmd1, file=sys.stderr)
		
		# Log command
		with open(self.log_file, 'a') as f:
			f.write(f"{cmd1}\n")
		
		self._run_shell(cmd1)
		
		# Set RETURN probe
		return_name = f"{function_name}__return"
		self._run_shell(f"sudo perf probe -q -d {return_name}", check=False)
		
		cmd2 = f"sudo perf probe {target} --no-demangle -a {function_name}='{address}%return'"
		print(cmd2, file=sys.stderr)
		
		# Log command
		with open(self.log_file, 'a') as f:
			f.write(f"{cmd2}\n\n")
		
		self._run_shell(cmd2)
	
	def probe_set_single(self, lib_path: str, probe_name: str, address: str = ""):
		"""Register a single (entry-only) probe."""
		if not address:
			address = probe_name

		self._run_shell(f"sudo perf probe -q -d {probe_name}", check=False)

		target = f"-x {lib_path}"
		if lib_path.endswith('.ko'):
			target = f"-m {lib_path}"

		cmd = f"sudo perf probe {target} --no-demangle -a {probe_name}={address}"
		print(cmd, file=sys.stderr)
		self._run_shell(cmd)

	def probe_set_from_binary(self, lib_path: str, symbol_filter: str):
		"""
		Register entry+return probes for every function in *lib_path* whose
		demangled name matches *symbol_filter* (regex).

		When pyelftools is available, the ELF address is used for the probe
		specifier (hex string), making the operation fully C++ compatible.
		When falling back to perf probe -F, the mangled symbol name is used.
		"""
		entries = self._get_symbols_with_demangle(lib_path, symbol_filter)
		if not entries:
			print("Error: No matching symbols found.", file=sys.stderr)
			return

		total = len(entries)
		for idx, (addr, mangled, demangled) in enumerate(entries, 1):
			raw_name = self._sanitize_probe_name(demangled)
			probe_name = self.get_unique_name(raw_name)

			# Prefer hex address (C++-safe); fall back to mangled name
			addr_or_sym = hex(addr) if addr != 0 else mangled

			print(
				f"({idx}/{total}) {probe_name}  [{demangled}]  addr={addr_or_sym}",
				file=sys.stderr,
			)
			self.probe_set_with_duration(lib_path, probe_name, addr_or_sym)

	def probe_remove(self, probe_name: str):
		"""Remove the entry and return probes for *probe_name*."""
		self._run_shell(f"sudo perf probe -q -d {probe_name}_entry", check=False)
		self._run_shell(f"sudo perf probe -q -d {probe_name}__return", check=False)

	def probe_remove_all(self):
		"""Remove every active perf probe."""
		self._run_shell("sudo perf probe -d '*'", check=False)

	def register_sdt(self, executable: str):
		"""
		Register an executable's SDT (Statically Defined Tracing) markers with
		perf's build-id cache so they appear in `perf list` and can be recorded.

		Equivalent to:
		    sudo perf buildid-cache --add <executable>

		This only needs to be done once per build of the binary.  After
		registration, SDT probes defined inside the binary (e.g. via
		LLTNG_UST_TRACEPOINT or custom SDT markers) are automatically visible
		under their namespace (e.g. sdt_videowall:*) without any additional
		probe-set step.
		"""
		exe_path = Path(executable).resolve()
		if not exe_path.exists():
			print(f"Error: executable not found: {exe_path}", file=sys.stderr)
			return

		cmd = f"sudo perf buildid-cache --add {exe_path}"
		print(cmd, file=sys.stderr)
		result = self._run_shell(cmd, check=False)
		if result.returncode == 0:
			print(f"Registered SDT markers from: {exe_path}", file=sys.stderr)
			print("Run 'sudo perf list sdt_*:*' to see available events.", file=sys.stderr)
		else:
			print(f"Error registering SDT markers: {result.stderr.strip()}", file=sys.stderr)
	
	def probe_set_from_csv(self, csv_file: str):
		"""
		Set probes as described in a CSV recipe file.

		CSV columns: library_path, process_name, symbol_filter
		  - library_path: absolute path, partial .so name, or .ko filename.
		  - process_name: needed only when library_path is a partial name.
		  - symbol_filter: regex matched against the *demangled* function name.

		Empty fields carry the previous non-empty value forward.
		"""
		csv_path = Path(csv_file)
		if not csv_path.exists():
			print(f"Error: CSV file not found: {csv_file}", file=sys.stderr)
			return

		with open(self.log_file, 'w') as lf:
			lf.write(f"\n# Adding probes from {csv_file}\n\n")

		previous_library_name = ""
		previous_process_name = ""

		with open(csv_path, 'r') as f:
			total_lines = sum(1 for _ in f)

		with open(csv_path, 'r') as f:
			reader = csv.reader(f)
			for current_line, row in enumerate(reader, 1):
				if not row:
					continue

				library_name = row[0].strip() if len(row) > 0 else ""
				process_name = row[1].strip() if len(row) > 1 else ""
				symbol_filter = row[2].strip() if len(row) > 2 else ""

				if library_name.startswith('#'):
					continue
				if not library_name and not process_name and not symbol_filter:
					continue

				# Carry-forward for library name
				if not library_name and previous_library_name:
					library_name = previous_library_name
				else:
					previous_library_name = library_name

				library_path = library_name

				if library_name.endswith('.ko'):
					result = self._run_shell(f"modinfo -n {library_name}", check=False)
					if result.returncode == 0 and result.stdout.strip():
						library_path = result.stdout.strip()

				elif not library_name.startswith('/'):
					if not process_name and previous_process_name:
						process_name = previous_process_name
					else:
						previous_process_name = process_name

					result = self._run_command(['pgrep', '-o', process_name], check=False)
					if result.returncode != 0 or not result.stdout.strip():
						print(f"Process '{process_name}' not running — skipping.", file=sys.stderr)
						continue

					pid = result.stdout.strip()
					maps_file = Path(f"/proc/{pid}/maps")
					library_path = ""
					if maps_file.exists():
						with open(maps_file, 'r') as mf:
							for line in mf:
								if library_name in line:
									parts = line.split()
									if len(parts) >= 6:
										library_path = parts[5]
										break

					if not library_path:
						print(
							f"Library '{library_name}' not found in maps for '{process_name}' — skipping.",
							file=sys.stderr,
						)
						continue

				print(
					f"({current_line}/{total_lines}) Processing: "
					f"{library_name},{process_name},{symbol_filter}",
					file=sys.stderr,
				)
				self.probe_set_from_binary(library_path, symbol_filter)
	
	def probe_remove_from_csv(self, csv_file: str):
		"""Remove probes listed in a CSV file (reads the symbol_filter column)."""
		csv_path = Path(csv_file)
		if not csv_path.exists():
			print(f"Error: CSV file not found: {csv_file}", file=sys.stderr)
			return

		with open(csv_path, 'r') as f:
			total_lines = sum(1 for _ in f)

		with open(csv_path, 'r') as f:
			reader = csv.reader(f)
			for current_line, row in enumerate(reader, 1):
				if not row or len(row) < 3:
					continue
				symbol_filter = row[2].strip()
				if symbol_filter and not symbol_filter.startswith('#'):
					print(f"({current_line}/{total_lines}) Removing: {symbol_filter}", file=sys.stderr)
					self.probe_remove(symbol_filter)
	
	def _resolve_events(self, patterns: List[str]) -> List[str]:
		"""
		Filter *patterns* to those that have at least one live perf event.

		Uses `sudo perf list PATTERN` to check each pattern against the kernel's
		current event catalogue.  Patterns with no matches are dropped so that
		`perf record` never receives an empty -e and prints "event parser found
		nothing".

		Note: `perf probe`-created events may appear under arbitrary namespaces
		(e.g. `sdt_videowall:*`, `probe:*`) depending on whether the target
		binary has ELF SDT markers.  Using `perf list` is therefore the only
		reliable way to check which patterns are actually live.
		"""
		active = []
		for pattern in patterns:
			result = self._run_shell(
				f"sudo perf list '{pattern}' 2>/dev/null",
				check=False,
			)
			# perf list prints matching events as "  name  [category]"
			# Any line containing '[' means at least one event was found.
			if re.search(r'\[', result.stdout):
				active.append(pattern)
			else:
				print(f"Note: no events match '{pattern}' — skipping", file=sys.stderr)
		return active

	def trace_capture_and_convert(
		self,
		duration: int = 8,
		target_process: Optional[str] = None,
		events: Optional[List[str]] = None,
	):
		"""
		Capture perf instrumentation + system traces and convert them to
		trace.html (Catapult) and flamegraph.svg (FlameGraph).

		*events* is a list of perf event patterns for the instrumentation trace
		(passed as separate -e flags).  Defaults to ["probe*:*"], which captures
		all events created by `perf probe`.  Add extra patterns to also capture
		SDT events or other namespaces, e.g.:
		    events=["probe*:*", "sdt_*:*"]
		"""
		thirdparty = self.trace_root / "3rdparty"
		if not thirdparty.exists():
			print("Error: TRACE_ROOT not set correctly.", file=sys.stderr)
			return

		ctf2ctf_bin = thirdparty / "ctf2ctf" / "build" / "ctf2ctf"
		if not ctf2ctf_bin.exists():
			print("Building ctf2ctf...", file=sys.stderr)
			ctf2ctf_build = thirdparty / "ctf2ctf" / "build"
			ctf2ctf_build.mkdir(parents=True, exist_ok=True)
			self._run_command(['cmake', '-B', str(ctf2ctf_build), '-S', str(thirdparty / "ctf2ctf")])
			self._run_command(['make', f'-j{os.cpu_count()}', '-C', str(ctf2ctf_build)])

		flamegraph_dir = thirdparty / "FlameGraph"
		if not flamegraph_dir.exists():
			print("Cloning FlameGraph...", file=sys.stderr)
			self._run_command(['git', '-C', str(thirdparty), 'clone',
							   'https://github.com/brendangregg/FlameGraph'])

		# Resolve target PID
		p_cmd = ""
		ctf_cmd = ""
		if target_process:
			target_pid: Optional[str] = None
			if target_process.isdigit():
				target_pid = target_process
			else:
				result = self._run_command(['pgrep', '-o', target_process], check=False)
				if result.returncode == 0 and result.stdout.strip():
					target_pid = result.stdout.strip()
				else:
					print(f"Warning: Process '{target_process}' not found.", file=sys.stderr)

			if target_pid:
				p_cmd = f"-p {target_pid}"
				ctf_cmd = f"--pid-whitelist={target_pid}"

		print(f"Capturing for {duration} seconds", file=sys.stderr)

		if events is None:
			events = ["probe*:*", "sdt_*:*"]

		# Drop patterns that currently have no matching events so perf record
		# never receives an empty -e and exits with "event parser found nothing".
		events = self._resolve_events(events)

		if not events:
			print(
				"Warning: no instrumentation events available (no probes set and no "
				"SDT providers found). Skipping instrumentation trace.",
				file=sys.stderr,
			)
			# Run system trace only
			events_flags = ""
		else:
			events_flags = " ".join(f"-e {e}" for e in events)
			print(f"Events: {' '.join(events)}", file=sys.stderr)

		output_dir = Path.cwd() / "output"
		output_dir.mkdir(exist_ok=True)

		for item in output_dir.iterdir():
			if item.is_file():
				item.unlink()
			elif item.is_dir():
				shutil.rmtree(item)
		print(f"Output directory: {p_cmd}")
		# Instrumentation trace (probes) — background; skipped when no events are available
		instrace_proc = None
		if events_flags:
			instrace_cmd = (
				f"sudo bash -c \"perf record {p_cmd} --running-time --timestamp-boundary "
				f"-B --namespaces -m 2048 -r50 {events_flags} "
				f"-o {output_dir}/instrace.data -aR sleep {duration}\""
			)
			instrace_proc = subprocess.Popen(instrace_cmd, shell=True)

		# System trace (call graph) — blocking
		systrace_cmd = (
			f"sudo bash -c \"perf record {p_cmd} -B --namespaces -m 2048 -F 1000 -r50 "
			f"-o {output_dir}/systrace.data -g -aR sleep {duration}\""
		)
		subprocess.run(systrace_cmd, shell=True)
		if instrace_proc:
			instrace_proc.wait()

		while True:
			result = self._run_command(['pgrep', '-x', 'perf'], check=False)
			if result.returncode != 0:
				break
			time.sleep(1)

		username = os.getenv('USER', 'root')
		self._run_shell(f"sudo chown {username} {output_dir}/*.data", check=False)

		print("Converting to CTF format...", file=sys.stderr)
		self._run_command(['perf', 'data', '-i', f'{output_dir}/systrace.data',
						   'convert', '--to-ctf', f'{output_dir}/systrace_data'])
		self._run_command(['perf', 'data', '-i', f'{output_dir}/instrace.data',
						   'convert', '--to-ctf', f'{output_dir}/instrace_data'])

		print("Converting to JSON...", file=sys.stderr)
		for name in ('systrace', 'instrace'):
			with open(f'{output_dir}/{name}.json', 'w') as out_fh:
				subprocess.run(
					f"{ctf2ctf_bin} {output_dir}/{name}_data/ {ctf_cmd}",
					shell=True, stdout=out_fh,
				)

		print("Generating trace HTML...", file=sys.stderr)
		trace2html = thirdparty / "catapult" / "tracing" / "bin" / "trace2html"
		self._run_command([
			str(trace2html),
			f'{output_dir}/systrace.json',
			f'{output_dir}/instrace.json',
			'--output', f'{output_dir}/trace.html',
			'--config', 'full',
		])

		print("Generating flamegraph...", file=sys.stderr)
		stackcollapse = flamegraph_dir / "stackcollapse-perf.pl"
		flamegraph_pl = flamegraph_dir / "flamegraph.pl"
		if stackcollapse.exists() and flamegraph_pl.exists():
			perf_script = self._run_command(
				['perf', 'script', '-i', f'{output_dir}/systrace.data']
			)
			collapse = subprocess.run(
				[str(stackcollapse)],
				input=perf_script.stdout,
				capture_output=True, text=True,
			)
			folded_path = f'{output_dir}/flamegraph.perf-folded'
			with open(folded_path, 'w') as fh:
				fh.write(collapse.stdout)
			with open(f'{output_dir}/flamegraph.svg', 'w') as fh:
				subprocess.run([str(flamegraph_pl), folded_path], stdout=fh)

		print(f"\nCapture done. Open:", file=sys.stderr)
		print(f"  {output_dir}/trace.html", file=sys.stderr)
		print(f"  {output_dir}/flamegraph.svg", file=sys.stderr)


def main():
	"""Command-line interface for BashfulProfiler"""
	parser = argparse.ArgumentParser(
		description='BashfulProfiler - Performance analysis tool using perf probes',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""
Examples:
  # Show loaded libraries from a process
  %(prog)s show-loaded gst-launch-1.0
  
  # Show symbols from a library
  %(prog)s show-symbols /usr/lib/libva.so.2 "^va"
  
  # Set probes from a binary
  %(prog)s set-binary /usr/lib/libva.so.2 "^va"
  
  # Set probes from CSV
  %(prog)s set-csv ./probes/intel_media.csv
  
  # Capture traces
  %(prog)s capture --duration 10 --process gst-launch-1.0
  
  # Remove all probes
  %(prog)s remove-all
		"""
	)
	
	subparsers = parser.add_subparsers(dest='command', help='Command to execute')

	p_loaded = subparsers.add_parser('show-loaded', help='Show loaded .so libraries from a process')
	p_loaded.add_argument('process', help='Process name or PID')
	p_loaded.add_argument('--filter', default='', help='Regex filter on library path')

	p_symbols = subparsers.add_parser('show-symbols', help='List functions in a binary')
	p_symbols.add_argument('library', help='Path to shared library or kernel module')
	p_symbols.add_argument('--filter', default='', help='Regex filter on demangled function name')

	p_set_bin = subparsers.add_parser('set-binary', help='Register probes for matching functions in a binary')
	p_set_bin.add_argument('library', help='Path to shared library or kernel module')
	p_set_bin.add_argument('filter', help='Regex filter on demangled function name')

	p_set_csv = subparsers.add_parser('set-csv', help='Register probes from a CSV recipe file')
	p_set_csv.add_argument('csv_file', help='Path to CSV file')

	p_remove = subparsers.add_parser('remove', help='Remove entry+return probes for a probe name')
	p_remove.add_argument('probe_name', help='Base probe name (without _entry / __return suffix)')

	subparsers.add_parser('remove-all', help='Remove all active perf probes')

	p_remove_csv = subparsers.add_parser('remove-csv', help='Remove probes listed in a CSV file')
	p_remove_csv.add_argument('csv_file', help='Path to CSV file')

	p_register_sdt = subparsers.add_parser(
		'register-sdt',
		help='Register SDT markers from an executable into perf build-id cache',
	)
	p_register_sdt.add_argument(
		'executable',
		help='Path to the executable whose SDT markers should be registered',
	)

	p_capture = subparsers.add_parser('capture', help='Capture perf traces and convert to HTML + SVG')
	p_capture.add_argument('--duration', type=int, default=8, help='Capture duration in seconds (default: 8)')
	p_capture.add_argument('--process', default=None, help='Process name or PID to filter')
	p_capture.add_argument(
		'--events', metavar='PATTERN', action='append', default=None,
		help=(
			'Perf event pattern for instrumentation trace (can be repeated). '
			'Default: probe*:*  sdt_*:*  '
			'Example: --events probe*:* --events "sdt_videowall:*"'
		),
	)

	args = parser.parse_args()

	if not args.command:
		parser.print_help()
		return

	profiler = BashfulProfiler()

	try:
		if args.command == 'show-loaded':
			for lib in profiler.probe_show_loaded(args.process, args.filter):
				print(lib)

		elif args.command == 'show-symbols':
			for mangled, demangled, addr in profiler.probe_show_symbols(args.library, args.filter):
				addr_str = hex(addr) if addr else 'n/a'
				print(f"{addr_str}\t{mangled}\t{demangled}")

		elif args.command == 'set-binary':
			profiler.probe_set_from_binary(args.library, args.filter)

		elif args.command == 'set-csv':
			profiler.probe_set_from_csv(args.csv_file)

		elif args.command == 'remove':
			profiler.probe_remove(args.probe_name)

		elif args.command == 'remove-all':
			profiler.probe_remove_all()

		elif args.command == 'remove-csv':
			profiler.probe_remove_from_csv(args.csv_file)

		elif args.command == 'register-sdt':
			profiler.register_sdt(args.executable)

		elif args.command == 'capture':
			profiler.trace_capture_and_convert(args.duration, args.process, args.events)

	except KeyboardInterrupt:
		print("\nInterrupted by user", file=sys.stderr)
		sys.exit(1)
	except Exception as e:
		print(f"Error: {e}", file=sys.stderr)
		sys.exit(1)


if __name__ == '__main__':
	main()
