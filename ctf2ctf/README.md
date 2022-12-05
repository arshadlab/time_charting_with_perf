# ctf2ctf - convert Common Trace Format to Chrome Trace Format

This little utility takes CTF trace data as recorded by e.g. LTTng
and converts it to the JSON Chrome Trace Format. Not only that,
it also adds some interpretation and extends the raw event data
to make the result much more useful.

To run:

```
./ctf2ctf path/to/lttng-trace | gzip > trace.json.gz
```

Then open chromium and go to [chrome://tracing](chrome://tracing)
and open the `trace.json.gz` file.

## Notable features

- global statistics over time:
  - CPU utilization: how many processes/threads are running in parallel
  - CPU state: which process is run on a given CPU
-- CPU frequency: at what frequency is a given CPU running
  - kernel memory: how much memory is allocated by the kernel
  - per-process memory: how large is the anon mmap region of a process
- per thread timelines with stacked begin/end events
- event metadata mapping:
  - page fault address to file
  - syscall `fd` to file
- filter results by process name or process id
- filter results by time

## Begin/Exit Events

Events names that end with `_entry` are considered to be *Begin Events*
and need to be followed by an *Exit Event* ending with `_exit`. Alternatively,
the names can contain `_begin_` or `_before_` for the *Begin Events* and
`_end_` or `_after` for the *Exit Events*.

For LTTng-ust tracef events, the first space-delimited word is taken as the
event name, if it matches one of the patterns above. For this to work, you'll
need to patch babeltrace with https://github.com/efficios/babeltrace/pull/98.
