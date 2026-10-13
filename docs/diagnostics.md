# Supported diagnostics

`--metrics` reports completed backend selection, DOS status, execution and I/O
counters. `--debug` adds service and loader messages. These controls are
independent of instruction tracing.

Normal execution has no cumulative limit on serviced DOS/DPMI boundaries or
backend continuations. Bounded diagnostic records do not limit command size.
Unicorn retains its per-emulation instruction guard. To bound elapsed time,
use host process cancellation or an external timeout (for example,
`timeout 60s ./build/debug/daze --backend kvm --mount "$work_dir" TOOL.EXE`).

## File write buffering

Regular output files use a 16 KiB write buffer on both backends. Set the host
environment variable `DAZE_BUFFERED_WRITES=0` to use immediate writes:

```sh
DAZE_BUFFERED_WRITES=0 ./build/debug/daze --backend kvm --mount "$work_dir" TOOL.EXE
```

Reads, seeks, metadata access and close flush pending data. Duplicate and
inherited handles share the buffer; independently opened handles to the same
file disable buffering for that file. Host standard streams and devices remain
unbuffered. Small writes can report success before a disk-full, quota or
file-size error is discovered during a later flush. Flush failures are returned
to the guest; failures during implicit exit cleanup also make the host exit
nonzero. Process cancellation can lose data still in the buffer.

## Unicorn instruction trace

Use an explicitly selected Unicorn backend and an established narrow linear
address range. Both inclusive endpoints are required:

```sh
DAZE_TRACE=1 DAZE_TRACE_BEGIN=0x10140 DAZE_TRACE_END=0x103d0 \
  ./build/debug/daze --backend unicorn --metrics --mount "$work_dir" TOOL.EXE
```

Numbers use C integer notation (decimal, `0x` hexadecimal, or leading-zero
octal). Signs, whitespace, incomplete tokens, overflow, reversed endpoints,
and ranges outside mapped guest memory are rejected before Unicorn execution.
The range may span at most 64 KiB. Trace options without `DAZE_TRACE` are also
rejected on Unicorn.

The trace writes at most 4,096 instruction records to stderr per invocation.
The next matching instruction prints one truncation notice; subsequent trace
output is suppressed while guest execution continues normally. An address
range alone does not bound output from a loop, so the record cap always applies.

Optionally set `DAZE_TRACE_DUMP_ADDRESS` and `DAZE_TRACE_DUMP_SIZE` to observe
one linear memory range at each printed instruction. Size defaults to 16 and
must be 1..64 bytes. The entire range must lie in mapped guest memory. This
stderr observation shares the instruction record budget and writes no file.

## Unicorn failure history

`DAZE_DIAGNOSTIC_HISTORY=1` enables a silent ring of the most recent 24 guest
instructions, with eight bytes per entry, for failure reporting. Instruction
tracing also enables this ring. History does not log selector changes or infer
fixture-specific fatal routines.

Trace/history require a full Unicorn code hook and are intended for diagnosis.
Ordinary execution retains only its required narrow gate hooks. These settings
are read only when Unicorn is selected, including an automatic pre-start
fallback; they do not change backend selection or describe KVM execution.

## Unicorn instruction limit

Set `DAZE_UNICORN_INSTRUCTION_LIMIT=50000000` to allow up to 50 million
instructions per Unicorn emulation run. The default is 20 million. The limit
applies to each emulation run between runtime boundaries, not cumulatively to
the whole DOS program. The value must be a positive decimal integer; an invalid
value is rejected before guest execution. KVM has no equivalent limit.

## KVM failure records

Retained KVM failure records observe raw exits, execution addresses, live
registers/segments/descriptors, table registers, and serviced boundaries.
`DAZE_KVM_FAIL_ENTRY_TRACE=1` enables bounded entry failure context;
`DAZE_KVM_POST_SUCCESSOR_TRACE` prints the owner's retained terminal record.
`DAZE_KVM_RM_CRASH_DUMP` adds live register/segment and bounded instruction
context for an unexpected RM exit. Unavailable state is reported explicitly.
These records do not step, replay, or change guest state.
