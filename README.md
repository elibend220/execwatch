# execwatch

A minimal eBPF program that traces process execution events at the kernel
level and streams them to userspace via a ring buffer, with a C loader
built on libbpf.

Written to demonstrate kernel level observability using eBPF in isolation,
independent of any larger monitoring system.

## What it does

`execwatch_kern.c` attaches to the `sched_process_exec` tracepoint, which
the kernel fires every time a process successfully calls `execve`. For each
event it captures the PID, UID, command name, and executed filename, and
pushes them into a `BPF_MAP_TYPE_RINGBUF` map.

`loader.c` opens the compiled object, loads it into the kernel, attaches it
to the tracepoint, and polls the ring buffer, printing one line per
execution observed.

## Design notes

* **No CO-RE dependency on `task_struct`.** An earlier version of this
  program read the parent PID via `BPF_CORE_READ` on `task_struct`. That
  requires the running kernel's BTF (`/sys/kernel/btf/vmlinux`) to be
  present at build time to resolve struct layout. Since that is not
  guaranteed in every build or CI environment, this version restricts
  itself to tracepoint supplied fields and stable helper functions
  (`bpf_get_current_pid_tgid`, `bpf_get_current_uid_gid`,
  `bpf_get_current_comm`), trading one field of information for
  portability across kernels without a `vmlinux.h`.
* **Ring buffer over perf buffer.** `BPF_MAP_TYPE_RINGBUF` avoids per-CPU
  buffer management and event loss under bursty process creation, at the
  cost of requiring a kernel of 5.8 or later.
* **Drop rather than block.** If `bpf_ringbuf_reserve` fails because the
  buffer is full, the program drops the event and returns immediately
  rather than blocking the kernel's exec path.

## Building

Requires `clang`, `libbpf-dev`, and kernel headers matching the target
architecture.

```bash
make
```

This produces `execwatch_kern.o` (BPF bytecode) and `loader` (the userspace
binary).

## Running

Requires root privileges (`CAP_BPF` and `CAP_SYS_ADMIN` in older kernels),
a kernel with `tracefs` mounted at `/sys/kernel/tracing`, and BTF exposed
at `/sys/kernel/btf/vmlinux`.

```bash
sudo ./loader execwatch_kern.o
```

Expected output, one line per process executed on the host while it runs:

```
execwatch: tracing process execution, press Ctrl+C to stop
pid=48213    uid=1000   comm=bash             filename=/usr/bin/ls
pid=48214    uid=1000   comm=sh               filename=/bin/cat
```

## Verification performed in this environment

This project was built and verified in a sandboxed container without
`tracefs` mounted and without exposed kernel BTF, which is the normal state
for a container that is not granted host tracing access. The following was
confirmed directly rather than assumed:

* `execwatch_kern.c` compiles cleanly to a valid eBPF ELF object
  (`file` reports `ELF 64-bit LSB relocatable, eBPF`), and its disassembly
  shows the expected ring buffer reserve, helper calls, and submit sequence.
* `loader.c` compiles cleanly against `libbpf` with `-Wall` and no warnings.
* Running the loader against the compiled object succeeds through object
  load and BPF map creation inside the kernel (the kernel verifier accepts
  the program and a ring buffer map is created with a valid file
  descriptor). The subsequent tracepoint attach step fails in this specific
  environment with `No such file or directory` against
  `/sys/kernel/tracing/events/...`, which is the expected error when
  `tracefs` is not mounted, not a defect in the program.

Full end to end output, an actual stream of exec events, requires running
`loader` as root on a Linux host (not a restricted container) with tracefs
mounted, which was not attempted here since this environment does not
provide it. Anyone reviewing this project should reproduce that last step
directly rather than take the claim on faith.

## Scope

This is intentionally a standalone utility with no relation to any other
project.
