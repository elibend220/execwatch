// SPDX-License-Identifier: MIT
//
// execwatch_kern.c
//
// A minimal eBPF program that attaches to the sched_process_exec tracepoint
// and emits one event per process execution: PID, parent PID, UID, and the
// executed binary's filename, via a BPF ring buffer.
//
// This program demonstrates kernel level observability using eBPF, entirely
// independent of any larger monitoring system: a single tracepoint, a single
// ring buffer, no external state, no userspace policy logic.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Deliberately does not read task_struct fields (e.g. parent PID) via CO-RE.
// Doing so requires the running kernel's BTF (/sys/kernel/btf/vmlinux) to be
// present at build time to resolve struct layout, which is not guaranteed
// in every build environment. Restricting this program to tracepoint
// provided fields and stable helper functions keeps it portable across
// kernels without a vmlinux.h dependency.
struct exec_event {
	__u32 pid;
	__u32 uid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

// Ring buffer used to stream events to userspace without the overhead of
// perf buffer's per-CPU polling, and without dropping events under bursty
// process creation load, up to the buffer's configured size.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracepoint format for sched:sched_process_exec. Field names and offsets
// are fixed by the kernel's tracepoint ABI, not by this program.
struct trace_event_raw_sched_process_exec {
	__u64 unused;
	__u32 __data_loc_filename;
	__u32 pid;
	__u32 old_pid;
};

SEC("tp/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct exec_event *evt;

	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0; // Buffer full: drop the event rather than block the kernel.

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	evt->pid = pid_tgid >> 32;
	evt->uid = (__u32)uid_gid;

	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	// __data_loc_filename encodes a 16 bit offset (low half) into the
	// tracepoint's data blob where the filename string lives.
	unsigned short offset = ctx->__data_loc_filename & 0xffff;
	const char *filename = (const char *)ctx + offset;
	bpf_probe_read_str(&evt->filename, sizeof(evt->filename), filename);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
