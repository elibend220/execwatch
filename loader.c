// SPDX-License-Identifier: MIT
//
// loader.c
//
// Userspace counterpart to execwatch_kern.c. Loads the compiled eBPF
// object, attaches it to the sched_process_exec tracepoint, and polls
// the ring buffer, printing one line per process execution observed.
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct exec_event {
	__u32 pid;
	__u32 uid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;
	const struct exec_event *e = data;
	printf("pid=%-8u uid=%-6u comm=%-16s filename=%s\n",
	       e->pid, e->uid, e->comm, e->filename);
	fflush(stdout);
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	(void)level;
	return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
	const char *obj_path = argc > 1 ? argv[1] : "execwatch_kern.o";

	libbpf_set_print(libbpf_print_fn);

	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) {
		fprintf(stderr, "execwatch: failed to open BPF object %s\n", obj_path);
		return 1;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "execwatch: failed to load BPF object into the kernel\n");
		fprintf(stderr, "execwatch: this requires CAP_BPF/CAP_SYS_ADMIN and a kernel\n");
		fprintf(stderr, "execwatch: with BTF exposed at /sys/kernel/btf/vmlinux\n");
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "trace_exec");
	if (!prog) {
		fprintf(stderr, "execwatch: program trace_exec not found in object\n");
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_link *link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "execwatch: failed to attach to tracepoint\n");
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
	if (!map) {
		fprintf(stderr, "execwatch: ring buffer map 'events' not found\n");
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "execwatch: failed to create ring buffer reader\n");
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	printf("execwatch: tracing process execution, press Ctrl+C to stop\n");
	while (!stop) {
		int err = ring_buffer__poll(rb, 200 /* ms */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "execwatch: ring buffer poll error: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
