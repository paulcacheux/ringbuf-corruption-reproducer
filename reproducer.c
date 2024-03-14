//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u8 payload[8];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("xdp")
int ringbuf_filler(struct pt_regs *ctx) {
	struct event evt = {0};
	bpf_ringbuf_output(&events, &evt, sizeof(struct event), 0);
	return 0;
}
