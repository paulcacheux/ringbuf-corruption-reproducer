//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PAYLOAD_SIZE 64

struct event {
	u8 payload[PAYLOAD_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("xdp")
int ringbuf_filler(struct pt_regs *ctx) {
	u32 size = bpf_get_prandom_u32() % PAYLOAD_SIZE;
	if (size == 0) {
		size = PAYLOAD_SIZE;
	}

	struct event evt = {0};
	bpf_ringbuf_output(&events, &evt, size, 0);
	return 0;
}
