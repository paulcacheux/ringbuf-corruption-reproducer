//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PAYLOAD_SIZE (512 - 2 * 8)

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
	struct event evt = {0};
	u32 value = bpf_get_prandom_u32();
	__builtin_memset(&evt, value, PAYLOAD_SIZE);

	bpf_ringbuf_output(&events, &evt, PAYLOAD_SIZE, 0);
	return 0;
}
