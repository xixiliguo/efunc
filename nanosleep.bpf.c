//go:build ignore


#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u64);
	__type(value, u64);
} ret_offset SEC(".maps");

char __license[] SEC("license") = "Dual MIT/GPL";

u64 entry_ip = 0;

SEC("ksyscall/nanosleep")
int funcentry(struct pt_regs *ctx) {
#ifdef bpf_target_x86
	entry_ip = PT_REGS_IP(ctx) - 1;
#else
	entry_ip = PT_REGS_IP(ctx);
#endif
	return 0;
}


SEC("kretsyscall/nanosleep")
int funcret(struct pt_regs *ctx) {
	struct trace_kprobe *tk;
	u64 fp, ip, i;
	/* get frame pointer */
	asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

	for (i = 1; i <= 50; i++) {
		bpf_probe_read_kernel(&tk, sizeof(tk), (void *)(fp + i * sizeof(u64)));
		ip = (u64)BPF_CORE_READ(tk, rp.kp.addr);
		if (entry_ip != 0 && ip ==entry_ip) {
			u64 key = 0;
			u64 value = i;
			bpf_printk("nanosleep entry_ip=%llx idx=%llx", entry_ip, i);
			bpf_map_update_elem(&ret_offset, &key, &value, BPF_ANY);
			return 0;
		}
	}
	return 0;
}