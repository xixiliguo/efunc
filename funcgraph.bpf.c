//go:build ignore


#include "include/vmlinux.h"
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";


volatile const bool verbose = false;
volatile const bool has_bpf_get_func_ip = false;
volatile const u64 kret_offset = 0;


#define COMM_LEN 16
#define PARA_LEN 5
#define MAX_STACK_DEPTH 32
#define MAX_KSTACK_DEPTH 128
#define MAX_FUNC_NAME_LEN 40
#define MAX_TRACE_FIELD_LEN 20


#define MAX_TRACES 5
#define MAX_TRACE_DATA 1024
#define MAX_TRACE_BUF	(MAX_TRACES * MAX_TRACE_DATA)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[COMM_LEN]);
	__type(value, bool);
	__uint(max_entries, 99); /* could be overriden from user-space */
} comms_filter SEC(".maps");
volatile const u32 comm_allow_cnt = 0;
volatile const u32 comm_deny_cnt = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, bool);
	__uint(max_entries, 99); /* could be overriden from user-space */
} pids_filter SEC(".maps");

volatile const u32 pid_allow_cnt = 0;
volatile const u32 pid_deny_cnt = 0;


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u64);
	__type(value, bool);
} ready SEC(".maps");

#define CMP_NOP		0
#define CMP_EQ		1
#define CMP_NOTEQ	2
#define CMP_GT		3
#define CMP_GE		4
#define CMP_LT		5
#define CMP_LE		6

struct trace_data {
	bool base_addr;
	u8 para;
	u64	base;       
	u64	index;       
	u64	scale;   
	u64	imm;               
	bool is_str;
	u8 field_cnt;
	u32 offsets[MAX_TRACE_FIELD_LEN];
	u16 size;
	bool is_sign;
	u8 cmp_operator;
	u64 target;
	s64 s_target;
	u32  bitOff;
	u32 bitSize;
};


struct func {
	u32 id;
	bool is_main_entry;
	u8 name[MAX_FUNC_NAME_LEN];
	u8 trace_cnt;
	struct trace_data trace[MAX_TRACES];
	u8 ret_trace_cnt;
	struct trace_data ret_trace[MAX_TRACES];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 9999);
	__type(key, u64);
	__type(value, struct func);
} func_info SEC(".maps");


#define CALL_EVENT 0
#define START_EVENT 1
#define ENTRY_EVENT 2
#define RET_EVENT 3

#define CALL_EVENT_SUCCESS 0
#define CALL_EVENT_DROP 1
#define START_EVENT_SUCCESS 2
#define START_EVENT_DROP 3
#define ENTRY_EVENT_SUCCESS 4
#define ENTRY_EVENT_DROP 5
#define RET_EVENT_SUCCESS 6
#define RET_EVENT_DROP 7



struct start_event {
	u8 type;
	u64 task;
};


struct func_entry_event {
	u8 type;
	u64 task;
	u32 cpu_id;
	u64 depth;
	u64 seq_id;
	u64 ip;
	u32 id;
	u64 time;
	u64 para[PARA_LEN];
	bool have_data;
	u8 buf[0];
};

struct func_ret_event {
	u8 type;
	u64 task;
	u32 cpu_id;
	u64 depth;
	u64 seq_id;
	u64 ip;
	u32 id;
	u64 time;
	u64 duration;
	u64 ret;
	bool have_data;
	u8 buf[0];
};

struct call_event {
	u8 type;
	u64 task;
	u32 pid;
	u32 tid;
	u8 group_comm[COMM_LEN];
	u8 comm[COMM_LEN];
	u64 ips[MAX_STACK_DEPTH];
	u64 durations[MAX_STACK_DEPTH];
	u64 kstack[MAX_KSTACK_DEPTH];
	u64 kstack_sz;
	u64 start_time;
	u64 end_time;
	u64 depth;
	u64 next_seq_id;
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, u64);
	__type(value, u64);
} event_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 9999);
	__type(key, u64);
	__type(value, struct call_event);
} call_events SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static const struct call_event empty_call_event;

const struct trace_data *trace_unused __attribute__((unused));
const struct start_event *start_unused __attribute__((unused));
const struct func_entry_event *entry_unused __attribute__((unused));
const struct func_ret_event *ret_unused __attribute__((unused));

static __always_inline u64 get_kprobe_func_ip(struct pt_regs *ctx)
{
	u64 ip = 0;
	if (has_bpf_get_func_ip) {
		ip = bpf_get_func_ip(ctx);
	} else {
#ifdef bpf_target_x86
		ip = PT_REGS_IP(ctx) - 1;
#else
		ip = PT_REGS_IP(ctx);
#endif
	}
	return ip;
}

static __always_inline u64 get_kret_func_ip(struct pt_regs  *ctx)
{
	if (!has_bpf_get_func_ip) {
		struct trace_kprobe *tk;
		u64 fp, ip;

		/* get frame pointer */
		asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

		bpf_probe_read_kernel(&tk, sizeof(tk), (void *)(fp + kret_offset * sizeof(__u64)));
		ip = (__u64)BPF_CORE_READ(tk, rp.kp.addr);
		return ip;
	}

	return bpf_get_func_ip(ctx);
}

static __always_inline bool is_ready() {
	u64 key = 0;
	bool *re = bpf_map_lookup_elem(&ready, &key);
	if (re) {
		return *re;
	}
	return false;
}


static __always_inline bool pid_allowed(void)
{
	bool *verdict_ptr;
	u32 pid;

	/* if no PID filters -- allow everything */
	if (pid_allow_cnt + pid_deny_cnt == 0)
		return true;

	pid = bpf_get_current_pid_tgid() >> 32;

	verdict_ptr = bpf_map_lookup_elem(&pids_filter, &pid);
	if (!verdict_ptr) {
		/* if allowlist is non-empty, then PID didn't pass the check */
		return pid_allow_cnt == 0;
	}
	return *verdict_ptr;
}

static __always_inline bool comm_allowed(void)
{
	char comm[COMM_LEN] = {};
	__builtin_memset(&comm, 0, sizeof(comm));

	bool *verdict_ptr;

	/* if no COMM filters -- allow everything */
	if (comm_allow_cnt + comm_deny_cnt == 0)
		return true;

	bpf_get_current_comm(comm, COMM_LEN);

	verdict_ptr = bpf_map_lookup_elem(&comms_filter, comm);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then COMM didn't pass the check */
		return comm_allow_cnt == 0;

	return *verdict_ptr;
}


static __always_inline void update_event_stat(u64 event_type) {
	u64 e = event_type;
	u64 *count = bpf_map_lookup_elem(&event_stats, &e);
	if (!count) {
		u64 init_count = 1;
		bpf_map_update_elem(&event_stats, &e, &init_count, BPF_ANY);
	} else {
		__sync_fetch_and_add(count, 1);
	}
	return;
}




static __always_inline void print_event(struct call_event *e, char *when) {
	bpf_printk("============= %s: EVENT DETAIL =============", when);
	bpf_printk("============= addr: %llx", e);
	bpf_printk("============= pid: %d tid: %d", e->pid, e->tid);
	bpf_printk("============= start_time: %lld end_time: %lld", e->start_time, e->end_time);
	bpf_printk("============= depth: %d", e->depth);
	for (int i=0; i < 5; i++) {
		bpf_printk("============= ips[%d]: %llx", i, e->ips[i]);
	}
	return;
}

static __always_inline void extract_trace_data(struct func_entry_event *e, struct func *fn) {

	for (int i=0; i < fn->trace_cnt && i < MAX_TRACES; i++) {
		u16 off = i * MAX_TRACE_DATA;
		struct trace_data t = fn->trace[i];
		if (t.size == 0) {
			break;
		}

		if (t.para < PARA_LEN) {
			u64 prev_data = 0;
			u64 data = e->para[t.para];
			if (t.base_addr) {
				if (t.base < i) {
				u16 b = t.base * MAX_TRACE_DATA; 
				bpf_probe_read_kernel(&data, 8, &e->buf[b]);
					if (t.scale != 0 && t.index < i) {
						u16 bi = t.index * MAX_TRACE_DATA; 
						u64 i = 0;
						bpf_probe_read_kernel(&i, 8, &e->buf[bi]);
						data = i * t.scale;
					}
				} else {
					continue;
				}
			}
			bpf_probe_read_kernel(&e->buf[off], 8, &data);
			for (u8 idx=0; idx < t.field_cnt && idx < MAX_TRACE_FIELD_LEN; idx++) {
				data += t.offsets[idx];
				prev_data = data;
				bpf_probe_read_kernel(&data, sizeof(data), (void *)data);
			}
			if (prev_data != 0) {
				// if (off + MAX_TRACE_DATA >= MAX_TRACE_BUF) {
				// 	break;
				// }
				// u8 *ptr = ;
				// if (ptr > &e->buf[MAX_TRACE_BUF]) {
				// 	continue;
				// }
				u16 sz = t.size;
				if (sz > MAX_TRACE_DATA) {
					sz = MAX_TRACE_DATA;
				}
				// if (verbose) {
				// 	bpf_printk("start: %d size: %d addr: %llx", start, t.size, prev_data);
				// }
				bpf_probe_read_kernel(&e->buf[off], sz, (void *)prev_data);
				if (t.is_str) {
					bpf_probe_read_kernel_str(&e->buf[off], MAX_TRACE_DATA, (void *)data);
				}
			}
		}
	}
}

static __always_inline void extract_ret_trace_data(struct func_ret_event *r, struct func *fn) {

	for (int i=0; i < fn->ret_trace_cnt && i < MAX_TRACES; i++) {
		u16 off = i * MAX_TRACE_DATA;
		struct trace_data t = fn->ret_trace[i];
		if (t.size == 0) {
			break;
		}
		u64 prev_data = 0;
		u64 data = r->ret;
		bpf_probe_read_kernel(&r->buf[off], 8, &data);
		for (u8 idx=0; idx < t.field_cnt && idx < MAX_TRACE_FIELD_LEN; idx++) {
			data += t.offsets[idx];
			prev_data = data;
			bpf_probe_read_kernel(&data, sizeof(data), (void *)data);
		}
		if (prev_data != 0) {
			// if (off + MAX_TRACE_DATA >= MAX_TRACE_BUF) {
			// 	break;
			// }
			// u8 *ptr = ;
			// if (ptr > &e->buf[MAX_TRACE_BUF]) {
			// 	continue;
			// }
			u16 sz = t.size;
			if (sz > MAX_TRACE_DATA) {
				sz = MAX_TRACE_DATA;
			}
			// if (verbose) {
			// 	bpf_printk("start: %d size: %d addr: %llx", start, t.size, prev_data);
			// }
			bpf_probe_read_kernel(&r->buf[off], sz, (void *)prev_data);
			if (t.is_str) {
				bpf_probe_read_kernel_str(&r->buf[off], MAX_TRACE_DATA, (void *)data);
			}
		}
		
	}
}

static __always_inline bool trace_have_filter_expr(struct func *fn) {

	for (int i=0; i < fn->trace_cnt && i < MAX_TRACES; i++) {
		struct trace_data t = fn->trace[i];
		if (t.cmp_operator != CMP_NOP) {
			return true;
		}
	}
	return false;
}

static __always_inline bool trace_data_allowed(struct func_entry_event *e, struct func *fn) {

	bool verdict = false;
	u8 cmp_cnt =  0;

	for (int i=0; i < fn->trace_cnt && i < MAX_TRACES; i++) {

		u64 src_data = 0;
		s64 s_src_data = 0;
		struct trace_data t = fn->trace[i];

		u16 off = i * MAX_TRACE_DATA;

		if (t.bitSize != 0) {
            u64 num = 0;

			if (t.size == 1) {
				num = *(u8 *)&e->buf[off];
				} 
			if (t.size == 2) {
				num = *(u16 *)&e->buf[off];
			} 
			if (t.size == 4) {
				num = *(u32 *)&e->buf[off];
			} 
			if (t.size == 8) {
				num = *(u64 *)&e->buf[off];
			} 

			u32 left = 64 - t.bitOff - t.bitSize;
			u32 right = 64 - t.bitSize;
			num = (num << (u64)left) >> (u64)right;

			if (!t.is_sign) {
				src_data = (u64)num;
			} else {
				s_src_data = (s64)num;
			}
		} else {
			if (!t.is_sign) {
				if (t.size == 1) {
					src_data = *(u8 *)&e->buf[off];
				} 
				if (t.size == 2) {
					src_data = *(u16 *)&e->buf[off];
				} 
				if (t.size == 4) {
					src_data = *(u32 *)&e->buf[off];
				} 
				if (t.size == 8) {
					src_data = *(u64 *)&e->buf[off];
				} 
			}

			if (t.is_sign) {
				if (t.size == 1) {
					s_src_data = *(s8 *)&e->buf[off];
				} 
				if (t.size == 2) {
					s_src_data = *(s16 *)&e->buf[off];
				} 
				if (t.size == 4) {
					s_src_data = *(s32 *)&e->buf[off];
				} 
				if (t.size == 8) {
					s_src_data = *(s64 *)&e->buf[off];
				} 
			}
		}

		if (t.cmp_operator == CMP_NOP) {
			continue;
		}

		cmp_cnt++;

		if (!t.is_sign  && t.cmp_operator == CMP_EQ && src_data == t.target){
				verdict = true;
				break;
		}
		if (!t.is_sign  && t.cmp_operator == CMP_NOTEQ && src_data != t.target){
			verdict = true;
			break;
		}
		if (!t.is_sign  && t.cmp_operator == CMP_GT && src_data > t.target){
			verdict = true;
			break;
		}
		if (!t.is_sign  && t.cmp_operator == CMP_GE && src_data >= t.target){
			verdict = true;
			break;
		}
		if (!t.is_sign  && t.cmp_operator == CMP_LT && src_data < t.target){
			verdict = true;
			break;
		}
		if (!t.is_sign == false && t.cmp_operator == CMP_LE && src_data <= t.target){
			verdict = true;
			break;
		}	

		if (t.is_sign  && t.cmp_operator == CMP_EQ && s_src_data == t.s_target){
				verdict = true;
				break;
		}
		if (t.is_sign  && t.cmp_operator == CMP_NOTEQ && s_src_data != t.s_target){
			verdict = true;
			break;
		}
		if (t.is_sign  && t.cmp_operator == CMP_GT && s_src_data > t.s_target){
			verdict = true;
			break;
		}
		if (t.is_sign  && t.cmp_operator == CMP_GE && s_src_data >= t.s_target){
			verdict = true;
			break;
		}
		if (t.is_sign  && t.cmp_operator == CMP_LT && s_src_data < t.s_target){
			verdict = true;
			break;
		}
		if (t.is_sign == false && t.cmp_operator == CMP_LE && s_src_data <= t.s_target){
			verdict = true;
			break;
		}	

	}

	if (cmp_cnt == 0) {
		return true;
	}
	
	return verdict;
}



static __always_inline void extract_func_paras(struct func_entry_event *e, struct pt_regs *ctx) {

	e->para[0] = PT_REGS_PARM1(ctx);
	e->para[1] = PT_REGS_PARM2(ctx);
	e->para[2] = PT_REGS_PARM3(ctx);
	e->para[3] = PT_REGS_PARM4(ctx);
	e->para[4] = PT_REGS_PARM5(ctx);
}



static __always_inline int handle_entry(struct pt_regs *ctx) {

	u64 ip = get_kprobe_func_ip(ctx);
	struct func *fn = bpf_map_lookup_elem(&func_info, &ip);
	if (!fn) {
		bpf_printk("no func info for kprobe addr %llx", ip);
		return 0;
	}

	u64 id   = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32)id;

	struct call_event *e;

	u64 task = bpf_get_current_task();
	e = bpf_map_lookup_elem(&call_events, &task);
	if (!e) {
		if (fn->is_main_entry == false) {
			if (verbose) {
				bpf_printk("func %s will not be traced when first time creating event", (char *)&fn->name);
			}
			return 0;
		}

		if (trace_have_filter_expr(fn)) {
			struct func_entry_event *entry_info;
			entry_info = bpf_ringbuf_reserve(&events, sizeof(struct func_entry_event) + MAX_TRACE_BUF, 0);
			if (!entry_info) {
			} else {
				entry_info->type = ENTRY_EVENT;
				entry_info->task = task;
				entry_info->cpu_id = bpf_get_smp_processor_id();
				entry_info->depth = 0;
				entry_info->seq_id = 0;
				entry_info->ip = ip;
				entry_info->id = fn->id;
				entry_info->time = bpf_ktime_get_ns();
				extract_func_paras(entry_info, ctx);
				entry_info->have_data = true;
				extract_trace_data(entry_info, fn);
				if (trace_data_allowed(entry_info,fn) == false) {
					if (verbose) {
						bpf_printk("func %s will not be traced since it was filtered", (char *)&fn->name);
					}
					bpf_ringbuf_discard(entry_info, 0);
					return 0;
				}
				bpf_ringbuf_discard(entry_info, 0);
			}
		}

		bpf_map_update_elem(&call_events, &task, &empty_call_event, BPF_ANY);
		e = bpf_map_lookup_elem(&call_events, &task);
		if (!e) {
			return 0;
		}
		e->type = CALL_EVENT;
		e->task = task;
		e->pid = pid;
		e->tid = tid;
		bpf_get_current_comm(&e->comm, COMM_LEN);
		struct task_struct *tsk = (struct task_struct *)task;
		BPF_CORE_READ_INTO(&e->group_comm, tsk, group_leader, comm);
		e->start_time = bpf_ktime_get_ns();
		e->next_seq_id = 1;
		if (verbose) {
			bpf_printk("create event %llx depth %d entry func %s", e, e->depth, (char *)&fn->name);
		}
		struct start_event *start_info;
		start_info = bpf_ringbuf_reserve(&events, sizeof(struct start_event), 0);
		if (!start_info) {
			update_event_stat(START_EVENT_DROP);
			bpf_map_delete_elem(&call_events, &task);
			return 0;
		} else {
			update_event_stat(START_EVENT_SUCCESS);
			start_info->type = START_EVENT;
			start_info->task = task;
			bpf_ringbuf_submit(start_info, 0);
		}
	}

	u64 d = e->depth;
	barrier_var(d);
	if (d >= MAX_STACK_DEPTH) {
		if (verbose) {
			bpf_printk("funcentry event %llx depth %d exceed %d", e, e->depth, MAX_STACK_DEPTH);
		}
		return 0;
	}

	if (d == 0 && fn->is_main_entry == false ) {
		bpf_printk("func %s which will be record at depth %d is not entry function", (char *)&fn->name, d);
		if (verbose) {
			print_event(e, "ABNORMAL");
		}
		bpf_map_delete_elem(&call_events, &task);
		return 0;
	}

	if (fn->trace_cnt == 0) {
		struct func_entry_event *entry_info;
		entry_info = bpf_ringbuf_reserve(&events, sizeof(struct func_entry_event), 0);
		if (!entry_info) {
			update_event_stat(ENTRY_EVENT_DROP);
		} else {
			update_event_stat(ENTRY_EVENT_SUCCESS);
			entry_info->type = ENTRY_EVENT;
			entry_info->task = task;
			entry_info->cpu_id = bpf_get_smp_processor_id();
			entry_info->depth = d;
			entry_info->seq_id = e->next_seq_id;
			entry_info->ip = ip;
			entry_info->id = fn->id;
			entry_info->time = bpf_ktime_get_ns();
			extract_func_paras(entry_info, ctx);
			bpf_ringbuf_submit(entry_info, 0);
		}
	} else {
		struct func_entry_event *entry_info;
		entry_info = bpf_ringbuf_reserve(&events, sizeof(struct func_entry_event) + MAX_TRACE_BUF, 0);
		if (!entry_info) {
			update_event_stat(ENTRY_EVENT_DROP);
		} else {
			update_event_stat(ENTRY_EVENT_SUCCESS);
			entry_info->type = ENTRY_EVENT;
			entry_info->task = task;
			entry_info->cpu_id = bpf_get_smp_processor_id();
			entry_info->depth = d;
			entry_info->seq_id = e->next_seq_id;
			entry_info->ip = ip;
			entry_info->id = fn->id;
			entry_info->time = bpf_ktime_get_ns();
			extract_func_paras(entry_info, ctx);
			entry_info->have_data = true;
			extract_trace_data(entry_info, fn);
			bpf_ringbuf_submit(entry_info, 0);
		}
	}
	
	e->next_seq_id++;
	e->ips[d] = ip;
	e->durations[d] = bpf_ktime_get_ns();
	e->depth = d +1;
	if (verbose) {
		print_event(e, "FUNCENTRY");
	}
	
	return 0;
}

SEC("kprobe/entry")
int funcentry(struct pt_regs *ctx) {

	if (is_ready() == false) {
		return 0;
	}

	if (!pid_allowed()) {
		return 0;
	}

	if (!comm_allowed()) {
		return 0;
	}

	return handle_entry(ctx);
}

static __always_inline int handle_ret(struct pt_regs *ctx) {
	
	u64 ip = get_kret_func_ip(ctx);
	struct func *fn = bpf_map_lookup_elem(&func_info, &ip);
	if (!fn) {
		if (verbose) {
			bpf_printk("no func info for kretprobe addr %llx", ip);
		}
		return 0;
	}

	u64 id   = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32)id;

	struct call_event *e;

	u64 task = bpf_get_current_task();
	e = bpf_map_lookup_elem(&call_events, &task);
	if (!e) {
		if (verbose) {
			bpf_printk("no event when kretprobe func %s", (char *)&fn->name);
		}
		return 0;
	}


	u64 d = e->depth;
	if (d == 0) {
		bpf_printk("shoud not depth 0 during kretprobe func %s", task, (char *)&fn->name);
		return 0;
	}
	d -= 1;
	barrier_var(d);
	if (d >= MAX_STACK_DEPTH) {
		bpf_printk("funcret depth %d exceed %d", d, MAX_STACK_DEPTH);
		return 0;
	}

	u64 prev = e->ips[d];
	if (prev != ip) {
		if (verbose) {
			bpf_printk("kprobe ip %llx is not enqual to kretprobe ip %llx", prev, ip);
			print_event(e, "ABNORMAL");
		}
		bpf_map_delete_elem(&call_events, &task);
		return 0;
	}



	// if (fn->trace_cnt == 0) {
	// 	struct func_entry_event *entry_info;
	// 	entry_info = bpf_ringbuf_reserve(&events, sizeof(struct func_entry_event), 0);
	// 	if (!entry_info) {
	// 		update_event_stat(ENTRY_EVENT_DROP);
	// 	} else {
	// 		update_event_stat(ENTRY_EVENT_SUCCESS);
	// 		entry_info->type = ENTRY_EVENT;
	// 		entry_info->task = task;
	// 		entry_info->cpu_id = bpf_get_smp_processor_id();
	// 		entry_info->depth = d;
	// 		entry_info->seq_id = e->next_seq_id;
	// 		entry_info->ip = ip;
	// 		entry_info->id = fn->id;
	// 		entry_info->time = bpf_ktime_get_ns();
	// 		extract_func_paras(entry_info, ctx);
	// 		bpf_ringbuf_submit(entry_info, 0);
	// 	}
	// } else {
	// 	struct func_entry_event *entry_info;
	// 	entry_info = bpf_ringbuf_reserve(&events, sizeof(struct func_entry_event) + MAX_TRACE_BUF, 0);
	// 	if (!entry_info) {
	// 		update_event_stat(ENTRY_EVENT_DROP);
	// 	} else {
	// 		update_event_stat(ENTRY_EVENT_SUCCESS);
	// 		entry_info->type = ENTRY_EVENT;
	// 		entry_info->task = task;
	// 		entry_info->cpu_id = bpf_get_smp_processor_id();
	// 		entry_info->depth = d;
	// 		entry_info->seq_id = e->next_seq_id;
	// 		entry_info->ip = ip;
	// 		entry_info->id = fn->id;
	// 		entry_info->time = bpf_ktime_get_ns();
	// 		extract_func_paras(entry_info, ctx);
	// 		entry_info->have_data = true;
	// 		extract_trace_data(entry_info, fn);
	// 		bpf_ringbuf_submit(entry_info, 0);
	// 	}
	// }

	if (fn->ret_trace_cnt == 0) {
		struct func_ret_event *ret_info;
		ret_info = bpf_ringbuf_reserve(&events, sizeof(struct func_ret_event), 0);
		if (!ret_info) {
			update_event_stat(RET_EVENT_DROP);
		} else {
			update_event_stat(RET_EVENT_SUCCESS);
			ret_info->type = RET_EVENT;
			ret_info->task = task;
			ret_info->cpu_id = bpf_get_smp_processor_id();
			ret_info->depth = d;
			ret_info->seq_id = e->next_seq_id;
			ret_info->ip = ip;
			ret_info->id = fn->id;
			ret_info->time = bpf_ktime_get_ns();
			ret_info->duration = ret_info->time - e->durations[d];
			ret_info->ret = PT_REGS_RC(ctx);
			bpf_ringbuf_submit(ret_info, 0);
		}
	} else {
		struct func_ret_event *ret_info;
		ret_info = bpf_ringbuf_reserve(&events, sizeof(struct func_ret_event) + MAX_TRACE_BUF, 0);
		if (!ret_info) {
			update_event_stat(RET_EVENT_DROP);
		} else {
			update_event_stat(RET_EVENT_SUCCESS);
			ret_info->type = RET_EVENT;
			ret_info->task = task;
			ret_info->cpu_id = bpf_get_smp_processor_id();
			ret_info->depth = d;
			ret_info->seq_id = e->next_seq_id;
			ret_info->ip = ip;
			ret_info->id = fn->id;
			ret_info->time = bpf_ktime_get_ns();
			ret_info->duration = ret_info->time - e->durations[d];
			ret_info->ret = PT_REGS_RC(ctx);
			ret_info->have_data = true;
			extract_ret_trace_data(ret_info, fn);
			bpf_ringbuf_submit(ret_info, 0);
		}
	}

	e->durations[d] = bpf_ktime_get_ns() - e->durations[d];
	e->depth = d;
	e->next_seq_id++;
	if (d == 0) {
		e->end_time = bpf_ktime_get_ns();
		struct call_event *call_info;
		call_info = bpf_ringbuf_reserve(&events, sizeof(struct call_event), 0);
		if (!call_info) {
			update_event_stat(CALL_EVENT_DROP);
			bpf_map_delete_elem(&call_events, &task);
			if (verbose) {
				print_event(e, "NO-SEND RINGBUF");
			}
			return 0;
		}
		update_event_stat(CALL_EVENT_SUCCESS);
		bpf_probe_read_kernel(call_info, sizeof(struct call_event), e);
		call_info->kstack_sz = bpf_get_stack(ctx, &call_info->kstack, sizeof(call_info->kstack), 0);
		bpf_ringbuf_submit(call_info, 0);
		bpf_map_delete_elem(&call_events, &task);
		if (verbose) {
			bpf_printk("send event %llx and delete it", e);
			print_event(e, "SEND RINGBUF");
		}
		return 0;
	}
	if (verbose) {
		print_event(e, "FUNCRET");
	}
	return 0;
}

SEC("kretprobe/ret")
int funcret(struct pt_regs *ctx) {

	if (is_ready() == false) {
		return 0;
	}

	if (!pid_allowed()) {
		return 0;
	}

	if (!comm_allowed()) {
		return 0;
	}

	return handle_ret(ctx);

}
