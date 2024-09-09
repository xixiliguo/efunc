//go:build ignore

#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define COMM_LEN 16
#define MAX_STACK_DEPTH 32
#define MAX_KSTACK_DEPTH 128
#define MAX_FUNC_NAME_LEN 40

enum trace_constant {
    PARA_LEN = 16,
    MAX_TRACE_FIELD_LEN = 5,
    MAX_TRACES = 9,
    MAX_TRACE_DATA = 1024,
    MAX_TRACE_BUF =  5 * MAX_TRACE_DATA,
};

#define CMP_NOP 0
#define CMP_EQ 1
#define CMP_NOTEQ 2
#define CMP_GT 3
#define CMP_GE 4
#define CMP_LT 5
#define CMP_LE 6

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

volatile const bool verbose = false;
volatile const bool has_bpf_get_func_ip = false;
volatile const u64 kret_offset = 0;

volatile const u8 max_depth = 32;

volatile const u32 comm_allow_cnt = 0;
volatile const u32 comm_deny_cnt = 0;
volatile const u32 pid_allow_cnt = 0;
volatile const u32 pid_deny_cnt = 0;

volatile const u64 duration_ms = 0;

enum arg_type {
    REG,
    STACK,
    ADDR,
    RET_REG,
    RET_STACK,
};

enum arg_addr {
    BASE_LEN = 4,
    BASE_SHIFT = 28,
    INDEX_LEN = 4,
    INDEX_SHIFT = 24,
    SCALE_LEN = 8,
    SCALE_SHIFT = 16,
    IMM_LEN = 16,
    IMM_SHIFT = 0,
};

enum trace_data_flags {
    DATA_STR = 1,
    DATA_DEREF = 2,
    DATA_SIGN = 4,
};

#define read_bits(v, len, shift) ((v >> shift) & ((1 << len) - 1))

struct trace_data {
    u32 arg;
    u32 arg_loc;
    u8 field_cnt;
    u16 offsets[MAX_TRACE_FIELD_LEN];
    u16 size;
    u8 bit_off;
    u8 bit_size;
    u8 flags;
    u8 cmp_operator;
    u64 target;
};
struct func {
    u32 id;
    bool is_main_entry;
    char name[MAX_FUNC_NAME_LEN];
    u8 trace_cnt;
    struct trace_data trace[MAX_TRACES];
    u8 ret_trace_cnt;
    struct trace_data ret_trace[MAX_TRACES];
};

struct start_event {
    u8 type;
    u64 task;
};

struct event_data {
    u16 data_len;
    s16 data_off[MAX_TRACES];
    u8 data[0];
};

struct func_entry_event {
    u8 type;
    u64 task;
    u32 cpu_id;
    u64 depth;
    u64 seq_id;
    u64 ip;
    u32 id;
    bool have_data;
    u64 time;
    u64 para[PARA_LEN];
    struct event_data buf[0];
};

struct func_ret_event {
    u8 type;
    u64 task;
    u32 cpu_id;
    u64 depth;
    u64 seq_id;
    u64 ip;
    u32 id;
    bool have_data;
    u64 time;
    u64 duration;
    u64 ret[2];
    struct event_data buf[0];
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
    __type(key, char[COMM_LEN]);
    __type(value, bool);
    __uint(max_entries, 99);
} comms_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, bool);
    __uint(max_entries, 99);
} pids_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u64);
    __type(value, bool);
} ready SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 9999);
    __type(key, u64);
    __type(value, struct func);
} func_info SEC(".maps");

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

const enum arg_type *arg_type_unused __attribute__((unused));
const enum arg_addr *arg_addr_unused __attribute__((unused));
const enum trace_constant *trace_constant_unused __attribute__((unused));
const enum trace_data_flags *trace_data_flags_unused __attribute__((unused));
const struct trace_data *trace_unused __attribute__((unused));
const struct start_event *start_unused __attribute__((unused));
const struct event_data *event_data_unused __attribute__((unused));
const struct func_entry_event *entry_unused __attribute__((unused));
const struct func_ret_event *ret_unused __attribute__((unused));

static __always_inline u64 get_kprobe_func_ip(struct pt_regs *ctx) {
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

static __always_inline u64 get_kret_func_ip(struct pt_regs *ctx) {
    if (!has_bpf_get_func_ip) {
        struct trace_kprobe *tk;
        u64 fp, ip;

        /* get frame pointer */
        asm volatile("%[fp] = r10" : [fp] "+r"(fp) :);

        bpf_probe_read_kernel(&tk, sizeof(tk),
                              (void *)(fp + kret_offset * sizeof(__u64)));
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

static __always_inline bool pid_allowed(void) {
    bool *verdict_ptr;
    u32 pid;

    if (pid_allow_cnt + pid_deny_cnt == 0) return true;

    pid = bpf_get_current_pid_tgid() >> 32;

    verdict_ptr = bpf_map_lookup_elem(&pids_filter, &pid);
    if (!verdict_ptr) {
        return pid_allow_cnt == 0;
    }
    return *verdict_ptr;
}

static __always_inline bool comm_allowed(void) {
    char comm[COMM_LEN] = {};
    __builtin_memset(&comm, 0, sizeof(comm));

    bool *verdict_ptr;

    if (comm_allow_cnt + comm_deny_cnt == 0) return true;

    bpf_get_current_comm(comm, COMM_LEN);

    verdict_ptr = bpf_map_lookup_elem(&comms_filter, comm);
    if (!verdict_ptr) return comm_allow_cnt == 0;

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
    bpf_printk("============= start_time: %lld end_time: %lld", e->start_time,
               e->end_time);
    bpf_printk("============= depth: %d", e->depth);
    for (int i = 0; i < 5; i++) {
        bpf_printk("============= ips[%d]: %llx", i, e->ips[i]);
    }
    return;
}

#ifdef __TARGET_ARCH_x86
static __always_inline u64 get_arg_reg_value(struct pt_regs *ctx, u32 arg_idx)
{

		switch (arg_idx) {
			case 0: return PT_REGS_PARM1(ctx);
			case 1: return PT_REGS_PARM2(ctx);
			case 2: return PT_REGS_PARM3(ctx);
			case 3: return PT_REGS_PARM4(ctx);
			case 4: return PT_REGS_PARM5(ctx);
			case 5: return PT_REGS_PARM6(ctx);
			default: return 0;
		}
	return 0;
}
#else /* !__TARGET_ARCH_x86 */
static __always_inline u64 get_arg_reg_value(struct pt_regs *ctx, u32 arg_idx)
{

		switch (arg_idx) {
			case 0: return PT_REGS_PARM1(ctx);
			case 1: return PT_REGS_PARM2(ctx);
			case 2: return PT_REGS_PARM3(ctx);
			case 3: return PT_REGS_PARM4(ctx);
			case 4: return PT_REGS_PARM5(ctx);
			case 5: return PT_REGS_PARM6(ctx);
            case 6: return PT_REGS_PARM7(ctx);
            case 7: return PT_REGS_PARM8(ctx);
			default: return 0;
		}
	return 0;
}

#endif

static __always_inline u64 get_stack_pointer(struct pt_regs *ctx)
{
	return PT_REGS_SP(ctx);
}

static __always_inline void extract_data(struct pt_regs *ctx, bool is_ret, struct func *fn, struct event_data *buf) {

    buf->data_len = 0;
    for (int i = 0; i < MAX_TRACES; i++) {
        u16 off;
        void *dst;
        struct trace_data *t = &fn->trace[i];
        if (is_ret) {
            t = &fn->ret_trace[i];
        }
        if (t->size == 0) {
            break;
        }
        if (buf->data_len >= MAX_TRACE_BUF) {
            buf->data_off[i] = -1;
            continue;
        }

        dst = buf->data + buf->data_len;
        u16 sz = t->size;
        u32 reg_idx, stack_off;
        u8 base, index;
        s8 scale;
        s16 imm;
        
        if (sz == 0) {
            break;
        }

        
        u64 vals[2];
        u64 data_ptr = (u64)vals;

        u32 idx_off = t->arg_loc;

        switch (t->arg) {
            case REG:
                vals[0]= get_arg_reg_value(ctx, idx_off);
                vals[1]= get_arg_reg_value(ctx, idx_off + 1);
                data_ptr = (u64)vals;
                break;
            case STACK:
                vals[0] = get_stack_pointer(ctx) + idx_off * 8;
                data_ptr = vals[0];
                break;
            case ADDR:
                //4 + 4 + 8 + 16
                base = (u8)(read_bits(idx_off, BASE_LEN, BASE_SHIFT));
                index = (u8)(read_bits(idx_off, INDEX_LEN, INDEX_SHIFT));
                scale = (s8)(read_bits(idx_off, SCALE_LEN, SCALE_SHIFT));
                imm = (s16)(read_bits(idx_off, IMM_LEN, IMM_SHIFT));
                
                s64 addr =0;
                bpf_probe_read_kernel(&addr, 8,  &buf->data[buf->data_off[base]]);
                if (scale != 0 && index < i) {
                    s64 index_data = 0;
                    barrier_var(index);
                    if (index >= MAX_TRACES) {
                        continue;
                    }
                    u16 index_sz = fn->trace[index].size;
                    if (is_ret) {
                        index_sz = fn->ret_trace[index].size;
                    }
                    if (index_sz > 8) {
                        continue;
                    }
                    bpf_probe_read_kernel(&index_data, index_sz, &buf->data[buf->data_off[index]]);
                    addr += index_data * scale;
                }
                addr += imm;
                
                vals[0] = (u64)addr;
                data_ptr = (u64)vals;
                break;
            case RET_REG:
                #ifdef __TARGET_ARCH_x86
                vals[0] = (u64)__PT_REGS_CAST((struct pt_regs *)ctx)->ax;
                vals[1] = (u64)__PT_REGS_CAST((struct pt_regs *)ctx)->dx;
                #else /* !__TARGET_ARCH_x86 */
                vals[0] = (u64)PT_REGS_PARM1((struct pt_regs *)ctx);
                vals[1] = (u64)PT_REGS_PARM2((struct pt_regs *)ctx);
                #endif
                data_ptr = (u64)vals;
                break;
            case RET_STACK:
                vals[0] = (u64)PT_REGS_RC((struct pt_regs *)ctx);
                data_ptr = vals[0];
                break;
        }

        for (u8 idx = 0;  idx < t->field_cnt && idx < MAX_TRACE_FIELD_LEN; idx++) {
            // if (t->offsets[idx] == 0) {
            //     break;
            // }
            bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)data_ptr);
            data_ptr += t->offsets[idx];
        }

        if (sz > MAX_TRACE_DATA) {
            sz = MAX_TRACE_DATA;
        }


        s16 err;
        if (t->flags & DATA_STR) {
            bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr),
                                  (void *)data_ptr);
            if ((long)data_ptr <= 0) {
                err  = bpf_probe_read_kernel_str(dst, MAX_TRACE_DATA,
                                           (void *)data_ptr);
            } else {
                err  = bpf_probe_read_user_str(dst, MAX_TRACE_DATA,
                                           (void *)data_ptr);
            }
            sz = err;
        } else {
            if (t->flags & DATA_DEREF) {
                bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr),
                                      (void *)data_ptr);
            }
            if ((long)data_ptr <= 0) {
                err  = bpf_probe_read_kernel(dst, sz, (void *)data_ptr);
            } else {
                err  = bpf_probe_read_user(dst, sz, (void *)data_ptr);
            }
        }

        if (err < 0) {
            buf->data_off[i] = err;
            return;
        }
        buf->data_off[i] = buf->data_len;
        buf->data_len = (buf->data_len + sz + 7) / 8 * 8;
    }
}

static __always_inline bool trace_have_filter_expr(struct func *fn) {
    for (int i = 0; i < MAX_TRACES; i++) {
        struct trace_data *t = &fn->trace[i];
        if (t->size == 0) {
            break;
        }
        if (t->cmp_operator != CMP_NOP) {
            return true;
        }
    }
    return false;
}

static __always_inline bool ret_trace_have_filter_expr(struct func *fn) {
    for (int i = 0; i < MAX_TRACES; i++) {
        struct trace_data *t = &fn->ret_trace[i];
        if (t->size == 0) {
            break;
        }
        if (t->cmp_operator != CMP_NOP) {
            return true;
        }
    }
    return false;
}

static __always_inline int __strncmp(const void *m1, const void *m2, size_t len) {
        const unsigned char *s1 = m1;
        const unsigned char *s2 = m2;
        int i, delta = 0;

        for (i = 0; i < len; i++) {
                delta = s1[i] - s2[i];
                if (delta || s1[i] == 0 || s2[i] == 0)
                        break;
        }
        return delta;
}

static __always_inline bool trace_data_allowed(struct event_data *buf, struct func *fn,
                                               bool ret) {

    struct trace_data *tp = fn->trace;
    if (ret) {
        tp = fn->ret_trace;
    }

    bool verdict = false;
    u8 cmp_cnt = 0;
    u8 cmp_cnt_allowed = 0;

    for (int i = 0; i < MAX_TRACES; i++) {
        u64 src_unsign_data = 0;
        s64 src_sign_data = 0;
        struct trace_data *t = tp + i;
        if (t->size == 0) {
            break;
        }
        u16 sz = t->size;

        u32 bit_off, bit_size;
        bit_off = t->bit_off;
        bit_size = t->bit_size;

        bool is_str = t->flags & DATA_STR;
        bool is_sign = t->flags & DATA_SIGN;

        if (t->cmp_operator == CMP_NOP) {
            continue;
        }

        if (buf->data_off[i] < 0) {
            continue;
        }
        if (buf->data_off[i] >= MAX_TRACE_BUF) {
            continue;
        }
        void *dst = buf->data + buf->data_off[i];

        if (sz == 1) {
            src_unsign_data = *(u8 *)dst;
            src_sign_data = *(s8 *)dst;
        }
        if (sz == 2) {
            src_unsign_data = *(u16 *)dst;
            src_sign_data = *(s16 *)dst;
        }
        if (sz == 4) {
            src_unsign_data = *(u32 *)dst;
            src_sign_data = *(s32 *)dst;
        }
        if (sz == 8) {
            src_unsign_data = *(u64 *)dst;
            src_sign_data = *(s64 *)dst;
        }

        if (bit_size) {
            u32 left = 64 - bit_off - bit_size;
            u32 right = 64 - bit_size;
            src_unsign_data = (src_unsign_data << (u64)left) >> (u64)right;
        }

        cmp_cnt++;

        if (is_str) {
            int re = __strncmp(dst, &t->target, 8);
            if (t->cmp_operator == CMP_EQ && re == 0) {
                cmp_cnt_allowed++;
            }
            if (t->cmp_operator == CMP_NOTEQ && re != 0) {
                cmp_cnt_allowed++;
            }
        } else {
            switch (t->cmp_operator) {
                case CMP_EQ:
                    if ((!is_sign && src_unsign_data == t->target) ||
                        (is_sign && src_sign_data == (s64)t->target)) {
                        cmp_cnt_allowed++;
                    }
                    break;
                case CMP_NOTEQ:
                    if ((!is_sign && src_unsign_data != t->target) ||
                        (is_sign && src_sign_data != (s64)t->target)) {
                        cmp_cnt_allowed++;
                    }
                    break;
                case CMP_GT:
                    if ((!is_sign && src_unsign_data > t->target) ||
                        (is_sign && src_sign_data > (s64)t->target)) {
                        cmp_cnt_allowed++;
                    }
                    break;
                case CMP_GE:
                    if ((!is_sign && src_unsign_data >= t->target) ||
                        (is_sign && src_sign_data >= (s64)t->target)) {
                        cmp_cnt_allowed++;
                    }
                    break;
                case CMP_LT:
                    if ((!is_sign && src_unsign_data < t->target) ||
                        (is_sign && src_sign_data < (s64)t->target)) {
                        cmp_cnt_allowed++;
                    }
                    break;
                case CMP_LE:
                    if ((!is_sign && src_unsign_data <= t->target) ||
                        (is_sign && src_sign_data <= (s64)t->target)) {
                        cmp_cnt_allowed++;
                    }
                    break;
            }
        }
    }

    return cmp_cnt == cmp_cnt_allowed;
}

static __always_inline void extract_func_paras(struct func_entry_event *e,
                                               struct pt_regs *ctx) {
    e->para[0] = PT_REGS_PARM1(ctx);
    e->para[1] = PT_REGS_PARM2(ctx);
    e->para[2] = PT_REGS_PARM3(ctx);
    e->para[3] = PT_REGS_PARM4(ctx);
    e->para[4] = PT_REGS_PARM5(ctx);
    e->para[5] = PT_REGS_PARM6(ctx);
#ifdef __TARGET_ARCH_arm64
    e->para[6] = PT_REGS_PARM7(ctx);
    e->para[7] = PT_REGS_PARM8(ctx);
#endif
    u64 sp = PT_REGS_SP(ctx);
    bpf_probe_read_kernel(&e->para[8], 8 * 8, (void *)sp);
}

static __always_inline void extract_func_ret(struct func_ret_event *r,
                                             struct pt_regs *ctx) {
#ifdef __TARGET_ARCH_x86
    r->ret[0] = (u64)__PT_REGS_CAST((struct pt_regs *)ctx)->ax;
    r->ret[1] = (u64)__PT_REGS_CAST((struct pt_regs *)ctx)->dx;
#else /* !__TARGET_ARCH_x86 */
    r->ret[0] = (u64)PT_REGS_PARM1((struct pt_regs *)ctx);
    r->ret[1] = (u64)PT_REGS_PARM2((struct pt_regs *)ctx);
#endif
}

static __always_inline int handle_entry(struct pt_regs *ctx) {
    u64 ip = get_kprobe_func_ip(ctx);
    struct func *fn = bpf_map_lookup_elem(&func_info, &ip);
    if (!fn) {
        bpf_printk("no func info for kprobe addr %llx", ip);
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    struct call_event *e;

    u64 task = bpf_get_current_task();
    e = bpf_map_lookup_elem(&call_events, &task);
    if (!e) {
        if (fn->is_main_entry == false) {
            if (verbose) {
                bpf_printk(
                    "func %s will not be traced when first time creating event",
                    (char *)&fn->name);
            }
            return 0;
        }

        if (trace_have_filter_expr(fn)) {
            struct func_entry_event *entry_info;
            entry_info = bpf_ringbuf_reserve(
                &events, sizeof(struct func_entry_event) + sizeof(struct event_data) + MAX_TRACE_BUF + MAX_TRACE_DATA, 0);
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
                extract_data(ctx, false, fn, entry_info->buf);
                if (trace_data_allowed(&entry_info->buf[0], fn, false) == false) {
                    if (verbose) {
                        bpf_printk(
                            "func %s will not be traced since it was filtered",
                            (char *)&fn->name);
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
            bpf_printk("create event %llx depth %d entry func %s", e, e->depth,
                       (char *)&fn->name);
        }
        struct start_event *start_info;
        start_info =
            bpf_ringbuf_reserve(&events, sizeof(struct start_event), 0);
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
    if (d >= max_depth || d >= MAX_STACK_DEPTH) {
        if (verbose) {
            bpf_printk("funcentry event %llx depth %d exceed %d", e, e->depth,
                       MAX_STACK_DEPTH);
        }
        e->depth = d + 1;
        return 0;
    }

    if (d == 0 && fn->is_main_entry == false) {
        bpf_printk(
            "func %s which will be record at depth %d is not entry function",
            (char *)&fn->name, d);
        if (verbose) {
            print_event(e, "ABNORMAL");
        }
        bpf_map_delete_elem(&call_events, &task);
        return 0;
    }

    if (fn->trace_cnt == 0) {
        struct func_entry_event *entry_info;
        entry_info =
            bpf_ringbuf_reserve(&events, sizeof(struct func_entry_event), 0);
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
            entry_info->have_data = false;
            bpf_ringbuf_submit(entry_info, 0);
        }
    } else {
        struct func_entry_event *entry_info;
        entry_info = bpf_ringbuf_reserve(
            &events, sizeof(struct func_entry_event) + sizeof(struct event_data) + MAX_TRACE_BUF + MAX_TRACE_DATA, 0);
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
            extract_data(ctx, false, fn, entry_info->buf);
            bpf_ringbuf_submit(entry_info, 0);
        }
    }

    e->next_seq_id++;
    e->ips[d] = ip;
    e->durations[d] = bpf_ktime_get_ns();
    e->depth = d + 1;
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

    u64 id = bpf_get_current_pid_tgid();
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
        bpf_printk("shoud not depth 0 during kretprobe func %s", task,
                   (char *)&fn->name);
        return 0;
    }
    d -= 1;
    barrier_var(d);
    if (d >= max_depth || d >= MAX_STACK_DEPTH) {
        if (verbose) {
            bpf_printk("funcret depth %d exceed %d", d, MAX_STACK_DEPTH);
        }
        e->depth = d;
        return 0;
    }

    u64 prev = e->ips[d];
    if (prev != ip) {
        if (verbose) {
            bpf_printk("kprobe ip %llx is not enqual to kretprobe ip %llx",
                       prev, ip);
            print_event(e, "ABNORMAL");
        }
        bpf_map_delete_elem(&call_events, &task);
        return 0;
    }

    bool skip = false;

    if (fn->ret_trace_cnt == 0) {
        struct func_ret_event *ret_info;
        ret_info =
            bpf_ringbuf_reserve(&events, sizeof(struct func_ret_event), 0);
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
            extract_func_ret(ret_info,ctx);
            ret_info->have_data = false;
            // ret_info->ret = PT_REGS_RC(ctx);
            bpf_ringbuf_submit(ret_info, 0);
        }
    } else {
        struct func_ret_event *ret_info;
        ret_info = bpf_ringbuf_reserve(
            &events, sizeof(struct func_ret_event) + sizeof(struct event_data) + MAX_TRACE_BUF + MAX_TRACE_DATA, 0);
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
            extract_func_ret(ret_info,ctx);
            ret_info->have_data = true;
            extract_data(ctx, true, fn, ret_info->buf);
            if (d == 0 && ret_trace_have_filter_expr(fn) && trace_data_allowed(&ret_info->buf[0],fn,true) == false) {
                skip = true;
            }
            bpf_ringbuf_submit(ret_info, 0);
        }
    }

    e->durations[d] = bpf_ktime_get_ns() - e->durations[d];
    e->depth = d;
    e->next_seq_id++;
    if (d == 0) {
        e->end_time = bpf_ktime_get_ns();
        if (duration_ms != 0 &&  (e->durations[0] / 1000000) < duration_ms) {
            bpf_map_delete_elem(&call_events, &task);
            return 0;
        }
        if (skip) {
            bpf_map_delete_elem(&call_events, &task);
            return 0; 
        }
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
        call_info->kstack_sz = bpf_get_stack(ctx, &call_info->kstack,
                                             sizeof(call_info->kstack), 0);
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

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid = ctx->child_pid;
    bool *verdict_ptr;
    bool allow = true;
    verdict_ptr = bpf_map_lookup_elem(&pids_filter, &parent_pid);
    if (verdict_ptr && *verdict_ptr) {
        bpf_map_update_elem(&pids_filter, &child_pid, &allow, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_free")
int handle_free(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = ctx->pid;
    bpf_map_delete_elem(&pids_filter, &pid);
    return 0;
}