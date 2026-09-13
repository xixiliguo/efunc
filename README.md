# efunc
**efunc** is general-purpose kernel function tracer tool like ftrace funcgraph, which was inspired by [retsnoop](https://https://github.com/anakryiko/retsnoop).

## Feature

* **function call graph** trace function entry and exit, even sub-fuction, final generate call relationship and duration.
* **record args and ret** record all args and ret of each traced function.
* **dump any variable base on args or ret** as `skb->head`, `*skb->dev`, you can get data of any variable which can be reached from args or ret, output as a human-readable format with BTF(like `gdb` print format)
* **filter by number or string** trace function only filter expression (similar C syntax) is allowed. support `>=` `>` `==` `<` `<=` `~` operator.
* **built-in function** `:str` show real string with char pointer. `:buf` print hex value in memory with pointer.
* **kernel stacktrace** show stacktrace, show source-level info with debuginfo.


## Example
`efunc trace -e "tcp_v4_rcv(skb, skb->head, skb->transport_header, (struct tcphdr *)(1,2,1,0)->syn == 1)" -a ":net/ipv4/*"`  
trace tcp_v4_rcv when tcp syn packet is received.   
``` bash
TIME: 07:21:10.410826 -> 07:21:10.411063 PID/TID: 0/0 (swapper/7 swapper/7)
 CPU   DURATION | FUNCTION GRAPH
 ---   -------- | --------------
  7)            | → tcp_v4_rcv skb=0xffff903541e66400
                    skb = (struct sk_buff *)0xffff903541e66400
                    skb->head = (unsigned char *)0xffff90344aa5dc00
                    skb->transport_header = (short unsigned int)98
                    ((struct tcphdr *)(1,2,1,0))->syn = (short unsigned int)1
  7)            |   → __inet_lookup_established net=0xffffffffa55e81c0 hashinfo=0xffffffffa55eb2a0 saddr=990095552 sport=41933 daddr=855877824 hnum=22 dif=2 sdif=0
  7)     2.13µs |     ↔ inet_ehashfn net=0xffffffffa55e81c0 laddr=855877824 lport=22 faddr=990095552 fport=41933 ret=691795317
  7)    5.392µs |   ← __inet_lookup_established ret=0x0
  7)            |   → __inet_lookup_listener net=0xffffffffa55e81c0 hashinfo=0xffffffffa55eb2a0 skb=0xffff903541e66400 doff=32 saddr=990095552 sport=41933 daddr=855877824 hnum=22 dif=2 sdif=0
  7)    1.099µs |     ↔ inet_lhash2_lookup net=0xffffffffa55e81c0 ilb2=0xffff903542d054b0 skb=0xffff903541e66400 doff=32 saddr=990095552 sport=41933 daddr=855877824 hnum=22 dif=2 sdif=0 ret=0x0
  7)    1.393µs |     ↔ inet_lhash2_lookup net=0xffffffffa55e81c0 ilb2=0xffff903542d019c0 skb=0xffff903541e66400 doff=32 saddr=990095552 sport=41933 daddr=0 hnum=22 dif=2 sdif=0 ret=0xffff903545411400
  7)     7.13µs |   ← __inet_lookup_listener ret=0xffff903545411400
  7)            |   → tcp_inbound_md5_hash sk=0xffff903545411400 skb=0xffff903541e66400 saddr=0xffff90344aa5dc5a daddr=0xffff90344aa5dc5e family=2 dif=2 sdif=0
  7)      858ns |     ↔ tcp_parse_md5sig_option th=0xffff90344aa5dc62 ret=0x0
  7)    3.613µs |   ← tcp_inbound_md5_hash ret=SKB_NOT_DROPPED_YET
  7)    2.898µs |   ↔ tcp_filter sk=0xffff903545411400 skb=0xffff903541e66400 ret=0
  7)      828ns |   ↔ tcp_v4_fill_cb skb=0xffff903541e66400 iph=0xffff90344aa5dc4e th=0xffff90344aa5dc62 ret=void
  7)            |   → tcp_v4_do_rcv sk=0xffff903545411400 skb=0xffff903541e66400
  7)            |     → tcp_rcv_state_process sk=0xffff903545411400 skb=0xffff903541e66400
```

`efunc trace -e 'do_filp_open(pathname->name:str == "/etc/hosts")' -s`  
trace do_filp_open to monitor who/when open /etc/hosts. alos stacktrace.  
``` bash
TIME: 07:23:14.777419 -> 07:23:14.777435 PID/TID: 5817/5817 (cat cat)
 CPU   DURATION | FUNCTION GRAPH
 ---   -------- | --------------
  1)   11.458µs | ↔ do_filp_open dfd=-100 pathname=0xffff9035430ed000 op=0xffffaf2140c27b44 ret=0xffff903547f8d000
                    pathname->name:str = /etc/hosts

do_sys_openat2+0x96                                             fs/open.c:1288
__x64_sys_openat+0x53                                           fs/open.c:1314
 (inline) do_syscall_x64                                        arch/x86/entry/common.c:52
do_syscall_64+0x5f                                              arch/x86/entry/common.c:83
entry_SYSCALL_64_after_hwframe+0x78                             arch/x86/entry/entry_64.S:130
```
## Installation

### Prebuilt binaries
Download binary from [release page](https://github.com/xixiliguo/efunc/releases).    
### Source
install from source code
```bash
go install github.com/xixiliguo/efunc@latest
```