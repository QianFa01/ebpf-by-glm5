#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} network_events SEC(".maps");

static __always_inline void get_container_id(char *container_id)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy;
    struct uts_namespace *uts_ns;
    
    nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy)
        return;
    
    uts_ns = BPF_CORE_READ(nsproxy, uts_ns);
    if (!uts_ns)
        return;
    
    const char *name = BPF_CORE_READ(uts_ns, name.nodename);
    bpf_probe_read_kernel_str(container_id, MAX_CONTAINER_ID, name);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk)
{
    struct network_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_NETWORK_CONNECT;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    event->protocol = IPPROTO_TCP;
    event->family = AF_INET;
    
    event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(trace_tcp_set_state, struct sock *sk, int newstate)
{
    if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE)
        return 0;

    struct network_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = newstate == TCP_ESTABLISHED ? EVENT_NETWORK_ACCEPT : EVENT_NETWORK_CLOSE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    event->protocol = IPPROTO_TCP;
    event->state = (u8)newstate;
    
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->family = family;
    
    if (family == AF_INET) {
        event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }
    
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct network_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_NETWORK_UDP_SEND;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    event->protocol = IPPROTO_UDP;
    
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->family = family;
    
    if (family == AF_INET) {
        event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        
        struct sockaddr_in *usin = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);
        if (usin) {
            event->daddr_v4 = BPF_CORE_READ(usin, sin_addr.s_addr);
            event->dport = bpf_ntohs(BPF_CORE_READ(usin, sin_port));
        }
    }
    
    event->sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
    struct network_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_NETWORK_UDP_RECV;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    event->protocol = IPPROTO_UDP;
    
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->family = family;
    
    if (family == AF_INET) {
        event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    }
    
    event->sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";