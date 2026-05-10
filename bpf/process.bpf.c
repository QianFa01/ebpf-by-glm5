#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} process_events SEC(".maps");

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

SEC("tp/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_event *event;
    
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_PROCESS_FORK;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = ctx->child_pid;
    event->ppid = ctx->parent_pid;
    event->tid = ctx->child_pid;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    BPF_CORE_READ_STR_INTO(&event->parent_comm, task, real_parent, comm);
    
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_PROCESS_EXEC;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    BPF_CORE_READ_STR_INTO(&event->parent_comm, task, real_parent, comm);
    
    const char __user *const __user *argv = (const char *const __user *)ctx->args[1];
    bpf_probe_read_user_str(event->args, MAX_ARGS_LEN, (const void *)argv);
    
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct process_event *event;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    if (pid != tid)
        return 0;

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_PROCESS_EXIT;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->exit_code = BPF_CORE_READ(task, exit_code) >> 8;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new)
{
    struct process_event *event;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 old_uid = BPF_CORE_READ(task, real_cred, uid.val);
    u32 new_uid = BPF_CORE_READ(new, uid.val);

    if (old_uid == 0 || new_uid != 0) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_PROCESS_PRIVILEGE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (u32)id;
    event->uid = old_uid;
    event->gid = BPF_CORE_READ(new, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    kernel_cap_t cap_effective = BPF_CORE_READ(new, cap_effective);
    event->capabilities = cap_effective.cap[0];
    
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";