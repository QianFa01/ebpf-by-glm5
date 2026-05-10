#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_events SEC(".maps");

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

static __always_inline void get_file_path(struct file *file, char *path, u32 size)
{
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(path, size, d_name.name);
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(trace_vfs_create, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, umode_t mode, bool want_excl)
{
    struct file_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_FILE_CREATE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(event->path, MAX_PATH_LEN, d_name.name);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    event->mode = mode;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(trace_vfs_write, struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    struct file_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_FILE_MODIFY;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(event->path, MAX_PATH_LEN, d_name.name);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(trace_vfs_unlink, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry)
{
    struct file_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_FILE_DELETE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(event->path, MAX_PATH_LEN, d_name.name);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/vfs_rename)
int BPF_KPROBE(trace_vfs_rename, struct renamedata *rd)
{
    struct file_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_FILE_RENAME;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    
    struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
    struct qstr old_name = BPF_CORE_READ(old_dentry, d_name);
    bpf_probe_read_kernel_str(event->path, MAX_PATH_LEN, old_name.name);
    
    struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);
    struct qstr new_name = BPF_CORE_READ(new_dentry, d_name);
    bpf_probe_read_kernel_str(event->new_path, MAX_PATH_LEN, new_name.name);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/notify_change")
int BPF_KPROBE(trace_notify_change, struct dentry *dentry, struct iattr *attr)
{
    struct file_event *event;
    u64 id = bpf_get_current_pid_tgid();
    
    unsigned int ia_valid = BPF_CORE_READ(attr, ia_valid);
    
    if (!(ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)))
        return 0;
    
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    if (ia_valid & ATTR_MODE) {
        event->type = EVENT_FILE_CHMOD;
        event->mode = BPF_CORE_READ(attr, ia_mode);
    } else {
        event->type = EVENT_FILE_CHOWN;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(event->path, MAX_PATH_LEN, d_name.name);
    
    event->new_uid = BPF_CORE_READ(attr, ia_uid.val);
    event->new_gid = BPF_CORE_READ(attr, ia_gid.val);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->uid = BPF_CORE_READ(task, cred, uid.val);
    event->gid = BPF_CORE_READ(task, cred, gid.val);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(event->container_id);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";