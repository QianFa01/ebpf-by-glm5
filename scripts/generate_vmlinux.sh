#!/bin/bash

set -e

echo "=== Generating vmlinux.h ==="
if ! command -v bpftool &> /dev/null; then
    echo "bpftool not found, installing..."
    sudo apt-get install -y bpftool || {
        echo "Failed to install bpftool, trying alternative method..."
        sudo apt-get install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r)
    }
fi

BTF_ID=$(bpftool btf list | grep "name: vmlinux" | awk '{print $1}' | cut -d: -f2)
if [ -z "$BTF_ID" ]; then
    echo "No BTF found for vmlinux, trying to generate from kernel..."
    bpftool btf dump cformat id 0 > bpf/vmlinux.h || {
        echo "Warning: Could not generate vmlinux.h, using fallback method..."
        cat > bpf/vmlinux.h << 'EOF'
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

struct task_struct {
    int pid;
    int tgid;
    struct task_struct *real_parent;
    struct cred *cred;
    struct nsproxy *nsproxy;
    char comm[16];
    int exit_code;
};

struct cred {
    __u32 uid;
    __u32 gid;
    __u32 suid;
    __u32 sgid;
    __u32 euid;
    __u32 egid;
    __u32 fsuid;
    __u32 fsgid;
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;
    kernel_cap_t cap_ambient;
};

struct kernel_cap_struct {
    __u32 cap[2];
};

typedef struct kernel_cap_struct kernel_cap_t;

struct nsproxy {
    struct uts_namespace *uts_ns;
    struct ipc_namespace *ipc_ns;
    struct mnt_namespace *mnt_ns;
    struct pid_namespace *pid_ns_for_children;
    struct net *net_ns;
};

struct uts_namespace {
    struct new_utsname name;
};

struct new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct sock {
    struct __sk_common __sk_common;
};

struct __sk_common {
    __u32 skc_rcv_saddr;
    __u32 skc_daddr;
    __u16 skc_num;
    __u16 skc_dport;
    __u16 skc_family;
};

struct file {
    struct path f_path;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct dentry {
    struct qstr d_name;
    struct inode *d_inode;
};

struct qstr {
    const char *name;
};

struct inode {
    __u32 i_mode;
};

struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

struct msghdr {
    void *msg_name;
};

struct iattr {
    __u32 ia_valid;
    __u32 ia_mode;
    struct {
        __u32 val;
    } ia_uid;
    struct {
        __u32 val;
    } ia_gid;
};

#define ATTR_MODE    (1 << 0)
#define ATTR_UID     (1 << 1)
#define ATTR_GID     (1 << 2)

#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

#define TCP_ESTABLISHED  1
#define TCP_CLOSE        7

#define S_IFREG   0100000

#endif
EOF
    }
else
    bpftool btf dump cformat id 0 > bpf/vmlinux.h
fi

echo "=== vmlinux.h generated ==="
ls -lh bpf/vmlinux.h