#ifndef __COMMON_H__
#define __COMMON_H__

#define TASK_COMM_LEN 16
#define MAX_ARGS_LEN 256
#define MAX_PATH_LEN 256
#define MAX_CONTAINER_ID 16

enum event_type {
    EVENT_PROCESS_FORK = 0,
    EVENT_PROCESS_EXEC = 1,
    EVENT_PROCESS_EXIT = 2,
    EVENT_PROCESS_PRIVILEGE = 3,
    EVENT_NETWORK_CONNECT = 4,
    EVENT_NETWORK_ACCEPT = 5,
    EVENT_NETWORK_CLOSE = 6,
    EVENT_NETWORK_UDP_SEND = 7,
    EVENT_NETWORK_UDP_RECV = 8,
    EVENT_FILE_CREATE = 9,
    EVENT_FILE_MODIFY = 10,
    EVENT_FILE_DELETE = 11,
    EVENT_FILE_RENAME = 12,
    EVENT_FILE_CHMOD = 13,
    EVENT_FILE_CHOWN = 14,
};

struct process_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char args[MAX_ARGS_LEN];
    __s32 exit_code;
    __u32 capabilities;
    char container_id[MAX_CONTAINER_ID];
};

struct network_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    char comm[TASK_COMM_LEN];
    __u16 family;
    __u16 protocol;
    __u16 sport;
    __u16 dport;
    __u32 saddr_v4;
    __u32 daddr_v4;
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u32 uid;
    __u32 gid;
    char container_id[MAX_CONTAINER_ID];
    __u8 state;
};

struct file_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
    char new_path[MAX_PATH_LEN];
    __u32 uid;
    __u32 gid;
    char container_id[MAX_CONTAINER_ID];
    __u32 mode;
    __u32 old_mode;
    __u32 new_uid;
    __u32 new_gid;
};

#endif