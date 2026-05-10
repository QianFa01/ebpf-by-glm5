package event

const (
	EventTypeProcessFork = iota
	EventTypeProcessExec
	EventTypeProcessExit
	EventTypeProcessPrivilege
	EventTypeNetworkConnect
	EventTypeNetworkAccept
	EventTypeNetworkClose
	EventTypeNetworkUdpSend
	EventTypeNetworkUdpRecv
	EventTypeFileCreate
	EventTypeFileModify
	EventTypeFileDelete
	EventTypeFileRename
	EventTypeFileChmod
	EventTypeFileChown
)

type ProcessEvent struct {
	Type        uint32 `json:"type"`
	Timestamp   uint64 `json:"timestamp"`
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	TID         uint32 `json:"tid"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Comm        string `json:"comm"`
	ParentComm  string `json:"parent_comm"`
	Args        string `json:"args"`
	ExitCode    int32  `json:"exit_code"`
	Capabilities uint32 `json:"capabilities"`
	ContainerID string `json:"container_id"`
}

type NetworkEvent struct {
	Type        uint32 `json:"type"`
	Timestamp   uint64 `json:"timestamp"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	Comm        string `json:"comm"`
	Family      uint16 `json:"family"`
	Protocol    uint16 `json:"protocol"`
	Sport       uint16 `json:"sport"`
	Dport       uint16 `json:"dport"`
	SaddrV4     uint32 `json:"saddr_v4"`
	DaddrV4     uint32 `json:"daddr_v4"`
	SaddrV6     string `json:"saddr_v6"`
	DaddrV6     string `json:"daddr_v6"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	ContainerID string `json:"container_id"`
	State       uint8  `json:"state"`
}

type FileEvent struct {
	Type        uint32 `json:"type"`
	Timestamp   uint64 `json:"timestamp"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	Comm        string `json:"comm"`
	Path        string `json:"path"`
	NewPath     string `json:"new_path"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	ContainerID string `json:"container_id"`
	Mode        uint32 `json:"mode"`
	OldMode     uint32 `json:"old_mode"`
	NewUID      uint32 `json:"new_uid"`
	NewGID      uint32 `json:"new_gid"`
}

type Event struct {
	Type      string      `json:"type"`
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"data"`
}

func GetEventTypeName(eventType uint32) string {
	names := map[uint32]string{
		EventTypeProcessFork:     "process_fork",
		EventTypeProcessExec:    "process_exec",
		EventTypeProcessExit:    "process_exit",
		EventTypeProcessPrivilege: "process_privilege",
		EventTypeNetworkConnect: "network_connect",
		EventTypeNetworkAccept:  "network_accept",
		EventTypeNetworkClose:   "network_close",
		EventTypeNetworkUdpSend: "network_udp_send",
		EventTypeNetworkUdpRecv: "network_udp_recv",
		EventTypeFileCreate:     "file_create",
		EventTypeFileModify:     "file_modify",
		EventTypeFileDelete:     "file_delete",
		EventTypeFileRename:     "file_rename",
		EventTypeFileChmod:      "file_chmod",
		EventTypeFileChown:      "file_chown",
	}
	return names[eventType]
}