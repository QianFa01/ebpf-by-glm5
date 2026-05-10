package bpf

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

type EventType uint32

const (
	EventTypeProcessFork      EventType = 0
	EventTypeProcessExec      EventType = 1
	EventTypeProcessExit      EventType = 2
	EventTypeProcessPrivilege EventType = 3
	EventTypeNetworkConnect   EventType = 4
	EventTypeNetworkAccept    EventType = 5
	EventTypeNetworkClose     EventType = 6
	EventTypeNetworkUdpSend   EventType = 7
	EventTypeNetworkUdpRecv   EventType = 8
	EventTypeFileCreate       EventType = 9
	EventTypeFileModify       EventType = 10
	EventTypeFileDelete       EventType = 11
	EventTypeFileRename       EventType = 12
	EventTypeFileChmod        EventType = 13
	EventTypeFileChown        EventType = 14
)

type ProcessEventRaw struct {
	Type         uint32
	Timestamp    uint64
	PID          uint32
	PPID         uint32
	TID          uint32
	UID          uint32
	GID          uint32
	Comm         [16]byte
	ParentComm   [16]byte
	Args         [256]byte
	ExitCode     int32
	Capabilities uint32
	ContainerID  [16]byte
}

type NetworkEventRaw struct {
	Type        uint32
	Timestamp   uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte
	Family      uint16
	Protocol    uint16
	Sport       uint16
	Dport       uint16
	SaddrV4     uint32
	DaddrV4     uint32
	SaddrV6     [16]byte
	DaddrV6     [16]byte
	UID         uint32
	GID         uint32
	ContainerID [16]byte
	State       uint8
	_           [3]byte
}

type FileEventRaw struct {
	Type        uint32
	Timestamp   uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte
	Path        [256]byte
	NewPath     [256]byte
	UID         uint32
	GID         uint32
	ContainerID [16]byte
	Mode        uint32
	OldMode     uint32
	NewUID      uint32
	NewGID      uint32
}

var eventTypeNames = map[uint32]string{
	0:  "fork",
	1:  "exec",
	2:  "exit",
	3:  "privilege",
	4:  "connect",
	5:  "accept",
	6:  "close",
	7:  "udp_send",
	8:  "udp_recv",
	9:  "create",
	10: "modify",
	11: "delete",
	12: "rename",
	13: "chmod",
	14: "chown",
}

func GetEventTypeName(t uint32) string {
	return eventTypeNames[t]
}

func IntToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func ParseProcessEvent(raw *ProcessEventRaw) map[string]interface{} {
	return map[string]interface{}{
		"type":         "process",
		"event_type":   GetEventTypeName(raw.Type),
		"timestamp":    raw.Timestamp,
		"pid":          raw.PID,
		"ppid":         raw.PPID,
		"tid":          raw.TID,
		"uid":          raw.UID,
		"gid":          raw.GID,
		"comm":         string(bytes.TrimRight(raw.Comm[:], "\x00")),
		"parent_comm":  string(bytes.TrimRight(raw.ParentComm[:], "\x00")),
		"args":         string(bytes.TrimRight(raw.Args[:], "\x00")),
		"exit_code":    raw.ExitCode,
		"capabilities": raw.Capabilities,
		"container_id": string(bytes.TrimRight(raw.ContainerID[:], "\x00")),
	}
}

func ParseNetworkEvent(raw *NetworkEventRaw) map[string]interface{} {
	event := map[string]interface{}{
		"type":         "network",
		"event_type":   GetEventTypeName(raw.Type),
		"timestamp":    raw.Timestamp,
		"pid":          raw.PID,
		"tid":          raw.TID,
		"comm":         string(bytes.TrimRight(raw.Comm[:], "\x00")),
		"family":       raw.Family,
		"protocol":     raw.Protocol,
		"sport":        raw.Sport,
		"dport":        raw.Dport,
		"uid":          raw.UID,
		"gid":          raw.GID,
		"container_id": string(bytes.TrimRight(raw.ContainerID[:], "\x00")),
		"state":        raw.State,
	}

	if raw.Family == 2 {
		event["src_ip"] = IntToIP(raw.SaddrV4)
		event["dst_ip"] = IntToIP(raw.DaddrV4)
	} else if raw.Family == 10 {
		event["src_ip"] = net.IP(raw.SaddrV6[:]).String()
		event["dst_ip"] = net.IP(raw.DaddrV6[:]).String()
	}

	return event
}

func ParseFileEvent(raw *FileEventRaw) map[string]interface{} {
	return map[string]interface{}{
		"type":         "file",
		"event_type":   GetEventTypeName(raw.Type),
		"timestamp":    raw.Timestamp,
		"pid":          raw.PID,
		"tid":          raw.TID,
		"comm":         string(bytes.TrimRight(raw.Comm[:], "\x00")),
		"path":         string(bytes.TrimRight(raw.Path[:], "\x00")),
		"new_path":     string(bytes.TrimRight(raw.NewPath[:], "\x00")),
		"uid":          raw.UID,
		"gid":          raw.GID,
		"container_id": string(bytes.TrimRight(raw.ContainerID[:], "\x00")),
		"mode":         raw.Mode,
		"old_mode":     raw.OldMode,
		"new_uid":      raw.NewUID,
		"new_gid":      raw.NewGID,
	}
}

func FormatTime(ns uint64) string {
	return time.Unix(0, int64(ns)).Format("2006-01-02 15:04:05.000")
}
