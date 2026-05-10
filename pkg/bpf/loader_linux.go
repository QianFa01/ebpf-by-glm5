//go:build linux

package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type EventType uint32

const (
	EventTypeProcessFork     EventType = 0
	EventTypeProcessExec     EventType = 1
	EventTypeProcessExit     EventType = 2
	EventTypeProcessPrivilege EventType = 3
	EventTypeNetworkConnect  EventType = 4
	EventTypeNetworkAccept   EventType = 5
	EventTypeNetworkClose    EventType = 6
	EventTypeNetworkUdpSend  EventType = 7
	EventTypeNetworkUdpRecv  EventType = 8
	EventTypeFileCreate      EventType = 9
	EventTypeFileModify      EventType = 10
	EventTypeFileDelete      EventType = 11
	EventTypeFileRename      EventType = 12
	EventTypeFileChmod       EventType = 13
	EventTypeFileChown       EventType = 14
)

type BpfLoader struct {
	objs      *bpfObjects
	links     []link.Link
	rings     []*ringbuf.Reader
	eventChan chan map[string]interface{}
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

type ProcessEventRaw struct {
	Type        uint32
	Timestamp   uint64
	PID         uint32
	PPID        uint32
	TID         uint32
	UID         uint32
	GID         uint32
	Comm        [16]byte
	ParentComm  [16]byte
	Args        [256]byte
	ExitCode    int32
	Capabilities uint32
	ContainerID [16]byte
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

func NewBpfLoader() (*BpfLoader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %v", err)
	}

	objs := &bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF spec: %v", err)
	}

	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %v", err)
	}

	return &BpfLoader{
		objs:      objs,
		eventChan: make(chan map[string]interface{}, 10000),
		stopChan:  make(chan struct{}),
	}, nil
}

func (l *BpfLoader) Attach() error {
	tpFork, err := link.Tracepoint("sched", "sched_process_fork", l.objs.TraceSchedProcessFork, nil)
	if err != nil {
		return fmt.Errorf("failed to attach fork tracepoint: %v", err)
	}
	l.links = append(l.links, tpFork)

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", l.objs.TraceExecve, nil)
	if err != nil {
		return fmt.Errorf("failed to attach execve tracepoint: %v", err)
	}
	l.links = append(l.links, tpExec)

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", l.objs.TraceSchedProcessExit, nil)
	if err != nil {
		return fmt.Errorf("failed to attach exit tracepoint: %v", err)
	}
	l.links = append(l.links, tpExit)

	kpCommit, err := link.Kprobe("commit_creds", l.objs.TraceCommitCreds, nil)
	if err != nil {
		return fmt.Errorf("failed to attach commit_creds kprobe: %v", err)
	}
	l.links = append(l.links, kpCommit)

	kpTcpConn, err := link.Kprobe("tcp_v4_connect", l.objs.TraceTcpV4Connect, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_v4_connect kprobe: %v", err)
	}
	l.links = append(l.links, kpTcpConn)

	kpTcpState, err := link.Kprobe("tcp_set_state", l.objs.TraceTcpSetState, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_set_state kprobe: %v", err)
	}
	l.links = append(l.links, kpTcpState)

	kpUdpSend, err := link.Kprobe("udp_sendmsg", l.objs.TraceUdpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach udp_sendmsg kprobe: %v", err)
	}
	l.links = append(l.links, kpUdpSend)

	kpUdpRecv, err := link.Kprobe("udp_recvmsg", l.objs.TraceUdpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach udp_recvmsg kprobe: %v", err)
	}
	l.links = append(l.links, kpUdpRecv)

	kpVfsCreate, err := link.Kprobe("vfs_create", l.objs.TraceVfsCreate, nil)
	if err != nil {
		return fmt.Errorf("failed to attach vfs_create kprobe: %v", err)
	}
	l.links = append(l.links, kpVfsCreate)

	kpVfsWrite, err := link.Kprobe("vfs_write", l.objs.TraceVfsWrite, nil)
	if err != nil {
		return fmt.Errorf("failed to attach vfs_write kprobe: %v", err)
	}
	l.links = append(l.links, kpVfsWrite)

	kpVfsUnlink, err := link.Kprobe("vfs_unlink", l.objs.TraceVfsUnlink, nil)
	if err != nil {
		return fmt.Errorf("failed to attach vfs_unlink kprobe: %v", err)
	}
	l.links = append(l.links, kpVfsUnlink)

	kpVfsRename, err := link.Kprobe("vfs_rename", l.objs.TraceVfsRename, nil)
	if err != nil {
		return fmt.Errorf("failed to attach vfs_rename kprobe: %v", err)
	}
	l.links = append(l.links, kpVfsRename)

	kpNotify, err := link.Kprobe("notify_change", l.objs.TraceNotifyChange, nil)
	if err != nil {
		return fmt.Errorf("failed to attach notify_change kprobe: %v", err)
	}
	l.links = append(l.links, kpNotify)

	processRing, err := ringbuf.NewReader(l.objs.ProcessEvents)
	if err != nil {
		return fmt.Errorf("failed to create process ring buffer: %v", err)
	}
	l.rings = append(l.rings, processRing)

	networkRing, err := ringbuf.NewReader(l.objs.NetworkEvents)
	if err != nil {
		return fmt.Errorf("failed to create network ring buffer: %v", err)
	}
	l.rings = append(l.rings, networkRing)

	fileRing, err := ringbuf.NewReader(l.objs.FileEvents)
	if err != nil {
		return fmt.Errorf("failed to create file ring buffer: %v", err)
	}
	l.rings = append(l.rings, fileRing)

	return nil
}

func (l *BpfLoader) Start() {
	l.wg.Add(3)
	go l.readProcessEvents()
	go l.readNetworkEvents()
	go l.readFileEvents()
}

func (l *BpfLoader) Stop() {
	close(l.stopChan)
	l.wg.Wait()

	for _, ring := range l.rings {
		ring.Close()
	}
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.objs.Close()
	close(l.eventChan)
}

func (l *BpfLoader) Events() <-chan map[string]interface{} {
	return l.eventChan
}

func (l *BpfLoader) readProcessEvents() {
	defer l.wg.Done()

	for {
		select {
		case <-l.stopChan:
			return
		default:
			record, err := l.rings[0].Read()
			if err != nil {
				continue
			}

			var raw ProcessEventRaw
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
				continue
			}

			event := l.parseProcessEvent(&raw)
			select {
			case l.eventChan <- event:
			default:
			}
		}
	}
}

func (l *BpfLoader) readNetworkEvents() {
	defer l.wg.Done()

	for {
		select {
		case <-l.stopChan:
			return
		default:
			record, err := l.rings[1].Read()
			if err != nil {
				continue
			}

			var raw NetworkEventRaw
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
				continue
			}

			event := l.parseNetworkEvent(&raw)
			select {
			case l.eventChan <- event:
			default:
			}
		}
	}
}

func (l *BpfLoader) readFileEvents() {
	defer l.wg.Done()

	for {
		select {
		case <-l.stopChan:
			return
		default:
			record, err := l.rings[2].Read()
			if err != nil {
				continue
			}

			var raw FileEventRaw
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
				continue
			}

			event := l.parseFileEvent(&raw)
			select {
			case l.eventChan <- event:
			default:
			}
		}
	}
}

func (l *BpfLoader) parseProcessEvent(raw *ProcessEventRaw) map[string]interface{} {
	return map[string]interface{}{
		"type":         "process",
		"event_type":   getEventTypeName(raw.Type),
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

func (l *BpfLoader) parseNetworkEvent(raw *NetworkEventRaw) map[string]interface{} {
	event := map[string]interface{}{
		"type":         "network",
		"event_type":   getEventTypeName(raw.Type),
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
		event["src_ip"] = intToIP(raw.SaddrV4)
		event["dst_ip"] = intToIP(raw.DaddrV4)
	} else if raw.Family == 10 {
		event["src_ip"] = net.IP(raw.SaddrV6[:]).String()
		event["dst_ip"] = net.IP(raw.DaddrV6[:]).String()
	}

	return event
}

func (l *BpfLoader) parseFileEvent(raw *FileEventRaw) map[string]interface{} {
	return map[string]interface{}{
		"type":         "file",
		"event_type":   getEventTypeName(raw.Type),
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

func getEventTypeName(t uint32) string {
	names := map[uint32]string{
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
	return names[t]
}

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func formatTime(ns uint64) string {
	return time.Unix(0, int64(ns)).Format("2006-01-02 15:04:05.000")
}