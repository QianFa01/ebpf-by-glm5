package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf process.bpf.c network.bpf.c file.bpf.c -- -I./headers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

type BpfLoader struct {
	objs      *bpfObjects
	links     []link.Link
	eventChan chan interface{}
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

type ProcessEventData struct {
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

type NetworkEventData struct {
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
}

type FileEventData struct {
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
	if err := loadBpfObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %v", err)
	}

	return &BpfLoader{
		objs:      objs,
		eventChan: make(chan interface{}, 10000),
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
		l.objs.Close()
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

	kpNotifyChange, err := link.Kprobe("notify_change", l.objs.TraceNotifyChange, nil)
	if err != nil {
		return fmt.Errorf("failed to attach notify_change kprobe: %v", err)
	}
	l.links = append(l.links, kpNotifyChange)

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

	for _, link := range l.links {
		link.Close()
	}
	l.objs.Close()
	close(l.eventChan)
}

func (l *BpfLoader) Events() <-chan interface{} {
	return l.eventChan
}

func (l *BpfLoader) readProcessEvents() {
	defer l.wg.Done()

	reader, err := ringbuf.NewReader(l.objs.ProcessEvents)
	if err != nil {
		return
	}
	defer reader.Close()

	for {
		select {
		case <-l.stopChan:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				continue
			}

			var event ProcessEventData
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			select {
			case l.eventChan <- l.parseProcessEvent(&event):
			default:
			}
		}
	}
}

func (l *BpfLoader) readNetworkEvents() {
	defer l.wg.Done()

	reader, err := ringbuf.NewReader(l.objs.NetworkEvents)
	if err != nil {
		return
	}
	defer reader.Close()

	for {
		select {
		case <-l.stopChan:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				continue
			}

			var event NetworkEventData
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			select {
			case l.eventChan <- l.parseNetworkEvent(&event):
			default:
			}
		}
	}
}

func (l *BpfLoader) readFileEvents() {
	defer l.wg.Done()

	reader, err := ringbuf.NewReader(l.objs.FileEvents)
	if err != nil {
		return
	}
	defer reader.Close()

	for {
		select {
		case <-l.stopChan:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				continue
			}

			var event FileEventData
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			select {
			case l.eventChan <- l.parseFileEvent(&event):
			default:
			}
		}
	}
}

func (l *BpfLoader) parseProcessEvent(e *ProcessEventData) map[string]interface{} {
	return map[string]interface{}{
		"type":         "process",
		"event_type":   getEventTypeName(e.Type),
		"timestamp":    time.Unix(0, int64(e.Timestamp)).Format(time.RFC3339Nano),
		"pid":          e.PID,
		"ppid":         e.PPID,
		"tid":          e.TID,
		"uid":          e.UID,
		"gid":          e.GID,
		"comm":         string(bytes.TrimRight(e.Comm[:], "\x00")),
		"parent_comm":  string(bytes.TrimRight(e.ParentComm[:], "\x00")),
		"args":         string(bytes.TrimRight(e.Args[:], "\x00")),
		"exit_code":    e.ExitCode,
		"capabilities": e.Capabilities,
		"container_id": string(bytes.TrimRight(e.ContainerID[:], "\x00")),
	}
}

func (l *BpfLoader) parseNetworkEvent(e *NetworkEventData) map[string]interface{} {
	event := map[string]interface{}{
		"type":         "network",
		"event_type":   getEventTypeName(e.Type),
		"timestamp":    time.Unix(0, int64(e.Timestamp)).Format(time.RFC3339Nano),
		"pid":          e.PID,
		"tid":          e.TID,
		"comm":         string(bytes.TrimRight(e.Comm[:], "\x00")),
		"family":       e.Family,
		"protocol":     e.Protocol,
		"sport":        e.Sport,
		"dport":        e.Dport,
		"uid":          e.UID,
		"gid":          e.GID,
		"container_id": string(bytes.TrimRight(e.ContainerID[:], "\x00")),
		"state":        e.State,
	}

	if e.Family == 2 {
		event["src_ip"] = intToIP(e.SaddrV4)
		event["dst_ip"] = intToIP(e.DaddrV4)
	} else if e.Family == 10 {
		event["src_ip"] = net.IP(e.SaddrV6[:]).String()
		event["dst_ip"] = net.IP(e.DaddrV6[:]).String()
	}

	return event
}

func (l *BpfLoader) parseFileEvent(e *FileEventData) map[string]interface{} {
	return map[string]interface{}{
		"type":         "file",
		"event_type":   getEventTypeName(e.Type),
		"timestamp":    time.Unix(0, int64(e.Timestamp)).Format(time.RFC3339Nano),
		"pid":          e.PID,
		"tid":          e.TID,
		"comm":         string(bytes.TrimRight(e.Comm[:], "\x00")),
		"path":         string(bytes.TrimRight(e.Path[:], "\x00")),
		"new_path":     string(bytes.TrimRight(e.NewPath[:], "\x00")),
		"uid":          e.UID,
		"gid":          e.GID,
		"container_id": string(bytes.TrimRight(e.ContainerID[:], "\x00")),
		"mode":         e.Mode,
		"old_mode":     e.OldMode,
		"new_uid":      e.NewUID,
		"new_gid":      e.NewGID,
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