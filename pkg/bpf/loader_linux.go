//go:build linux

package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type BpfLoader struct {
	objs      *bpfObjects
	links     []link.Link
	rings     []*ringbuf.Reader
	eventChan chan map[string]interface{}
	stopChan  chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
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
	l.stopOnce.Do(func() {
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
	})
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
			select {
			case l.eventChan <- ParseProcessEvent(&raw):
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
			select {
			case l.eventChan <- ParseNetworkEvent(&raw):
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
			select {
			case l.eventChan <- ParseFileEvent(&raw):
			default:
			}
		}
	}
}
