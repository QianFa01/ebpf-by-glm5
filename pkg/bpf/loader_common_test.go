package bpf

import (
	"testing"
)

func TestGetEventTypeName(t *testing.T) {
	tests := []struct {
		input    uint32
		expected string
	}{
		{0, "fork"}, {1, "exec"}, {2, "exit"}, {3, "privilege"},
		{4, "connect"}, {5, "accept"}, {6, "close"},
		{7, "udp_send"}, {8, "udp_recv"},
		{9, "create"}, {10, "modify"}, {11, "delete"},
		{12, "rename"}, {13, "chmod"}, {14, "chown"},
		{99, ""}, {100, ""},
	}
	for _, tt := range tests {
		result := GetEventTypeName(tt.input)
		if result != tt.expected {
			t.Errorf("GetEventTypeName(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIntToIP(t *testing.T) {
	tests := []struct {
		input    uint32
		expected string
	}{
		{0x0100007F, "127.0.0.1"},
		{0x00000000, "0.0.0.0"},
		{0x0A00A8C0, "192.168.0.10"},
		{0x0101A8C0, "192.168.1.1"},
		{0x00000A0A, "10.10.0.0"},
	}
	for _, tt := range tests {
		result := IntToIP(tt.input)
		if result != tt.expected {
			t.Errorf("IntToIP(0x%08X) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseProcessEvent(t *testing.T) {
	raw := &ProcessEventRaw{
		Type:      0,
		Timestamp: 1234567890,
		PID:       100,
		PPID:      1,
		TID:        100,
		UID:        1000,
		GID:        1000,
		ExitCode:   0,
		Capabilities: 0,
	}
	copy(raw.Comm[:], "test-process\x00")
	copy(raw.ParentComm[:], "init\x00")
	copy(raw.Args[:], "--flag=value\x00")
	copy(raw.ContainerID[:], "abc123def456\x00")

	result := ParseProcessEvent(raw)

	if result["type"] != "process" {
		t.Errorf("type = %v, want process", result["type"])
	}
	if result["event_type"] != "fork" {
		t.Errorf("event_type = %v, want fork", result["event_type"])
	}
	if result["timestamp"] != uint64(1234567890) {
		t.Errorf("timestamp = %v, want 1234567890", result["timestamp"])
	}
	if result["pid"] != uint32(100) {
		t.Errorf("pid = %v, want 100", result["pid"])
	}
	if result["ppid"] != uint32(1) {
		t.Errorf("ppid = %v, want 1", result["ppid"])
	}
	if result["comm"] != "test-process" {
		t.Errorf("comm = %q, want %q", result["comm"], "test-process")
	}
	if result["parent_comm"] != "init" {
		t.Errorf("parent_comm = %q, want %q", result["parent_comm"], "init")
	}
	if result["args"] != "--flag=value" {
		t.Errorf("args = %q, want %q", result["args"], "--flag=value")
	}
	if result["container_id"] != "abc123def456" {
		t.Errorf("container_id = %q, want %q", result["container_id"], "abc123def456")
	}
}

func TestParseNetworkEvent_IPv4(t *testing.T) {
	raw := &NetworkEventRaw{
		Type:      4,
		Timestamp: 9876543210,
		PID:       200,
		TID:        200,
		Family:     2,
		Protocol:   6,
		Sport:      12345,
		Dport:      80,
		SaddrV4:    0x0100007F,
		DaddrV4:    0x0A00A8C0,
		UID:        0,
		GID:        0,
		State:      1,
	}
	copy(raw.Comm[:], "curl\x00")

	result := ParseNetworkEvent(raw)

	if result["type"] != "network" {
		t.Errorf("type = %v, want network", result["type"])
	}
	if result["event_type"] != "connect" {
		t.Errorf("event_type = %v, want connect", result["event_type"])
	}
	if result["src_ip"] != "127.0.0.1" {
		t.Errorf("src_ip = %q, want 127.0.0.1", result["src_ip"])
	}
	if result["dst_ip"] != "192.168.0.10" {
		t.Errorf("dst_ip = %q, want 192.168.0.10", result["dst_ip"])
	}
	if result["sport"] != uint16(12345) {
		t.Errorf("sport = %v, want 12345", result["sport"])
	}
	if result["dport"] != uint16(80) {
		t.Errorf("dport = %v, want 80", result["dport"])
	}
}

func TestParseNetworkEvent_NoIPv4(t *testing.T) {
	raw := &NetworkEventRaw{
		Type:   4,
		PID:    200,
		Family: 0,
	}
	copy(raw.Comm[:], "test\x00")

	result := ParseNetworkEvent(raw)

	if _, ok := result["src_ip"]; ok {
		t.Error("src_ip should not be present for non-IPv4/IPv6 family")
	}
	if _, ok := result["dst_ip"]; ok {
		t.Error("dst_ip should not be present for non-IPv4/IPv6 family")
	}
}

func TestParseFileEvent(t *testing.T) {
	raw := &FileEventRaw{
		Type:      9,
		Timestamp: 1111111111,
		PID:       300,
		TID:       300,
		UID:       0,
		GID:       0,
		Mode:      0644,
		OldMode:   0755,
		NewUID:    1000,
		NewGID:    1000,
	}
	copy(raw.Comm[:], "touch\x00")
	copy(raw.Path[:], "/tmp/test.txt\x00")
	copy(raw.NewPath[:], "\x00")
	copy(raw.ContainerID[:], "\x00")

	result := ParseFileEvent(raw)

	if result["type"] != "file" {
		t.Errorf("type = %v, want file", result["type"])
	}
	if result["event_type"] != "create" {
		t.Errorf("event_type = %v, want create", result["event_type"])
	}
	if result["path"] != "/tmp/test.txt" {
		t.Errorf("path = %q, want /tmp/test.txt", result["path"])
	}
	if result["mode"] != uint32(0644) {
		t.Errorf("mode = %v, want 420", result["mode"])
	}
}

func TestParseProcessEvent_CommTrimming(t *testing.T) {
	raw := &ProcessEventRaw{Type: 1}
	copy(raw.Comm[:], "short\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	result := ParseProcessEvent(raw)
	if result["comm"] != "short" {
		t.Errorf("comm = %q, want %q", result["comm"], "short")
	}
}

func TestFormatTime(t *testing.T) {
	ns := uint64(1609459200000000000)
	result := FormatTime(ns)
	if result != "2021-01-01 00:00:00.000" {
		t.Errorf("FormatTime = %q, want %q", result, "2021-01-01 00:00:00.000")
	}
}
