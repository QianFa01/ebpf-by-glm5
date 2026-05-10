package event

import "testing"

func TestEventTypeConstants(t *testing.T) {
	expected := map[int]uint32{
		0:  0,
		1:  1,
		2:  2,
		3:  3,
		4:  4,
		5:  5,
		6:  6,
		7:  7,
		8:  8,
		9:  9,
		10: 10,
		11: 11,
		12: 12,
		13: 13,
		14: 14,
	}
	constants := []uint32{
		EventTypeProcessFork,
		EventTypeProcessExec,
		EventTypeProcessExit,
		EventTypeProcessPrivilege,
		EventTypeNetworkConnect,
		EventTypeNetworkAccept,
		EventTypeNetworkClose,
		EventTypeNetworkUdpSend,
		EventTypeNetworkUdpRecv,
		EventTypeFileCreate,
		EventTypeFileModify,
		EventTypeFileDelete,
		EventTypeFileRename,
		EventTypeFileChmod,
		EventTypeFileChown,
	}
	for i, c := range constants {
		if c != expected[i] {
			t.Errorf("constant[%d] = %d, want %d", i, c, expected[i])
		}
	}
}

func TestGetEventTypeName(t *testing.T) {
	tests := []struct {
		input    uint32
		expected string
	}{
		{EventTypeProcessFork, "process_fork"},
		{EventTypeProcessExec, "process_exec"},
		{EventTypeProcessExit, "process_exit"},
		{EventTypeProcessPrivilege, "process_privilege"},
		{EventTypeNetworkConnect, "network_connect"},
		{EventTypeNetworkAccept, "network_accept"},
		{EventTypeNetworkClose, "network_close"},
		{EventTypeNetworkUdpSend, "network_udp_send"},
		{EventTypeNetworkUdpRecv, "network_udp_recv"},
		{EventTypeFileCreate, "file_create"},
		{EventTypeFileModify, "file_modify"},
		{EventTypeFileDelete, "file_delete"},
		{EventTypeFileRename, "file_rename"},
		{EventTypeFileChmod, "file_chmod"},
		{EventTypeFileChown, "file_chown"},
		{99, ""},
	}
	for _, tt := range tests {
		result := GetEventTypeName(tt.input)
		if result != tt.expected {
			t.Errorf("GetEventTypeName(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
