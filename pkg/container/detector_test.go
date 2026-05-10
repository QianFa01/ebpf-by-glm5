package container

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempCgroup(t *testing.T, dir string, pid int, content string) {
	t.Helper()
	procDir := filepath.Join(dir, "proc", string(rune('0'+pid)))
	if pid >= 10 {
		procDir = filepath.Join(dir, "proc", "1")
	}
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestGetContainerID_Docker(t *testing.T) {
	detector := NewDetector()
	cgroupContent := "12:devices:/docker/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc", "123")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
		t.Fatal(err)
	}

	origGetCgroupPath := getCgroupPathForPID
	getCgroupPathForPID = func(pid uint32) string {
		return filepath.Join(tmpDir, "proc", "123", "cgroup")
	}
	defer func() { getCgroupPathForPID = origGetCgroupPath }()

	cid := detector.GetContainerID(123)
	if cid != "abcdef123456" {
		t.Errorf("GetContainerID = %q, want %q", cid, "abcdef123456")
	}
}

func TestGetContainerID_NoContainer(t *testing.T) {
	detector := NewDetector()
	cgroupContent := "12:devices:/system.slice/sshd.service"

	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc", "456")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
		t.Fatal(err)
	}

	origGetCgroupPath := getCgroupPathForPID
	getCgroupPathForPID = func(pid uint32) string {
		return filepath.Join(tmpDir, "proc", "456", "cgroup")
	}
	defer func() { getCgroupPathForPID = origGetCgroupPath }()

	cid := detector.GetContainerID(456)
	if cid != "" {
		t.Errorf("GetContainerID = %q, want empty", cid)
	}
}

func TestIsContainerPID_Docker(t *testing.T) {
	detector := NewDetector()
	cgroupContent := "12:devices:/docker/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc", "789")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
		t.Fatal(err)
	}

	origGetCgroupPath := getCgroupPathForPID
	getCgroupPathForPID = func(pid uint32) string {
		return filepath.Join(tmpDir, "proc", "789", "cgroup")
	}
	defer func() { getCgroupPathForPID = origGetCgroupPath }()

	if !detector.IsContainerPID(789) {
		t.Error("IsContainerPID should return true for docker cgroup")
	}
}

func TestIsContainerPID_Kubepods(t *testing.T) {
	detector := NewDetector()
	cgroupContent := "12:devices:/kubepods/besteffort/pod123/container456"

	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc", "100")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
		t.Fatal(err)
	}

	origGetCgroupPath := getCgroupPathForPID
	getCgroupPathForPID = func(pid uint32) string {
		return filepath.Join(tmpDir, "proc", "100", "cgroup")
	}
	defer func() { getCgroupPathForPID = origGetCgroupPath }()

	if !detector.IsContainerPID(100) {
		t.Error("IsContainerPID should return true for kubepods cgroup")
	}
}

func TestIsContainerPID_Host(t *testing.T) {
	detector := NewDetector()
	cgroupContent := "12:devices:/system.slice/cron.service"

	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc", "1")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
		t.Fatal(err)
	}

	origGetCgroupPath := getCgroupPathForPID
	getCgroupPathForPID = func(pid uint32) string {
		return filepath.Join(tmpDir, "proc", "1", "cgroup")
	}
	defer func() { getCgroupPathForPID = origGetCgroupPath }()

	if detector.IsContainerPID(1) {
		t.Error("IsContainerPID should return false for host process")
	}
}
