package container

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var getCgroupPathForPID = func(pid uint32) string {
	return fmt.Sprintf("/proc/%d/cgroup", pid)
}

type ContainerInfo struct {
	ID        string
	Name      string
	Image     string
	PID       uint32
	Labels    map[string]string
}

type Detector struct {
	containers map[string]*ContainerInfo
	mu         sync.RWMutex
}

func NewDetector() *Detector {
	return &Detector{
		containers: make(map[string]*ContainerInfo),
	}
}

func (d *Detector) GetContainerID(pid uint32) string {
	cgroupPath := getCgroupPathForPID(pid)
	file, err := os.Open(cgroupPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				if len(part) == 64 {
					return part[:12]
				}
			}
		}
	}
	return ""
}

func (d *Detector) GetContainerInfo(containerID string) (*ContainerInfo, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	info, ok := d.containers[containerID]
	return info, ok
}

func (d *Detector) IsContainerPID(pid uint32) bool {
	cgroupPath := getCgroupPathForPID(pid)
	file, err := os.Open(cgroupPath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "docker") || 
		   strings.Contains(line, "containerd") ||
		   strings.Contains(line, "kubepods") {
			return true
		}
	}
	return false
}

func (d *Detector) Refresh() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	dockerPath := "/var/lib/docker/containers"
	if _, err := os.Stat(dockerPath); err == nil {
		entries, err := os.ReadDir(dockerPath)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() && len(entry.Name()) == 64 {
					containerID := entry.Name()[:12]
					configPath := filepath.Join(dockerPath, entry.Name(), "config.v2.json")
					if _, err := os.Stat(configPath); err == nil {
						d.containers[containerID] = &ContainerInfo{
							ID:     containerID,
							Labels: make(map[string]string),
						}
					}
				}
			}
		}
	}

	return nil
}

func (d *Detector) ListContainers() []*ContainerInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*ContainerInfo, 0, len(d.containers))
	for _, info := range d.containers {
		result = append(result, info)
	}
	return result
}