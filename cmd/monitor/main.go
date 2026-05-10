package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ebpf-monitor/pkg/bpf"
	"github.com/ebpf-monitor/pkg/container"
	"github.com/ebpf-monitor/web/server"
)

func main() {
	detector := container.NewDetector()
	if err := detector.Refresh(); err != nil {
		log.Printf("Warning: failed to refresh container list: %v", err)
	}

	loader, err := bpf.NewBpfLoader()
	if err != nil {
		log.Fatalf("Failed to create BPF loader: %v", err)
	}

	if err := loader.Attach(); err != nil {
		log.Fatalf("Failed to attach BPF programs: %v", err)
	}
	defer loader.Stop()

	loader.Start()
	log.Println("eBPF monitoring started successfully")

	eventChan := make(chan interface{}, 10000)
	go func() {
		for event := range loader.Events() {
			if m, ok := event.(map[string]interface{}); ok {
				if pid, ok := m["pid"].(uint32); ok {
					if cid := detector.GetContainerID(pid); cid != "" {
						if existing, ok := m["container_id"].(string); !ok || existing == "" {
							m["container_id"] = cid
						}
					}
				}
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			select {
			case eventChan <- data:
			default:
			}
		}
	}()

	srv := server.NewServer(":8080", eventChan)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		loader.Stop()
		os.Exit(0)
	}()

	log.Println("Web interface available at http://localhost:8080")
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}