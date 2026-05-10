package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func resetState() {
	recentEventsMux.Lock()
	recentEvents = nil
	recentEventsMux.Unlock()
	eventCountsMux.Lock()
	eventCounts = make(map[string]int)
	eventCountsMux.Unlock()
}

func TestAddRecentEvent(t *testing.T) {
	resetState()
	event := Event{Type: "process", Timestamp: time.Now().UnixNano(), Data: map[string]interface{}{"pid": 1}}
	addRecentEvent(event)

	recentEventsMux.Lock()
	count := len(recentEvents)
	recentEventsMux.Unlock()

	if count != 1 {
		t.Errorf("recentEvents count = %d, want 1", count)
	}
}

func TestGetRecentEvents_Empty(t *testing.T) {
	resetState()
	events := getRecentEventsCopy()
	if len(events) != 0 {
		t.Errorf("expected empty events, got %d", len(events))
	}
}

func TestGetRecentEvents_WithEvents(t *testing.T) {
	resetState()
	for i := 0; i < 3; i++ {
		addRecentEvent(Event{Type: "process", Timestamp: int64(i)})
	}
	events := getRecentEventsCopy()
	if len(events) != 3 {
		t.Errorf("events count = %d, want 3", len(events))
	}
}

func TestGetRecentEvents_MaxHundred(t *testing.T) {
	resetState()
	for i := 0; i < 150; i++ {
		addRecentEvent(Event{Type: "process", Timestamp: int64(i)})
	}
	events := getRecentEventsCopy()
	if len(events) != 100 {
		t.Errorf("events count = %d, want 100", len(events))
	}
	if events[0].Timestamp != 50 {
		t.Errorf("first event timestamp = %d, want 50", events[0].Timestamp)
	}
}

func TestAddRecentEvent_UpdatesCounts(t *testing.T) {
	resetState()
	addRecentEvent(Event{Type: "process"})
	addRecentEvent(Event{Type: "process"})
	addRecentEvent(Event{Type: "network"})

	eventCountsMux.Lock()
	processCount := eventCounts["process"]
	networkCount := eventCounts["network"]
	eventCountsMux.Unlock()

	if processCount != 2 {
		t.Errorf("process count = %d, want 2", processCount)
	}
	if networkCount != 1 {
		t.Errorf("network count = %d, want 1", networkCount)
	}
}

func getRecentEventsCopy() []RecentEvent {
	recentEventsMux.Lock()
	events := make([]RecentEvent, len(recentEvents))
	copy(events, recentEvents)
	recentEventsMux.Unlock()
	return events
}

func TestGetStats_HTTP(t *testing.T) {
	resetState()
	s := &Server{
		clients:    make(map[*Client]bool),
		clientsMux: sync.RWMutex{},
	}

	router := http.NewServeMux()
	router.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		s.clientsMux.RLock()
		totalClients := len(s.clients)
		s.clientsMux.RUnlock()

		eventCountsMux.Lock()
		counts := make(map[string]int)
		for k, v := range eventCounts {
			counts[k] = v
		}
		eventCountsMux.Unlock()

		stats := Stats{
			TotalClients: totalClients,
			EventCounts:  counts,
			Uptime:       int64(time.Since(startTime).Seconds()),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	addRecentEvent(Event{Type: "process"})

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var stats Stats
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.TotalClients != 0 {
		t.Errorf("TotalClients = %d, want 0", stats.TotalClients)
	}
}

func TestGetRecentEvents_HTTP(t *testing.T) {
	resetState()
	s := &Server{
		clients:    make(map[*Client]bool),
		clientsMux: sync.RWMutex{},
	}

	addRecentEvent(Event{Type: "process", Timestamp: 100})
	addRecentEvent(Event{Type: "network", Timestamp: 200})

	router := http.NewServeMux()
	router.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		recentEventsMux.Lock()
		events := make([]RecentEvent, len(recentEvents))
		copy(events, recentEvents)
		recentEventsMux.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	})

	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var events []RecentEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("events count = %d, want 2", len(events))
	}

	_ = s
}
