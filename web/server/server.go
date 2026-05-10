package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Event struct {
	Type      string                 `json:"type"`
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

type Client struct {
	conn      *websocket.Conn
	send      chan Event
	sessionID string
}

type Server struct {
	clients    map[*Client]bool
	clientsMux sync.RWMutex
	register   chan *Client
	unregister chan *Client
	broadcast  chan Event
	eventChan  <-chan interface{}
	addr       string
}

func NewServer(addr string, eventChan <-chan interface{}) *Server {
	return &Server{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client, 10),
		unregister: make(chan *Client, 10),
		broadcast:  make(chan Event, 10000),
		eventChan:  eventChan,
		addr:       addr,
	}
}

func (s *Server) Start() {
	go s.run()
	go s.readEvents()

	router := gin.Default()
	router.Static("/static", "./web/static")
	router.GET("/", func(c *gin.Context) {
		c.File("./web/static/index.html")
	})
	router.GET("/ws", s.handleWebSocket)
	router.GET("/api/events", s.getRecentEvents)
	router.GET("/api/stats", s.getStats)

	log.Printf("Starting server on %s", s.addr)
	if err := router.Run(s.addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (s *Server) run() {
	for {
		select {
		case client := <-s.register:
			s.clientsMux.Lock()
			s.clients[client] = true
			s.clientsMux.Unlock()
			log.Printf("Client connected. Total clients: %d", len(s.clients))

		case client := <-s.unregister:
			s.clientsMux.Lock()
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				close(client.send)
			}
			s.clientsMux.Unlock()
			log.Printf("Client disconnected. Total clients: %d", len(s.clients))

		case event := <-s.broadcast:
			s.clientsMux.RLock()
			for client := range s.clients {
				select {
				case client.send <- event:
				default:
					close(client.send)
					delete(s.clients, client)
				}
			}
			s.clientsMux.RUnlock()
		}
	}
}

func (s *Server) readEvents() {
	for data := range s.eventChan {
		event := Event{
			Timestamp: time.Now().UnixNano(),
		}

		if m, ok := data.(map[string]interface{}); ok {
			if t, ok := m["type"].(string); ok {
				event.Type = t
			}
			if ts, ok := m["timestamp"]; ok {
				switch v := ts.(type) {
				case uint64:
					event.Timestamp = int64(v)
				case float64:
					event.Timestamp = int64(v)
				}
			}
			event.Data = m
		}

		addRecentEvent(event)

		select {
		case s.broadcast <- event:
		default:
		}
	}
}

func (s *Server) handleWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	client := &Client{
		conn:      conn,
		send:      make(chan Event, 100),
		sessionID: c.Query("session"),
	}

	s.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case event, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			data, err := json.Marshal(event)
			if err != nil {
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

type Stats struct {
	TotalClients int            `json:"total_clients"`
	EventCounts  map[string]int `json:"event_counts"`
	Uptime       int64          `json:"uptime"`
}

var startTime = time.Now()
var eventCounts = make(map[string]int)
var eventCountsMux sync.Mutex

func (s *Server) getStats(c *gin.Context) {
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

	c.JSON(http.StatusOK, stats)
}

type RecentEvent struct {
	Type      string                 `json:"type"`
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

var recentEvents []RecentEvent
var recentEventsMux sync.Mutex

func (s *Server) getRecentEvents(c *gin.Context) {
	recentEventsMux.Lock()
	events := make([]RecentEvent, len(recentEvents))
	copy(events, recentEvents)
	recentEventsMux.Unlock()

	c.JSON(http.StatusOK, events)
}

func addRecentEvent(event Event) {
	recentEventsMux.Lock()
	defer recentEventsMux.Unlock()

	recentEvents = append(recentEvents, event)
	if len(recentEvents) > 100 {
		recentEvents = recentEvents[len(recentEvents)-100:]
	}

	eventCountsMux.Lock()
	eventCounts[event.Type]++
	eventCountsMux.Unlock()
}

