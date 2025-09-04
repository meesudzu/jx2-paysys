package server

import (
	"fmt"
	"log"
	"net"
	"sync"

	"jx2-paysys/internal/protocol"
)

// PaysysServer represents the main paysys server
type PaysysServer struct {
	ip       string
	port     int
	listener net.Listener
	handler  *protocol.Handler
	wg       sync.WaitGroup
	shutdown chan struct{}
}

// NewPaysysServer creates a new paysys server instance
func NewPaysysServer(ip string, port int, handler *protocol.Handler) *PaysysServer {
	return &PaysysServer{
		ip:       ip,
		port:     port,
		handler:  handler,
		shutdown: make(chan struct{}),
	}
}

// Start starts the paysys server
func (s *PaysysServer) Start() error {
	address := fmt.Sprintf("%s:%d", s.ip, s.port)
	
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	
	s.listener = listener
	log.Printf("[Server] Listening on %s", address)
	
	// Accept connections
	for {
		select {
		case <-s.shutdown:
			return nil
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.shutdown:
					return nil
				default:
					log.Printf("[Server] Error accepting connection: %v", err)
					continue
				}
			}
			
			// Handle connection in a goroutine
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handler.HandleConnection(conn)
			}()
		}
	}
}

// Stop stops the paysys server
func (s *PaysysServer) Stop() {
	log.Println("[Server] Shutting down...")
	
	close(s.shutdown)
	
	if s.listener != nil {
		s.listener.Close()
	}
	
	// Wait for all connections to finish
	s.wg.Wait()
	
	log.Println("[Server] Shutdown complete")
}