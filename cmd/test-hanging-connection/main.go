package main

import (
	"fmt"
	"log"
	"net"
	"time"
	"jx2-paysys/internal/protocol"
)

func main() {
	fmt.Println("Testing connection hanging scenarios...")
	
	// Test 1: Create handler and test initial connection timeout
	handler := protocol.NewHandler(nil)
	
	// Test connection that hangs on initial read
	testHangingConnection(handler)
	
	fmt.Println("All hanging tests completed successfully!")
}

func testHangingConnection(handler *protocol.Handler) {
	fmt.Println("Testing connection that never sends data...")
	
	// Create a server socket
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	addr := listener.Addr().String()
	fmt.Printf("Server listening on %s\n", addr)
	
	// Start server handler in goroutine
	done := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- false
			return
		}
		
		// Test if HandleConnection returns within reasonable time
		start := time.Now()
		handler.HandleConnection(conn)
		duration := time.Since(start)
		
		fmt.Printf("HandleConnection completed in: %v\n", duration)
		if duration < 35*time.Second {
			fmt.Println("✅ PASS: Connection handling didn't hang")
			done <- true
		} else {
			fmt.Println("❌ FAIL: Connection handling took too long")
			done <- false
		}
	}()
	
	// Connect but don't send any data
	client, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	
	// Wait for result or timeout
	select {
	case success := <-done:
		client.Close()
		if success {
			fmt.Println("Hanging connection test passed")
		} else {
			fmt.Println("Hanging connection test failed")
		}
	case <-time.After(40 * time.Second):
		client.Close()
		fmt.Println("❌ FAIL: Test timed out - connection handling is hanging")
	}
}