package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"jx2-paysys/internal/config"
	"jx2-paysys/internal/database"
	"jx2-paysys/internal/protocol"
	"jx2-paysys/internal/server"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("paysys.ini")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database connection
	db, err := database.NewConnection(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize protocol handler
	protocolHandler := protocol.NewHandler(db)

	// Create and start the paysys server
	paysysServer := server.NewPaysysServer(cfg.Paysys.IP, cfg.Paysys.Port, protocolHandler)

	// Start server in a goroutine
	go func() {
		if err := paysysServer.Start(); err != nil {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	fmt.Printf("[Paysys] Server started on %s:%d\n", cfg.Paysys.IP, cfg.Paysys.Port)
	fmt.Printf("[Database] Connected to MySQL at %s:%d\n", cfg.Database.IP, cfg.Database.Port)

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("\n[Paysys] Shutting down server...")
	paysysServer.Stop()
}