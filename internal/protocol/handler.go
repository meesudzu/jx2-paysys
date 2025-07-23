package protocol

import (
	"log"
	"net"

	"jx2-paysys/internal/database"
)

// Handler handles protocol operations
type Handler struct {
	db *database.Connection
}

// NewHandler creates a new protocol handler
func NewHandler(db *database.Connection) *Handler {
	return &Handler{db: db}
}

// HandleConnection handles a new client connection
func (h *Handler) HandleConnection(conn net.Conn) {
	defer conn.Close()
	
	clientAddr := conn.RemoteAddr().String()
	log.Printf("[Protocol] New connection from %s", clientAddr)
	
	// Read packet data
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("[Protocol] Error reading from %s: %v", clientAddr, err)
		return
	}
	
	data := buffer[:n]
	log.Printf("[Protocol] Received %d bytes from %s", n, clientAddr)
	log.Printf("[Protocol] Raw data: %x", data)
	
	// Parse the packet
	packet, err := ParsePacket(data)
	if err != nil {
		log.Printf("[Protocol] Error parsing packet from %s: %v", clientAddr, err)
		return
	}
	
	// Handle based on packet type
	var response []byte
	switch p := packet.(type) {
	case *BishopLoginPacket:
		response = h.handleBishopLogin(p, clientAddr)
	case *UserLoginPacket:
		response = h.handleUserLogin(p, clientAddr)
	default:
		log.Printf("[Protocol] Unknown packet type from %s", clientAddr)
		return
	}
	
	// Send response
	if response != nil {
		_, err = conn.Write(response)
		if err != nil {
			log.Printf("[Protocol] Error sending response to %s: %v", clientAddr, err)
		} else {
			log.Printf("[Protocol] Sent %d bytes response to %s", len(response), clientAddr)
			log.Printf("[Protocol] Response data: %x", response)
		}
	}
}

func (h *Handler) handleBishopLogin(packet *BishopLoginPacket, clientAddr string) []byte {
	log.Printf("[Protocol] Bishop login from %s", clientAddr)
	log.Printf("[Protocol] Bishop ID: %x", packet.BishopID)
	log.Printf("[Protocol] Unknown fields: %08x %08x %08x", packet.Unknown1, packet.Unknown2, packet.Unknown3)
	
	// For now, always accept Bishop connections
	// In a real implementation, you'd verify the Bishop ID against a whitelist
	response := CreateBishopResponse(0) // 0 = success
	log.Printf("[Protocol] Bishop login accepted for %s", clientAddr)
	
	return response
}

func (h *Handler) handleUserLogin(packet *UserLoginPacket, clientAddr string) []byte {
	log.Printf("[Protocol] User login from %s", clientAddr)
	log.Printf("[Protocol] Encrypted data (%d bytes): %x", len(packet.EncryptedData), packet.EncryptedData)
	
	// Decrypt the login data
	decryptedData := DecryptXOR(packet.EncryptedData)
	log.Printf("[Protocol] Decrypted data: %x", decryptedData)
	log.Printf("[Protocol] Decrypted as string: %q", string(decryptedData))
	
	// Parse username and password
	username, password, err := ParseLoginData(decryptedData)
	if err != nil {
		log.Printf("[Protocol] Error parsing login data from %s: %v", clientAddr, err)
		response := CreateEncryptedLoginResponse(1, "Failed to parse login data")
		return response
	}
	
	log.Printf("[Protocol] Login attempt - Username: %s, Password: %s", username, password)
	
	// Verify credentials against database
	if h.db != nil {
		isValid, err := h.db.AccountLogin(username, password)
		if err != nil {
			log.Printf("[Protocol] Database error for %s: %v", username, err)
			response := CreateEncryptedLoginResponse(2, "Database error")
			return response
		}
		
		if !isValid {
			log.Printf("[Protocol] Invalid credentials for %s from %s", username, clientAddr)
			response := CreateEncryptedLoginResponse(3, "Invalid credentials")
			return response
		}
		
		// Check account state
		state, err := h.db.GetAccountState(username)
		if err != nil {
			log.Printf("[Protocol] Error getting account state for %s: %v", username, err)
			response := CreateEncryptedLoginResponse(2, "Account state error")
			return response
		}
		
		if state != 0 {
			log.Printf("[Protocol] Account %s is banned/suspended (state: %d)", username, state)
			response := CreateEncryptedLoginResponse(4, "Account suspended")
			return response
		}
	}
	
	log.Printf("[Protocol] Login successful for %s from %s", username, clientAddr)
	response := CreateEncryptedLoginResponse(0, "Login successful")
	return response
}

// HandlePing handles ping packets to keep connections alive
func (h *Handler) HandlePing(conn net.Conn) {
	// Simple ping response - just echo back
	response := []byte{0x01, 0x00, 0x00, 0x00} // Simple ping response
	conn.Write(response)
}