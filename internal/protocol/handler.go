package protocol

import (
	"log"
	"net"
	"time"

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
	
	// Based on the working JavaScript implementation and the original paysys,
	// we need to immediately send a security key packet to all new connections
	// Bishop connections expect this as the first thing
	securityKeyPacket := h.createSecurityKeyPacket()
	
	log.Printf("[Protocol] Sending security key to %s (%d bytes)", clientAddr, len(securityKeyPacket))
	log.Printf("[Protocol] Security key data: %x", securityKeyPacket)
	
	_, err := conn.Write(securityKeyPacket)
	if err != nil {
		log.Printf("[Protocol] Failed to send security key to %s: %v", clientAddr, err)
		return
	}
	
	// Now handle the client's response
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
	switch p := packet.(type) {
	case *BishopLoginPacket:
		h.handleBishopConnection(conn, p, clientAddr)
	case *UserLoginPacket:
		response := h.handleUserLogin(p, clientAddr)
		if response != nil {
			conn.Write(response)
		}
	default:
		log.Printf("[Protocol] Unknown packet type from %s", clientAddr)
	}
}

// createSecurityKeyPacket creates the security key packet that Bishop expects
func (h *Handler) createSecurityKeyPacket() []byte {
	// From working JavaScript implementation:
	// 34-byte packet with header 0x22, 0x00, 0x20, 0x00 (size=34, protocol=0x2000)
	// Includes 8-byte security key and 16 bytes of padding
	packet := []byte{
		0x22, 0x00, 0x20, 0x00, // Header: size=34, protocol=0x2000 (CIPHER_PROTOCOL_TYPE)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
		// Security key (8 bytes) - using same pattern as working capture
		0xf5, 0x4d, 0x3f, 0xc9, 0x5a, 0xcf, 0xb2, 0x5e,
		// Padding (16 zero bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	return packet
}

func (h *Handler) handleBishopConnection(conn net.Conn, packet *BishopLoginPacket, clientAddr string) {
	log.Printf("[Protocol] Bishop login from %s", clientAddr)
	log.Printf("[Protocol] Bishop ID: %x", packet.BishopID)
	log.Printf("[Protocol] Unknown fields: %08x %08x %08x", packet.Unknown1, packet.Unknown2, packet.Unknown3)
	
	// Send Bishop authentication response
	response := CreateBishopResponse(0) // 0 = success
	_, err := conn.Write(response)
	if err != nil {
		log.Printf("[Protocol] Error sending Bishop response to %s: %v", clientAddr, err)
		return
	}
	log.Printf("[Protocol] Sent %d bytes Bishop response to %s", len(response), clientAddr)
	log.Printf("[Protocol] Response data: %x", response)
	
	// For Bishop connections, keep the connection alive and handle additional packets
	log.Printf("[Protocol] Bishop connection established, keeping connection alive for %s", clientAddr)
	
	// Bishop connections may expect additional handshake or ongoing communication
	// Keep reading for additional packets
	buffer := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second)) // 30 second timeout
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[Protocol] Bishop connection timeout for %s", clientAddr)
			} else {
				log.Printf("[Protocol] Bishop connection closed by %s: %v", clientAddr, err)
			}
			break
		}
		
		if n > 0 {
			data := buffer[:n]
			log.Printf("[Protocol] Bishop follow-up packet from %s: %d bytes", clientAddr, n)
			log.Printf("[Protocol] Data: %x", data)
			
			// Parse and handle additional packets
			followupPacket, err := ParsePacket(data)
			if err != nil {
				log.Printf("[Protocol] Error parsing Bishop follow-up packet: %v", err)
				continue
			}
			
			// Handle different packet types from Bishop
			switch followupPacket.(type) {
			case *BishopLoginPacket:
				// Duplicate login - just ack again
				conn.Write(CreateBishopResponse(0))
			default:
				log.Printf("[Protocol] Unknown Bishop packet type, ignoring")
			}
		}
	}
	
	log.Printf("[Protocol] Bishop connection handler ending for %s", clientAddr)
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
		
		// Check account locked state (0 = not locked, 1 = locked)
		lockedState, err := h.db.GetAccountState(username)
		if err != nil {
			log.Printf("[Protocol] Error getting account state for %s: %v", username, err)
			response := CreateEncryptedLoginResponse(2, "Account state error")
			return response
		}
		
		if lockedState != 0 {
			log.Printf("[Protocol] Account %s is locked (locked: %d)", username, lockedState)
			response := CreateEncryptedLoginResponse(4, "Account locked")
			return response
		}
	} else {
		// No database mode - accept all logins for testing
		log.Printf("[Protocol] No database mode - accepting login for %s", username)
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