package protocol

import (
	"log"
	"net"
	"sync"
	"time"

	"jx2-paysys/internal/database"
)

// BishopSession represents an active Bishop session
type BishopSession struct {
	ID        string
	Conn      net.Conn
	StartTime time.Time
	LastActivity time.Time
	BishopID  [16]byte
}

// Handler handles protocol operations
type Handler struct {
	db             *database.Connection
	bishopSessions map[string]*BishopSession
	sessionMutex   sync.RWMutex
}

// NewHandler creates a new protocol handler
func NewHandler(db *database.Connection) *Handler {
	return &Handler{
		db:             db,
		bishopSessions: make(map[string]*BishopSession),
	}
}

// HandleConnection handles a new client connection
func (h *Handler) HandleConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()
	log.Printf("[Protocol] New connection from %s", clientAddr)
	
	// Based on Bishop error logs, the client initiates the security handshake
	// The Bishop client expects to send a request first, not receive unsolicited data
	// So we wait for the client to send the first packet
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("[Protocol] Error reading initial packet from %s: %v", clientAddr, err)
		conn.Close()
		return
	}
	
	data := buffer[:n]
	log.Printf("[Protocol] Received initial %d bytes from %s", n, clientAddr)
	log.Printf("[Protocol] Raw data: %x", data)
	
	// Parse the packet
	packet, err := ParsePacket(data)
	if err != nil {
		log.Printf("[Protocol] Error parsing packet from %s: %v", clientAddr, err)
		conn.Close()
		return
	}
	
	// Handle based on packet type
	switch p := packet.(type) {
	case *BishopLoginPacket:
		// Bishop requests security key exchange - send the security key response
		log.Printf("[Protocol] Bishop requesting security key exchange")
		securityKeyPacket := h.createSecurityKeyPacket()
		
		log.Printf("[Protocol] Sending security key to %s (%d bytes)", clientAddr, len(securityKeyPacket))
		log.Printf("[Protocol] Security key data: %x", securityKeyPacket)
		
		_, err := conn.Write(securityKeyPacket)
		if err != nil {
			log.Printf("[Protocol] Failed to send security key to %s: %v", clientAddr, err)
			conn.Close()
			return
		}
		
		// Now continue with Bishop session management
		h.handleBishopConnection(conn, p, clientAddr)
		// handleBishopConnection manages its own connection lifecycle
	case *UserLoginPacket:
		// User login connections are short-lived
		response := h.handleUserLogin(p, clientAddr)
		if response != nil {
			conn.Write(response)
		}
		conn.Close()
	default:
		log.Printf("[Protocol] Unknown packet type from %s", clientAddr)
		conn.Close()
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
	defer conn.Close() // Ensure connection is closed when this function exits
	
	log.Printf("[Protocol] Bishop login from %s", clientAddr)
	log.Printf("[Protocol] Bishop ID: %x", packet.BishopID)
	log.Printf("[Protocol] Unknown fields: %08x %08x %08x", packet.Unknown1, packet.Unknown2, packet.Unknown3)
	
	// Create and register Bishop session
	sessionID := clientAddr // Use client address as session ID for now
	session := &BishopSession{
		ID:           sessionID,
		Conn:         conn,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		BishopID:     packet.BishopID,
	}
	
	h.sessionMutex.Lock()
	h.bishopSessions[sessionID] = session
	h.sessionMutex.Unlock()
	
	defer func() {
		// Clean up session when connection ends
		h.sessionMutex.Lock()
		delete(h.bishopSessions, sessionID)
		h.sessionMutex.Unlock()
		log.Printf("[Protocol] Bishop session %s cleaned up", sessionID)
	}()
	
	// Send Bishop authentication response
	response := CreateBishopResponse(0) // 0 = success
	_, err := conn.Write(response)
	if err != nil {
		log.Printf("[Protocol] Error sending Bishop response to %s: %v", clientAddr, err)
		return
	}
	log.Printf("[Protocol] Sent %d bytes Bishop response to %s", len(response), clientAddr)
	log.Printf("[Protocol] Response data: %x", response)
	
	// Bishop session established
	log.Printf("[Protocol] Bishop session %s established, managing connection for %s", sessionID, clientAddr)
	
	// Bishop connections require persistent session management
	// Keep reading for additional packets and handle session state
	buffer := make([]byte, 4096)
	sessionActive := true
	
	for sessionActive {
		// Set a longer timeout for Bishop sessions - they may have periods of inactivity
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute)) // 5 minute timeout
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[Protocol] Bishop session %s timeout (no activity for 5 minutes)", sessionID)
			} else {
				log.Printf("[Protocol] Bishop session %s ended: %v", sessionID, err)
			}
			sessionActive = false
			break
		}
		
		if n > 0 {
			// Update session activity
			h.sessionMutex.Lock()
			if sess, exists := h.bishopSessions[sessionID]; exists {
				sess.LastActivity = time.Now()
			}
			h.sessionMutex.Unlock()
			
			data := buffer[:n]
			log.Printf("[Protocol] Bishop session %s packet: %d bytes", sessionID, n)
			log.Printf("[Protocol] Data: %x", data)
			
			// Parse and handle session packets
			sessionPacket, err := ParsePacket(data)
			if err != nil {
				log.Printf("[Protocol] Error parsing Bishop session packet: %v", err)
				// Don't break session for parsing errors, just log and continue
				continue
			}
			
			// Handle different packet types during Bishop session
			switch sp := sessionPacket.(type) {
			case *BishopLoginPacket:
				// Re-authentication request - respond with success
				log.Printf("[Protocol] Bishop re-authentication in session %s", sessionID)
				reAuthResponse := CreateBishopResponse(0)
				_, err := conn.Write(reAuthResponse)
				if err != nil {
					log.Printf("[Protocol] Error sending Bishop re-auth response: %v", err)
					sessionActive = false
				}
			case *UserLoginPacket:
				// User login request via Bishop connection
				log.Printf("[Protocol] User login via Bishop session %s", sessionID)
				userResponse := h.handleUserLogin(sp, clientAddr)
				if userResponse != nil {
					_, err := conn.Write(userResponse)
					if err != nil {
						log.Printf("[Protocol] Error sending user login response via Bishop: %v", err)
						sessionActive = false
					}
				}
			default:
				log.Printf("[Protocol] Unknown packet type in Bishop session %s, sending ACK", sessionID)
				// Send a simple acknowledgment for unknown packets
				ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK packet
				conn.Write(ackResponse)
			}
		}
	}
	
	log.Printf("[Protocol] Bishop session %s ended", sessionID)
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

// GetActiveBishopSessions returns information about active Bishop sessions
func (h *Handler) GetActiveBishopSessions() map[string]*BishopSession {
	h.sessionMutex.RLock()
	defer h.sessionMutex.RUnlock()
	
	sessions := make(map[string]*BishopSession)
	for id, session := range h.bishopSessions {
		sessions[id] = &BishopSession{
			ID:           session.ID,
			StartTime:    session.StartTime,
			LastActivity: session.LastActivity,
			BishopID:     session.BishopID,
			// Don't copy the connection object for safety
		}
	}
	return sessions
}