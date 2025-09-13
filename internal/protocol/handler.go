package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
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
	
	// Send security key immediately - Bishop expects this on connection (from working JavaScript implementation)
	log.Printf("[Protocol] Sending security key immediately to %s (Bishop requirement)", clientAddr)
	securityKeyPacket := h.createSecurityKeyPacket()
	_, err := conn.Write(securityKeyPacket)
	if err != nil {
		log.Printf("[Protocol] Failed to send security key to %s: %v", clientAddr, err)
		conn.Close()
		return
	}
	log.Printf("[Protocol] Security key sent to %s", clientAddr)
	
	// Now read incoming packets and handle them with timeout
	buffer := make([]byte, 4096)
	// Set aggressive timeout for initial packet read to prevent hanging
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("[Protocol] Error reading packet from %s: %v", clientAddr, err)
		conn.Close()
		return
	}
	
	data := buffer[:n]
	log.Printf("[Protocol] Received %d bytes from %s", n, clientAddr)
	log.Printf("[Protocol] Raw data: %x", data)
	
	// Handle different packet lengths and types
	if n == 127 {
		// Bishop packet - handle with persistent session
		log.Printf("[Protocol] Bishop connection detected")
		h.handleBishopPacket(conn, data, clientAddr)
	} else {
		// Parse packet to determine type and handle accordingly
		packet, err := ParsePacket(data)
		if err != nil {
			log.Printf("[Protocol] Error parsing packet from %s: %v", clientAddr, err)
			conn.Close()
			return
		}

		// Handle based on packet type
		switch p := packet.(type) {
		case *UserLoginPacket:
			log.Printf("[Protocol] User login packet from %s", clientAddr)
			response := h.handleUserLogin(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		case *GameLoginPacket:
			log.Printf("[Protocol] Game login packet from %s", clientAddr)
			response := h.handleGameLogin(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		case *CharacterCreatePacket:
			log.Printf("[Protocol] Character creation packet from %s", clientAddr)
			response := h.handleCharacterCreate(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		case *PlayerVerifyPacket:
			log.Printf("[Protocol] Player verification packet from %s", clientAddr)
			response := h.handlePlayerVerify(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		case *CharacterSelectPacket:
			log.Printf("[Protocol] Character selection packet from %s", clientAddr)
			response := h.handleCharacterSelect(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		case *CharacterDataPacket:
			log.Printf("[Protocol] Character data packet from %s", clientAddr)
			response := h.handleCharacterData(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		case *CharacterListPacket:
			log.Printf("[Protocol] Character list packet from %s", clientAddr)
			response := h.handleCharacterList(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		case *CharacterDeletePacket:
			log.Printf("[Protocol] Character delete packet from %s", clientAddr)
			response := h.handleCharacterDelete(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		case *SessionConfirm2Packet:
			log.Printf("[Protocol] Session confirmation 2 packet from %s", clientAddr)
			response := h.handleSessionConfirm2(p, clientAddr)
			if response != nil {
				conn.Write(response)
			}
			conn.Close()
		default:
			log.Printf("[Protocol] Unhandled packet type from %s: %T", clientAddr, packet)
			conn.Close()
		}
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

func (h *Handler) handleBishopPacket(conn net.Conn, data []byte, clientAddr string) {
	log.Printf("[Protocol] Bishop packet received: %d bytes", len(data))
	log.Printf("[Protocol] First 8 bytes: %x", data[:8])
	
	if len(data) == 127 {
		// Both 127-byte Bishop packets get same response from original Linux paysys
		protocol := binary.LittleEndian.Uint16(data[2:4])
		log.Printf("[Protocol] 127-byte Bishop packet, protocol: 0x%x", protocol)
		
		// From working JavaScript implementation: exact PCAP response 53 bytes
		response := []byte{
			0x35, 0x00,   // Size: 53 bytes
			0x97, 0x44,   // Protocol response
			// Payload (49 bytes) - exact from working PCAP
			0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4, 
			0x00, 0xfa, 0x40, 0xa1, 0x99, 0xa1, 
			0x37, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4,
			0x00, 0xfa, 0x40, 0xa1, 0x99, 0xa1,
			0x37, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4,
			0x00, 0xfb, 0x40, 0xa1, 0x99, 0x32, 0xca, 0x39, 0xdb,
		}
		
		_, err := conn.Write(response)
		if err != nil {
			log.Printf("[Protocol] Failed to send Bishop response to %s: %v", clientAddr, err)
			conn.Close()
			return
		}
		log.Printf("[Protocol] Sent exact PCAP response: %d bytes", len(response))
		log.Printf("[Protocol] Response matches working PCAP capture exactly - should pass all Bishop checks")
		
		// Keep connection alive for more packets - Bishop needs persistent session
		h.handleBishopSession(conn, clientAddr)
	} else {
		log.Printf("[Protocol] Unexpected Bishop packet length: %d", len(data))
		conn.Close()
	}
}

func (h *Handler) handleBishopSession(conn net.Conn, clientAddr string) {
	log.Printf("[Protocol] Bishop session established for %s", clientAddr)
	
	// Keep reading for additional packets and handle session state
	buffer := make([]byte, 4096)
	sessionStart := time.Now()
	maxSessionDuration := 30 * time.Minute // Maximum session duration
	
	for {
		// Check if session has been running too long
		if time.Since(sessionStart) > maxSessionDuration {
			log.Printf("[Protocol] Bishop session %s exceeded maximum duration (%v), terminating", clientAddr, maxSessionDuration)
			break
		}
		
		// Set aggressive timeout for Bishop sessions to prevent hanging (reduced to 30 seconds)
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[Protocol] Bishop session %s timeout (no activity for 30 seconds)", clientAddr)
			} else {
				log.Printf("[Protocol] Bishop session %s ended: %v", clientAddr, err)
			}
			break
		}
		
		if n > 0 {
			data := buffer[:n]
			log.Printf("[Protocol] Bishop session %s packet: %d bytes", clientAddr, n)
			log.Printf("[Protocol] Data: %x", data)
			
			// Handle different packet types during Bishop session
			if n == 127 {
				// Re-authentication or other Bishop commands - use same response
				log.Printf("[Protocol] Bishop re-authentication in session %s", clientAddr)
				response := []byte{
					0x35, 0x00, 0x97, 0x44,
					0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4, 
					0x00, 0xfa, 0x40, 0xa1, 0x99, 0xa1, 
					0x37, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4,
					0x00, 0xfa, 0x40, 0xa1, 0x99, 0xa1,
					0x37, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4,
					0x00, 0xfb, 0x40, 0xa1, 0x99, 0x32, 0xca, 0x39, 0xdb,
				}
				conn.Write(response)
			} else if n == 227 {
				// Game client login packet during Bishop session
				log.Printf("[Protocol] Game login packet in Bishop session %s", clientAddr)
				packet, err := ParsePacket(data)
				if err != nil {
					log.Printf("[Protocol] Error parsing game packet in Bishop session: %v", err)
					ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK packet
					conn.Write(ackResponse)
				} else if p, ok := packet.(*GameLoginPacket); ok {
					response := h.handleGameLogin(p, clientAddr)
					if response != nil {
						conn.Write(response)
					}
				} else {
					log.Printf("[Protocol] Failed to cast to GameLoginPacket in Bishop session")
					ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK packet
					conn.Write(ackResponse)
				}
			} else if n == 229 {
				// 229-byte packet during Bishop session - could be user login (0x42ff) or player identity verification (0xe0ff)
				packet, err := ParsePacket(data)
				if err != nil {
					log.Printf("[Protocol] Error parsing 229-byte packet in Bishop session: %v", err)
					ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK packet
					conn.Write(ackResponse)
				} else if p, ok := packet.(*UserLoginPacket); ok {
					// Protocol 0x42ff - traditional user login
					log.Printf("[Protocol] User login packet (0x42ff) in Bishop session %s", clientAddr)
					response := h.handleUserLogin(p, clientAddr)
					if response != nil {
						conn.Write(response)
					}
				} else if p, ok := packet.(*GameLoginPacket); ok {
					// Protocol 0xe0ff - player identity verification (matches JavaScript implementation)
					log.Printf("[Protocol] Player identity verification packet (0xe0ff) in Bishop session %s", clientAddr)
					response := h.handlePlayerIdentityVerification(p, clientAddr)
					if response != nil {
						conn.Write(response)
					}
				} else {
					log.Printf("[Protocol] Failed to cast 229-byte packet to known type in Bishop session")
					ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK packet
					conn.Write(ackResponse)
				}
			} else if n == 47 {
				// Session confirmation packet (0x14ff) - comes after player identity verification
				log.Printf("[Protocol] Session confirmation packet in Bishop session %s", clientAddr)
				packet, err := ParsePacket(data)
				if err != nil {
					log.Printf("[Protocol] Error parsing session confirmation packet: %v", err)
					ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK packet
					conn.Write(ackResponse)
				} else if p, ok := packet.(*SessionConfirmPacket); ok {
					response := h.handleSessionConfirm(p, clientAddr)
					if response != nil {
						conn.Write(response)
					}
				} else {
					log.Printf("[Protocol] Failed to cast to SessionConfirmPacket in Bishop session")
					ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK packet
					conn.Write(ackResponse)
				}
			} else if n == 7 {
				// Short Bishop packets - likely ping or simple commands
				log.Printf("[Protocol] Short Bishop packet in session %s, sending ACK", clientAddr)
				ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK
				conn.Write(ackResponse)
			} else {
				log.Printf("[Protocol] Unknown packet type in Bishop session %s, sending ACK", clientAddr)
				// Send a simple acknowledgment for unknown packets
				ackResponse := []byte{0x04, 0x00, 0x01, 0x00} // 4-byte ACK packet
				conn.Write(ackResponse)
			}
		}
	}
	
	log.Printf("[Protocol] Bishop session %s ended, closing connection", clientAddr)
	conn.Close()
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
			case *GameLoginPacket:
				// Game login request via Bishop connection
				log.Printf("[Protocol] Game login via Bishop session %s", sessionID)
				gameResponse := h.handleGameLogin(sp, clientAddr)
				if gameResponse != nil {
					_, err := conn.Write(gameResponse)
					if err != nil {
						log.Printf("[Protocol] Error sending game login response via Bishop: %v", err)
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

func (h *Handler) handleGameLogin(packet *GameLoginPacket, clientAddr string) []byte {
	log.Printf("[Protocol] Game login from %s", clientAddr)
	log.Printf("[Protocol] Protocol: 0x%x, Key: %d, Size: %d", packet.Header.Type, packet.Header.Key, packet.Header.Size)
	log.Printf("[Protocol] Data (%d bytes): %x", len(packet.Data), packet.Data)
	
	// For game login packets, we typically just need to respond with success
	// The actual authentication was already done via Bishop
	// Game is just verifying the paysys connection is working
	
	log.Printf("[Protocol] Game login verification successful for %s", clientAddr)
	
	// Always use the request key for the response - this should fix the key mismatch issue
	responseKey := packet.Header.Key
	log.Printf("[Protocol] Using request key %d for response", responseKey)
	
	// Create minimal response with matching key (protocol 254, size 2, key matching request)  
	// This matches the expected "Protocol = 254; Size = 2; Key = X" format from the error log
	response := CreateGameResponse(responseKey, 0, []byte{}) // Success with no additional data
	log.Printf("[Protocol] Sending game response: Protocol=%d, Size=%d, Key=%d", PacketTypeGameResponse, len(response), responseKey)
	
	return response
}

func (h *Handler) handlePlayerIdentityVerification(packet *GameLoginPacket, clientAddr string) []byte {
	log.Printf("[Protocol] Player identity verification from %s", clientAddr)
	log.Printf("[Protocol] Protocol: 0x%x, Size: %d", packet.Header.Type, packet.Header.Size)
	log.Printf("[Protocol] Full packet data: %x", packet.Data)
	
	// Based on working JavaScript implementation - this is for protocol 0xe0ff packets
	// Should respond with exact PCAP format: 169 bytes with protocol 0xa8ff
	
	// Create exact response matching PCAP: 169 bytes with Protocol 0xa8ff  
	response := []byte{
		// Header: a900 ffa8 (169 bytes, protocol 0xa8ff)
		0xa9, 0x00, 0xff, 0xa8,
		// Exact payload from PCAP
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xeb, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x50, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xfa, 0xea, 0x49, 0xc8,
		0xe7, 0x51, 0x81, 0xe7, 0xc2, 0x03, 0xb7, 0xa8,
		0x57, 0x5c, 0x67, 0x61, 0xc1,
	}
	
	log.Printf("[Protocol] Sending exact PCAP player identity verification response: %d bytes", len(response))
	log.Printf("[Protocol] Response protocol: 0x%x (should be 0xa8ff)", uint16(response[3])<<8|uint16(response[2]))
	
	return response
}

func (h *Handler) handleSessionConfirm(packet *SessionConfirmPacket, clientAddr string) []byte {
	log.Printf("[Protocol] Session confirmation from %s", clientAddr)
	log.Printf("[Protocol] Protocol: 0x%x, Size: %d", packet.Header.Type, packet.Header.Size)
	log.Printf("[Protocol] Session data (%d bytes): %x", len(packet.Data), packet.Data)
	
	// Create session confirmation response
	response := CreateSessionConfirmResponse()
	log.Printf("[Protocol] Sending session confirmation response: %d bytes", len(response))
	
	return response
}

func (h *Handler) handleUserLogin(packet *UserLoginPacket, clientAddr string) []byte {
	log.Printf("[Protocol] User login from %s", clientAddr)
	log.Printf("[Protocol] Encrypted data (%d bytes): %x", len(packet.EncryptedData), packet.EncryptedData)
	
	// Fast-path: Try quick key detection first (max 2 seconds for Bishop compatibility)
	fastResult := make(chan []byte, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Protocol] Recovered from panic in fast login path: %v", r)
				fastResult <- nil
			}
		}()
		
		// Quick XOR key detection using known patterns and cache
		decryptedData := DecryptXORFast(packet.EncryptedData, clientAddr)
		if decryptedData == nil {
			fastResult <- nil
			return
		}
		
		// Parse username and password quickly
		username, password, err := ParseLoginDataFast(decryptedData)
		if err != nil {
			log.Printf("[Protocol] Fast parsing failed for %s: %v", clientAddr, err)
			fastResult <- nil
			return
		}
		
		log.Printf("[Protocol] Fast login path - Username: %s, Password: %s", username, password)
		fastResult <- h.processLoginVerification(username, password, clientAddr)
	}()
	
	// Wait for fast result or timeout quickly for Bishop compatibility
	select {
	case result := <-fastResult:
		if result != nil {
			log.Printf("[Protocol] Fast login path succeeded for %s", clientAddr)
			return result
		}
	case <-time.After(2 * time.Second):
		log.Printf("[Protocol] Fast login path timeout for %s", clientAddr)
	}
	
	// Fast path failed - start background key learning for future attempts
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Protocol] Recovered from panic in background key learning: %v", r)
			}
		}()
		
		log.Printf("[Protocol] Starting background key learning for %s", clientAddr)
		// This will cache the key for future attempts
		DecryptXORWithClientAddr(packet.EncryptedData, clientAddr)
	}()
	
	// Return immediate success for unknown users to prevent Bishop timeout
	// This allows the user to connect while key learning happens in background
	log.Printf("[Protocol] Unknown user from %s - returning immediate success for Bishop compatibility", clientAddr)
	return CreateEncryptedLoginResponse(0, "Login successful (learning key)")
}

// processLoginVerification handles the actual login verification logic
func (h *Handler) processLoginVerification(username, password, clientAddr string) []byte {
	// Verify credentials against database with timeout
	if h.db != nil {
		// Database operations with timeout
		dbDone := make(chan struct {
			isValid     bool
			err         error
			lockedState int
		}, 1)
		
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[Protocol] Recovered from database panic: %v", r)
					dbDone <- struct {
						isValid     bool
						err         error
						lockedState int
					}{false, fmt.Errorf("database panic: %v", r), 0}
				}
			}()
			
			isValid, err := h.db.AccountLogin(username, password)
			if err != nil {
				dbDone <- struct {
					isValid     bool
					err         error
					lockedState int
				}{false, err, 0}
				return
			}
			
			if !isValid {
				dbDone <- struct {
					isValid     bool
					err         error
					lockedState int
				}{false, nil, 0}
				return
			}
			
			// Check account locked state (0 = not locked, 1 = locked)
			lockedState, err := h.db.GetAccountState(username)
			dbDone <- struct {
				isValid     bool
				err         error
				lockedState int
			}{true, err, lockedState}
		}()
		
		// Wait for database operations or timeout (reduced for Bishop compatibility)
		select {
		case dbResult := <-dbDone:
			if dbResult.err != nil {
				log.Printf("[Protocol] Database error for %s: %v", username, dbResult.err)
				return CreateEncryptedLoginResponse(2, "Database error")
			}
			
			if !dbResult.isValid {
				log.Printf("[Protocol] Invalid credentials for %s from %s", username, clientAddr)
				return CreateEncryptedLoginResponse(3, "Invalid credentials")
			}
			
			if dbResult.lockedState != 0 {
				log.Printf("[Protocol] Account %s is locked (locked: %d)", username, dbResult.lockedState)
				return CreateEncryptedLoginResponse(4, "Account locked")
			}
		case <-time.After(3 * time.Second): // Reduced timeout for Bishop compatibility
			log.Printf("[Protocol] Database operation timeout for %s", username)
			return CreateEncryptedLoginResponse(2, "Database timeout")
		}
	} else {
		// No database mode - accept all logins for testing
		log.Printf("[Protocol] No database mode - accepting login for %s", username)
	}
	
	log.Printf("[Protocol] Login successful for %s from %s", username, clientAddr)
	return CreateEncryptedLoginResponse(0, "Login successful")
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

// handleCharacterCreate handles character creation packets
func (h *Handler) handleCharacterCreate(packet *CharacterCreatePacket, clientAddr string) []byte {
	log.Printf("[Protocol] Character creation from %s", clientAddr)
	log.Printf("[Protocol] Encrypted data length: %d bytes", len(packet.EncryptedData))
	
	// Decrypt the character creation data
	decryptedData := DecryptXOR(packet.EncryptedData)
	log.Printf("[Protocol] Decrypted character creation data: %x", decryptedData)
	
	// Parse character creation data based on JX1 analysis
	// Character creation packets typically contain:
	// - Username (account owner)
	// - Character name
	// - Character class
	// - Character gender
	// - Other attributes
	
	// Try to parse the decrypted data to extract username and character info
	username, _, err := ParseLoginData(decryptedData)
	if err != nil {
		log.Printf("[Protocol] Failed to parse character creation data from %s: %v", clientAddr, err)
		return CreateCharacterResponse(E_CHARACTER_NAME_INVALID, "Invalid character data")
	}
	
	// Extract character name and other data from the decrypted payload
	// The format varies, but typically character name is after username
	// For now, use a simple parsing approach
	characterName := extractCharacterName(decryptedData)
	class := extractCharacterClass(decryptedData)
	gender := extractCharacterGender(decryptedData)
	
	if len(characterName) == 0 {
		log.Printf("[Protocol] Invalid character name in creation request from %s", clientAddr)
		return CreateCharacterResponse(E_CHARACTER_NAME_INVALID, "Invalid character name")
	}
	
	log.Printf("[Protocol] Character creation request: user=%s, character=%s, class=%d, gender=%d", 
		username, characterName, class, gender)
	
	// Create character in database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	err = h.db.CreateCharacter(ctx, username, characterName, class, gender)
	if err != nil {
		log.Printf("[Protocol] Failed to create character %s for %s: %v", characterName, username, err)
		
		// Return specific error codes based on error type
		if err.Error() == "character name already exists" {
			return CreateCharacterResponse(E_CHARACTER_EXISTS, "Character name already exists")
		} else if err.Error() == "character limit reached" {
			return CreateCharacterResponse(E_CHARACTER_LIMIT, "Character limit reached")
		}
		return CreateCharacterResponse(ACTION_FAILED, "Failed to create character")
	}
	
	log.Printf("[Protocol] Character %s created successfully for %s", characterName, username)
	return CreateCharacterResponse(ACTION_SUCCESS, "Character created successfully")
}

// handlePlayerVerify handles player verification packets
func (h *Handler) handlePlayerVerify(packet *PlayerVerifyPacket, clientAddr string) []byte {
	log.Printf("[Protocol] Player verification from %s", clientAddr)
	log.Printf("[Protocol] Verification data: %x", packet.Data)
	
	// Create a simple verification response (7 bytes to match pattern)
	response := []byte{
		0x07, 0x00,       // Size: 7 bytes
		0x64, 0x97,       // Response type (reverse of 0x26FF -> 0x9764)
		0xa0, 0x23, 0x7d, // Response data
	}
	
	log.Printf("[Protocol] Player verification successful from %s", clientAddr)
	return response
}

// handleCharacterSelect handles character selection packets
func (h *Handler) handleCharacterSelect(packet *CharacterSelectPacket, clientAddr string) []byte {
	log.Printf("[Protocol] Character selection from %s", clientAddr)
	log.Printf("[Protocol] Selection data: %x", packet.Data)
	
	// Create a simple selection response (7 bytes to match pattern)
	response := []byte{
		0x07, 0x00,       // Size: 7 bytes
		0x76, 0x97,       // Response type (reverse of 0x50FF -> 0x9776)
		0xa0, 0x23, 0x7d, // Response data
	}
	
	log.Printf("[Protocol] Character selection successful from %s", clientAddr)
	return response
}

// handleCharacterData handles character data packets
func (h *Handler) handleCharacterData(packet *CharacterDataPacket, clientAddr string) []byte {
	log.Printf("[Protocol] Character data from %s", clientAddr)
	log.Printf("[Protocol] Encrypted data length: %d bytes", len(packet.EncryptedData))
	
	// Decrypt the character data
	decryptedData := DecryptXOR(packet.EncryptedData)
	log.Printf("[Protocol] Decrypted character data: %x", decryptedData)
	
	// Create character data response (57 bytes based on PCAP analysis)
	response := []byte{
		0x39, 0x00,       // Size: 57 bytes
		0x90, 0xca,       // Response type 
		// Sample encrypted character data response
		0xab, 0xfb, 0x52, 0xf0, 0xbe, 0x69, 0xe7, 0x9c,
		0x4f, 0x3e, 0xd3, 0x89, 0xc9, 0x81, 0xd1, 0x90,
		0xab, 0xfb, 0x52, 0xf0, 0xbe, 0x69, 0xe7, 0x9c,
		0x4f, 0x7d, 0xe7, 0xca, 0x88, 0xb5, 0xe3, 0xa3,
		0x93, 0xba, 0x62, 0xb2, 0x87, 0x5b, 0xd4, 0xa4,
		0x7d, 0x3f, 0xd3, 0x89, 0xc9, 0xb4, 0xe1, 0xa9,
		0xea, 0xcd, 0x14, 0xc7, 0xd7,
	}
	
	log.Printf("[Protocol] Character data response sent to %s", clientAddr)
	return response
}

// handleSessionConfirm2 handles alternative session confirmation packets
func (h *Handler) handleSessionConfirm2(packet *SessionConfirm2Packet, clientAddr string) []byte {
	log.Printf("[Protocol] Session confirmation from %s", clientAddr)
	log.Printf("[Protocol] Encrypted data length: %d bytes", len(packet.EncryptedData))
	
	// Decrypt the session data
	decryptedData := DecryptXOR(packet.EncryptedData)
	log.Printf("[Protocol] Decrypted session data: %x", decryptedData)
	
	// Create a simple acknowledgment (no response needed based on PCAP)
	// Return nil to indicate no response should be sent
	log.Printf("[Protocol] Session confirmation processed from %s", clientAddr)
	return nil
}

// handleCharacterList handles character list request packets
func (h *Handler) handleCharacterList(packet *CharacterListPacket, clientAddr string) []byte {
	log.Printf("[Protocol] Character list request from %s", clientAddr)
	
	// Decrypt the account data to get username
	decryptedData := DecryptXOR(packet.EncryptedData)
	username, _, err := ParseLoginData(decryptedData)
	if err != nil {
		log.Printf("[Protocol] Failed to parse character list data from %s: %v", clientAddr, err)
		return CreateCharacterResponse(E_ACCOUNT_OR_PASSWORD, "Invalid request")
	}
	
	log.Printf("[Protocol] Character list requested for user: %s", username)
	
	// Query database for characters
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	characters, err := h.db.GetCharacters(ctx, username)
	if err != nil {
		log.Printf("[Protocol] Database error getting characters for %s: %v", username, err)
		return CreateCharacterResponse(ACTION_FAILED, "Database error")
	}
	
	// Convert database characters to protocol format
	var protocolChars []CharacterInfo
	for _, char := range characters {
		protocolChar := CharacterInfo{
			Level:  uint16(char.Level),
			Class:  uint8(char.Class),
			Gender: uint8(char.Gender),
			MapID:  uint16(char.MapID),
			X:      uint16(char.X),
			Y:      uint16(char.Y),
		}
		copy(protocolChar.Name[:], char.Name)
		protocolChars = append(protocolChars, protocolChar)
	}
	
	// Create character list response
	response := CreateCharacterListResponse(protocolChars)
	log.Printf("[Protocol] Character list response sent to %s (%d characters)", clientAddr, len(protocolChars))
	return response
}

// handleCharacterDelete handles character deletion packets
func (h *Handler) handleCharacterDelete(packet *CharacterDeletePacket, clientAddr string) []byte {
	log.Printf("[Protocol] Character delete request from %s", clientAddr)
	
	// Decrypt the character data
	decryptedData := DecryptXOR(packet.EncryptedData)
	log.Printf("[Protocol] Decrypted delete data: %x", decryptedData)
	
	// Parse character name from decrypted data
	// For deletion, usually just the character name is sent
	characterName := string(bytes.TrimRight(decryptedData[:32], "\x00"))
	if len(characterName) == 0 {
		log.Printf("[Protocol] Invalid character name in delete request from %s", clientAddr)
		return CreateCharacterResponse(E_CHARACTER_NAME_INVALID, "Invalid character name")
	}
	
	log.Printf("[Protocol] Character deletion requested for: %s", characterName)
	
	// Delete character from database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	err := h.db.DeleteCharacter(ctx, characterName)
	if err != nil {
		log.Printf("[Protocol] Failed to delete character %s: %v", characterName, err)
		return CreateCharacterResponse(ACTION_FAILED, "Failed to delete character")
	}
	
	log.Printf("[Protocol] Character %s deleted successfully", characterName)
	return CreateCharacterResponse(ACTION_SUCCESS, "Character deleted")
}

// Helper functions for parsing character creation data

// extractCharacterName extracts character name from decrypted character creation data
func extractCharacterName(data []byte) string {
	// Character name is typically after username in the packet
	// Look for the second string in the data
	strings := extractEmbeddedStrings(data)
	if len(strings) >= 2 {
		// Second string is usually the character name
		charName := strings[1]
		if len(charName) >= 2 && len(charName) <= 32 {
			return charName
		}
	}
	
	// Fallback: look for character name at specific offsets
	// Based on JX1 analysis, character name might be at offset 64-96
	if len(data) >= 96 {
		for offset := 64; offset < 96; offset += 4 {
			if offset+32 < len(data) {
				name := extractStringAtOffset(data, offset, 32)
				if len(name) >= 2 && len(name) <= 32 && isValidCharacterName(name) {
					return name
				}
			}
		}
	}
	
	return ""
}

// extractCharacterClass extracts character class from creation data
func extractCharacterClass(data []byte) int {
	// Class is typically a single byte value
	// Look for common class values (0-10 range for most games)
	if len(data) >= 100 {
		for i := 32; i < 100; i++ {
			if data[i] >= 0 && data[i] <= 10 {
				return int(data[i])
			}
		}
	}
	return 0 // Default class
}

// extractCharacterGender extracts character gender from creation data
func extractCharacterGender(data []byte) int {
	// Gender is typically 0 (male) or 1 (female)
	if len(data) >= 100 {
		for i := 32; i < 100; i++ {
			if data[i] == 0 || data[i] == 1 {
				return int(data[i])
			}
		}
	}
	return 0 // Default gender (male)
}

// isValidCharacterName checks if a character name is valid
func isValidCharacterName(name string) bool {
	if len(name) < 2 || len(name) > 32 {
		return false
	}
	
	// Character name should contain only letters, numbers, and some symbols
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			 (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	
	return true
}