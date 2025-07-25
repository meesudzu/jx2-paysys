package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PacketType represents different packet types
type PacketType uint16

const (
	// Bishop connection packets
	PacketTypeBishopLogin    PacketType = 0x0020  // From PCAP analysis
	PacketTypeBishopLoginAlt PacketType = 0x1D97  // Alternative Bishop login from actual Bishop binary
	PacketTypeBishopResponse PacketType = 0x0021
	
	// User login packets  
	PacketTypeUserLogin      PacketType = 0x42FF  // From PCAP analysis 
	PacketTypeUserResponse   PacketType = 0xA8FF  // From PCAP response analysis
	
	// Game client protocol packets (with key field)
	PacketTypeGameLogin      PacketType = 0x003E  // Protocol 62 - game client login verification
	PacketTypeGameLoginAlt   PacketType = 0xe0ff  // Alternative game login format from actual game client
	PacketTypeGameResponse   PacketType = 0x00FE  // Protocol 254 - game response
	
	// Account management packets (inferred from JX2 system)
	PacketTypeUserLogout     PacketType = 0x0001
	PacketTypeUserVerify     PacketType = 0x0002
	PacketTypeAccountExchange PacketType = 0x0003
	PacketTypeItemBuy        PacketType = 0x0004
	PacketTypeItemUse        PacketType = 0x0005
	PacketTypeCoinQuery      PacketType = 0x0006
	PacketTypeCoinUpdate     PacketType = 0x0007
	PacketTypeAccountInfo    PacketType = 0x0008
	PacketTypePasswordChange PacketType = 0x0009
	PacketTypeAccountLock    PacketType = 0x000A
	PacketTypeAccountUnlock  PacketType = 0x000B
)

// PacketHeader represents the common packet header
type PacketHeader struct {
	Size uint16      // Packet size
	Type PacketType  // Packet type
}

// ExtendedPacketHeader represents packet header with key for game client packets
type ExtendedPacketHeader struct {
	Size uint16      // Packet size
	Type PacketType  // Packet type
	Key  uint32      // Packet key for request/response matching
}

// BishopLoginPacket represents Bishop login request
type BishopLoginPacket struct {
	Header PacketHeader
	Unknown1 uint32   // Always seems to be 0x20000000 based on PCAP
	Unknown2 uint32   // Always seems to be 0x00000000
	Unknown3 uint32   // Varies - possibly session ID or timestamp
	BishopID [16]byte // Bishop identifier or auth data
}

// GameLoginPacket represents game client login verification packet
type GameLoginPacket struct {
	Header ExtendedPacketHeader
	Data   []byte // Game login data
}

// UserLoginPacket represents user login request (encrypted)
type UserLoginPacket struct {
	Header PacketHeader
	EncryptedData []byte // XOR encrypted login data
}

// LoginResponse represents login response
type LoginResponse struct {
	Header PacketHeader
	Result uint8    // Login result: 0=success, 1=failed, etc.
	Data   []byte   // Additional response data
}

// CoinQueryPacket represents coin balance query
type CoinQueryPacket struct {
	Header PacketHeader
	Username [32]byte // Username for coin query
}

// CoinUpdatePacket represents coin balance update
type CoinUpdatePacket struct {
	Header PacketHeader
	Username [32]byte // Username for coin update
	Amount   int64    // Coin amount change (positive or negative)
	Type     uint8    // Update type: 0=set, 1=add, 2=subtract
}

// AccountInfoPacket represents account information request
type AccountInfoPacket struct {
	Header PacketHeader
	Username [32]byte // Username for info query
}

// PasswordChangePacket represents password change request
type PasswordChangePacket struct {
	Header PacketHeader
	EncryptedData []byte // XOR encrypted: username + old_password + new_password
}

// ParsePacket parses incoming packet data
func ParsePacket(data []byte) (interface{}, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short")
	}

	// Read header
	var header PacketHeader
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Validate packet size
	if int(header.Size) != len(data) {
		return nil, fmt.Errorf("packet size mismatch: expected %d, got %d", header.Size, len(data))
	}

	// Parse based on packet type
	switch header.Type {
	case PacketTypeBishopLogin, PacketTypeBishopLoginAlt:
		return parseBishopLoginPacket(data)
	case PacketTypeUserLogin:
		return parseUserLoginPacket(data)
	case PacketTypeGameLogin, PacketTypeGameLoginAlt:
		return parseGameLoginPacket(data)
	default:
		return nil, fmt.Errorf("unknown packet type: 0x%04X", header.Type)
	}
}

func parseBishopLoginPacket(data []byte) (*BishopLoginPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("bishop login packet too short")
	}

	packet := &BishopLoginPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}
	
	// Handle different Bishop packet structures based on size
	if len(data) >= 34 {
		// Original structure for 34-byte packets
		if err := binary.Read(buf, binary.LittleEndian, &packet.Unknown1); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &packet.Unknown2); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &packet.Unknown3); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &packet.BishopID); err != nil {
			return nil, err
		}
	} else {
		// For shorter packets, just read what we can
		remainingData := make([]byte, len(data)-4)
		if _, err := buf.Read(remainingData); err != nil {
			return nil, err
		}
		// Store first 16 bytes as Bishop ID if available
		if len(remainingData) >= 16 {
			copy(packet.BishopID[:], remainingData[:16])
		}
	}

	return packet, nil
}

func parseGameLoginPacket(data []byte) (*GameLoginPacket, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("game login packet too short")
	}

	packet := &GameLoginPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is game login data
	packet.Data = make([]byte, len(data)-8)
	copy(packet.Data, data[8:])

	return packet, nil
}

func parseUserLoginPacket(data []byte) (*UserLoginPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("user login packet too short")
	}

	packet := &UserLoginPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is encrypted data
	packet.EncryptedData = make([]byte, len(data)-4)
	copy(packet.EncryptedData, data[4:])

	return packet, nil
}

// CreateLoginResponse creates a login response packet
func CreateLoginResponse(result uint8, additionalData []byte) []byte {
	header := PacketHeader{
		Size: uint16(4 + 1 + len(additionalData)),
		Type: PacketTypeUserResponse,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, header)
	binary.Write(buf, binary.LittleEndian, result)
	buf.Write(additionalData)

	return buf.Bytes()
}

// CreateBishopResponse creates a Bishop response packet
func CreateBishopResponse(result uint8) []byte {
	// According to the working JavaScript implementation, Bishop response should be:
	// Response type 0x971E with 32-byte payload
	header := PacketHeader{
		Size: 36, // header(4) + payload(32)
		Type: PacketType(0x971E), // Response type from JavaScript implementation
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, header)
	
	// Create 32-byte response payload like the JavaScript version
	responseData := make([]byte, 32)
	binary.LittleEndian.PutUint32(responseData[0:], 1) // Success code
	copy(responseData[4:], []byte("PAYSYS_OK")) // Status message
	
	buf.Write(responseData)
	return buf.Bytes()
}

// CreateGameResponse creates a game response packet with matching key
func CreateGameResponse(key uint32, result uint8, data []byte) []byte {
	// Based on Bishop logs, it expects "Protocol = 254; Size = 2; Key = X"
	// This suggests a 2-byte payload (likely just a status code)
	payload := make([]byte, 2)
	payload[0] = result  // Status code
	payload[1] = 0       // Reserved/padding
	
	header := ExtendedPacketHeader{
		Size: uint16(8 + len(payload)), // header(8) + payload(2) = 10 total
		Type: PacketTypeGameResponse,    // Protocol 254
		Key:  key,                      // Match the request key
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, header)
	buf.Write(payload)
	
	return buf.Bytes()
}