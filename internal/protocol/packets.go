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
	PacketTypeBishopResponse PacketType = 0x0021
	
	// User login packets  
	PacketTypeUserLogin      PacketType = 0x42FF  // From PCAP analysis 
	PacketTypeUserResponse   PacketType = 0xA8FF  // From PCAP response analysis
	
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

// BishopLoginPacket represents Bishop login request
type BishopLoginPacket struct {
	Header PacketHeader
	Unknown1 uint32   // Always seems to be 0x20000000 based on PCAP
	Unknown2 uint32   // Always seems to be 0x00000000
	Unknown3 uint32   // Varies - possibly session ID or timestamp
	BishopID [16]byte // Bishop identifier or auth data
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
	case PacketTypeBishopLogin:
		return parseBishopLoginPacket(data)
	case PacketTypeUserLogin:
		return parseUserLoginPacket(data)
	default:
		return nil, fmt.Errorf("unknown packet type: 0x%04X", header.Type)
	}
}

func parseBishopLoginPacket(data []byte) (*BishopLoginPacket, error) {
	if len(data) < 34 { // 4 bytes header + 4 + 4 + 4 + 16 bytes data
		return nil, fmt.Errorf("bishop login packet too short")
	}

	packet := &BishopLoginPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}
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

// CreateBishopResponse creates a bishop response packet with security key
func CreateBishopResponse(result uint8) []byte {
	// Bishop client expects security key data after the result
	// Based on error "_RecvSecurityKey", we need to provide key material
	securityKey := [16]byte{
		0x45, 0x73, 0x77, 0x29, 0x2F, 0xDA, 0x9A, 0x21,
		0x10, 0x52, 0xB1, 0x9C, 0x70, 0x93, 0x0E, 0xA0,
	}
	
	// Additional session data (common in game protocols)
	sessionData := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	
	header := PacketHeader{
		Size: 4 + 1 + 16 + 8, // header(4) + result(1) + key(16) + session(8) = 29
		Type: PacketTypeBishopResponse,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, header)
	binary.Write(buf, binary.LittleEndian, result)
	buf.Write(securityKey[:])
	buf.Write(sessionData[:])

	return buf.Bytes()
}