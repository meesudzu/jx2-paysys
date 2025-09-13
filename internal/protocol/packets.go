package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

// PacketType represents different packet types
type PacketType uint16

// JX1/JX2 Protocol Constants (based on JX1 Paysys source analysis)
const (
	// Protocol ranges from JX1 source
	C2S_ACCOUNT_BEGIN     = 0x10
	C2S_MULTISERVER_BEGIN = 0x20
	
	// JX1-style account protocol packets
	C2S_ACCOUNT_LOGIN   = C2S_ACCOUNT_BEGIN + 0x01  // 0x11
	C2S_GAME_LOGIN      = C2S_ACCOUNT_BEGIN + 0x02  // 0x12  
	C2S_ACCOUNT_LOGOUT  = C2S_ACCOUNT_BEGIN + 0x03  // 0x13
	C2S_GATEWAY_VERIFY  = C2S_ACCOUNT_BEGIN + 0x04  // 0x14
	C2S_GATEWAY_VERIFY_AGAIN = C2S_ACCOUNT_BEGIN + 0x05  // 0x15
	C2S_PING            = 0x08
	
	// Server to client responses
	S2C_ACCOUNT_LOGIN_RET = 0x81
	S2C_GAME_LOGIN_RET    = 0x82
	S2C_GATEWAY_VERIFY    = 0x84
	S2C_PING              = 0x88
)

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
	
	// Session/Follow-up packets
	PacketTypeSessionConfirm PacketType = 0x14ff  // 47-byte session confirmation packet after player identity verification
	
	// Character and player management packets (from new PCAP analysis)
	PacketTypeCharacterCreate  PacketType = 0xDDFF  // Character creation packet (229 bytes)
	PacketTypePlayerVerify     PacketType = 0x26FF  // Player verification packet (7 bytes)
	PacketTypeCharacterSelect  PacketType = 0x50FF  // Character selection packet (7 bytes)
	PacketTypeCharacterData    PacketType = 0xDBFF  // Character data packet (61 bytes)
	PacketTypeSessionConfirm2  PacketType = 0x9DFF  // Alternative session confirmation (47 bytes)
	PacketTypeCharacterList    PacketType = 0xDCFF  // Character list request
	PacketTypeCharacterDelete  PacketType = 0xDEFF  // Character deletion request
	
	// Account management packets (enhanced with JX1 patterns)
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

// JX1-style response codes
const (
	ACTION_SUCCESS            = 0x1
	ACTION_FAILED             = 0x2
	E_ACCOUNT_OR_PASSWORD     = 0x3
	E_ACCOUNT_EXIST           = 0x4
	E_ACCOUNT_NODEPOSIT       = 0x5  // No deposit/coins
	E_ACCOUNT_ACCESSDENIED    = 0x6
	E_ADDRESS_OR_PORT         = 0x7
	E_ACCOUNT_FREEZE          = 0x8
	E_CHARACTER_NAME_INVALID  = 0x9
	E_CHARACTER_EXISTS        = 0xA
	E_CHARACTER_LIMIT         = 0xB
	E_SERVER_FULL             = 0xC
)

// JX1-style Account Header (based on KAccountHead structure)
type AccountHeader struct {
	Size    uint16    // Size of the struct
	Version uint16    // Account current version (1)
	Type    uint16    // Packet type
	Operate uint32    // Gateway used (operation ID)
}

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

// JX1-style structured login packets
const (
	LOGIN_USER_ACCOUNT_MIN_LEN  = 4
	LOGIN_USER_ACCOUNT_MAX_LEN  = 32
	LOGIN_USER_PASSWORD_MIN_LEN = 6
	LOGIN_USER_PASSWORD_MAX_LEN = 64
	ACCOUNT_CURRENT_VERSION     = 1
)

// AccountUser represents basic account structure (based on KAccountUser)
type AccountUser struct {
	Header  AccountHeader
	Account [LOGIN_USER_ACCOUNT_MAX_LEN]byte // Account name
}

// AccountUserLoginInfo represents login information (based on KAccountUserLoginInfo)
type AccountUserLoginInfo struct {
	Header   AccountHeader
	Account  [LOGIN_USER_ACCOUNT_MAX_LEN]byte  // Account name
	Password [LOGIN_USER_PASSWORD_MAX_LEN]byte // Password
}

// AccountUserReturn represents login response (based on KAccountUserReturn)
type AccountUserReturn struct {
	Header  AccountHeader
	Account [LOGIN_USER_ACCOUNT_MAX_LEN]byte // Account name
	Result  int32                            // Return code
}

// AccountUserReturnExt represents extended login response (based on KAccountUserReturnExt)
type AccountUserReturnExt struct {
	Header    AccountHeader
	Account   [LOGIN_USER_ACCOUNT_MAX_LEN]byte // Account name
	Result    int32                            // Return code
	ExtPoint  uint16                           // Extension points
	LeftTime  uint32                           // Remaining time in seconds
}

// Character management structures
type CharacterInfo struct {
	Name     [32]byte  // Character name
	Level    uint16    // Character level
	Class    uint8     // Character class
	Gender   uint8     // Character gender
	MapID    uint16    // Current map
	X        uint16    // X coordinate
	Y        uint16    // Y coordinate
	Reserved [16]byte  // Reserved for future use
}

type CharacterCreateInfo struct {
	Name   [32]byte // Character name
	Class  uint8    // Character class  
	Gender uint8    // Character gender
	Face   uint8    // Face type
	Hair   uint8    // Hair type
}

type CharacterListResponse struct {
	Header    AccountHeader
	Count     uint8                      // Number of characters
	Characters [8]CharacterInfo          // Maximum 8 characters per account
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

// SessionConfirmPacket represents session confirmation packet (47 bytes)
type SessionConfirmPacket struct {
	Header PacketHeader
	Data   []byte // Session confirmation data
}

// GameLoginPacket represents game client login verification packet
type GameLoginPacket struct {
	Header ExtendedPacketHeader
	Data   []byte // Game login data
}

// LoginResponse represents login response
type LoginResponse struct {
	Header PacketHeader
	Result uint8    // Login result: 0=success, 1=failed, etc.
	Data   []byte   // Additional response data
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

// CharacterCreatePacket represents character creation request (encrypted)
type CharacterCreatePacket struct {
	Header PacketHeader
	EncryptedData []byte // XOR encrypted character creation data
}

// PlayerVerifyPacket represents player verification request (7 bytes)
type PlayerVerifyPacket struct {
	Header PacketHeader
	Data   []byte // Small verification data
}

// CharacterSelectPacket represents character selection request (7 bytes)
type CharacterSelectPacket struct {
	Header PacketHeader
	Data   []byte // Character selection data
}

// CharacterDataPacket represents character data packet (61 bytes)
type CharacterDataPacket struct {
	Header PacketHeader
	EncryptedData []byte // XOR encrypted character data
}

// SessionConfirm2Packet represents alternative session confirmation (47 bytes)
type SessionConfirm2Packet struct {
	Header PacketHeader
	EncryptedData []byte // XOR encrypted session data
}

// ParsePacket parses incoming packet data
func ParsePacket(data []byte) (interface{}, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short")
	}

	// For packets that have keys (game packets), we need to read the extended header first
	// Let's check the protocol type to determine the header format
	protocol := binary.LittleEndian.Uint16(data[2:4])
	
	// Protocol 62 (0x003E) and 0xe0ff are game packets with extended headers (8 bytes)
	if protocol == 0x003E || protocol == 0xe0ff {
		if len(data) < 8 {
			return nil, fmt.Errorf("game packet too short for extended header")
		}
		return parseGameLoginPacket(data)
	}

	// Other packets use basic header (4 bytes)
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
	case PacketTypeSessionConfirm:
		return parseSessionConfirmPacket(data)
	case PacketTypeCharacterCreate:
		return parseCharacterCreatePacket(data)
	case PacketTypePlayerVerify:
		return parsePlayerVerifyPacket(data)
	case PacketTypeCharacterSelect:
		return parseCharacterSelectPacket(data)
	case PacketTypeCharacterData:
		return parseCharacterDataPacket(data)
	case PacketTypeSessionConfirm2:
		return parseSessionConfirm2Packet(data)
	case PacketTypeCharacterList:
		return parseCharacterListPacket(data)
	case PacketTypeCharacterDelete:
		return parseCharacterDeletePacket(data)
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
	
	// Game login packets use ExtendedPacketHeader (with key field)
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is game login data
	packet.Data = make([]byte, len(data)-8)
	copy(packet.Data, data[8:])

	return packet, nil
}

func parseSessionConfirmPacket(data []byte) (*SessionConfirmPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("session confirm packet too short")
	}

	packet := &SessionConfirmPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is session confirmation data
	packet.Data = make([]byte, len(data)-4)
	copy(packet.Data, data[4:])

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

// CreateSessionConfirmResponse creates a session confirmation response
func CreateSessionConfirmResponse() []byte {
	// Create a simple success response for session confirmation
	// Based on pattern of other successful responses, using a small response
	header := PacketHeader{
		Size: 6, // header(4) + result(1) + padding(1)
		Type: PacketType(0x15ff), // Response type (incrementing from request 0x14ff)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, header)
	binary.Write(buf, binary.LittleEndian, uint8(0)) // Success
	binary.Write(buf, binary.LittleEndian, uint8(0)) // Padding

	return buf.Bytes()
}

// CreateGameResponse creates a game response packet with matching key
func CreateGameResponse(key uint32, result uint8, data []byte) []byte {
	// Based on Bishop logs expecting "Protocol = 254; Size = 2; Key = X"
	// Size = 2 means 2-byte payload, so total packet = header(8) + payload(2) = 10 bytes
	
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

// parseCharacterCreatePacket parses character creation packet
func parseCharacterCreatePacket(data []byte) (*CharacterCreatePacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("character create packet too short")
	}

	packet := &CharacterCreatePacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is encrypted character creation data
	packet.EncryptedData = make([]byte, len(data)-4)
	copy(packet.EncryptedData, data[4:])

	return packet, nil
}

// parsePlayerVerifyPacket parses player verification packet
func parsePlayerVerifyPacket(data []byte) (*PlayerVerifyPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("player verify packet too short")
	}

	packet := &PlayerVerifyPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is verification data
	packet.Data = make([]byte, len(data)-4)
	copy(packet.Data, data[4:])

	return packet, nil
}

// parseCharacterSelectPacket parses character selection packet
func parseCharacterSelectPacket(data []byte) (*CharacterSelectPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("character select packet too short")
	}

	packet := &CharacterSelectPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is selection data
	packet.Data = make([]byte, len(data)-4)
	copy(packet.Data, data[4:])

	return packet, nil
}

// parseCharacterDataPacket parses character data packet
func parseCharacterDataPacket(data []byte) (*CharacterDataPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("character data packet too short")
	}

	packet := &CharacterDataPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is encrypted character data
	packet.EncryptedData = make([]byte, len(data)-4)
	copy(packet.EncryptedData, data[4:])

	return packet, nil
}

// CharacterListPacket represents character list request
type CharacterListPacket struct {
	Header PacketHeader
	EncryptedData []byte // XOR encrypted account data
}

// CharacterDeletePacket represents character deletion request
type CharacterDeletePacket struct {
	Header PacketHeader
	EncryptedData []byte // XOR encrypted character name/ID
}

// parseCharacterListPacket parses character list request packet
func parseCharacterListPacket(data []byte) (*CharacterListPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("character list packet too short")
	}

	packet := &CharacterListPacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is encrypted account data
	packet.EncryptedData = make([]byte, len(data)-4)
	copy(packet.EncryptedData, data[4:])

	return packet, nil
}

// parseCharacterDeletePacket parses character deletion packet
func parseCharacterDeletePacket(data []byte) (*CharacterDeletePacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("character delete packet too short")
	}

	packet := &CharacterDeletePacket{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is encrypted character data
	packet.EncryptedData = make([]byte, len(data)-4)
	copy(packet.EncryptedData, data[4:])

	return packet, nil
}

// CreateCharacterListResponse creates a character list response
func CreateCharacterListResponse(characters []CharacterInfo) []byte {
	// Create JX1-style structured response
	headerSize := 8 // Size of AccountHeader
	characterSize := 64 // Approximate size per character
	totalSize := headerSize + 1 + (len(characters) * characterSize) + 8*characterSize // Add space for max 8 characters
	
	response := CharacterListResponse{
		Header: AccountHeader{
			Size:    uint16(totalSize),
			Version: ACCOUNT_CURRENT_VERSION,
			Type:    uint16(PacketTypeCharacterList),
			Operate: 0,
		},
		Count: uint8(len(characters)),
	}
	
	// Copy character data (max 8 characters)
	for i, char := range characters {
		if i >= 8 {
			break
		}
		response.Characters[i] = char
	}
	
	// Serialize to bytes
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, response)
	return buf.Bytes()
}

// CreateCharacterResponse creates a character operation response
func CreateCharacterResponse(result uint8, message string) []byte {
	// Create structured response similar to JX1
	headerSize := 8 // Size of AccountHeader struct
	header := AccountHeader{
		Size:    uint16(headerSize + 1 + len(message)),
		Version: ACCOUNT_CURRENT_VERSION,
		Type:    uint16(PacketTypeCharacterCreate), // Will be adjusted based on operation
		Operate: 0,
	}
	
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, header)
	binary.Write(buf, binary.LittleEndian, result)
	buf.Write([]byte(message))
	
	return buf.Bytes()
}

// parseSessionConfirm2Packet parses alternative session confirmation packet
func parseSessionConfirm2Packet(data []byte) (*SessionConfirm2Packet, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("session confirm2 packet too short")
	}

	packet := &SessionConfirm2Packet{}
	buf := bytes.NewReader(data)
	
	if err := binary.Read(buf, binary.LittleEndian, &packet.Header); err != nil {
		return nil, err
	}

	// Rest is encrypted session data
	packet.EncryptedData = make([]byte, len(data)-4)
	copy(packet.EncryptedData, data[4:])

	return packet, nil
}

// CreateBishopVerifyResponse creates a proper Bishop verification response for ProcessVerifyReplyFromPaysys
func CreateBishopVerifyResponse(result uint8, message string) []byte {
	// Based on JX1 Paysys source analysis, Bishop expects a specific format
	// Use immediate compact response format to prevent timeout
	
	log.Printf("[Protocol] Creating Bishop verify response: result=%d, message=%s", result, message)
	
	if result == 0 {
		// Success response - JX1 compatible format for immediate processing
		response := []byte{
			0x0C, 0x00,      // Size: 12 bytes
			0xFF, 0x38,      // Response protocol 0x38FF (immediate response)
			0x00,            // Result code (0 = success)
			0x4F, 0x4B,      // "OK" status
			0x00, 0x00, 0x00, 0x00, 0x00, // Padding for alignment
		}
		log.Printf("[Protocol] Bishop success response: %d bytes, protocol 0x%04X", len(response), 0x38FF)
		return response
	} else {
		// Error response - also JX1 compatible
		response := []byte{
			0x0C, 0x00,      // Size: 12 bytes  
			0xFF, 0x38,      // Response protocol 0x38FF
			result,          // Result code (non-zero = error)
			0x46, 0x41, 0x49, 0x4C, // "FAIL"
			0x00, 0x00, 0x00, // Padding
		}
		log.Printf("[Protocol] Bishop error response: %d bytes, protocol 0x%04X", len(response), 0x38FF)
		return response
	}
}