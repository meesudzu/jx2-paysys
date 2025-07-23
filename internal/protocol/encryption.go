package protocol

import (
	"fmt"
	"strings"
)

// DecryptXOR performs XOR decryption on login data
// Based on analysis of the player login PCAP, there appears to be a repeating pattern
func DecryptXOR(data []byte) []byte {
	// From PCAP analysis, I can see repeating patterns that suggest XOR encryption
	// The pattern "457377292fda9a211052b19c70930ea0" appears multiple times
	// This suggests a fixed XOR key is being used
	
	// Extract the presumed XOR key from the repeating pattern
	// Looking at the encrypted data, we can see patterns that repeat
	xorKey := extractXORKey(data)
	if len(xorKey) == 0 {
		// Fallback to a default key if pattern extraction fails
		xorKey = []byte{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0}
	}
	
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	
	return result
}

// extractXORKey tries to extract the XOR key from repeating patterns
func extractXORKey(data []byte) []byte {
	// Look for the repeating pattern in the encrypted data
	// Pattern: 457377292fda9a211052b19c70930ea0 (16 bytes)
	pattern := []byte{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0}
	
	// Find this pattern in the encrypted data
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			// Found the pattern, this suggests it might be XORed with zeros
			// or it's the actual key. Let's return it as the key.
			return pattern
		}
	}
	
	return nil
}

// EncryptXOR performs XOR encryption on response data
func EncryptXOR(data []byte) []byte {
	// Use the same key for encryption
	xorKey := []byte{0x45, 0x73, 0x77, 0x29, 0x2f, 0xda, 0x9a, 0x21, 0x10, 0x52, 0xb1, 0x9c, 0x70, 0x93, 0x0e, 0xa0}
	
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	
	return result
}

// ParseLoginData parses decrypted login data to extract username and password
func ParseLoginData(decryptedData []byte) (username, password string, err error) {
	// Remove null bytes and non-printable characters
	cleanData := make([]byte, 0, len(decryptedData))
	for _, b := range decryptedData {
		if b >= 32 && b <= 126 { // Printable ASCII characters
			cleanData = append(cleanData, b)
		} else if b == 0 {
			cleanData = append(cleanData, 0) // Keep null terminators
		}
	}
	
	// Split by null bytes to find strings
	parts := strings.Split(string(cleanData), "\x00")
	validParts := make([]string, 0)
	
	for _, part := range parts {
		if len(part) > 0 && len(part) < 256 { // Reasonable length for username/password
			validParts = append(validParts, part)
		}
	}
	
	// Typically, username comes first, then password
	if len(validParts) >= 2 {
		username = validParts[0]
		password = validParts[1]
		return username, password, nil
	} else if len(validParts) >= 1 {
		// Only one string found, might be username only
		username = validParts[0]
		return username, "", nil
	}
	
	return "", "", fmt.Errorf("could not parse login data")
}

// CreateEncryptedLoginResponse creates an encrypted login response
func CreateEncryptedLoginResponse(result uint8, message string) []byte {
	// Create response data
	responseData := make([]byte, 0, 256)
	responseData = append(responseData, result)
	responseData = append(responseData, []byte(message)...)
	responseData = append(responseData, 0) // Null terminator
	
	// Pad to a reasonable size
	for len(responseData) < 64 {
		responseData = append(responseData, 0)
	}
	
	// Encrypt the response
	encryptedData := EncryptXOR(responseData)
	
	// Create packet header
	header := PacketHeader{
		Size: uint16(4 + len(encryptedData)),
		Type: PacketTypeUserResponse,
	}
	
	// Combine header and encrypted data
	result_packet := make([]byte, 0, int(header.Size))
	result_packet = append(result_packet, byte(header.Size&0xFF), byte((header.Size>>8)&0xFF))
	result_packet = append(result_packet, byte(header.Type&0xFF), byte((header.Type>>8)&0xFF))
	result_packet = append(result_packet, encryptedData...)
	
	return result_packet
}